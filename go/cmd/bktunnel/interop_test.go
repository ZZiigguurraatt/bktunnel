package main

// Interop tests exercise a real TLS handshake between the bash+stunnel
// implementation and this Go implementation across every role pairing —
// bash<->go, go<->bash, and bash<->bash — plus a wrong-pin rejection. They are
// the source of truth for wire compatibility. (Go<->go lives in e2e_test.go.)
//
// The bash side needs stunnel, xxd, openssl + the repo-root bktunnel script. If
// any is missing the tests fail (they do not skip), so a green run always means
// interop actually ran. Run them where the deps exist, from the go/ module:
// go test -run Interop -v ./...

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireInteropDeps fails the test unless stunnel, xxd, openssl and
// ../../../bktunnel exist. Missing deps are a failure, not a skip, so a green
// run always means interop was exercised. Returns the bash script's abs path.
func requireInteropDeps(t *testing.T) string {
	t.Helper()
	for _, bin := range []string{"stunnel", "xxd", "openssl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("interop test needs %q in PATH", bin)
		}
	}
	script, err := filepath.Abs("../../../bktunnel")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("bash script not found at %s", script)
	}
	return script
}

// requirePython fails the test unless python3 and the 'cryptography' package are
// available (the conformance probe builds its certs with cryptography).
func requirePython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatalf("conformance test needs python3 in PATH")
	}
	if out, err := exec.Command("python3", "-c", "import ssl, cryptography").CombinedOutput(); err != nil {
		t.Fatalf("conformance test needs the python 'cryptography' package "+
			"(pip install cryptography): %v\n%s", err, out)
	}
}

// pythonScript returns the abs path to the Python conformance impl, failing if
// it is missing.
func pythonScript(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../../conformance/bktunnel.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("python conformance impl not found at %s", p)
	}
	return p
}

// buildGoBinary compiles this package to a temp path and returns it.
func buildGoBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bktunnel-go")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// genKeypair returns a fresh base64 privkey and pubkey. Piped `-g -` prints only
// the bare private key, so the pubkey is derived from it with `-P`.
func genKeypair(t *testing.T, tool string) (priv, pub string) {
	t.Helper()
	out, err := exec.Command(tool, "-g", "-").Output()
	if err != nil {
		t.Fatalf("keygen (%s): %v", tool, err)
	}
	priv = strings.TrimSpace(string(out))
	pout, err := exec.Command(tool, "-k", priv, "-P").Output()
	if err != nil {
		t.Fatalf("derive pubkey (%s): %v", tool, err)
	}
	f := strings.Fields(string(pout)) // "pubkey <b64>"
	if priv == "" || len(f) < 2 {
		t.Fatalf("could not build keypair (priv=%q, pubout=%q)", priv, pout)
	}
	pub = f[len(f)-1]
	return priv, pub
}

// writeKey writes a base64 privkey to a 0600 temp file and returns its path.
func writeKey(t *testing.T, priv string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "privkey")
	if err := os.WriteFile(f, []byte(priv+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// freePort returns a currently-free 127.0.0.1:port (small race window is fine).
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// startEcho runs an in-process TCP echo backend and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

// startProc starts a tunnel process, capturing stderr and killing it on cleanup.
func startProc(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	var errb strings.Builder
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() && errb.Len() > 0 {
			t.Logf("%s stderr:\n%s", filepath.Base(name), errb.String())
		}
	})
}

// payloadSize is large enough to span many TCP segments and overflow the
// kernel/tunnel relay buffers, so a round-trip exercises real streaming rather
// than a single small write.
const payloadSize = 1 << 20 // 1 MiB

// testPayload builds a reproducible ~1 MiB blob. A fixed seed keeps runs
// identical (easy to debug), and the pseudo-random content spans the full
// 0x00–0xFF byte range — including NULs and newlines — so a clean echo proves
// the tunnel carries arbitrary binary data unchanged, not just printable text.
func testPayload() []byte {
	buf := make([]byte, payloadSize)
	rng := rand.New(rand.NewSource(1))
	_, _ = rng.Read(buf)
	return buf
}

// tryRoundTrip dials the client-side plaintext port, streams the full payload
// through the tunnel, and checks the exact same bytes echo back, retrying the
// connection until timeout. Returns nil on success.
func tryRoundTrip(addr string, timeout time.Duration) error {
	payload := testPayload()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Long enough to move a MiB over loopback, short enough that the
		// wrong-pin case (nothing ever echoes) keeps retrying and ultimately
		// fails via the outer timeout rather than hanging.
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		err = roundTrip(c, payload)
		c.Close()
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("no round-trip within %s: %v", timeout, lastErr)
}

// roundTrip writes payload while concurrently reading len(payload) bytes back,
// then checks they match. Reading and writing at once means a payload larger
// than the socket buffers can't deadlock (write-all-then-read-all would wedge
// once the return path fills). It reads an exact byte count rather than
// scanning for a newline, so the payload can be arbitrary binary. A single
// Read and a single Write on one net.Conn run safely in parallel.
func roundTrip(c net.Conn, payload []byte) error {
	got := make([]byte, len(payload))
	readErr := make(chan error, 1) // buffered: reader can finish after we return
	go func() {
		_, err := io.ReadFull(c, got)
		readErr <- err
	}()
	if _, err := c.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := <-readErr; err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("payload came back corrupted (%d bytes)", len(got))
	}
	return nil
}

// runPair wires up a server tunnel and a client tunnel (each either the bash
// script via `bash <script>` or the Go binary) and returns the client-side
// plaintext address to connect to. serverPin/clientPin let callers inject a
// wrong pin for the rejection test.
func runPair(t *testing.T, script, goBin, serverTool, clientTool, serverPin, clientPin string) string {
	backend := startEcho(t)
	sPriv, sPub := genKeypair(t, goBin)
	cPriv, cPub := genKeypair(t, goBin)
	if serverPin == "" {
		serverPin = cPub // server pins the client
	}
	if clientPin == "" {
		clientPin = sPub // client pins the server
	}
	p1 := freePort(t) // server: TLS accept
	p2 := freePort(t) // client: plaintext accept

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	invoke := func(tool string) []string {
		switch tool {
		case "bash":
			return []string{"bash", script}
		case "python":
			return []string{"python3", pythonScript(t)}
		}
		return []string{goBin}
	}
	srv := invoke(serverTool)
	cli := invoke(clientTool)

	startProc(t, ctx, srv[0], append(srv[1:],
		"-r", "server", "-a", p1, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", serverPin)...)
	startProc(t, ctx, cli[0], append(cli[1:],
		"-r", "client", "-a", p2, "-c", p1, "-k", "@"+writeKey(t, cPriv), "-p", clientPin)...)

	return p2
}

func TestInteropBashServerGoClient(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	addr := runPair(t, script, goBin, "bash", "go", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("bash server <-> go client: %v", err)
	}
}

func TestInteropGoServerBashClient(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	addr := runPair(t, script, goBin, "go", "bash", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("go server <-> bash client: %v", err)
	}
}

// TestInteropBashServerBashClient runs two bash+stunnel instances against each
// other. This pairing had no coverage before, which is how a broken pin scheme
// (stunnel rejecting the identity cert) went unnoticed: the Go<->go path never
// touches stunnel, so it takes bash on BOTH ends to exercise the bash/stunnel
// verification path itself — and to keep it working from here on.
func TestInteropBashServerBashClient(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	addr := runPair(t, script, goBin, "bash", "bash", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("bash server <-> bash client: %v", err)
	}
}

func TestInteropWrongPinRejected(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	// go client pins a key that is NOT the bash server's identity.
	_, wrongPub := genKeypair(t, goBin)
	addr := runPair(t, script, goBin, "bash", "go", "", wrongPub)
	if err := tryRoundTrip(addr, 5*time.Second); err == nil {
		t.Fatal("expected the tunnel to reject the peer with a wrong pin, but data flowed")
	}
}
