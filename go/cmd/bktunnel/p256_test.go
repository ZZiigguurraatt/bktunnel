package main

// Tests for dual-algorithm identities: bktunnel peers using ECDSA P-256 (for
// browser/mobile clients that can't use Ed25519), Ed25519<->P-256 mixed mutual
// TLS, and a single server pinning both key types at once.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// genKeypairAlgo is genKeypair for a chosen algorithm ("ed25519" or "p256"):
// `-g - -t ALGO` prints the private key (labelled for non-default algos), and
// `-k <priv> -P` recovers the bare pubkey.
func genKeypairAlgo(t *testing.T, goBin, algo string) (priv, pub string) {
	t.Helper()
	out, err := exec.Command(goBin, "-g", "-", "-t", algo).Output()
	if err != nil {
		t.Fatalf("keygen (%s): %v", algo, err)
	}
	priv = strings.TrimSpace(string(out))
	pout, err := exec.Command(goBin, "-k", priv, "-P").Output()
	if err != nil {
		t.Fatalf("derive pubkey (%s): %v", algo, err)
	}
	f := strings.Fields(string(pout)) // "pubkey <b64>"
	if len(f) < 2 {
		t.Fatalf("derive pubkey (%s): unexpected output %q", algo, pout)
	}
	return priv, f[len(f)-1]
}

// runGoTunnel starts a Go bktunnel server (pinning the client) forwarding to an
// echo backend, and a Go bktunnel client (pinning the server); it returns the
// client's local plaintext address. Keys/algos are whatever the caller passes.
func runGoTunnel(t *testing.T, goBin, sPriv, sPub, cPriv, cPub string) string {
	t.Helper()
	backend := startEcho(t)
	p1 := freePort(t) // server TLS accept
	p2 := freePort(t) // client plaintext accept
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startProc(t, ctx, goBin,
		"-r", "server", "-a", p1, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", cPub)
	startProc(t, ctx, goBin,
		"-r", "client", "-a", p2, "-c", p1, "-k", "@"+writeKey(t, cPriv), "-p", sPub)
	return p2
}

// runPairAlgo is runGoTunnel generalized to any tool pairing: it generates both
// keys of the chosen algo (with the Go binary; the format is wire-compatible, so
// bash/python read them too) and wires a server+client pair from the named tools.
func runPairAlgo(t *testing.T, script, goBin, serverTool, clientTool, algo string) string {
	t.Helper()
	backend := startEcho(t)
	sPriv, sPub := genKeypairAlgo(t, goBin, algo)
	cPriv, cPub := genKeypairAlgo(t, goBin, algo)
	p1 := freePort(t)
	p2 := freePort(t)
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
	srv, cli := invoke(serverTool), invoke(clientTool)
	startProc(t, ctx, srv[0], append(srv[1:],
		"-r", "server", "-a", p1, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", cPub)...)
	startProc(t, ctx, cli[0], append(cli[1:],
		"-r", "client", "-a", p2, "-c", p1, "-k", "@"+writeKey(t, cPriv), "-p", sPub)...)
	return p2
}

func TestInteropP256GoServerBashClient(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	if err := tryRoundTrip(runPairAlgo(t, script, goBin, "go", "bash", "p256"), 15*time.Second); err != nil {
		t.Fatalf("go server <-> bash client (p256): %v", err)
	}
}

func TestInteropP256BashServerGoClient(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	if err := tryRoundTrip(runPairAlgo(t, script, goBin, "bash", "go", "p256"), 15*time.Second); err != nil {
		t.Fatalf("bash server <-> go client (p256): %v", err)
	}
}

// TestGoAuthorizedKeysSSHStyle pins via an ssh-style authorized_keys file that
// mixes key types, type-prefixed lines, a whole-line '#' comment, a blank line,
// a trailing free-text comment, and a trailing '#' comment.
func TestGoAuthorizedKeysSSHStyle(t *testing.T) {
	goBin := buildGoBinary(t)
	sPriv, sPub := genKeypairAlgo(t, goBin, "ed25519")
	cPriv, cPub := genKeypairAlgo(t, goBin, "p256")
	_, decoyPub := genKeypairAlgo(t, goBin, "ed25519")

	authFile := filepath.Join(t.TempDir(), "authorized_keys")
	content := "# team pins\n" +
		"ed25519 " + decoyPub + " decoy-peer\n" +
		"\n" +
		"p256 " + cPub + "   # browser client\n"
	if err := os.WriteFile(authFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	backend := startEcho(t)
	p1 := freePort(t)
	p2 := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startProc(t, ctx, goBin,
		"-r", "server", "-a", p1, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", "@"+authFile)
	startProc(t, ctx, goBin,
		"-r", "client", "-a", p2, "-c", p1, "-k", "@"+writeKey(t, cPriv), "-p", sPub)
	if err := tryRoundTrip(p2, 15*time.Second); err != nil {
		t.Fatalf("p256 client via ssh-style mixed authorized_keys: %v", err)
	}
}

func TestGoP256Tunnel(t *testing.T) {
	goBin := buildGoBinary(t)
	sPriv, sPub := genKeypairAlgo(t, goBin, "p256")
	cPriv, cPub := genKeypairAlgo(t, goBin, "p256")
	if err := tryRoundTrip(runGoTunnel(t, goBin, sPriv, sPub, cPriv, cPub), 15*time.Second); err != nil {
		t.Fatalf("p256 server <-> p256 client: %v", err)
	}
}

func TestGoMixedEd25519ServerP256Client(t *testing.T) {
	goBin := buildGoBinary(t)
	sPriv, sPub := genKeypairAlgo(t, goBin, "ed25519")
	cPriv, cPub := genKeypairAlgo(t, goBin, "p256")
	if err := tryRoundTrip(runGoTunnel(t, goBin, sPriv, sPub, cPriv, cPub), 15*time.Second); err != nil {
		t.Fatalf("ed25519 server <-> p256 client: %v", err)
	}
}

// TestGoMixedPins pins both an Ed25519 and a P-256 client on one server (mixed
// authorized_keys) and connects each in turn.
func TestGoMixedPins(t *testing.T) {
	goBin := buildGoBinary(t)
	sPriv, sPub := genKeypairAlgo(t, goBin, "ed25519")
	edPriv, edPub := genKeypairAlgo(t, goBin, "ed25519")
	ecPriv, ecPub := genKeypairAlgo(t, goBin, "p256")

	backend := startEcho(t)
	p1 := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startProc(t, ctx, goBin,
		"-r", "server", "-a", p1, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", edPub, "-p", ecPub)

	for _, c := range []struct{ name, priv string }{{"ed25519", edPriv}, {"p256", ecPriv}} {
		p2 := freePort(t)
		startProc(t, ctx, goBin,
			"-r", "client", "-a", p2, "-c", p1, "-k", "@"+writeKey(t, c.priv), "-p", sPub)
		if err := tryRoundTrip(p2, 15*time.Second); err != nil {
			t.Fatalf("%s client via mixed-pin server: %v", c.name, err)
		}
	}
}
