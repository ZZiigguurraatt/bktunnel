package main

// These tests exercise the `-g --pem` output (a self-signed PEM cert + PKCS#8
// key over the identity key) from the angle it exists for: a STOCK TLS client
// that presents those files and connects straight to a bktunnel server, with no
// bktunnel proxy on the client side. The server still authenticates by pinning
// the bare public key, so a clean round-trip proves the exported files carry the
// same identity as the base64 key. The Go stock-client case lives here (no extra
// deps); the Python stdlib-ssl case is in pem_conformance_test.go.
//
// Shared helper genKeypairPEM is defined here (untagged) so the conformance test
// can use it too.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// genKeypairPEM runs the Go binary's `-g FILE --pem` in a temp dir and returns
// the base64 public key plus the paths to the self-signed cert and PKCS#8 key it
// wrote. Those two files are what a proxy-less client presents.
func genKeypairPEM(t *testing.T, goBin string) (pub, certFile, keyFile string) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "id_ed25519")
	out, err := exec.Command(goBin, "-g", base, "--pem").Output()
	if err != nil {
		t.Fatalf("keygen --pem: %v", err)
	}
	f := strings.Fields(string(out)) // stdout is the shareable "pubkey <b64>" line
	if len(f) < 2 {
		t.Fatalf("keygen --pem: unexpected stdout %q", out)
	}
	return f[len(f)-1], base + ".crt", base + ".key"
}

// genKeypairPEMBash is genKeypairPEM's twin for the bash implementation: it runs
// `bash <script> -g FILE --pem` and returns the pubkey plus the cert/key paths.
// Proves the two implementations' --pem output is interchangeable.
func genKeypairPEMBash(t *testing.T, script string) (pub, certFile, keyFile string) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "id_ed25519")
	out, err := exec.Command("bash", script, "-g", base, "--pem").Output()
	if err != nil {
		t.Fatalf("bash keygen --pem: %v", err)
	}
	f := strings.Fields(string(out)) // stdout is the shareable "pubkey <b64>" line
	if len(f) < 2 {
		t.Fatalf("bash keygen --pem: unexpected stdout %q", out)
	}
	return f[len(f)-1], base + ".crt", base + ".key"
}

// tryRoundTripTLS is tryRoundTrip's TLS twin: it dials addr with cfg (presenting
// whatever client cert cfg carries), streams the payload, and checks the same
// bytes echo back, retrying the connection until timeout.
func tryRoundTripTLS(addr string, cfg *tls.Config, timeout time.Duration) error {
	payload := testPayload()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		d := &net.Dialer{Timeout: 300 * time.Millisecond}
		c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		err = roundTrip(c, payload)
		c.Close()
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("no TLS round-trip within %s: %v", timeout, lastErr)
}

// TestGoPEMStockClient connects a plain crypto/tls client (NOT the bktunnel
// client role) that loads FILE.crt/FILE.key straight to a bktunnel Go server. It
// is the in-language proof that the --pem files work with a stock TLS stack; the
// server pins the client's bare pubkey, so a round-trip means the cert
// authenticates the same identity as the base64 key.
func TestGoPEMStockClient(t *testing.T) {
	goBin := buildGoBinary(t)
	backend := startEcho(t)
	sPriv, _ := genKeypair(t, goBin)
	cPub, certFile, keyFile := genKeypairPEM(t, goBin)

	tlsAddr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// bktunnel server: accept TLS on tlsAddr, pin the client's pubkey, forward to echo.
	startProc(t, ctx, goBin,
		"-r", "server", "-a", tlsAddr, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", cPub)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load PEM keypair: %v", err)
	}
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // the server's pinned cert has no CA; we don't verify it here
		MinVersion:         tls.VersionTLS12,
	}
	if err := tryRoundTripTLS(tlsAddr, cfg, 15*time.Second); err != nil {
		t.Fatalf("stock TLS client with --pem cert: %v", err)
	}
}

// TestInteropPEMBashCert proves the bash implementation's --pem output is
// interchangeable with the Go one: a stock crypto/tls client loads the
// BASH-generated FILE.crt/FILE.key and authenticates to a Go bktunnel server.
func TestInteropPEMBashCert(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	backend := startEcho(t)
	sPriv, _ := genKeypair(t, goBin)
	cPub, certFile, keyFile := genKeypairPEMBash(t, script)

	tlsAddr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startProc(t, ctx, goBin,
		"-r", "server", "-a", tlsAddr, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", cPub)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load bash --pem keypair: %v", err)
	}
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	if err := tryRoundTripTLS(tlsAddr, cfg, 15*time.Second); err != nil {
		t.Fatalf("stock TLS client with bash --pem cert -> go server: %v", err)
	}
}

// TestInteropPEMCertBashServer proves a --pem cert authenticates against a
// bktunnel *server* run by the bash/stunnel implementation, not just the Go
// server. stunnel rejects a self-signed leaf outright, so this is the test that
// catches a regression to a self-signed exported cert (the distinct-issuer form
// is what makes it work here).
func TestInteropPEMCertBashServer(t *testing.T) {
	script := requireInteropDeps(t)
	goBin := buildGoBinary(t)
	backend := startEcho(t)
	sPriv, _ := genKeypair(t, goBin)
	cPub, certFile, keyFile := genKeypairPEM(t, goBin)

	tlsAddr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// bash/stunnel server pins the client's --pem pubkey.
	startProc(t, ctx, "bash", script,
		"-r", "server", "-a", tlsAddr, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", cPub)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load PEM keypair: %v", err)
	}
	// Present the cert unconditionally (as curl/openssl do). A bktunnel server
	// backed by stunnel sends acceptable-CA names in its CertificateRequest; Go's
	// default Certificates selection would filter our cert out (issuer doesn't
	// match) and send none — the same quirk the bktunnel client works around.
	cfg := &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
		InsecureSkipVerify:   true,
		MinVersion:           tls.VersionTLS12,
	}
	if err := tryRoundTripTLS(tlsAddr, cfg, 15*time.Second); err != nil {
		t.Fatalf("stock TLS client with --pem cert -> bash/stunnel server: %v", err)
	}
}

// TestGoPEMStockServer proves the other direction the README
// documents: the --pem files serve just as well as a stock TLS *server's*
// certificate. A plain crypto/tls listener (NOT the bktunnel server role) loads
// FILE.crt/FILE.key, and a bktunnel client that pins the server's bare pubkey
// connects through it. It also pins down the documented caveat: the stock server
// uses NoClientCert — it does not reproduce bktunnel's bare-pubkey client
// pinning — yet the tunnel still works because the bktunnel client authenticates
// the server by pin. Client authentication is what's given up on this side.
func TestGoPEMStockServer(t *testing.T) {
	goBin := buildGoBinary(t)
	sPub, sCert, sKey := genKeypairPEM(t, goBin)
	cPriv, _ := genKeypair(t, goBin)

	cert, err := tls.LoadX509KeyPair(sCert, sKey)
	if err != nil {
		t.Fatalf("load PEM keypair: %v", err)
	}
	// Stock TLS terminator: presents the --pem cert, does NO client-cert pinning,
	// and echoes the decrypted stream back (standing in for a real backend).
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	p2 := freePort(t) // bktunnel client's plaintext accept port
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// bktunnel CLIENT pins the stock server's bare pubkey with -p.
	startProc(t, ctx, goBin,
		"-r", "client", "-a", p2, "-c", ln.Addr().String(), "-k", "@"+writeKey(t, cPriv), "-p", sPub)

	if err := tryRoundTrip(p2, 15*time.Second); err != nil {
		t.Fatalf("bktunnel client <-> stock TLS server (--pem cert): %v", err)
	}
}
