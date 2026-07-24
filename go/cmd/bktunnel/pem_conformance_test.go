//go:build conformance

package main

// Cross-implementation proof for the `-g --pem` output: a FOREIGN TLS stack
// (Python's stdlib `ssl`, OpenSSL under the hood) loads the Go-generated
// FILE.crt/FILE.key and connects straight to a bktunnel Go server, no bktunnel
// proxy on the client side. Unlike the other conformance tests this needs only
// python3 + stdlib ssl (NOT the `cryptography` package), because Python here is
// just a client presenting existing files, not minting keys.
//
// Gated behind the `conformance` tag because it shells out to python3; run with
// `go test -tags conformance`.

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// requirePythonSSL fails unless python3 with the stdlib ssl module is available.
// It deliberately does NOT require the cryptography package (this test only
// loads existing PEM files, it does not generate keys).
func requirePythonSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatalf("test needs python3 in PATH")
	}
	if out, err := exec.Command("python3", "-c", "import ssl").CombinedOutput(); err != nil {
		t.Fatalf("test needs python3 with the stdlib ssl module: %v\n%s", err, out)
	}
}

// pemClientPy is a minimal stdlib-ssl TLS client: load the cert/key, connect,
// send a deterministic payload, read the same number of bytes back, and exit
// non-zero on any mismatch. Server-cert verification is disabled (bktunnel pins,
// it has no CA). Args: host port certfile keyfile.
const pemClientPy = `
import socket, ssl, sys

host, port, certfile, keyfile = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

payload = bytes((i * 1103515245 + 12345) & 0xFF for i in range(65536))  # 64 KiB, deterministic
with socket.create_connection((host, port), timeout=10) as raw:
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        s.sendall(payload)
        got = bytearray()
        while len(got) < len(payload):
            chunk = s.recv(len(payload) - len(got))
            if not chunk:
                break
            got += chunk

if bytes(got) != payload:
    sys.stderr.write("mismatch: got %d of %d bytes\n" % (len(got), len(payload)))
    sys.exit(1)
`

// TestConformancePEMPythonClient proves a foreign TLS stack (Python stdlib ssl) can
// authenticate to a bktunnel server using only the --pem cert/key, with no
// bktunnel proxy on the client side.
func TestConformancePEMPythonClient(t *testing.T) {
	requirePythonSSL(t)
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

	script := filepath.Join(t.TempDir(), "pem_client.py")
	if err := os.WriteFile(script, []byte(pemClientPy), 0o644); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(tlsAddr)
	if err != nil {
		t.Fatal(err)
	}

	// Retry: the client run only succeeds once the server is listening.
	deadline := time.Now().Add(15 * time.Second)
	var lastOut []byte
	var lastErr error
	for time.Now().Before(deadline) {
		out, err := exec.Command("python3", script, host, port, certFile, keyFile).CombinedOutput()
		if err == nil {
			return // handshake + round-trip succeeded
		}
		lastOut, lastErr = out, err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("python stdlib-ssl client with --pem cert: %v\n%s", lastErr, lastOut)
}

// TestConformancePEMCertPythonServer proves a --pem cert authenticates against a
// bktunnel server run by the Python conformance implementation, not just the Go
// server — the server-side mirror of the bash-server interop test.
func TestConformancePEMCertPythonServer(t *testing.T) {
	requirePython(t)
	py := pythonScript(t)
	goBin := buildGoBinary(t)
	backend := startEcho(t)
	sPriv, _ := genKeypair(t, goBin)
	cPub, certFile, keyFile := genKeypairPEM(t, goBin)

	tlsAddr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Python bktunnel server pins the client's --pem pubkey.
	startProc(t, ctx, "python3", py,
		"-r", "server", "-a", tlsAddr, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", cPub)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load PEM keypair: %v", err)
	}
	// Present the cert unconditionally (as curl/openssl do); the Python server
	// sends acceptable-CA names, which Go's default Certificates selection would
	// filter against — see the bash-server test for the same workaround.
	cfg := &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
		InsecureSkipVerify:   true,
		MinVersion:           tls.VersionTLS12,
	}
	if err := tryRoundTripTLS(tlsAddr, cfg, 20*time.Second); err != nil {
		t.Fatalf("stock TLS client with --pem cert -> python server: %v", err)
	}
}

// TestConformanceP256PythonClientGoServer proves P-256 identities interoperate
// with the Python conformance implementation (a P-256 mutual-TLS tunnel between
// the Python client and the Go server).
func TestConformanceP256PythonClientGoServer(t *testing.T) {
	requirePython(t)
	goBin := buildGoBinary(t)
	if err := tryRoundTrip(runPairAlgo(t, "", goBin, "go", "python", "p256"), 15*time.Second); err != nil {
		t.Fatalf("python client <-> go server (p256): %v", err)
	}
}
