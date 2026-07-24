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
