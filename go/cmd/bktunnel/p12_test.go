package main

// Tests for `-g FILE -t p256 --p12`, the empty-password PKCS#12 bundle a browser
// or OS keystore imports. The REGRESSION these guard is subtle: a bundle written
// with no MAC and no encryption (openssl `-keypbe NONE -certpbe NONE -nomac`, or
// go-pkcs12's Passwordless encoder) round-trips fine through openssl AND through
// Go's own pkcs12 decoder, so a naive "generate then decode" check passes it -
// yet NSS/Firefox and Android REJECT it ("not in PKCS #12 format ... corrupted").
// The distinguishing property is the MAC: a well-formed bundle carries one, so a
// WRONG password is rejected; a MAC-less bundle accepts ANY password. We assert
// that structural property with openssl (the Go decoder can't see the difference)
// and separately prove the bundle carries the right identity end to end.

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireOpenSSL fails the test unless openssl is in PATH; the --p12 tests inspect
// the bundle's MAC with it (the property browsers care about but Go's decoder and
// a plain round-trip don't reveal).
func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatalf("--p12 test needs openssl in PATH")
	}
}

// bashScriptPath returns the abs path to the bash implementation (without pulling
// in the stunnel/xxd requirement of requireInteropDeps, which --p12 doesn't need).
func bashScriptPath(t *testing.T) string {
	t.Helper()
	s, err := filepath.Abs("../../../bktunnel")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s); err != nil {
		t.Fatalf("bash script not found at %s", s)
	}
	return s
}

// genP12 runs `<tool...> -g FILE -t p256 --p12` and returns the printed bare
// pubkey plus the path to the .p12 it wrote beside FILE.
func genP12(t *testing.T, tool ...string) (pub, p12File string) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "id_p256")
	args := append(append([]string{}, tool[1:]...), "-g", base, "-t", "p256", "--p12")
	out, err := exec.Command(tool[0], args...).Output()
	if err != nil {
		t.Fatalf("keygen --p12 (%v): %v", tool, err)
	}
	f := strings.Fields(string(out)) // stdout is the shareable "<type> <b64>" line
	if len(f) < 2 {
		t.Fatalf("keygen --p12 (%v): unexpected stdout %q", tool, out)
	}
	return f[len(f)-1], base + ".p12"
}

// assertMACdEmptyPasswordP12 checks the property NSS/Firefox and Android require
// and that an openssl round-trip alone misses: the bundle is MAC'd, so the empty
// password decodes it but a WRONG password is rejected. A MAC-less bundle (a
// reverted NONE/-nomac or Passwordless encoding) decodes under ANY password and
// is what browsers reject, so the wrong-password rejection is the regression lock.
func assertMACdEmptyPasswordP12(t *testing.T, p12File string) {
	t.Helper()
	// -info reports the MAC; a MAC-less bundle prints no "MAC:" line.
	info, err := exec.Command("openssl", "pkcs12", "-in", p12File,
		"-passin", "pass:", "-info", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl could not read %s with an empty password: %v\n%s", p12File, err, info)
	}
	if !bytes.Contains(info, []byte("MAC:")) {
		t.Fatalf("%s carries no MAC (NSS/Firefox and Android reject a MAC-less PKCS#12):\n%s", p12File, info)
	}
	// A non-empty password must FAIL - only true when a MAC guards the bundle.
	if out, err := exec.Command("openssl", "pkcs12", "-in", p12File,
		"-passin", "pass:wrong-not-empty", "-nokeys", "-noout").CombinedOutput(); err == nil {
		t.Fatalf("%s accepted a WRONG password - it is MAC-less/unencrypted and browsers will reject it:\n%s", p12File, out)
	}
}

// p12ToTLSCert converts an empty-password .p12 to a tls.Certificate via openssl
// (p12 -> PEM key+cert). Going through openssl keeps the loader path identical for
// Go- and bash-generated bundles regardless of their internal PBE, so the identity
// check doesn't depend on any one PKCS#12 decoder's algorithm coverage.
func p12ToTLSCert(t *testing.T, p12File string) tls.Certificate {
	t.Helper()
	pemFile := filepath.Join(filepath.Dir(p12File), "from_p12.pem")
	if out, err := exec.Command("openssl", "pkcs12", "-in", p12File,
		"-passin", "pass:", "-nodes", "-out", pemFile).CombinedOutput(); err != nil {
		t.Fatalf("openssl pkcs12 -> PEM: %v\n%s", err, out)
	}
	cert, err := tls.LoadX509KeyPair(pemFile, pemFile) // both cert and key blocks live in the one file
	if err != nil {
		t.Fatalf("load cert/key from p12-derived PEM: %v", err)
	}
	return cert
}

// stockClientRoundTrip stands up a Go bktunnel server that pins clientPub and
// forwards to an echo backend, then dials it with a stock crypto/tls client
// presenting cert - proving the .p12 carries the same identity as the pinned key.
func stockClientRoundTrip(t *testing.T, goBin, clientPub string, cert tls.Certificate) {
	t.Helper()
	backend := startEcho(t)
	sPriv, _ := genKeypair(t, goBin) // server identity may stay Ed25519; client is P-256
	tlsAddr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startProc(t, ctx, goBin,
		"-r", "server", "-a", tlsAddr, "-c", backend, "-k", "@"+writeKey(t, sPriv), "-p", clientPub)

	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // server's pinned cert has no CA; identity is by pin
		MinVersion:         tls.VersionTLS12,
	}
	if err := tryRoundTripTLS(tlsAddr, cfg, 15*time.Second); err != nil {
		t.Fatalf("stock TLS client with --p12 identity: %v", err)
	}
}

// TestGoP12EmptyPasswordMACd generates a Go --p12 bundle, locks in that it is a
// MAC'd empty-password PKCS#12 (not a browser-rejected MAC-less one), and proves
// it authenticates a stock TLS client to a bktunnel server by its pinned pubkey.
func TestGoP12EmptyPasswordMACd(t *testing.T) {
	requireOpenSSL(t)
	goBin := buildGoBinary(t)
	cPub, p12File := genP12(t, goBin)
	assertMACdEmptyPasswordP12(t, p12File)
	stockClientRoundTrip(t, goBin, cPub, p12ToTLSCert(t, p12File))
}

// TestInteropP12BashEmptyPasswordMACd is the same guard for the bash implementation
// and proves its .p12 is interchangeable with the Go one: a bash-generated bundle
// is MAC'd and authenticates a stock TLS client to a Go bktunnel server.
func TestInteropP12BashEmptyPasswordMACd(t *testing.T) {
	requireOpenSSL(t)
	script := bashScriptPath(t)
	goBin := buildGoBinary(t)
	cPub, p12File := genP12(t, "bash", script)
	assertMACdEmptyPasswordP12(t, p12File)
	stockClientRoundTrip(t, goBin, cPub, p12ToTLSCert(t, p12File))
}
