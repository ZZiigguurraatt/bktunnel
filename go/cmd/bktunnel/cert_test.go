package main

// Tests for --cert: presenting a persisted PEM cert on the wire instead of a
// freshly minted one, so the on-wire cert is byte-stable across restarts (a
// browser keys its trust exception on the whole-cert fingerprint, which only
// holds if the same bytes reappear each run). loadCert is unit-tested directly;
// the wire behaviour is checked by capturing what a server with --cert actually
// presents to a stock TLS client and comparing it to the file.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// certFileDER returns the DER bytes of the single CERTIFICATE block in a PEM file.
func certFileDER(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("%s: no PEM CERTIFICATE block", path)
	}
	return blk.Bytes
}

// TestLoadCertMatchesFileAndKey covers loadCert directly: it returns the file's
// exact DER when the cert's key matches the identity key, and errors when the
// cert is over a different key or isn't a cert at all.
func TestLoadCertMatchesFileAndKey(t *testing.T) {
	dir := t.TempDir()
	priv, err := generateKey(algoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certDER(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "id.crt")
	writePEMCert(t, certPath, der)

	got, err := loadCert(certPath, priv)
	if err != nil {
		t.Fatalf("loadCert with matching key: %v", err)
	}
	if len(got.Certificate) != 1 || string(got.Certificate[0]) != string(der) {
		t.Fatal("loadCert did not present the file's exact cert bytes")
	}

	// A cert over a DIFFERENT key must be rejected (its pubkey ≠ the identity key,
	// so the pin a peer holds for us would never match what we present).
	other, err := generateKey(algoP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadCert(certPath, other); err == nil {
		t.Fatal("loadCert accepted a cert whose key does not match the identity key")
	}

	// A non-certificate file must be rejected.
	junk := filepath.Join(dir, "junk.crt")
	if err := os.WriteFile(junk, []byte("not a pem cert\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCert(junk, priv); err == nil {
		t.Fatal("loadCert accepted a non-certificate file")
	}
}

func writePEMCert(t *testing.T, path string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

// genPEMIdentity runs `-g base -t algo --pem` and returns the base path (usable
// as -k @base and as --cert base.crt) plus the printed bare pubkey.
func genPEMIdentity(t *testing.T, goBin, algo string) (base, pub string) {
	t.Helper()
	base = filepath.Join(t.TempDir(), "id")
	out, err := exec.Command(goBin, "-g", base, "-t", algo, "--pem").Output()
	if err != nil {
		t.Fatalf("keygen --pem: %v", err)
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		t.Fatalf("keygen --pem: unexpected stdout %q", out)
	}
	return base, f[len(f)-1]
}

// dialCaptureServerCert dials a bktunnel server presenting clientCert and returns
// the DER of the leaf cert the SERVER presented, retrying until the server is up.
func dialCaptureServerCert(t *testing.T, addr string, clientCert tls.Certificate) []byte {
	t.Helper()
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		d := &net.Dialer{Timeout: 300 * time.Millisecond}
		c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		state := c.ConnectionState()
		c.Close()
		if len(state.PeerCertificates) == 0 {
			t.Fatal("server presented no certificate")
		}
		return state.PeerCertificates[0].Raw
	}
	t.Fatalf("could not connect to %s within timeout", addr)
	return nil
}

// TestGoCertOnWireIsFileBytes checks that a server started with --cert presents
// the file's exact cert on the wire, and does so identically across two separate
// server instances (the restart-stability that keeps a browser exception valid).
func TestGoCertOnWireIsFileBytes(t *testing.T) {
	goBin := buildGoBinary(t)
	base, _ := genPEMIdentity(t, goBin, "p256")
	cliBase, cPub := genPEMIdentity(t, goBin, "p256")
	wantDER := certFileDER(t, base+".crt")

	clientCert, err := tls.LoadX509KeyPair(cliBase+".crt", cliBase+".key")
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}

	var seen [][]byte
	for i := 0; i < 2; i++ {
		backend := startEcho(t)
		tlsAddr := freePort(t)
		ctx, cancel := context.WithCancel(context.Background())
		startProc(t, ctx, goBin,
			"-r", "server", "-a", tlsAddr, "-c", backend, "-k", "@"+base, "-p", cPub, "--cert", base+".crt")
		seen = append(seen, dialCaptureServerCert(t, tlsAddr, clientCert))
		cancel()
	}

	for i, der := range seen {
		if _, err := x509.ParseCertificate(der); err != nil {
			t.Fatalf("run %d presented an unparseable cert: %v", i, err)
		}
		if string(der) != string(wantDER) {
			t.Fatalf("run %d presented cert bytes differ from the --cert file", i)
		}
	}
	if string(seen[0]) != string(seen[1]) {
		t.Fatal("server presented different cert bytes across restarts (--cert should keep them stable)")
	}
}

// TestGoCertBareDerivesFromKeyFile checks that a bare --cert (no filename) derives
// <keyfile>.crt from the -k @FILE key and presents that file's exact bytes.
func TestGoCertBareDerivesFromKeyFile(t *testing.T) {
	goBin := buildGoBinary(t)
	base, _ := genPEMIdentity(t, goBin, "p256")
	cliBase, cPub := genPEMIdentity(t, goBin, "p256")
	wantDER := certFileDER(t, base+".crt")
	clientCert, err := tls.LoadX509KeyPair(cliBase+".crt", cliBase+".key")
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}

	backend := startEcho(t)
	tlsAddr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// bare --cert: the expander turns a trailing "--cert" into the derive sentinel.
	startProc(t, ctx, goBin,
		"-r", "server", "-a", tlsAddr, "-c", backend, "-k", "@"+base, "-p", cPub, "--cert")
	got := dialCaptureServerCert(t, tlsAddr, clientCert)
	if string(got) != string(wantDER) {
		t.Fatal("bare --cert did not present the derived <keyfile>.crt bytes")
	}
}
