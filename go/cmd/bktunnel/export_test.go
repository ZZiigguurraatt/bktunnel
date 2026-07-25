package main

// Tests for --pem/--p12 used WITHOUT -g: exporting the cert/key/PKCS#12 files
// from whatever -k resolves to (an existing identity), written beside the key
// file. requireOpenSSL and assertMACdEmptyPasswordP12 live in p12_test.go.

import (
	"crypto/tls"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGoExportPEMP12FromKey generates a bare key (no --pem/--p12), then exports
// both file sets from it with `-k @base --pem --p12` (no -g) and checks the files
// appear beside the key, the cert/key correspond, and the .p12 is MAC'd.
func TestGoExportPEMP12FromKey(t *testing.T) {
	requireOpenSSL(t)
	goBin := buildGoBinary(t)
	base := filepath.Join(t.TempDir(), "id_p256")
	if out, err := exec.Command(goBin, "-g", base, "-t", "p256").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	for _, ext := range []string{".crt", ".key", ".p12"} {
		if _, err := os.Stat(base + ext); err == nil {
			t.Fatalf("%s should not exist before export", base+ext)
		}
	}

	if out, err := exec.Command(goBin, "-k", "@"+base, "--pem", "--p12").CombinedOutput(); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}

	// tls.LoadX509KeyPair verifies the cert's public key matches the private key,
	// so this both confirms the files exist and that they are a consistent pair.
	if _, err := tls.LoadX509KeyPair(base+".crt", base+".key"); err != nil {
		t.Fatalf("exported cert/key do not load or correspond: %v", err)
	}
	assertMACdEmptyPasswordP12(t, base+".p12")
}

// TestGoExportNeedsKeyFile checks that --pem/--p12 without -g and without a key
// FILE to write beside (a literal -k) fails instead of guessing a path.
func TestGoExportNeedsKeyFile(t *testing.T) {
	goBin := buildGoBinary(t)
	priv, _ := genKeypairAlgo(t, goBin, "p256") // labelled literal private key, no backing file
	out, err := exec.Command(goBin, "-k", priv, "--pem").CombinedOutput()
	if err == nil {
		t.Fatalf("expected --pem with a literal key to error, got success:\n%s", out)
	}
}

// TestGoExportRefusesOverwrite checks that a re-export refuses to clobber existing
// files non-interactively (exec's stdin is not a TTY), the same guard the -g path
// uses. The first export succeeds (files absent); the second must fail.
func TestGoExportRefusesOverwrite(t *testing.T) {
	goBin := buildGoBinary(t)
	base := filepath.Join(t.TempDir(), "id_p256")
	if out, err := exec.Command(goBin, "-g", base, "-t", "p256").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	if out, err := exec.Command(goBin, "-k", "@"+base, "--pem", "--p12").CombinedOutput(); err != nil {
		t.Fatalf("first export should succeed (targets absent): %v\n%s", err, out)
	}
	out, err := exec.Command(goBin, "-k", "@"+base, "--pem", "--p12").CombinedOutput()
	if err == nil {
		t.Fatalf("re-export should refuse to clobber non-interactively, got success:\n%s", out)
	}
}
