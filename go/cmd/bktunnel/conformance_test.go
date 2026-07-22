//go:build conformance

package main

// Conformance tests prove the bktunnel wire is stock mutual-TLS by driving it
// with a THIRD implementation: the Python client+server in conformance/bktunnel.py
// (stdlib `ssl` + the `cryptography` package). They are gated behind the
// `conformance` build tag (and their own python3/cryptography dependency) so the
// default `make test` stays bash+go only. Run them with `make test-conformance`.
//
// All four cross pairings with Python on one end are covered. Keys are generated
// with the Go binary; they are wire-compatible, and the point here is the TLS
// handshake, not keygen.

import (
	"testing"
	"time"
)

func TestConformancePythonClientBashServer(t *testing.T) {
	script := requireInteropDeps(t) // stunnel, xxd, openssl + bash script
	requirePython(t)
	goBin := buildGoBinary(t)
	addr := runPair(t, script, goBin, "bash", "python", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("python client <-> bash server: %v", err)
	}
}

func TestConformancePythonClientGoServer(t *testing.T) {
	requirePython(t) // no stunnel/xxd/bash script needed for a Go server
	goBin := buildGoBinary(t)
	addr := runPair(t, "", goBin, "go", "python", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("python client <-> go server: %v", err)
	}
}

func TestConformanceBashClientPythonServer(t *testing.T) {
	script := requireInteropDeps(t) // bash client needs stunnel etc.
	requirePython(t)
	goBin := buildGoBinary(t)
	addr := runPair(t, script, goBin, "python", "bash", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("bash client <-> python server: %v", err)
	}
}

func TestConformanceGoClientPythonServer(t *testing.T) {
	requirePython(t)
	goBin := buildGoBinary(t)
	addr := runPair(t, "", goBin, "python", "go", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("go client <-> python server: %v", err)
	}
}
