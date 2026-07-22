package main

// End-to-end tests of the Go implementation talking to itself (Go server <-> Go
// client), plus a Go-only wrong-pin rejection. Unlike the interop tests, these
// need only the Go toolchain — no stunnel, xxd, openssl, or bash script — so
// they run everywhere (including CI without those tools) and give the Go tunnel
// real functional coverage on its own. They reuse the helpers defined in
// interop_test.go (buildGoBinary, runPair, tryRoundTrip, genKeypair); a Go<->Go
// pair never touches the bash script, so runPair's script argument is "".

import (
	"testing"
	"time"
)

func TestGoServerGoClient(t *testing.T) {
	goBin := buildGoBinary(t)
	addr := runPair(t, "", goBin, "go", "go", "", "")
	if err := tryRoundTrip(addr, 15*time.Second); err != nil {
		t.Fatalf("go server <-> go client: %v", err)
	}
}

func TestGoWrongPinRejected(t *testing.T) {
	goBin := buildGoBinary(t)
	// The client pins a key that is NOT the server's identity.
	_, wrongPub := genKeypair(t, goBin)
	addr := runPair(t, "", goBin, "go", "go", "", wrongPub)
	if err := tryRoundTrip(addr, 5*time.Second); err == nil {
		t.Fatal("expected the tunnel to reject the peer with a wrong pin, but data flowed")
	}
}
