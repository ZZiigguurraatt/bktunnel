package main

import (
	"crypto"
	"crypto/x509"
	"math/big"
	"testing"
)

// TestCertSerialsUnique guards the X.509 (issuer, serial) uniqueness that browsers
// enforce. Every bktunnel cert carries the SAME issuer name (leafIssuerCN), so the
// serial is what makes each cert's identity unique; a fixed serial (the old
// big.NewInt(1)) makes every cert collide on (issuer, serial), and NSS/Firefox
// reject the collision — SEC_ERROR_REUSED_ISSUER_AND_SERIAL ("same issuer/serial
// as an existing cert, but ... not the same cert") — the moment a browser holds
// one bktunnel cert (an imported --p12 client identity) and a bktunnel server
// presents another. certDER must therefore give every cert a distinct serial.
func TestCertSerialsUnique(t *testing.T) {
	serialOf := func(priv crypto.Signer) *big.Int {
		der, err := certDER(priv)
		if err != nil {
			t.Fatalf("certDER: %v", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse cert: %v", err)
		}
		if c.Issuer.CommonName != leafIssuerCN {
			t.Fatalf("issuer CN = %q, want %q", c.Issuer.CommonName, leafIssuerCN)
		}
		return c.SerialNumber
	}

	one := big.NewInt(1)
	seen := map[string]bool{}
	for _, algo := range []string{algoEd25519, algoP256} {
		for i := 0; i < 8; i++ {
			priv, err := generateKey(algo)
			if err != nil {
				t.Fatalf("generateKey(%s): %v", algo, err)
			}
			// Two certs over the SAME key (e.g. --pem's .crt and --p12's cert) must
			// also differ, so mint twice per key.
			for _, s := range []*big.Int{serialOf(priv), serialOf(priv)} {
				if s.Sign() <= 0 {
					t.Fatalf("%s serial %s is not positive", algo, s)
				}
				if s.Cmp(one) == 0 {
					t.Fatalf("%s serial is the fixed value 1 (the reused-serial bug)", algo)
				}
				k := s.Text(16)
				if seen[k] {
					t.Fatalf("%s serial %s repeated — certs would collide on (issuer, serial)", algo, k)
				}
				seen[k] = true
			}
		}
	}
}
