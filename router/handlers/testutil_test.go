package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// mustParsePubKey parses a PEM-encoded public key for use in JWT tests.
// Fatals on error.
func mustParsePubKey(t *testing.T, pemBytes []byte) any {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("decode pem: nil block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	return pub
}
