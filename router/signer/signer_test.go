package signer

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestLocalSignerRoundTrip(t *testing.T) {
	s, err := NewLocalSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	now := time.Now()
	claims := &AllocClaims{
		TEEKAddr:    "10.0.0.1:443",
		TEETAddr:    "10.0.0.2:443",
		ClientNonce: "nonce-123",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "router.test",
			Audience:  jwt.ClaimStrings{"pair-abc"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second)),
			ID:        "jti-xyz",
		},
	}

	tokenStr, err := s.Sign(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("empty token")
	}

	pemBytes, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatalf("public key pem: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("decode pem: nil block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected key type %T", pub)
	}

	parsed, err := jwt.ParseWithClaims(tokenStr, &AllocClaims{}, func(_ *jwt.Token) (any, error) {
		return ecPub, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, ok := parsed.Claims.(*AllocClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	if got.TEEKAddr != claims.TEEKAddr || got.TEETAddr != claims.TEETAddr || got.ClientNonce != claims.ClientNonce {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.ID != "jti-xyz" || got.Issuer != "router.test" {
		t.Fatalf("registered claims mismatch: %+v", got.RegisteredClaims)
	}
}
