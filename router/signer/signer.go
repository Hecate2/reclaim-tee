package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Signer mints allocation JWTs. The production implementation will be
// KMS-backed; LocalSigner is for local dev and tests.
type Signer interface {
	Sign(claims *AllocClaims) (string, error)
	// PublicKeyPEM returns the verification key for callers that need to
	// embed it elsewhere (e.g., TEE image metadata in production).
	PublicKeyPEM() ([]byte, error)
}

// LocalSigner signs with an in-process ECDSA P-256 key. Generated fresh on
// each call to NewLocalSigner unless a key is supplied. Not for production.
type LocalSigner struct {
	priv *ecdsa.PrivateKey
}

// NewLocalSigner generates a new ECDSA P-256 keypair and returns a signer
// bound to it.
func NewLocalSigner() (*LocalSigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	return &LocalSigner{priv: priv}, nil
}

// NewLocalSignerFromKey wraps an existing ECDSA private key. Useful for
// tests that need stable signing material across runs.
func NewLocalSignerFromKey(priv *ecdsa.PrivateKey) *LocalSigner {
	return &LocalSigner{priv: priv}
}

func (s *LocalSigner) Sign(claims *AllocClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return tok.SignedString(s.priv)
}

func (s *LocalSigner) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
