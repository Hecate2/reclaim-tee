package signer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// kmsSignTimeout caps the TOTAL time (across all retries) of a single Sign
// call. KMS asymmetric sign typically returns in ~50ms; the budget is large
// enough to absorb 2 retries with backoff on transient 5xx, small enough to
// keep /allocate p99 bounded under KMS hiccups.
const kmsSignTimeout = 5 * time.Second

// kmsSignMaxAttempts is the total number of attempts (initial + retries) on
// transient KMS errors before giving up.
const kmsSignMaxAttempts = 3

// KMSSigner signs allocation JWTs using a GCP KMS asymmetric ES256 key.
// The private key never leaves KMS; this binary only holds the public key
// (cached at construction so handler hot path doesn't fetch).
type KMSSigner struct {
	client    *kms.KeyManagementClient
	keyName   string
	publicPEM []byte
}

// NewKMSSigner constructs a KMSSigner bound to the named key version. keyName
// must be the full resource path, e.g.
// "projects/X/locations/Y/keyRings/Z/cryptoKeys/router-jwt/cryptoKeyVersions/1".
// Fails fast if KMS is unreachable or the key is not an ECDSA-P256-SHA256 key.
func NewKMSSigner(ctx context.Context, keyName string) (*KMSSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyName})
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("kms get public key %q: %w", keyName, err)
	}
	if resp.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
		_ = client.Close()
		return nil, fmt.Errorf("kms key %q has unsupported algorithm %s; need EC_SIGN_P256_SHA256",
			keyName, resp.Algorithm)
	}
	return &KMSSigner{
		client:    client,
		keyName:   keyName,
		publicPEM: []byte(resp.Pem),
	}, nil
}

// Close releases the KMS client.
func (s *KMSSigner) Close() error {
	return s.client.Close()
}

func (s *KMSSigner) Sign(claims *AllocClaims) (string, error) {
	tok := jwt.NewWithClaims(&kmsSigningMethod{signer: s}, claims)
	return tok.SignedString(nil) // key argument unused — KMS holds the key
}

// PublicKeyPEM returns the public half of the signing key, cached at construction.
// This is what operators bake into TEE image metadata so TEEs can verify
// allocation JWTs offline.
func (s *KMSSigner) PublicKeyPEM() ([]byte, error) {
	return s.publicPEM, nil
}

// kmsSigningMethod plugs KMS into the golang-jwt signing-method interface.
// Alg() returns "ES256" so the JWT header is correctly set; Sign() calls
// AsymmetricSign and converts the DER-encoded signature to the raw r||s
// form JWS requires.
type kmsSigningMethod struct {
	signer *KMSSigner
}

func (m *kmsSigningMethod) Alg() string { return "ES256" }

func (m *kmsSigningMethod) Sign(signingString string, _ any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kmsSignTimeout)
	defer cancel()

	digest := sha256.Sum256([]byte(signingString))
	req := &kmspb.AsymmetricSignRequest{
		Name:   m.signer.keyName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
	}

	var lastErr error
	for attempt := 1; attempt <= kmsSignMaxAttempts; attempt++ {
		resp, err := m.signer.client.AsymmetricSign(ctx, req)
		if err == nil {
			return asn1ToJWS(resp.Signature)
		}
		lastErr = err
		if !isRetryableKMSError(err) {
			break
		}
		if attempt == kmsSignMaxAttempts || ctx.Err() != nil {
			break
		}
		// Jittered backoff: 50ms / 100ms / 200ms base with ±25% jitter.
		base := time.Duration(50*(1<<(attempt-1))) * time.Millisecond
		jitterByte := [1]byte{}
		_, _ = rand.Read(jitterByte[:])
		jitter := time.Duration(int(jitterByte[0])-128) * base / 512
		select {
		case <-time.After(base + jitter):
		case <-ctx.Done():
			return nil, fmt.Errorf("kms asymmetric sign: %w", ctx.Err())
		}
	}
	return nil, fmt.Errorf("kms asymmetric sign (after %d attempts): %w", kmsSignMaxAttempts, lastErr)
}

// isRetryableKMSError reports whether a KMS error is a transient 5xx-ish
// condition where a retry is likely to succeed. Permission, auth, and
// invalid-arg failures are NOT retried (the next attempt would fail too).
func isRetryableKMSError(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch s.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted, codes.Internal:
		return true
	}
	return false
}

// Verify is never called in the router flow (the router only mints; TEEs
// verify with the public key offline). Returning ErrInvalidKey is the safe
// thing in case some future caller invokes it accidentally.
func (m *kmsSigningMethod) Verify(_ string, _ []byte, _ any) error {
	return errors.New("KMSSigner does not implement Verify; verify with PublicKeyPEM externally")
}

// asn1ToJWS converts a P-256 ECDSA signature from ASN.1 DER (the form KMS
// returns) to the raw 64-byte r||s form JWS ES256 requires (RFC 7515 §A.3).
func asn1ToJWS(der []byte) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal ecdsa asn1: %w", err)
	}
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	if len(rBytes) > 32 || len(sBytes) > 32 {
		return nil, fmt.Errorf("ecdsa component too large: r=%d s=%d", len(rBytes), len(sBytes))
	}
	out := make([]byte, 64)
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out, nil
}
