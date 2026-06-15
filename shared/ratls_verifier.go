//go:build !mobile

package shared

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// RATLSVerifyOptions controls the peer-certificate check installed via
// tls.Config.VerifyPeerCertificate. PeerRole is the role of the side whose
// cert we are about to verify ("tee_k" or "tee_t"); ExpectedImageDigest is
// the image digest we require the peer to attest to (matches the value
// passed via metadata at deploy time, e.g. EXPECTED_PEER_IMAGE_DIGEST).
type RATLSVerifyOptions struct {
	PeerRole            string
	ExpectedImageDigest string
	Logger              *Logger
}

// validateRATLSCertStructure parses + validates an RA-TLS leaf cert
// without pinning a specific image_digest. Steps:
//
//  1. Pull the GCP attestation JWT out of the AttestationOID extension.
//  2. Validate JWT signature against Google's roots.
//  3. Confirm the SPKI hash nonce inside the JWT matches the cert's
//     actual SPKI (binds the keypair to this attestation).
//
// Returns the image_digest claim so callers can either pin it
// (TEE-to-TEE) or capture it for downstream use (clients).
//
// Standalone certs (no attestation extension) are rejected. Local-dev
// flows must avoid this verifier.
func validateRATLSCertStructure(rawCerts [][]byte, peerRole string, logger *Logger) (imageDigest string, err error) {
	if len(rawCerts) == 0 {
		return "", errors.New("ratls: no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", fmt.Errorf("ratls: parse peer cert: %w", err)
	}

	attestation, err := ExtractAttestationFromCert(leaf)
	if err != nil {
		return "", fmt.Errorf("ratls: %w", err)
	}

	attestor, err := NewGoogleAttestor()
	if err != nil {
		return "", fmt.Errorf("ratls: build attestor: %w", err)
	}
	if err := attestor.Validate(attestation, logger); err != nil {
		return "", fmt.Errorf("ratls: attestation invalid: %w", err)
	}

	imageDigest, err = ExtractImageDigestFromGCPAttestation(attestation, logger)
	if err != nil {
		return "", fmt.Errorf("ratls: extract image digest: %w", err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return "", fmt.Errorf("ratls: marshal peer SPKI: %w", err)
	}
	actualHash := sha256.Sum256(spkiDER)
	actualHex := hex.EncodeToString(actualHash[:])

	expectedHex, err := FindNonceValue(attestation, SPKINoncePrefix(peerRole))
	if err != nil {
		return "", fmt.Errorf("ratls: %w", err)
	}
	if expectedHex != actualHex {
		return "", fmt.Errorf("ratls: SPKI hash mismatch: attestation says %q, cert is %q",
			expectedHex, actualHex)
	}
	return imageDigest, nil
}

// VerifyRATLSPeer returns a tls.Config.VerifyPeerCertificate callback for
// TEE↔TEE mTLS: validates the cert structure and pins the image_digest
// to opts.ExpectedImageDigest. Any failure aborts the TLS handshake.
func VerifyRATLSPeer(opts RATLSVerifyOptions) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		gotDigest, err := validateRATLSCertStructure(rawCerts, opts.PeerRole, opts.Logger)
		if err != nil {
			return err
		}
		if gotDigest != opts.ExpectedImageDigest {
			return fmt.Errorf("ratls: image_digest mismatch: expected %q, got %q",
				opts.ExpectedImageDigest, gotDigest)
		}
		return nil
	}
}

// VerifyRATLSAttestation returns a tls.Config.VerifyPeerCertificate
// callback for CLIENT→TEE connections: validates cert structure +
// attestation integrity without pinning image_digest.
//
// Clients deliberately do NOT pin image_digest themselves — the TEEs
// embed their full attestation reports into the signed claim bundles
// the attestor later inspects. The client's only job at TLS time is to
// confirm the cert is genuine RA-TLS (Google-signed attestation + SPKI
// binding). What's INSIDE the attestation is decided downstream.
func VerifyRATLSAttestation(peerRole string, logger *Logger) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		_, err := validateRATLSCertStructure(rawCerts, peerRole, logger)
		return err
	}
}

// ExtractAttestationFromCert returns the raw GCP attestation JWT bytes from
// the AttestationOID X.509 extension on the given cert, or an error if the
// extension is missing.
func ExtractAttestationFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AttestationOID) {
			return ext.Value, nil
		}
	}
	return nil, errors.New("attestation extension not present on certificate")
}

// FindNonceValue inspects the eat_nonce claim of an attestation JWT for a
// nonce starting with the given prefix and returns the substring after the
// prefix. Handles both string and []any forms of eat_nonce.
//
// Does NOT validate the JWT signature — call attestor.Validate first. The
// attestation parameter is the raw JWT bytes.
func FindNonceValue(attestation []byte, prefix string) (string, error) {
	tokenStr := strings.TrimSpace(string(attestation))
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}
	raw, ok := claims["eat_nonce"]
	if !ok {
		return "", errors.New("eat_nonce missing from attestation")
	}
	switch v := raw.(type) {
	case string:
		if val, ok := strings.CutPrefix(v, prefix); ok {
			return val, nil
		}
	case []any:
		for _, n := range v {
			s, ok := n.(string)
			if !ok {
				continue
			}
			if val, ok := strings.CutPrefix(s, prefix); ok {
				return val, nil
			}
		}
	}
	return "", fmt.Errorf("nonce with prefix %q not found", prefix)
}
