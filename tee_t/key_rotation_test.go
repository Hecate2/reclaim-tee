package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

// newRotationTestTEET builds a minimal TEET whose attestation generation is
// stubbed (the stub echoes the nonces verbatim), so tests can assert which
// keys an attestation commits to without a launcher/SEV-guest dependency.
func newRotationTestTEET(t *testing.T) *TEET {
	t.Helper()
	m, err := shared.NewRATLSManager(t.Context(), "tee_t", nil)
	if err != nil {
		t.Fatalf("new ratls manager: %v", err)
	}
	kp, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("gen signing key: %v", err)
	}
	return &TEET{
		logger:         shared.NewNopLogger(),
		signingKeyPair: kp,
		ratls:          m,
		genAttestationDocFn: func(_ context.Context, nonces ...string) ([]byte, error) {
			return []byte(strings.Join(nonces, "\n")), nil
		},
	}
}

// TestSigningEpoch_AttestationBindsSnapshotKey is the forward-secrecy invariant
// for TEE_T: signingEpoch returns a keypair whose ETH address the bundled
// attestation commits to, so a verifier never sees a signature and attestation
// from different rotation epochs.
func TestSigningEpoch_AttestationBindsSnapshotKey(t *testing.T) {
	teet := newRotationTestTEET(t)
	bootKey := teet.signingKeyPair

	kp, att, err := teet.signingEpoch("test-session")
	if err != nil {
		t.Fatalf("signingEpoch: %v", err)
	}
	if kp == nil || att == nil {
		t.Fatal("expected a keypair and attestation in router mode")
	}

	if kp.GetEthAddress().Hex() == bootKey.GetEthAddress().Hex() {
		t.Fatal("signing key did not rotate on refresh")
	}

	wantKeyNonce := fmt.Sprintf("tee_t_public_key:%s", kp.GetEthAddress().Hex())
	if !strings.Contains(string(att.Report), wantKeyNonce) {
		t.Fatalf("attestation does not bind snapshot signing key; want %q in:\n%s", wantKeyNonce, att.Report)
	}

	spki := teet.ratls.SPKIHash()
	wantSPKINonce := shared.SPKINoncePrefix("tee_t") + fmt.Sprintf("%x", spki[:])
	if !strings.Contains(string(att.Report), wantSPKINonce) {
		t.Fatalf("attestation does not bind current SPKI; want %q", wantSPKINonce)
	}
}

// TestRefreshAttestation_RotatesSigningKey asserts each refresh mints a fresh
// signing key.
func TestRefreshAttestation_RotatesSigningKey(t *testing.T) {
	teet := newRotationTestTEET(t)

	if err := teet.refreshAttestation(); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	first := teet.signingKeyPair.GetEthAddress().Hex()

	if err := teet.refreshAttestation(); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	second := teet.signingKeyPair.GetEthAddress().Hex()

	if first == second {
		t.Fatalf("signing key did not rotate between refreshes (both %s)", first)
	}
}
