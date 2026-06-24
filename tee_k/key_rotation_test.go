package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

// newRotationTestTEEK builds a minimal TEEK whose attestation generation is
// stubbed (the stub echoes the nonces verbatim), so tests can assert which
// keys an attestation commits to without a launcher/SEV-guest dependency.
func newRotationTestTEEK(t *testing.T) *TEEK {
	t.Helper()
	m, err := shared.NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new ratls manager: %v", err)
	}
	kp, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("gen signing key: %v", err)
	}
	return &TEEK{
		logger:         shared.NewNopLogger(),
		signingKeyPair: kp,
		ratls:          m,
		genAttestationDocFn: func(_ context.Context, nonces ...string) ([]byte, error) {
			return []byte(strings.Join(nonces, "\n")), nil
		},
	}
}

// TestSigningEpoch_AttestationBindsSnapshotKey is the core forward-secrecy
// invariant: signingEpoch returns a keypair whose ETH address the bundled
// attestation commits to. Because the keypair rotates on refresh, the snapshot
// must read {signingKeyPair, cachedAttestation} as one epoch — otherwise a
// bundle could be signed by one key while carrying an attestation that binds
// another, and the attestor would reject it.
func TestSigningEpoch_AttestationBindsSnapshotKey(t *testing.T) {
	teek := newRotationTestTEEK(t)
	bootKey := teek.signingKeyPair

	kp, att, err := teek.signingEpoch("test-session")
	if err != nil {
		t.Fatalf("signingEpoch: %v", err)
	}
	if kp == nil || att == nil {
		t.Fatal("expected a keypair and attestation in router mode")
	}

	// The keypair must have rotated away from the boot key.
	if kp.GetEthAddress().Hex() == bootKey.GetEthAddress().Hex() {
		t.Fatal("signing key did not rotate on refresh")
	}

	// The attestation must bind the snapshot's signing key...
	wantKeyNonce := fmt.Sprintf("tee_k_public_key:%s", kp.GetEthAddress().Hex())
	if !strings.Contains(string(att.Report), wantKeyNonce) {
		t.Fatalf("attestation does not bind snapshot signing key; want %q in:\n%s", wantKeyNonce, att.Report)
	}

	// ...and the current RA-TLS SPKI.
	spki := teek.ratls.SPKIHash()
	wantSPKINonce := shared.SPKINoncePrefix("tee_k") + fmt.Sprintf("%x", spki[:])
	if !strings.Contains(string(att.Report), wantSPKINonce) {
		t.Fatalf("attestation does not bind current SPKI; want %q", wantSPKINonce)
	}
}

// TestRefreshAttestation_RotatesSigningKey asserts each refresh mints a fresh
// signing key — the property that bounds an extracted key's blast radius to one
// refresh interval.
func TestRefreshAttestation_RotatesSigningKey(t *testing.T) {
	teek := newRotationTestTEEK(t)

	if err := teek.refreshAttestation(); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	first := teek.signingKeyPair.GetEthAddress().Hex()

	if err := teek.refreshAttestation(); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	second := teek.signingKeyPair.GetEthAddress().Hex()

	if first == second {
		t.Fatalf("signing key did not rotate between refreshes (both %s)", first)
	}
}
