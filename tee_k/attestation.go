package main

import (
	"context"
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// getCurrentCertRaw returns the bytes of the RA-TLS certificate currently
// being served on this TEE_K's TLS endpoint (rotated by RATLSManager.Refresh).
// Returns an error in standalone mode (no RA-TLS).
func (t *TEEK) getCurrentCertRaw() ([]byte, error) {
	raw := t.ratls.CertificateRaw()
	if raw == nil {
		return nil, fmt.Errorf("RA-TLS cert not yet available")
	}
	return raw, nil
}

// generateAttestationDoc produces a fresh GCP attestation token bound to
// the supplied nonces, against the launcher socket on the host.
func (t *TEEK) generateAttestationDoc(ctx context.Context, nonces ...string) ([]byte, error) {
	return shared.GenerateGCPAttestation(ctx, nonces...)
}

// refreshAttestation generates a new attestation and caches it
func (t *TEEK) refreshAttestation() error {
	// Skip in standalone mode (no RA-TLS — no attestation primitives).
	if t.ratls == nil {
		return nil
	}

	// Get ETH address for this key pair
	ethAddress := t.signingKeyPair.GetEthAddress()

	// Bind the attestation to the TLS *keypair* via SPKI hash — invariant
	// across cert refreshes. The cert envelope (DER bytes) changes every
	// 4 minutes when the cert rotates, but the keypair (and therefore the
	// SPKI) is generated once and never rotates. A previous version used
	// sha256(cert.DER) here; that produced mismatches when a session
	// straddled a cert refresh because the client's TLS conn was frozen
	// on the old DER while this cached attestation moved to the new one.
	spkiHash := t.ratls.SPKIHash()

	publicKeyNonce := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())
	spkiHashNonce := shared.SPKINoncePrefix("tee_k") + fmt.Sprintf("%x", spkiHash[:])

	attestationDoc, err := t.generateAttestationDoc(context.Background(), publicKeyNonce, spkiHashNonce)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	// Create structured report
	attestationReport := &teeproto.AttestationReport{
		Type:   "gcp",
		Report: attestationDoc,
	}

	// Cache the new attestation
	t.attestationMutex.Lock()
	t.cachedAttestation = attestationReport
	t.attestationExpiry = time.Now().Add(5 * time.Minute) // Cache valid for 5 minutes
	t.attestationMutex.Unlock()

	t.logger.Debug("Cached new attestation")

	return nil
}

// getCachedAttestation returns the cached attestation if valid, otherwise
// generates a new one. Concurrent cache-miss callers are coalesced via
// singleflight so only ONE launcher-socket call fires per miss; all
// waiters share that one result.
func (t *TEEK) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	// Skip in standalone mode
	if t.ratls == nil {
		return nil, nil
	}

	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()

	// Fast path — cache hit.
	if cached != nil && time.Now().Before(expiry) {
		t.logger.WithSession(sessionID).Debug("Using cached attestation",
			zap.String("type", cached.Type))
		return cached, nil
	}

	// Cache miss. Use singleflight so N concurrent miss-callers fire only
	// one refresh. The "refresh" key is constant — there's only one global
	// per-TEE attestation cache.
	t.logger.WithSession(sessionID).Warn("Cached attestation expired or missing, coalescing refresh")
	val, err, _ := t.attestationSF.Do("refresh", func() (any, error) {
		// Re-check inside the singleflight — another caller may have just
		// completed the refresh while we were waiting at the door.
		t.attestationMutex.RLock()
		cached := t.cachedAttestation
		expiry := t.attestationExpiry
		t.attestationMutex.RUnlock()
		if cached != nil && time.Now().Before(expiry) {
			return cached, nil
		}
		if err := t.refreshAttestation(); err != nil {
			return nil, fmt.Errorf("failed to generate fallback attestation: %v", err)
		}
		t.attestationMutex.RLock()
		result := t.cachedAttestation
		t.attestationMutex.RUnlock()
		return result, nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*teeproto.AttestationReport), nil
}

// generateAttestationReport generates an AttestationReport for enclave mode (uses cache for performance)
func (t *TEEK) generateAttestationReport(sessionID string) (*teeproto.AttestationReport, error) {
	// Use cached attestation for performance
	return t.getCachedAttestation(sessionID)
}

// generateAttestationForTEET generates attestation for mutual auth with TEE_T
func (t *TEEK) generateAttestationForTEET() (*teeproto.AttestationReport, error) {
	// Standalone (local-dev) mode: TEE_T won't run a real attestation
	// verifier — exchange a sentinel value so both sides know not to expect
	// a real GCP token.
	if t.ratls == nil {
		return &teeproto.AttestationReport{
			Type:   "standalone",
			Report: []byte("standalone"),
		}, nil
	}

	// Router mode: generate attestation with eth address and SPKI hash.
	// SPKI is invariant across cert refreshes; binding to it eliminates
	// the mid-session-refresh race that cert-DER hashing introduced.
	ethAddress := t.signingKeyPair.GetEthAddress()
	spkiHash := t.ratls.SPKIHash()

	publicKeyNonce := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())
	spkiHashNonce := shared.SPKINoncePrefix("tee_k") + fmt.Sprintf("%x", spkiHash[:])

	attestationDoc, err := t.generateAttestationDoc(context.Background(), publicKeyNonce, spkiHashNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	return &teeproto.AttestationReport{
		Type:   "gcp",
		Report: attestationDoc,
	}, nil
}

// verifyTEETAttestation verifies TEE_T's attestation response
func (t *TEEK) verifyTEETAttestation(msgBytes []byte, tlsCert []byte) error {
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Check for error message
	if errMsg, ok := env.Payload.(*teeproto.Envelope_Error); ok {
		return fmt.Errorf("TEE_T rejected attestation: %s", errMsg.Error.Message)
	}

	resp, ok := env.Payload.(*teeproto.Envelope_TeetAttestation)
	if !ok {
		return fmt.Errorf("unexpected message type: %T", env.Payload)
	}

	attestation := resp.TeetAttestation.AttestationReport

	// Standalone (local-dev) mode
	if attestation.Type == "standalone" {
		if t.ratls == nil && string(attestation.Report) == "standalone" {
			t.logger.Debug("Standalone mode attestation accepted")
			return nil
		}
		return fmt.Errorf("mode mismatch: received standalone but in router mode")
	}

	// Router mode
	if t.ratls == nil {
		return fmt.Errorf("mode mismatch: received GCP attestation but in standalone mode")
	}

	// Verify the SPKI hash in the attestation against TEE_T's TLS keypair.
	// Binding to SPKI (not the full cert DER) means the check is stable
	// across cert refreshes — the keypair is invariant.
	if attestation.Type != "gcp" {
		return fmt.Errorf("unsupported attestation type: %s", attestation.Type)
	}
	attestor, err := shared.NewGoogleAttestor()
	if err != nil {
		return fmt.Errorf("build attestor: %w", err)
	}
	if err := attestor.Validate(attestation.Report, t.logger); err != nil {
		return fmt.Errorf("validate TEE_T attestation: %w", err)
	}

	expectedSPKI, err := shared.SPKIHashFromCertDER(tlsCert)
	if err != nil {
		return fmt.Errorf("compute TEE_T SPKI hash: %w", err)
	}
	expectedHex := fmt.Sprintf("%x", expectedSPKI[:])
	gotHex, err := shared.FindNonceValue(attestation.Report, shared.SPKINoncePrefix("tee_t"))
	if err != nil {
		return fmt.Errorf("find tee_t_spki_hash nonce: %w", err)
	}
	if gotHex != expectedHex {
		t.logger.Error("SPKI hash mismatch", zap.String("expected", expectedHex), zap.String("got", gotHex))
		return fmt.Errorf("TEE_T SPKI hash mismatch")
	}

	t.logger.Debug("TEE_T SPKI hash verified")
	return nil
}
