package main

import (
	"context"
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// getCurrentCertRaw returns the bytes of the RA-TLS certificate currently
// being served on this TEE_T's TLS endpoint (rotated by RATLSManager.Refresh).
// Returns an error in standalone mode (no RA-TLS).
func (t *TEET) getCurrentCertRaw() ([]byte, error) {
	raw := t.ratls.CertificateRaw()
	if raw == nil {
		return nil, fmt.Errorf("RA-TLS cert not yet available")
	}
	return raw, nil
}

// generateAttestationDoc produces a fresh GCP attestation token bound to
// the supplied nonces, against the launcher socket on the host.
func (t *TEET) generateAttestationDoc(ctx context.Context, nonces ...string) ([]byte, error) {
	if shared.IsSEVSNPMode() {
		return shared.GenerateSEVSNPNonceAttestation(nonces)
	}
	return shared.GenerateGCPAttestation(ctx, nonces...)
}

// attestationReportType labels the app-layer attestation by platform so the
// peer verifier picks the right validation path.
func attestationReportType() string {
	if shared.IsSEVSNPMode() {
		return "sev-snp"
	}
	return "gcp"
}

func (t *TEET) refreshAttestation() error {
	if t.ratls == nil {
		return nil
	}
	ethAddress := t.signingKeyPair.GetEthAddress()

	// Bind to SPKI (stable across cert refreshes), not cert DER (changes
	// every 4 min). See tee_k/attestation.go's refreshAttestation for the
	// full rationale.
	spkiHash := t.ratls.SPKIHash()

	publicKeyNonce := fmt.Sprintf("tee_t_public_key:%s", ethAddress.Hex())
	spkiHashNonce := shared.SPKINoncePrefix("tee_t") + fmt.Sprintf("%x", spkiHash[:])

	raw, err := t.generateAttestationDoc(context.Background(), publicKeyNonce, spkiHashNonce)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	attestationReport := &teeproto.AttestationReport{Type: attestationReportType(), Report: raw}
	t.attestationMutex.Lock()
	t.cachedAttestation = attestationReport
	// Expiry tracks the real NitroTPM leaf (AWS) so we stop serving / refresh
	// before it expires, instead of a fixed guess; falls back to the cache TTL
	// for GCP/CS. A cache miss regenerates, so this self-heals if AWS shortens
	// the leaf.
	t.attestationExpiry = shared.SNPAttestationExpiry(raw)
	t.attestationMutex.Unlock()
	t.logger.Debug("Cached new attestation",
		zap.String("type", attestationReport.Type),
		zap.Int("bytes", len(attestationReport.Report)))
	return nil
}

// nextRATLSRefresh is the adaptive cadence passed to RunRATLSRefresh: for
// SEV-SNP, refresh when the cached attestation is due to go stale (the
// NitroTPM leaf expiry minus margin), clamped to a floor (avoid churn) and the
// RATLSRefreshIntervalSNP ceiling. Returns 0 for CS so the fixed cadence applies.
func (t *TEET) nextRATLSRefresh() time.Duration {
	if !shared.IsSEVSNPMode() {
		return 0
	}
	t.attestationMutex.RLock()
	exp := t.attestationExpiry
	t.attestationMutex.RUnlock()
	d := time.Until(exp)
	if d > shared.RATLSRefreshIntervalSNP {
		d = shared.RATLSRefreshIntervalSNP
	}
	if d < 10*time.Minute {
		d = 10 * time.Minute
	}
	return d
}

// getCachedAttestation returns the cached attestation if valid, otherwise
// generates a new one. Concurrent cache-miss callers are coalesced via
// singleflight so only ONE launcher-socket call fires; all waiters share
// the result.
func (t *TEET) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	if t.ratls == nil {
		return nil, nil
	}
	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()
	if cached != nil && time.Now().Before(expiry) {
		t.logger.Debug("Using cached attestation",
			zap.String("session_id", sessionID),
			zap.String("type", cached.Type))
		return cached, nil
	}

	t.logger.WarnIf("Cached attestation expired or missing, coalescing refresh",
		zap.String("session_id", sessionID))
	val, err, _ := t.attestationSF.Do("refresh", func() (any, error) {
		// Re-check inside the singleflight in case another caller just
		// finished refreshing while we were waiting at the door.
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

func (t *TEET) generateAttestationReport(sessionID string) (*teeproto.AttestationReport, error) {
	return t.getCachedAttestation(sessionID)
}

// generateAttestationForTEEK generates attestation with cert hash for mutual auth
func (t *TEET) generateAttestationForTEEK() (*teeproto.AttestationReport, error) {
	// Standalone (local-dev) mode: peer won't run a real attestation verifier.
	if t.ratls == nil {
		return &teeproto.AttestationReport{
			Type:   "standalone",
			Report: []byte("standalone"),
		}, nil
	}

	// SPKI binding — see refreshAttestation comment for rationale.
	spkiHash := t.ratls.SPKIHash()
	userData := shared.SPKINoncePrefix("tee_t") + fmt.Sprintf("%x", spkiHash[:])

	t.logger.Debug("Generating attestation for TEE_K (SPKI-bound)")

	attestationDoc, err := t.generateAttestationDoc(context.Background(), userData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	attestationType := attestationReportType()

	t.logger.Debug("Generated attestation for TEE_K",
		zap.String("type", attestationType))

	return &teeproto.AttestationReport{
		Type:   attestationType,
		Report: attestationDoc,
	}, nil
}

// verifyTEEKAttestation verifies TEE_K's attestation request. Symmetric to
// TEE_K's verifyTEETAttestation: validates the JWT signature, then confirms
// the eat_nonce array carries a `tee_k_cert_hash:<sha256(peer cert)>` entry
// — binding the inner attestation to the TLS cert TEE_K presented during
// the mTLS handshake.
//
// TEE_K's attestation carries TWO nonces (tee_k_public_key:<eth-addr> and
// tee_k_cert_hash:<hash>), so we look up by prefix rather than reading
// nonce[0].
//
// peerCert is the raw DER of TEE_K's client cert (PeerCertificates[0] of
// the TLS connection underlying this control WebSocket). Pass nil in
// standalone mode; the function will branch into the standalone path.
func (t *TEET) verifyTEEKAttestation(req *teeproto.TEEKAttestationRequest, peerCert []byte) error {
	attestation := req.AttestationReport

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

	if len(peerCert) == 0 {
		return fmt.Errorf("no peer TLS certificate available for SPKI binding")
	}

	expectedSPKI, err := shared.SPKIHashFromCertDER(peerCert)
	if err != nil {
		return fmt.Errorf("compute TEE_K SPKI hash: %w", err)
	}
	expectedSPKIHex := fmt.Sprintf("%x", expectedSPKI[:])

	// SEV-SNP: the attestation binds a presentable nonce list; verify it against
	// AMD+vTPM hardware, then confirm the tee_k SPKI nonce matches the mTLS peer.
	if attestation.Type == "sev-snp" {
		nonces, _, _, err := shared.VerifyCombinedSEVSNPNonceAttestation(attestation.Report)
		if err != nil {
			return fmt.Errorf("validate TEE_K SEV-SNP attestation: %w", err)
		}
		gotHex, err := shared.FindNonceInList(nonces, shared.SPKINoncePrefix("tee_k"))
		if err != nil {
			return fmt.Errorf("find tee_k_spki_hash nonce: %w", err)
		}
		if gotHex != expectedSPKIHex {
			return fmt.Errorf("TEE_K SPKI mismatch: attestation says %q, peer cert SPKI hashes to %q", gotHex, expectedSPKIHex)
		}
		t.logger.Debug("TEE_K SEV-SNP attestation verified")
		return nil
	}

	// RA-TLS already verified peer image_digest at the TLS handshake.
	// Bind the attestation to TEE_K's TLS keypair via the SPKI nonce —
	// stable across cert refreshes, unlike a full cert-DER hash.
	attestor, err := shared.NewGoogleAttestor()
	if err != nil {
		return fmt.Errorf("build attestor: %w", err)
	}
	if err := attestor.Validate(attestation.Report, t.logger); err != nil {
		return fmt.Errorf("validate TEE_K attestation JWT: %w", err)
	}

	gotHex, err := shared.FindNonceValue(attestation.Report, shared.SPKINoncePrefix("tee_k"))
	if err != nil {
		return fmt.Errorf("find tee_k_spki_hash nonce: %w", err)
	}
	if gotHex != expectedSPKIHex {
		return fmt.Errorf("TEE_K SPKI mismatch: attestation says %q, peer cert SPKI hashes to %q", gotHex, expectedSPKIHex)
	}

	t.logger.Debug("TEE_K SPKI hash verified")
	return nil
}
