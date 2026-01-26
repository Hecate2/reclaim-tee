package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

func (t *TEET) startAttestationRefresh(ctx context.Context) {
	t.logger.Info("Starting background attestation refresh (4-minute interval)")
	if err := t.refreshAttestation(); err != nil {
		t.logger.Error("Failed to pre-generate initial attestation", zap.Error(err))
	} else {
		t.logger.Info("Successfully pre-generated initial attestation")
	}
	ticker := time.NewTicker(4 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Stopping attestation refresh due to context cancellation")
			return
		case <-ticker.C:
			if err := t.refreshAttestation(); err != nil {
				t.logger.Error("Failed to refresh attestation", zap.Error(err))
			} else {
				t.logger.Info("Successfully refreshed attestation")
			}
		}
	}
}

func (t *TEET) refreshAttestation() error {
	if t.enclaveManager == nil {
		return nil
	}
	ethAddress := t.signingKeyPair.GetEthAddress()
	userData := fmt.Sprintf("tee_t_public_key:%s", ethAddress.Hex())

	raw, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	// Attestation type is always GCP
	attestationReport := &teeproto.AttestationReport{Type: "gcp", Report: raw}
	t.attestationMutex.Lock()
	t.cachedAttestation = attestationReport
	t.attestationExpiry = time.Now().Add(5 * time.Minute)
	t.attestationMutex.Unlock()
	t.logger.Info("Cached new attestation",
		zap.String("type", attestationReport.Type),
		zap.Int("bytes", len(attestationReport.Report)),
		zap.Time("expires", t.attestationExpiry))
	return nil
}

func (t *TEET) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	if t.enclaveManager == nil {
		return nil, nil
	}
	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()
	if cached != nil && time.Now().Before(expiry) {
		t.logger.Info("Using cached attestation",
			zap.String("session_id", sessionID),
			zap.String("type", cached.Type),
			zap.Time("expires", expiry))
		return cached, nil
	}
	t.logger.WarnIf("Cached attestation expired or missing, generating new one",
		zap.String("session_id", sessionID))
	if err := t.refreshAttestation(); err != nil {
		return nil, fmt.Errorf("failed to generate fallback attestation: %v", err)
	}
	t.attestationMutex.RLock()
	result := t.cachedAttestation
	t.attestationMutex.RUnlock()
	return result, nil
}

func (t *TEET) generateAttestationReport(sessionID string) (*teeproto.AttestationReport, error) {
	return t.getCachedAttestation(sessionID)
}

// generateAttestationForTEEK generates attestation with cert hash for mutual auth
func (t *TEET) generateAttestationForTEEK() (*teeproto.AttestationReport, error) {
	// Standalone mode: return "standalone" string
	if t.enclaveManager == nil {
		return &teeproto.AttestationReport{
			Type:   "standalone",
			Report: []byte("standalone"),
		}, nil
	}

	// Enclave mode: generate attestation with cert hash in userData
	// Always fetch the current certificate from enclave manager to ensure it matches
	// what's being served via TLS (handles certificate renewals correctly).
	tlsCert, err := t.enclaveManager.GetCertificateRaw()
	if err != nil {
		return nil, fmt.Errorf("failed to get current TLS certificate: %v", err)
	}
	if len(tlsCert) == 0 {
		return nil, fmt.Errorf("TLS certificate not loaded")
	}

	certHash := sha256.Sum256(tlsCert)
	userData := fmt.Sprintf("tee_t_cert_hash:%x", certHash[:])

	t.logger.Info("Generating attestation for TEE_K",
		zap.String("user_data", userData),
		zap.Int("cert_bytes", len(tlsCert)))

	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	// Attestation type is always GCP
	attestationType := "gcp"

	t.logger.Info("Generated attestation for TEE_K",
		zap.String("type", attestationType),
		zap.String("user_data", userData))

	return &teeproto.AttestationReport{
		Type:   attestationType,
		Report: attestationDoc,
	}, nil
}

// verifyTEEKAttestation verifies TEE_K's attestation request
func (t *TEET) verifyTEEKAttestation(req *teeproto.TEEKAttestationRequest) error {
	attestation := req.AttestationReport

	// Standalone mode
	if attestation.Type == "standalone" {
		if t.enclaveManager == nil && string(attestation.Report) == "standalone" {
			t.logger.Info("Standalone mode attestation accepted")
			return nil
		}
		return fmt.Errorf("mode mismatch: received standalone attestation")
	}

	// Enclave mode
	if t.enclaveManager == nil {
		return fmt.Errorf("mode mismatch: not in enclave mode")
	}

	// Verify PCR0
	if t.expectedTEEKPCR0 == "" {
		return fmt.Errorf("EXPECTED_TEEK_PCR0 not configured")
	}

	pcr0, err := shared.ExtractPCR0FromAttestation(attestation, t.logger)
	if err != nil {
		return fmt.Errorf("failed to extract PCR0: %v", err)
	}

	if pcr0 != t.expectedTEEKPCR0 {
		return fmt.Errorf("PCR0 mismatch: expected %s, got %s",
			t.expectedTEEKPCR0, pcr0)
	}

	t.logger.Info("TEE_K PCR0 verified", zap.String("pcr0", pcr0))

	// Verify attestation contains TEE_K public key identifier
	// For GCP, the public key is in the eat_nonce claim of the JWT
	userData, err := shared.ExtractUserDataFromGCPAttestation(attestation.Report, t.logger)
	if err != nil {
		t.logger.Warn("Failed to extract user data from TEE_K attestation", zap.Error(err))
	} else if bytes.Contains([]byte(userData), []byte("tee_k_public_key:")) {
		t.logger.Info("TEE_K attestation contains valid public key identifier", zap.String("userData", userData))
	} else {
		t.logger.Warn("TEE_K attestation missing public key identifier", zap.String("userData", userData))
	}

	return nil
}
