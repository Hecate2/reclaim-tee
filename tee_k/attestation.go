package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// startAttestationRefresh starts a background goroutine that pre-generates and refreshes attestations
func (t *TEEK) startAttestationRefresh(ctx context.Context) {
	t.logger.Debug("Starting background attestation refresh")

	// Pre-generate the first attestation
	if err := t.refreshAttestation(); err != nil {
		t.logger.Error("Failed to pre-generate initial attestation", zap.Error(err))
	} else {
		t.logger.Debug("Pre-generated initial attestation")
	}

	// Set up 4-minute ticker for refresh
	ticker := time.NewTicker(4 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.logger.Debug("Stopping attestation refresh")
			return
		case <-ticker.C:
			if err := t.refreshAttestation(); err != nil {
				t.logger.Error("Failed to refresh attestation", zap.Error(err))
			} else {
				t.logger.Debug("Refreshed attestation")
			}
		}
	}
}

// refreshAttestation generates a new attestation and caches it
func (t *TEEK) refreshAttestation() error {
	// Skip in standalone mode
	if t.enclaveManager == nil {
		return nil
	}

	// Get ETH address for this key pair
	ethAddress := t.signingKeyPair.GetEthAddress()

	// Create user data containing the ETH address
	userData := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())

	// Generate attestation document using enclave manager
	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
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

// getCachedAttestation returns the cached attestation if valid, otherwise generates a new one
func (t *TEEK) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	// Skip in standalone mode
	if t.enclaveManager == nil {
		return nil, nil
	}

	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()

	// Use cached attestation if valid
	if cached != nil && time.Now().Before(expiry) {
		t.logger.WithSession(sessionID).Debug("Using cached attestation",
			zap.String("type", cached.Type))
		return cached, nil
	}

	// Fallback: generate new attestation if cache is invalid
	t.logger.WithSession(sessionID).Warn("Cached attestation expired or missing, generating new one")

	if err := t.refreshAttestation(); err != nil {
		return nil, fmt.Errorf("failed to generate fallback attestation: %v", err)
	}

	t.attestationMutex.RLock()
	result := t.cachedAttestation
	t.attestationMutex.RUnlock()

	return result, nil
}

// generateAttestationReport generates an AttestationReport for enclave mode (uses cache for performance)
func (t *TEEK) generateAttestationReport(sessionID string) (*teeproto.AttestationReport, error) {
	// Use cached attestation for performance
	return t.getCachedAttestation(sessionID)
}

// generateAttestationForTEET generates attestation for mutual auth with TEE_T
func (t *TEEK) generateAttestationForTEET() (*teeproto.AttestationReport, error) {
	// Standalone mode: return "standalone" string
	if t.enclaveManager == nil {
		return &teeproto.AttestationReport{
			Type:   "standalone",
			Report: []byte("standalone"),
		}, nil
	}

	// Enclave mode: generate real attestation with eth address in userData
	ethAddress := t.signingKeyPair.GetEthAddress()
	userData := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())

	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
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

	// Standalone mode
	if attestation.Type == "standalone" {
		if t.enclaveManager == nil && string(attestation.Report) == "standalone" {
			t.logger.Debug("Standalone mode attestation accepted")
			return nil
		}
		return fmt.Errorf("mode mismatch: received standalone but in enclave mode")
	}

	// Enclave mode
	if t.enclaveManager == nil {
		return fmt.Errorf("mode mismatch: received enclave attestation but in standalone mode")
	}

	// Verify cert hash in userData - properly parse attestation document
	certHash := sha256.Sum256(tlsCert)
	expectedUserData := fmt.Sprintf("tee_t_cert_hash:%x", certHash[:])

	t.logger.Debug("Verifying TEE_T certificate hash")

	// Extract userData from attestation document based on type
	var actualUserData string
	var err error

	switch attestation.Type {
	case "gcp":
		actualUserData, err = shared.ExtractUserDataFromGCPAttestation(attestation.Report, t.logger)
		if err != nil {
			return fmt.Errorf("failed to extract userData from GCP attestation: %v", err)
		}
	default:
		return fmt.Errorf("unsupported attestation type: %s", attestation.Type)
	}

	if actualUserData != expectedUserData {
		t.logger.Error("Cert hash mismatch")
		return fmt.Errorf("cert hash mismatch")
	}

	t.logger.Debug("TEE_T certificate hash verified")

	// Verify PCR0
	expectedPCR0 := os.Getenv("EXPECTED_TEET_PCR0")
	if expectedPCR0 != "" {
		pcr0, err := shared.ExtractPCR0FromAttestation(attestation, t.logger)
		if err != nil {
			return fmt.Errorf("failed to extract PCR0: %v", err)
		}

		if pcr0 != expectedPCR0 {
			return fmt.Errorf("PCR0 mismatch: expected %s, got %s", expectedPCR0, pcr0)
		}

		t.logger.Debug("TEE_T PCR0 verified")
	}

	return nil
}
