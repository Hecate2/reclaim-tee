package auth

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// AttestationValidator validates a GCP Confidential Space attestation JWT
// (the same kind produced by `shared.GenerateGCPAttestation`) and returns
// the deployed image digest.
type AttestationValidator interface {
	Validate(token []byte) (imageDigest string, err error)
}

// CSAttestationValidator delegates JWT signature + chain validation to
// shared.ExtractImageDigestFromGCPAttestation, which is the same code path
// the TEEs use to verify each other today.
type CSAttestationValidator struct {
	logger *zap.Logger
}

func NewCSAttestationValidator(logger *zap.Logger) *CSAttestationValidator {
	return &CSAttestationValidator{logger: logger}
}

func (v *CSAttestationValidator) Validate(token []byte) (string, error) {
	// shared.Logger embeds *zap.Logger; the diagnostic Warn/Info calls in
	// the attestation validator only touch the embedded logger.
	digest, err := shared.ExtractImageDigestFromGCPAttestation(token, &shared.Logger{Logger: v.logger})
	if err != nil {
		return "", fmt.Errorf("validate CS attestation: %w", err)
	}
	return digest, nil
}
