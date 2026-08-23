package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// Attestation types carried in the /register body's attestation_type field.
// Empty defaults to CS so existing Confidential Space TEEs need no change.
// Sourced from shared so the TEE and router agree on the wire value.
const (
	AttestationTypeCS         = shared.AttestationTypeCS
	AttestationTypeSEVSNP     = shared.AttestationTypeSEVSNP
	AttestationTypeSecureBoot = shared.AttestationTypeSecureBoot
)

// AttestationValidator validates a TEE attestation and returns the image
// identity to pin (sha256:<digest> for Confidential Space, snp-app:<hex> for
// SNP) plus the SPKI hash the attestation commits to. spkiDER is the registering
// key; SNP evidence binds it to the provider TPM. baseIdentity is set only by
// legacy SEV2, whose per-cloud PCR 11 value remains allowlisted during migration.
type AttestationValidator interface {
	Validate(attType, role string, token, spkiDER []byte) (imageIdentity, baseIdentity string, spkiHash [32]byte, err error)
}

// DispatchingValidator routes by attestation type so Confidential Space and
// SEV-SNP TEEs share one /register path.
type DispatchingValidator struct {
	logger *zap.Logger
}

func NewDispatchingValidator(logger *zap.Logger) *DispatchingValidator {
	return &DispatchingValidator{logger: logger}
}

func (v *DispatchingValidator) Validate(attType, role string, token, spkiDER []byte) (string, string, [32]byte, error) {
	switch attType {
	case AttestationTypeSEVSNP:
		return validateSEVSNP(token, spkiDER)
	case AttestationTypeSecureBoot:
		return validateSecureBoot(token, spkiDER)
	case AttestationTypeCS, "":
		return validateCS(token, role, v.logger)
	default:
		var zero [32]byte
		return "", "", zero, fmt.Errorf("unknown attestation type %q", attType)
	}
}

// validateCS verifies a Confidential Space attestation JWT (signature + chain)
// and returns the image digest and the role-scoped SPKI hash from eat_nonce.
// ExtractImageDigestFromGCPAttestation verifies the JWT, so the nonce read by
// FindNonceValue afterward is trustworthy.
func validateCS(token []byte, role string, logger *zap.Logger) (string, string, [32]byte, error) {
	var spki [32]byte
	digest, err := shared.ExtractImageDigestFromGCPAttestation(token, &shared.Logger{Logger: logger})
	if err != nil {
		return "", "", spki, fmt.Errorf("validate CS attestation: %w", err)
	}
	nonceRole := "tee_k"
	if store.Role(role) == store.RoleT {
		nonceRole = "tee_t"
	}
	expectedHex, err := shared.FindNonceValue(token, shared.SPKINoncePrefix(nonceRole))
	if err != nil {
		return "", "", spki, fmt.Errorf("find SPKI nonce: %w", err)
	}
	raw, err := hex.DecodeString(expectedHex)
	if err != nil || len(raw) != 32 {
		return "", "", spki, errors.New("CS eat_nonce SPKI hash malformed")
	}
	copy(spki[:], raw)
	return digest, "", spki, nil // CS has no separate base UKI
}

// validateSEVSNP verifies a combined vTPM+SEV-SNP attestation and returns the
// app (payload) identity (snp-app:<hex>). token is base64(std) of the marshaled
// go-tpm-tools Attestation proto (base64 because the register body is JSON).
// VerifyCombinedGCPAttestation enforces report_data == sha512(AkPub||spkiDER),
// so the SPKI is bound by the attestation itself; we return sha256(spkiDER) as
// the bind hash the register handler checks against req.SPKIDer + body sig.
func validateSEVSNP(token, spkiDER []byte) (string, string, [32]byte, error) {
	var spki [32]byte
	raw, err := base64.StdEncoding.DecodeString(string(token))
	if err != nil {
		return "", "", spki, fmt.Errorf("decode SEV-SNP attestation base64: %w", err)
	}
	appID, baseID, err := shared.VerifyCombinedSEVSNPAttestation(raw, spkiDER)
	if err != nil {
		return "", "", spki, fmt.Errorf("validate SEV-SNP attestation: %w", err)
	}
	// Both the app (payload, cross-cloud) and the per-cloud base UKI are pinned
	// against the allowlist by the register handler.
	return appID, baseID, sha256.Sum256(spkiDER), nil
}

func validateSecureBoot(token, spkiDER []byte) (string, string, [32]byte, error) {
	var spki [32]byte
	raw, err := base64.StdEncoding.DecodeString(string(token))
	if err != nil {
		return "", "", spki, fmt.Errorf("decode Secure Boot attestation base64: %w", err)
	}
	appID, _, err := shared.VerifyCombinedSecureBootAttestation(raw, spkiDER)
	if err != nil {
		return "", "", spki, fmt.Errorf("validate Secure Boot attestation: %w", err)
	}
	// R replaces the per-cloud PCR 11 allowlist. The app identity remains the
	// cross-cloud allowlist key and the registration body remains SPKI-bound.
	return appID, "", sha256.Sum256(spkiDER), nil
}
