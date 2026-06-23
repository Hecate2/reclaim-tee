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
	AttestationTypeCS     = shared.AttestationTypeCS
	AttestationTypeSEVSNP = shared.AttestationTypeSEVSNP
)

// AttestationValidator validates a TEE attestation and returns the image
// identity to pin (sha256:<digest> for Confidential Space, snp-app:<hex> for
// SEV-SNP) plus the SPKI hash the attestation commits to. spkiDER is the
// registering key; the SEV-SNP path needs it to check report_data binds the
// vTPM AK to this exact key. The caller binds the returned hash to the key.
type AttestationValidator interface {
	Validate(attType, role string, token, spkiDER []byte) (imageIdentity string, spkiHash [32]byte, err error)
}

// DispatchingValidator routes by attestation type so Confidential Space and
// SEV-SNP TEEs share one /register path.
type DispatchingValidator struct {
	logger *zap.Logger
}

func NewDispatchingValidator(logger *zap.Logger) *DispatchingValidator {
	return &DispatchingValidator{logger: logger}
}

func (v *DispatchingValidator) Validate(attType, role string, token, spkiDER []byte) (string, [32]byte, error) {
	switch attType {
	case AttestationTypeSEVSNP:
		return validateSEVSNP(token, spkiDER)
	case AttestationTypeCS, "":
		return validateCS(token, role, v.logger)
	default:
		var zero [32]byte
		return "", zero, fmt.Errorf("unknown attestation type %q", attType)
	}
}

// validateCS verifies a Confidential Space attestation JWT (signature + chain)
// and returns the image digest and the role-scoped SPKI hash from eat_nonce.
// ExtractImageDigestFromGCPAttestation verifies the JWT, so the nonce read by
// FindNonceValue afterward is trustworthy.
func validateCS(token []byte, role string, logger *zap.Logger) (string, [32]byte, error) {
	var spki [32]byte
	digest, err := shared.ExtractImageDigestFromGCPAttestation(token, &shared.Logger{Logger: logger})
	if err != nil {
		return "", spki, fmt.Errorf("validate CS attestation: %w", err)
	}
	nonceRole := "tee_k"
	if store.Role(role) == store.RoleT {
		nonceRole = "tee_t"
	}
	expectedHex, err := shared.FindNonceValue(token, shared.SPKINoncePrefix(nonceRole))
	if err != nil {
		return "", spki, fmt.Errorf("find SPKI nonce: %w", err)
	}
	raw, err := hex.DecodeString(expectedHex)
	if err != nil || len(raw) != 32 {
		return "", spki, errors.New("CS eat_nonce SPKI hash malformed")
	}
	copy(spki[:], raw)
	return digest, spki, nil
}

// validateSEVSNP verifies a combined vTPM+SEV-SNP attestation and returns the
// app (payload) identity (snp-app:<hex>). token is base64(std) of the marshaled
// go-tpm-tools Attestation proto (base64 because the register body is JSON).
// VerifyCombinedGCPAttestation enforces report_data == sha512(AkPub||spkiDER),
// so the SPKI is bound by the attestation itself; we return sha256(spkiDER) as
// the bind hash the register handler checks against req.SPKIDer + body sig.
func validateSEVSNP(token, spkiDER []byte) (string, [32]byte, error) {
	var spki [32]byte
	raw, err := base64.StdEncoding.DecodeString(string(token))
	if err != nil {
		return "", spki, fmt.Errorf("decode SEV-SNP attestation base64: %w", err)
	}
	appID, _, err := shared.VerifyCombinedSEVSNPAttestation(raw, spkiDER)
	if err != nil {
		return "", spki, fmt.Errorf("validate SEV-SNP attestation: %w", err)
	}
	// Pin the app (payload) identity against the allowlist; the per-cloud base
	// is pinned separately (attestor / base allowlist).
	return appID, sha256.Sum256(spkiDER), nil
}
