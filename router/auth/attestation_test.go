package auth

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestDispatchingValidator_SEVSNP drives the SEV-SNP path end-to-end against a
// real combined vTPM+SEV-SNP attestation captured from a GCP SEV-SNP CVM: the
// base64 proto + the bound SPKI verify to a snp-pcr:<hex> code identity.
func TestDispatchingValidator_SEVSNP(t *testing.T) {
	raw, err := os.ReadFile("../../shared/testdata/gcp_combined_attestation.bin")
	if err != nil {
		t.Skipf("no combined fixture: %v", err)
	}
	spki, err := os.ReadFile("../../shared/testdata/gcp_combined_attestation.spki")
	if err != nil {
		t.Fatalf("read spki: %v", err)
	}
	// The dispatcher reads a 1-byte cloud tag prefix (0x01 = GCP).
	token := []byte(base64.StdEncoding.EncodeToString(append([]byte{0x01}, raw...)))

	v := NewDispatchingValidator(zap.NewNop())
	id, base, bind, err := v.Validate(AttestationTypeSEVSNP, "T", token, spki)
	if err != nil {
		t.Fatalf("validate SEV-SNP: %v", err)
	}
	if !strings.HasPrefix(id, "snp-app:") {
		t.Fatalf("identity = %q, want snp-app: prefix", id)
	}
	if !strings.HasPrefix(base, "snp-base:") {
		t.Fatalf("base = %q, want snp-base: prefix", base)
	}
	if len(id) != len("snp-app:")+64 {
		t.Fatalf("identity = %q, want 64 hex chars", id)
	}
	if len(bind) != 32 {
		t.Fatalf("bind hash len = %d, want 32", len(bind))
	}
}

// Wrong SPKI must fail the report_data binding.
func TestDispatchingValidator_SEVSNPRejectsWrongSPKI(t *testing.T) {
	raw, err := os.ReadFile("../../shared/testdata/gcp_combined_attestation.bin")
	if err != nil {
		t.Skipf("no combined fixture: %v", err)
	}
	token := []byte(base64.StdEncoding.EncodeToString(append([]byte{0x01}, raw...)))
	v := NewDispatchingValidator(zap.NewNop())
	if _, _, _, err := v.Validate(AttestationTypeSEVSNP, "T", token, []byte("wrong spki")); err == nil {
		t.Fatal("expected binding failure with wrong SPKI")
	}
}

func TestDispatchingValidator_RejectsBadType(t *testing.T) {
	v := NewDispatchingValidator(zap.NewNop())
	if _, _, _, err := v.Validate("nonsense", "K", []byte("x"), nil); err == nil {
		t.Fatal("expected error for unknown attestation type")
	}
}

func TestDispatchingValidator_SEVSNPRejectsGarbage(t *testing.T) {
	v := NewDispatchingValidator(zap.NewNop())
	if _, _, _, err := v.Validate(AttestationTypeSEVSNP, "T", []byte("!!not base64!!"), []byte("spki")); err == nil {
		t.Fatal("expected error for non-base64 SEV-SNP token")
	}
}
