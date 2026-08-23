package shared

import "testing"

func TestCurrentSNPAttestationType(t *testing.T) {
	t.Setenv(snpAttestationTypeEnv, "")
	if got := CurrentSNPAttestationType(); got != AttestationTypeSEVSNP {
		t.Fatalf("default type = %q, want %q", got, AttestationTypeSEVSNP)
	}

	t.Setenv(snpAttestationTypeEnv, AttestationTypeSecureBoot)
	if got := CurrentSNPAttestationType(); got != AttestationTypeSecureBoot {
		t.Fatalf("secure type = %q, want %q", got, AttestationTypeSecureBoot)
	}
}

func TestValidateSNPAttestationType(t *testing.T) {
	for _, value := range []string{"", AttestationTypeSEVSNP, AttestationTypeSecureBoot} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(snpAttestationTypeEnv, value)
			if err := ValidateSNPAttestationType(); err != nil {
				t.Fatalf("valid value %q rejected: %v", value, err)
			}
		})
	}

	t.Setenv(snpAttestationTypeEnv, "secureboot")
	if err := ValidateSNPAttestationType(); err == nil {
		t.Fatal("unknown explicit attestation type accepted")
	}
}

func TestSecureBootTagsAreNotLegacySEV2(t *testing.T) {
	for _, tag := range []byte{snpAttestTagSecureBootGCP, snpAttestTagSecureBootAWS} {
		att := []byte{tag}
		if !IsSecureBootAttestation(att) {
			t.Fatalf("tag 0x%02x not recognized as Secure Boot", tag)
		}
		if _, _, err := VerifyCombinedSEVSNPAttestation(att, []byte("spki")); err == nil {
			t.Fatalf("legacy SEV2 verifier accepted Secure Boot tag 0x%02x", tag)
		}
	}
}

func TestPeerAttestationGenerationMustMatchLocalMode(t *testing.T) {
	legacy := []byte{snpAttestTagGCP}
	secure := []byte{snpAttestTagSecureBootGCP}

	t.Setenv(snpAttestationTypeEnv, AttestationTypeSEVSNP)
	if err := validatePeerSNPAttestationType(legacy); err != nil {
		t.Fatalf("legacy peer rejected in SEV2 mode: %v", err)
	}
	if err := validatePeerSNPAttestationType(secure); err == nil {
		t.Fatal("Secure Boot peer accepted in SEV2 mode")
	}

	t.Setenv(snpAttestationTypeEnv, AttestationTypeSecureBoot)
	if err := validatePeerSNPAttestationType(secure); err != nil {
		t.Fatalf("Secure Boot peer rejected in Secure Boot mode: %v", err)
	}
	if err := validatePeerSNPAttestationType(legacy); err == nil {
		t.Fatal("legacy peer accepted in Secure Boot mode")
	}
}
