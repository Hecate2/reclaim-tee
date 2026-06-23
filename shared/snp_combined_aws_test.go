//go:build !mobile

package shared

import (
	"os"
	"strings"
	"testing"
)

// TestVerifyCombinedAWSAttestation drives the AWS verifier against a real
// combined attestation (NitroTPM doc + SEV report) captured from an AWS
// SEV-SNP + NitroTPM instance via the nitroprobe.
func TestVerifyCombinedAWSAttestation(t *testing.T) {
	env, err := os.ReadFile("testdata/aws_combined_attestation.bin")
	if err != nil {
		t.Skipf("no AWS combined fixture: %v", err)
	}
	spki, err := os.ReadFile("testdata/aws_combined_attestation.spki")
	if err != nil {
		t.Fatalf("read spki: %v", err)
	}
	app, base, err := VerifyCombinedAWSAttestation(env, spki)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.HasPrefix(app, SEVSNPAppPrefix) || !strings.HasPrefix(base, SEVSNPBasePrefix) {
		t.Fatalf("bad identities app=%q base=%q", app, base)
	}
	if _, _, err := VerifyCombinedAWSAttestation(env, []byte("wrong spki")); err == nil {
		t.Fatal("expected binding failure with wrong SPKI")
	}
	t.Logf("verified AWS combined: app=%s base=%s", app, base)
}
