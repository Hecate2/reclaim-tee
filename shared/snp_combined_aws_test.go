//go:build !mobile

package shared

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
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

func TestVerifyCombinedAWSAttestationV2PolicyRejectsLegacy(t *testing.T) {
	env, err := os.ReadFile("testdata/aws_combined_attestation.bin")
	if err != nil {
		t.Skipf("no AWS combined fixture: %v", err)
	}
	spki, err := os.ReadFile("testdata/aws_combined_attestation.spki")
	if err != nil {
		t.Fatalf("read spki: %v", err)
	}
	t.Setenv(awsAttestationV2RequiredEnv, "1")
	if _, _, err := VerifyCombinedAWSAttestation(env, spki); err == nil || !strings.Contains(err.Error(), "no same-guest v2 proof") {
		t.Fatalf("legacy evidence under v2 policy: %v", err)
	}
}

func TestAWSAttestationV2PolicyFailsSecureOnTypos(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", false},
		{"0", false},
		{"1", true},
		{"true", true},
		{"typo", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(awsAttestationV2RequiredEnv, tc.value)
			if got := requireAWSAttestationV2(); got != tc.want {
				t.Fatalf("requireAWSAttestationV2() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAWSCombinedV2ReportDataBindsEveryField(t *testing.T) {
	bound := []byte("bound")
	app := bytes.Repeat([]byte{0x42}, 32)
	doc := []byte("signed NitroTPM document")
	want := awsCombinedV2ReportData(bound, app, doc)

	for name, fields := range map[string][][]byte{
		"bound": {[]byte("other"), app, doc},
		"app":   {bound, bytes.Repeat([]byte{0x43}, 32), doc},
		"doc":   {bound, app, []byte("other document")},
	} {
		t.Run(name, func(t *testing.T) {
			got := awsCombinedV2ReportData(fields[0], fields[1], fields[2])
			if got == want {
				t.Fatal("mutated transcript produced the same commitment")
			}
		})
	}
}

func TestAWSCombinedV2EnvelopeRemainsLegacyDecodable(t *testing.T) {
	type legacyEnvelope struct {
		AppHash  []byte   `cbor:"app"`
		NitroTPM []byte   `cbor:"nitrotpm,omitempty"`
		SEV      []byte   `cbor:"sev,omitempty"`
		Nonces   []string `cbor:"nonces,omitempty"`
	}

	want := combinedEnvelope{
		AppHash:  []byte("app"),
		NitroTPM: []byte("nitro"),
		SEV:      []byte("legacy"),
		SEV2:     []byte("same-guest"),
		Nonces:   []string{"nonce"},
	}
	raw, err := cbor.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got legacyEnvelope
	if err := cbor.Unmarshal(raw, &got); err != nil {
		t.Fatalf("legacy decoder rejected expanded envelope: %v", err)
	}
	if !bytes.Equal(got.AppHash, want.AppHash) || !bytes.Equal(got.NitroTPM, want.NitroTPM) ||
		!bytes.Equal(got.SEV, want.SEV) || len(got.Nonces) != 1 || got.Nonces[0] != "nonce" {
		t.Fatalf("legacy fields changed: %+v", got)
	}
}
