//go:build !mobile

package shared

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestBuildSEVSNPReportData_Layout(t *testing.T) {
	spki := sha256.Sum256([]byte("spki"))
	bin := sha256.Sum256([]byte("binary"))
	rd := BuildSEVSNPReportData(spki, bin)

	if !bytes.Equal(rd[:32], spki[:]) {
		t.Errorf("report_data[0:32] = %x, want SPKI hash %x", rd[:32], spki)
	}
	if !bytes.Equal(rd[32:], bin[:]) {
		t.Errorf("report_data[32:64] = %x, want binary hash %x", rd[32:], bin)
	}
}

func TestSEVSNPIdentity_Format(t *testing.T) {
	measurement := make([]byte, 48)
	for i := range measurement {
		measurement[i] = byte(i)
	}
	id := SEVSNPIdentity(measurement)
	rest, ok := strings.CutPrefix(id, SEVSNPIdentityPrefix)
	if !ok {
		t.Fatalf("identity %q missing prefix %q", id, SEVSNPIdentityPrefix)
	}
	if len(rest) != 96 {
		t.Errorf("hex portion = %d chars, want 96 (48 bytes)", len(rest))
	}
	if rest != hex.EncodeToString(measurement) {
		t.Errorf("hex portion = %q, want %q", rest, hex.EncodeToString(measurement))
	}
}

func TestVerifySEVSNPAttestation_Rejects(t *testing.T) {
	if _, _, err := VerifySEVSNPAttestation(nil, true); err == nil {
		t.Error("expected error for empty attestation, got nil")
	}
	if _, _, err := VerifySEVSNPAttestation([]byte("not-a-proto-\xff\xfe"), true); err == nil {
		t.Error("expected error for malformed proto, got nil")
	}
}

// TestVerifySEVSNPAttestation_AWS_VLEK verifies a real AWS SEV-SNP attestation
// (captured by deploy/snp-aws-poc.sh). AWS signs with VLEK and ships only the
// VLEK leaf, so this exercises the VLEK trusted-roots path offline (the ASVK
// comes from go-sev-guest's embedded AMD bundle, not the report).
func TestVerifySEVSNPAttestation_AWS_VLEK(t *testing.T) {
	raw, err := os.ReadFile("testdata/aws_vlek_attestation.bin")
	if err != nil {
		t.Skip("no AWS VLEK fixture: " + err.Error())
	}
	measurement, rd, err := VerifySEVSNPAttestation(raw, true)
	if err != nil {
		t.Fatalf("verify AWS VLEK attestation: %v", err)
	}
	if len(measurement) != 48 {
		t.Errorf("measurement = %d bytes, want 48", len(measurement))
	}
	// snp-poc put a fixed placeholder in report_data[0:32]; just confirm it parsed.
	if rd.SPKIHash == ([32]byte{}) {
		t.Error("report_data SPKI half is all zero")
	}
}

func TestSelfBinaryHash(t *testing.T) {
	h, err := SelfBinaryHash()
	if err != nil {
		t.Fatalf("SelfBinaryHash: %v", err)
	}
	if h == ([32]byte{}) {
		t.Error("self binary hash is all zero")
	}
}
