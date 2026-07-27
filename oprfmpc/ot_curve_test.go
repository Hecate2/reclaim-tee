package oprfmpc

import (
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

// The pair pins P-256 on both halves; a wire value naming any other curve
// means the peer disagrees about the group and must be rejected.
func TestDeserializeRejectsForeignCurveName(t *testing.T) {
	setups := make([]ot.COSenderSetup, 1)
	setup, err := ot.GenerateCOSenderSetup(rand.Reader, elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateCOSenderSetup: %v", err)
	}
	setups[0] = setup

	wire := SerializeBulkCOSenderSetup(setups)
	if _, err := DeserializeBulkCOSenderSetup(wire); err != nil {
		t.Fatalf("round trip of a genuine P-256 setup must succeed: %v", err)
	}

	forged := forgeCurveName(t, wire, "P-384")
	_, err = DeserializeBulkCOSenderSetup(forged)
	if err == nil || !strings.Contains(err.Error(), "unexpected OT curve") {
		t.Fatalf("expected foreign curve rejection, got %v", err)
	}
}

func TestReceiverDataRejectsForeignCurveName(t *testing.T) {
	setup, err := ot.GenerateCOSenderSetup(rand.Reader, elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateCOSenderSetup: %v", err)
	}

	genuine := &OTReceiverData{CurveName: otCurveName, Ax: setup.Ax, Ay: setup.Ay}
	if _, err := DeserializeBulkOTReceiverData(SerializeBulkOTReceiverData(genuine)); err != nil {
		t.Fatalf("round trip of genuine P-256 receiver data must succeed: %v", err)
	}

	forged := &OTReceiverData{CurveName: "P-384", Ax: setup.Ax, Ay: setup.Ay}
	_, err = DeserializeBulkOTReceiverData(SerializeBulkOTReceiverData(forged))
	if err == nil || !strings.Contains(err.Error(), "unexpected OT curve") {
		t.Fatalf("expected foreign curve rejection, got %v", err)
	}
}

// forgeCurveName rewrites the first entry's curve name, keeping the rest of
// the buffer intact, to model a peer that claims a different group.
func forgeCurveName(t *testing.T, wire []byte, name string) []byte {
	t.Helper()

	oldLen := int(wire[4])<<8 | int(wire[5])
	rest := wire[6+oldLen:]

	out := make([]byte, 0, len(wire)+len(name))
	out = append(out, wire[:4]...)
	out = append(out, byte(len(name)>>8), byte(len(name)))
	out = append(out, name...)
	return append(out, rest...)
}
