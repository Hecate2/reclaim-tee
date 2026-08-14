package mpc

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestOnlineWireCodecs(t *testing.T) {
	corrections := make([]bool, InputBits)
	for i := range corrections {
		corrections[i] = i%3 == 0
	}
	correctionData, err := MarshalChoiceCorrections(corrections)
	if err != nil {
		t.Fatal(err)
	}
	decodedCorrections, err := UnmarshalChoiceCorrections(correctionData)
	if err != nil {
		t.Fatal(err)
	}
	for i := range corrections {
		if decodedCorrections[i] != corrections[i] {
			t.Fatalf("correction %d changed", i)
		}
	}
	if _, err := UnmarshalChoiceCorrections(correctionData[:len(correctionData)-1]); err == nil {
		t.Fatal("accepted a truncated correction message")
	}

	masks := make([]OTMask, InputBits)
	for i := range masks {
		masks[i] = OTMask{M0: Label{D0: uint64(i)}, M1: Label{D1: uint64(i + 1)}}
	}
	maskData, err := MarshalOTMasks(masks)
	if err != nil {
		t.Fatal(err)
	}
	decodedMasks, err := UnmarshalOTMasks(maskData)
	if err != nil {
		t.Fatal(err)
	}
	for i := range masks {
		if decodedMasks[i] != masks[i] {
			t.Fatalf("mask %d changed", i)
		}
	}
	assertRejectsBadCountAndLength(t, maskData, UnmarshalOTMasks)

	labels := make([]Label, OutputBits)
	for i := range labels {
		labels[i] = Label{D0: uint64(i), D1: ^uint64(i)}
	}
	labelData, err := MarshalOutputLabels(labels)
	if err != nil {
		t.Fatal(err)
	}
	decodedLabels, err := UnmarshalOutputLabels(labelData)
	if err != nil {
		t.Fatal(err)
	}
	for i := range labels {
		if decodedLabels[i] != labels[i] {
			t.Fatalf("output label %d changed", i)
		}
	}
	assertRejectsBadCountAndLength(t, labelData, UnmarshalOutputLabels)
}

func TestPrecomputeWireFraming(t *testing.T) {
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	begin := PrecomputeBegin{SessionID: session, StartIndex: 1234, Count: InputBits}
	encodedBegin, err := MarshalPrecomputeBegin(begin)
	if err != nil {
		t.Fatal(err)
	}
	decodedBegin, err := UnmarshalPrecomputeBegin(encodedBegin)
	if err != nil {
		t.Fatal(err)
	}
	if decodedBegin != begin || PrecomputeRequestPhase(encodedBegin) != PrecomputePhaseBegin {
		t.Fatal("precompute begin round trip changed data")
	}
	if _, err := UnmarshalPrecomputeBegin(append(encodedBegin, 0)); err == nil {
		t.Fatal("accepted trailing precompute begin data")
	}

	base, _, _ := testBaseSeeds(t)
	request, _, err := ExtendReceiver(rand.Reader, base, session, begin.StartIndex, int(begin.Count))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, baseCipherMessageSize)
	copy(ciphertext[:4], "BOT1")
	finalData, err := MarshalPrecomputeFinal(ciphertext, request)
	if err != nil {
		t.Fatal(err)
	}
	decodedCiphertext, decodedRequest, err := UnmarshalPrecomputeFinal(finalData)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedCiphertext) != len(ciphertext) || decodedRequest.SessionID != session || decodedRequest.StartIndex != begin.StartIndex {
		t.Fatal("precompute final round trip changed data")
	}
	if _, _, err := UnmarshalPrecomputeFinal(append(finalData, 0)); err == nil {
		t.Fatal("accepted trailing precompute final data")
	}
	badLength := append([]byte(nil), finalData...)
	binary.BigEndian.PutUint32(badLength[4:8], uint32(baseCipherMessageSize-1))
	if _, _, err := UnmarshalPrecomputeFinal(badLength); err == nil {
		t.Fatal("accepted an invalid base ciphertext length")
	}

	if ExtensionEpoch(session) == "" || ExtensionEpoch(session) != ExtensionEpoch(session) {
		t.Fatal("extension epoch is not deterministic")
	}
}

func assertRejectsBadCountAndLength[T any](t *testing.T, encoded []byte, decode func([]byte) ([]T, error)) {
	t.Helper()
	badCount := append([]byte(nil), encoded...)
	binary.BigEndian.PutUint32(badCount[:4], 0)
	if _, err := decode(badCount); err == nil {
		t.Fatal("accepted a bad encoded count")
	}
	if _, err := decode(append(encoded, 0)); err == nil {
		t.Fatal("accepted trailing encoded data")
	}
}
