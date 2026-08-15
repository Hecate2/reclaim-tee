package mpc

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
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
	epoch := testEpoch(t)
	begin := PrecomputeBegin{SessionID: session, StartIndex: 1234, Count: InputBits, Epoch: epoch}
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
	oldBegin := append([]byte(nil), encodedBegin...)
	copy(oldBegin[:4], "KOB1")
	if PrecomputeRequestPhase(oldBegin) != PrecomputePhaseUnknown {
		t.Fatal("accepted KOS1 begin version")
	}

	baseSender, setup, err := StartBaseOTSender(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	setupFrame, err := MarshalPrecomputeBaseSetup(session, setup)
	if err != nil {
		t.Fatal(err)
	}
	decodedSetup, err := UnmarshalPrecomputeBaseSetup(setupFrame, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPrecomputeBaseSetup(append(setupFrame, 0), session); err == nil {
		t.Fatal("accepted trailing base setup data")
	}
	oldSetup := append([]byte(nil), setupFrame...)
	copy(oldSetup[:4], "KBS1")
	if _, err := UnmarshalPrecomputeBaseSetup(oldSetup, session); err == nil {
		t.Fatal("accepted KOS1 base setup wrapper")
	}
	baseReceiver, choices, err := StartBaseOTReceiver(rand.Reader, session, decodedSetup)
	if err != nil {
		t.Fatal(err)
	}
	choiceFrame, err := MarshalPrecomputeBaseChoices(session, choices)
	if err != nil {
		t.Fatal(err)
	}
	if PrecomputeRequestPhase(choiceFrame) != PrecomputePhaseBaseChoices {
		t.Fatal("did not classify KOS2 base choices")
	}
	decodedChoices, err := UnmarshalPrecomputeBaseChoices(choiceFrame, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPrecomputeBaseChoices(append(choiceFrame, 0), session); err == nil {
		t.Fatal("accepted trailing base choice data")
	}
	oldChoices := append([]byte(nil), choiceFrame...)
	copy(oldChoices[:4], "KBC1")
	if _, err := UnmarshalPrecomputeBaseChoices(oldChoices, session); err == nil {
		t.Fatal("accepted KOS1 base choice wrapper")
	}
	ciphertext, base, err := FinishBaseOTSender(baseSender, decodedChoices)
	if err != nil {
		t.Fatal(err)
	}
	receiverState, commitment, _, err := StartExtensionReceiver(rand.Reader, base, epoch, ciphertext, session, begin.StartIndex, int(begin.Count))
	if err != nil {
		t.Fatal(err)
	}
	commitmentFrame, err := MarshalPrecomputeCommitment(ciphertext, commitment)
	if err != nil {
		t.Fatal(err)
	}
	decodedCiphertext, decodedCommitment, err := UnmarshalPrecomputeCommitment(commitmentFrame)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedCiphertext) != len(ciphertext) || decodedCommitment.SessionID != session || decodedCommitment.StartIndex != begin.StartIndex {
		t.Fatal("precompute commitment round trip changed data")
	}
	if _, _, err := UnmarshalPrecomputeCommitment(append(commitmentFrame, 0)); err == nil {
		t.Fatal("accepted trailing precompute commitment data")
	}
	oldCommitment := append([]byte(nil), commitmentFrame...)
	copy(oldCommitment[:4], "KOF1")
	if _, _, err := UnmarshalPrecomputeCommitment(oldCommitment); err == nil {
		t.Fatal("accepted KOS1 commitment version")
	}
	encodedCommitment, err := MarshalExtensionCommitment(commitment)
	if err != nil {
		t.Fatal(err)
	}
	oldExtension := append([]byte(nil), encodedCommitment...)
	copy(oldExtension[:4], "KOS1")
	if _, err := UnmarshalExtensionCommitment(oldExtension); err == nil {
		t.Fatal("accepted KOS1 extension version")
	}
	badLength := append([]byte(nil), commitmentFrame...)
	binary.BigEndian.PutUint32(badLength[4:8], uint32(baseCipherMessageSize-1))
	if _, _, err := UnmarshalPrecomputeCommitment(badLength); err == nil {
		t.Fatal("accepted an invalid base ciphertext length")
	}
	selected, delta, err := FinishBaseOTReceiver(baseReceiver, decodedCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	senderState, challenge, err := StartExtensionSender(rand.Reader, selected, delta, epoch, decodedCiphertext, decodedCommitment)
	if err != nil {
		t.Fatal(err)
	}
	challengeFrame, err := MarshalExtensionChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if PrecomputeRequestPhase(challengeFrame) != PrecomputePhaseChallenge {
		t.Fatal("did not classify KOS2 challenge")
	}
	decodedChallenge, err := UnmarshalExtensionChallenge(challengeFrame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalExtensionChallenge(append(challengeFrame, 0)); err == nil {
		t.Fatal("accepted trailing challenge data")
	}
	oldChallenge := append([]byte(nil), challengeFrame...)
	copy(oldChallenge[:4], "KCH1")
	if _, err := UnmarshalExtensionChallenge(oldChallenge); err == nil {
		t.Fatal("accepted KOS1 challenge version")
	}
	proof, err := FinishExtensionReceiver(receiverState, decodedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	proofFrame, err := MarshalExtensionProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	decodedProof, err := UnmarshalExtensionProof(proofFrame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalExtensionProof(append(proofFrame, 0)); err == nil {
		t.Fatal("accepted trailing proof data")
	}
	oldProof := append([]byte(nil), proofFrame...)
	copy(oldProof[:4], "KPR1")
	if _, err := UnmarshalExtensionProof(oldProof); err == nil {
		t.Fatal("accepted KOS1 proof version")
	}
	if _, err := FinishExtensionSender(senderState, decodedProof); err != nil {
		t.Fatal(err)
	}
	framesBeforeComplete := [][]byte{encodedBegin, setupFrame, choiceFrame, commitmentFrame, challengeFrame, proofFrame}
	if got := len(framesBeforeComplete) + 1; got != 7 {
		t.Fatalf("precompute frame count=%d, want 7", got)
	}
	wantFrameBytes := []int{91, 105, 4_296, 16_544, 184, 2_132}
	for i := range framesBeforeComplete {
		if len(framesBeforeComplete[i]) != wantFrameBytes[i] {
			t.Fatalf("frame %d bytes=%d, want %d", i, len(framesBeforeComplete[i]), wantFrameBytes[i])
		}
	}

	if ExtensionEpoch(session) == "" || ExtensionEpoch(session) != ExtensionEpoch(session) || ExtensionEpoch(session)[:5] != "kos2:" {
		t.Fatal("extension epoch is not deterministic")
	}
}

func TestKOS2PrecomputeExactFrameCountAndWireBytes(t *testing.T) {
	if got, err := PrecomputeCommitmentWireSize(InputBits); err != nil || got != 16_544 {
		t.Fatalf("640-OT commitment bytes=%d err=%v, want 16544", got, err)
	}
	if got, err := PrecomputeChallengeWireSize(InputBits); err != nil || got != 184 {
		t.Fatalf("640-OT challenge bytes=%d err=%v, want 184", got, err)
	}
	if got := PrecomputeProofWireSize(); got != 2_132 {
		t.Fatalf("proof bytes=%d, want 2132", got)
	}
	if got, err := PrecomputeCommitmentWireSize(100_000); err != nil || got != 1_607_840 {
		t.Fatalf("100k commitment bytes=%d err=%v, want 1607840", got, err)
	}
	if got, err := PrecomputeChallengeWireSize(100_000); err != nil || got != 12_616 {
		t.Fatalf("100k challenge bytes=%d err=%v, want 12616", got, err)
	}
}

func TestKOS2GenericCodecsRoundTripAboveProductionLimit(t *testing.T) {
	const count = MaxPrecomputeOTs + 1
	padded, err := extensionPaddedCount(count)
	if err != nil {
		t.Fatal(err)
	}
	commitment := &ExtensionCommitment{Count: count, PaddedCount: uint32(padded), U: make([]byte, BaseOTCount*padded/8)}
	commitment.SessionID[0] = 1
	encodedCommitment, err := MarshalExtensionCommitment(commitment)
	if err != nil {
		t.Fatal(err)
	}
	decodedCommitment, err := UnmarshalExtensionCommitment(encodedCommitment)
	if err != nil {
		t.Fatal(err)
	}
	if decodedCommitment.Count != count || decodedCommitment.PaddedCount != uint32(padded) || len(decodedCommitment.U) != len(commitment.U) {
		t.Fatalf("generic commitment round trip count=%d padded=%d U=%d", decodedCommitment.Count, decodedCommitment.PaddedCount, len(decodedCommitment.U))
	}

	challenge := &ExtensionChallenge{SessionID: commitment.SessionID, Chi: make([]Label, extensionChallengeCount(padded))}
	challenge.Transcript = extensionChallengeTranscript(challenge)
	encodedChallenge, err := MarshalExtensionChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	decodedChallenge, err := UnmarshalExtensionChallenge(encodedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if decodedChallenge.SessionID != challenge.SessionID || len(decodedChallenge.Chi) != len(challenge.Chi) {
		t.Fatalf("generic challenge round trip session=%x Chi=%d", decodedChallenge.SessionID, len(decodedChallenge.Chi))
	}
}

func TestKOS2DecodersRejectTinyHighCountFramesBeforeAllocation(t *testing.T) {
	maxGenericPadded, err := extensionPaddedCount(maxExtensionOTs)
	if err != nil {
		t.Fatal(err)
	}
	truncatedCommitment := make([]byte, extensionCommitmentHeaderSize)
	copy(truncatedCommitment[:4], "KOC2")
	binary.BigEndian.PutUint32(truncatedCommitment[44:48], maxExtensionOTs)
	binary.BigEndian.PutUint32(truncatedCommitment[48:52], uint32(maxGenericPadded))
	if _, err := UnmarshalExtensionCommitment(truncatedCommitment); err == nil || !strings.Contains(err.Error(), "commitment length") {
		t.Fatalf("truncated high-count commitment error=%v, want exact-length rejection before copy", err)
	}

	truncatedChallenge := make([]byte, extensionChallengeHeaderSize)
	copy(truncatedChallenge[:4], "KCH2")
	binary.BigEndian.PutUint32(truncatedChallenge[100:104], uint32(extensionChallengeCount(maxGenericPadded)))
	if _, err := UnmarshalExtensionChallenge(truncatedChallenge); err == nil || !strings.Contains(err.Error(), "challenge length") {
		t.Fatalf("truncated high-count challenge error=%v, want exact-length rejection before allocation", err)
	}

	var session [32]byte
	session[0] = 9
	expected := PrecomputeBegin{SessionID: session, Count: 1, Epoch: ExtensionEpoch(session)}
	if _, _, err := UnmarshalPrecomputeCommitmentFor([]byte("KOF2"), PrecomputeBegin{Count: MaxPrecomputeOTs + 1}); err == nil || !strings.Contains(err.Error(), "unsupported OT precompute count") {
		t.Fatalf("production oversize commitment error=%v, want cap before length/copy", err)
	}
	tinyCommitment := make([]byte, 8+baseCipherMessageSize+extensionCommitmentHeaderSize)
	copy(tinyCommitment[:4], "KOF2")
	binary.BigEndian.PutUint32(tinyCommitment[4:8], baseCipherMessageSize)
	if _, _, err := UnmarshalPrecomputeCommitmentFor(tinyCommitment, expected); err == nil || !strings.Contains(err.Error(), "commitment length") {
		t.Fatalf("short expected commitment error=%v, want exact-length preflight", err)
	}

	challengeSize, err := PrecomputeChallengeWireSize(1)
	if err != nil {
		t.Fatal(err)
	}
	tinyWrongCount := make([]byte, challengeSize)
	copy(tinyWrongCount[:4], "KCH2")
	copy(tinyWrongCount[4:36], session[:])
	binary.BigEndian.PutUint32(tinyWrongCount[100:104], uint32(extensionChallengeCount(maxGenericPadded)))
	if _, err := UnmarshalExtensionChallengeFor(tinyWrongCount, session, 1); err == nil || !strings.Contains(err.Error(), "coefficient count mismatch") {
		t.Fatalf("wrong pending challenge error=%v, want expected-count rejection before allocation", err)
	}

	if _, err := UnmarshalExtensionProofFor([]byte("KPR2"), session); err == nil {
		t.Fatal("accepted tiny production proof")
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
