package mpc_test

import (
	"crypto/aes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	markot "github.com/markkurossi/mpc/ot"
	"github.com/reclaimprotocol/reclaim-tee/mpc"
	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
)

func TestAESCMACEndToEnd(t *testing.T) {
	for test := 0; test < 3; test++ {
		senderOTs, receiverOTs := matchedOTs(t, uint64(test*mpc.InputBits))
		var garblerInput, evaluatorInput [80]byte
		mustRead(t, garblerInput[:])
		mustRead(t, evaluatorInput[:])

		got := runNewOPRF(t, garblerInput, evaluatorInput, senderOTs, receiverOTs)
		want := expectedCMAC(garblerInput, evaluatorInput)
		if got != want {
			t.Fatalf("case %d: CMAC mismatch: got %x want %x", test, got, want)
		}
	}
}

func TestMatchesLegacyCircuit(t *testing.T) {
	var garblerInput, evaluatorInput [80]byte
	mustRead(t, garblerInput[:])
	mustRead(t, evaluatorInput[:])

	senderOTs, receiverOTs := matchedOTs(t, 0)
	newResult := runNewOPRF(t, garblerInput, evaluatorInput, senderOTs, receiverOTs)
	legacyResult := runLegacyOPRF(t, garblerInput, evaluatorInput)
	if newResult != legacyResult {
		t.Fatalf("new result %x != legacy result %x", newResult, legacyResult)
	}
}

func TestOnlinePayloadRoundTripAndSize(t *testing.T) {
	senderOTs, receiverOTs := matchedOTs(t, 7_000)
	var garblerInput, evaluatorInput [80]byte
	mustRead(t, garblerInput[:])
	mustRead(t, evaluatorInput[:])

	payload, garbler, err := mpc.GarblerOnline(rand.Reader, garblerInput, senderOTs, 7_000)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mpc.MarshalOnlinePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	wantSize, err := mpc.OnlinePayloadSize()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != wantSize {
		t.Fatalf("encoded size %d, want %d", len(encoded), wantSize)
	}
	decoded, err := mpc.UnmarshalOnlinePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	payload.Release()

	evaluator, corrections, err := mpc.EvaluatorPrepare(decoded, evaluatorInput, receiverOTs)
	if err != nil {
		t.Fatal(err)
	}
	masks, err := mpc.ApplyCorrections(garbler, corrections)
	if err != nil {
		t.Fatal(err)
	}
	result, err := mpc.EvaluatorOnline(evaluator, masks)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := mpc.VerifyOutput(garbler, result.OutputLabels)
	if err != nil {
		t.Fatal(err)
	}
	if trusted != expectedCMAC(garblerInput, evaluatorInput) {
		t.Fatalf("CMAC mismatch after payload round trip")
	}

	if _, err := mpc.UnmarshalOnlinePayload(append(encoded, 0)); err == nil {
		t.Fatal("accepted trailing payload byte")
	}
	badVersion := append([]byte(nil), encoded...)
	badVersion[3] ^= 1
	if _, err := mpc.UnmarshalOnlinePayload(badVersion); err == nil {
		t.Fatal("accepted unsupported payload version")
	}
}

func TestSessionsAndIndicesAreSingleUse(t *testing.T) {
	senderOTs, receiverOTs := matchedOTs(t, 100)
	var garblerInput, evaluatorInput [80]byte
	payload, garbler, err := mpc.GarblerOnline(rand.Reader, garblerInput, senderOTs, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Release()
	evaluator, corrections, err := mpc.EvaluatorPrepare(payload, evaluatorInput, receiverOTs)
	if err != nil {
		t.Fatal(err)
	}
	masks, err := mpc.ApplyCorrections(garbler, corrections)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mpc.ApplyCorrections(garbler, corrections); err == nil {
		t.Fatal("accepted repeated corrections")
	}
	result, err := mpc.EvaluatorOnline(evaluator, masks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mpc.EvaluatorOnline(evaluator, masks); err == nil {
		t.Fatal("accepted repeated evaluation")
	}
	result.OutputLabels[0].D0 ^= 1
	if _, err := mpc.VerifyOutput(garbler, result.OutputLabels); err == nil {
		t.Fatal("accepted modified output label")
	}
	if _, err := mpc.VerifyOutput(garbler, result.OutputLabels); err == nil {
		t.Fatal("accepted repeated output verification")
	}

	badSender := append([]mpc.SenderOT(nil), senderOTs...)
	badSender[17].Index++
	if _, _, err := mpc.GarblerOnline(rand.Reader, garblerInput, badSender, 100); err == nil {
		t.Fatal("accepted non-contiguous sender OT indices")
	}
	badReceiver := append([]mpc.ReceiverOT(nil), receiverOTs...)
	badReceiver[17].Index++
	if _, _, err := mpc.EvaluatorPrepare(payload, evaluatorInput, badReceiver); err == nil {
		t.Fatal("accepted non-contiguous receiver OT indices")
	}
}

func BenchmarkOPRFNewGarbler(b *testing.B) {
	senderOTs, _ := matchedOTs(b, 0)
	var input [80]byte
	mustRead(b, input[:])
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		payload, _, err := mpc.GarblerOnline(rand.Reader, input, senderOTs, 0)
		if err != nil {
			b.Fatal(err)
		}
		payload.Release()
	}
}

func BenchmarkOPRFNewEndToEnd(b *testing.B) {
	senderOTs, receiverOTs := matchedOTs(b, 0)
	var garblerInput, evaluatorInput [80]byte
	mustRead(b, garblerInput[:])
	mustRead(b, evaluatorInput[:])
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		payload, garbler, err := mpc.GarblerOnline(rand.Reader, garblerInput, senderOTs, 0)
		if err != nil {
			b.Fatal(err)
		}
		evaluator, corrections, err := mpc.EvaluatorPrepare(payload, evaluatorInput, receiverOTs)
		if err != nil {
			b.Fatal(err)
		}
		masks, err := mpc.ApplyCorrections(garbler, corrections)
		if err != nil {
			b.Fatal(err)
		}
		result, err := mpc.EvaluatorOnline(evaluator, masks)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := mpc.VerifyOutput(garbler, result.OutputLabels); err != nil {
			b.Fatal(err)
		}
		payload.Release()
	}
}

func BenchmarkOPRFNewSerialize(b *testing.B) {
	senderOTs, _ := matchedOTs(b, 0)
	var input [80]byte
	payload, _, err := mpc.GarblerOnline(rand.Reader, input, senderOTs, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer payload.Release()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := mpc.MarshalOnlinePayload(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func runNewOPRF(t testing.TB, garblerInput, evaluatorInput [80]byte, senderOTs []mpc.SenderOT, receiverOTs []mpc.ReceiverOT) [16]byte {
	payload, garbler, err := mpc.GarblerOnline(rand.Reader, garblerInput, senderOTs, senderOTs[0].Index)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Release()
	evaluator, corrections, err := mpc.EvaluatorPrepare(payload, evaluatorInput, receiverOTs)
	if err != nil {
		t.Fatal(err)
	}
	masks, err := mpc.ApplyCorrections(garbler, corrections)
	if err != nil {
		t.Fatal(err)
	}
	result, err := mpc.EvaluatorOnline(evaluator, masks)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := mpc.VerifyOutput(garbler, result.OutputLabels)
	if err != nil {
		t.Fatal(err)
	}
	if trusted != result.CMACOutput {
		t.Fatalf("garbler result %x != evaluator result %x", trusted, result.CMACOutput)
	}
	return trusted
}

func matchedOTs(t testing.TB, start uint64) ([]mpc.SenderOT, []mpc.ReceiverOT) {
	sender := make([]mpc.SenderOT, mpc.InputBits)
	receiver := make([]mpc.ReceiverOT, mpc.InputBits)
	var buf [33]byte
	for i := range sender {
		mustRead(t, buf[:])
		r0 := mpc.Label{D0: bytesToUint64(buf[:8]), D1: bytesToUint64(buf[8:16])}
		r1 := mpc.Label{D0: bytesToUint64(buf[16:24]), D1: bytesToUint64(buf[24:32])}
		choice := buf[32]&1 != 0
		index := start + uint64(i)
		sender[i] = mpc.SenderOT{R0: r0, R1: r1, Index: index}
		received := r0
		if choice {
			received = r1
		}
		receiver[i] = mpc.ReceiverOT{R: received, Choice: choice, Index: index}
	}
	return sender, receiver
}

func runLegacyOPRF(t testing.TB, garblerInput, evaluatorInput [80]byte) [16]byte {
	curve := elliptic.P256()
	sender := make([]*oprfmpc.OTPoolEntry, oprfmpc.OTsPerOPRF)
	receiver := make([]*oprfmpc.OTReceiverEntry, oprfmpc.OTsPerOPRF)
	for i := range sender {
		setup, err := markot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			t.Fatal(err)
		}
		bundle, points, err := markot.BuildCOChoices(rand.Reader, curve, setup.Ax, setup.Ay, []bool{i&1 != 0})
		if err != nil {
			t.Fatal(err)
		}
		sender[i] = &oprfmpc.OTPoolEntry{SenderSetup: setup, ReceiverPoint: points[0], Index: i}
		receiver[i] = &oprfmpc.OTReceiverEntry{
			ReceiverBundle: bundle, SenderPublicPoint: markot.ECPoint{X: setup.Ax, Y: setup.Ay}, Index: i,
		}
	}
	payload, garbler, err := oprfmpc.CMACGarblerOnline(rand.Reader, curve, garblerInput, sender, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Release()
	evaluator, corrections, err := oprfmpc.CMACEvaluatorPrepare(payload, evaluatorInput, receiver)
	if err != nil {
		t.Fatal(err)
	}
	masks, err := oprfmpc.CMACGarblerApplyCorrections(garbler, corrections)
	if err != nil {
		t.Fatal(err)
	}
	result, err := oprfmpc.CMACEvaluatorOnline(curve, evaluator, masks)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := oprfmpc.CMACGarblerVerifyOutput(garbler, result.OutputLabels)
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

func expectedCMAC(garblerInput, evaluatorInput [80]byte) [16]byte {
	var key [16]byte
	var message [64]byte
	for i := range key {
		key[i] = garblerInput[64+i] ^ evaluatorInput[64+i]
	}
	for i := range message {
		message[i] = garblerInput[i] ^ evaluatorInput[i]
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	var zero, l [16]byte
	block.Encrypt(l[:], zero[:])
	k1 := leftShift(l)
	var c [16]byte
	for blockIndex := 0; blockIndex < 4; blockIndex++ {
		var m [16]byte
		copy(m[:], message[blockIndex*16:(blockIndex+1)*16])
		if blockIndex == 3 {
			for i := range m {
				m[i] ^= k1[i]
			}
		}
		for i := range m {
			m[i] ^= c[i]
		}
		block.Encrypt(c[:], m[:])
	}
	return c
}

func leftShift(in [16]byte) [16]byte {
	var out [16]byte
	var carry byte
	for i := 15; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if in[0]>>7 != 0 {
		out[15] ^= 0x87
	}
	return out
}

func mustRead(t testing.TB, dst []byte) {
	t.Helper()
	if _, err := rand.Read(dst); err != nil {
		t.Fatal(err)
	}
}

func bytesToUint64(src []byte) uint64 {
	return uint64(src[0])<<56 | uint64(src[1])<<48 | uint64(src[2])<<40 | uint64(src[3])<<32 |
		uint64(src[4])<<24 | uint64(src[5])<<16 | uint64(src[6])<<8 | uint64(src[7])
}
