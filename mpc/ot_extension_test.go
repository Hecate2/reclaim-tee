package mpc

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"strconv"
	"testing"
)

func TestTranspose128MatchesDefinition(t *testing.T) {
	const rows = 256
	const byteRows = rows / 8
	matrix := make([]byte, BaseOTCount*byteRows)
	if _, err := rand.Read(matrix); err != nil {
		t.Fatal(err)
	}
	got := make([]Label, rows)
	transposeColumns(matrix, byteRows, got)
	for row := 0; row < rows; row++ {
		for col := 0; col < BaseOTCount; col++ {
			want := matrix[col*byteRows+row/8]>>uint(row&7)&1 != 0
			if deltaBit(got[row], col) != want {
				t.Fatalf("row %d column %d: got %t want %t", row, col, deltaBit(got[row], col), want)
			}
		}
	}
}

func TestGF128Identities(t *testing.T) {
	values := []Label{{}, {D0: 1}, {D1: 1}, {D0: 0x0123456789abcdef, D1: 0xfedcba9876543210}}
	one := Label{D0: 1}
	for _, a := range values {
		if got := gf128Mul(a, one); got != a {
			t.Fatalf("a*1=%v, want %v", got, a)
		}
		if got := gf128Mul(a, Label{}); got != (Label{}) {
			t.Fatalf("a*0=%v", got)
		}
		for _, b := range values {
			if gf128Mul(a, b) != gf128Mul(b, a) {
				t.Fatalf("multiplication is not commutative for %v and %v", a, b)
			}
			for _, c := range values {
				if gf128Mul(a, b.xor(c)) != gf128Mul(a, b).xor(gf128Mul(a, c)) {
					t.Fatal("multiplication is not distributive")
				}
			}
		}
	}
}

func TestGF128AcceleratedMatchesGeneric(t *testing.T) {
	var buf [32]byte
	for i := 0; i < 1_000; i++ {
		if _, err := rand.Read(buf[:]); err != nil {
			t.Fatal(err)
		}
		a := labelFromBytes(buf[:16])
		b := labelFromBytes(buf[16:])
		if got, want := gf128Mul(a, b), gf128MulGeneric(a, b); got != want {
			t.Fatalf("case %d: accelerated product %v, want %v", i, got, want)
		}
	}
}

func TestKOS2ExtensionRoundTrip(t *testing.T) {
	for _, count := range []int{1, InputBits, 4_097, 100_000} {
		t.Run(testCountName(count), func(t *testing.T) {
			sender, receiver := runKOS2Extension(t, count, 9_000, rand.Reader, rand.Reader)
			assertMatchedOTs(t, sender, receiver)
		})
	}
}

func TestKOS2ExtensionCountBoundaries(t *testing.T) {
	for _, count := range []int{1, maxExtensionOTs} {
		if _, err := extensionPaddedCount(count); err != nil {
			t.Fatalf("valid count %d: %v", count, err)
		}
		if _, err := PrecomputeCommitmentWireSize(count); err != nil {
			t.Fatalf("wire size for valid count %d: %v", count, err)
		}
	}
	for _, count := range []int{0, -1, maxExtensionOTs + 1} {
		if _, err := extensionPaddedCount(count); err == nil {
			t.Fatalf("accepted invalid count %d", count)
		}
	}
}

func TestBaseOTAndKOS2ExtensionRoundTrip(t *testing.T) {
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := testEpoch(t)
	baseSender, setupMessage, err := StartBaseOTSender(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	baseReceiver, choiceMessage, err := StartBaseOTReceiver(rand.Reader, session, setupMessage)
	if err != nil {
		t.Fatal(err)
	}
	cipherMessage, basePairs, err := FinishBaseOTSender(baseSender, choiceMessage)
	if err != nil {
		t.Fatal(err)
	}
	receiverState, commitment, receiver, err := StartExtensionReceiver(rand.Reader, basePairs, epoch, cipherMessage, session, 41, InputBits)
	if err != nil {
		t.Fatal(err)
	}
	selected, delta, err := FinishBaseOTReceiver(baseReceiver, cipherMessage)
	if err != nil {
		t.Fatal(err)
	}
	if baseSender.setup.Scalar != nil || baseSender.seeds != ([BaseOTCount]BaseOTSeedPair{}) {
		t.Fatal("base OT sender secrets were not cleared")
	}
	if len(baseReceiver.bundle.Scalars) != 0 || baseReceiver.delta != (Label{}) {
		t.Fatal("base OT receiver secrets were not cleared")
	}
	extensionSender, challenge, err := StartExtensionSender(rand.Reader, selected, delta, epoch, cipherMessage, commitment)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := FinishExtensionReceiver(receiverState, challenge)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := FinishExtensionSender(extensionSender, proof)
	if err != nil {
		t.Fatal(err)
	}
	assertMatchedOTs(t, sender, receiver)

	if _, _, err := FinishBaseOTSender(baseSender, choiceMessage); err == nil {
		t.Fatal("accepted reused base OT sender state")
	}
	if _, _, err := FinishBaseOTReceiver(baseReceiver, cipherMessage); err == nil {
		t.Fatal("accepted reused base OT receiver state")
	}
}

func TestKOS2FormulaMatchesIndependentOracle(t *testing.T) {
	const padded = 384
	const byteRows = padded / 8
	choices := deterministicBytes(byteRows, 3)
	matrix := deterministicBytes(BaseOTCount*byteRows, 17)
	chi := []Label{
		labelFromBytes(deterministicBytes(16, 41)),
		labelFromBytes(deterministicBytes(16, 79)),
	}
	got := repetitionReceiverProof(choices, matrix, padded, chi)

	mainBytes := (padded - KOSCheckOTs) / 8
	wantX := labelFromBytes(choices[mainBytes : mainBytes+16])
	for j := range chi {
		wantX = wantX.xor(gf128MulGeneric(labelFromBytes(choices[j*16:(j+1)*16]), chi[j]))
	}
	if got.X != wantX {
		t.Fatalf("x=%v, oracle=%v", got.X, wantX)
	}
	for col := 0; col < BaseOTCount; col++ {
		column := matrix[col*byteRows : (col+1)*byteRows]
		wantT := labelFromBytes(column[mainBytes : mainBytes+16])
		for j := range chi {
			wantT = wantT.xor(gf128MulGeneric(labelFromBytes(column[j*16:(j+1)*16]), chi[j]))
		}
		if got.T[col] != wantT {
			t.Fatalf("t[%d]=%v, oracle=%v", col, got.T[col], wantT)
		}
	}
}

func TestKOS2ChecksEveryColumn(t *testing.T) {
	var transcript [32]byte
	transcript[0] = 9
	proof := &ExtensionProof{Transcript: transcript}
	for col := 0; col < BaseOTCount; col++ {
		state := &ExtensionSenderState{
			commitment:          ExtensionCommitment{Count: 1, PaddedCount: 256},
			challengeTranscript: transcript,
			rows:                make([]Label, 256),
		}
		bad := *proof
		bad.T[col].D0 = 1
		if _, err := FinishExtensionSender(state, &bad); !errors.Is(err, errKOSCheck) {
			t.Fatalf("column %d: got %v, want KOS check failure", col, err)
		}
	}
}

func TestKOS2RejectsCommitmentChallengeAndProofTampering(t *testing.T) {
	base, selected, delta := testBaseSeeds(t)
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := testEpoch(t)
	cipher := testCipherMessage(session)
	receiverState, commitment, _, err := StartExtensionReceiver(rand.Reader, base, epoch, cipher, session, 123, InputBits)
	if err != nil {
		t.Fatal(err)
	}

	commitmentTampering := []struct {
		name   string
		mutate func(*ExtensionCommitment)
	}{
		{"matrix", func(c *ExtensionCommitment) { c.U[len(c.U)/2] ^= 1 }},
		{"session", func(c *ExtensionCommitment) { c.SessionID[0] ^= 1 }},
		{"start-index", func(c *ExtensionCommitment) { c.StartIndex++ }},
		{"count", func(c *ExtensionCommitment) { c.Count++ }},
		{"padded-count", func(c *ExtensionCommitment) { c.PaddedCount += 128 }},
		{"epoch", func(c *ExtensionCommitment) { c.EpochHash[0] ^= 1 }},
		{"transcript", func(c *ExtensionCommitment) { c.Transcript[0] ^= 1 }},
	}
	for _, test := range commitmentTampering {
		t.Run(test.name, func(t *testing.T) {
			tampered := cloneExtensionCommitment(*commitment)
			test.mutate(&tampered)
			reader := &countingReader{reader: rand.Reader}
			if _, _, err := StartExtensionSender(reader, selected, delta, epoch, cipher, &tampered); err == nil {
				t.Fatal("accepted tampered commitment")
			}
			if reader.n != 0 {
				t.Fatalf("sampled %d challenge bytes before rejecting commitment", reader.n)
			}
		})
	}
	tamperedCipher := append([]byte(nil), cipher...)
	tamperedCipher[len(tamperedCipher)-1] ^= 1
	reader := &countingReader{reader: rand.Reader}
	if _, _, err := StartExtensionSender(reader, selected, delta, epoch, tamperedCipher, commitment); err == nil {
		t.Fatal("accepted tampered base OT ciphertext transcript")
	}
	if reader.n != 0 {
		t.Fatalf("sampled %d challenge bytes before rejecting BOT", reader.n)
	}

	senderState, challenge, err := StartExtensionSender(rand.Reader, selected, delta, epoch, cipher, commitment)
	if err != nil {
		t.Fatal(err)
	}
	badChallenge := cloneChallenge(challenge)
	badChallenge.Chi[0].D0 ^= 1
	badChallenge.Transcript = extensionChallengeTranscript(badChallenge)
	proof, err := FinishExtensionReceiver(receiverState, badChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FinishExtensionSender(senderState, proof); err == nil {
		t.Fatal("accepted proof for a modified challenge")
	}
}

func TestKOS2RejectsReplayAndWrongOrder(t *testing.T) {
	base, selected, delta := testBaseSeeds(t)
	session, _ := NewExtensionSession(rand.Reader)
	epoch := testEpoch(t)
	cipher := testCipherMessage(session)
	receiverState, commitment, _, err := StartExtensionReceiver(rand.Reader, base, epoch, cipher, session, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	senderState, challenge, err := StartExtensionSender(rand.Reader, selected, delta, epoch, cipher, commitment)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := FinishExtensionReceiver(receiverState, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FinishExtensionReceiver(receiverState, challenge); err == nil {
		t.Fatal("accepted replayed challenge")
	}
	if _, err := FinishExtensionSender(senderState, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := FinishExtensionSender(senderState, proof); err == nil {
		t.Fatal("accepted replayed proof")
	}
}

func TestKOS2ChallengeIsFullFreshRandomVector(t *testing.T) {
	base, selected, delta := testBaseSeeds(t)
	session, _ := NewExtensionSession(rand.Reader)
	epoch := testEpoch(t)
	cipher := testCipherMessage(session)
	_, commitment, _, err := StartExtensionReceiver(rand.Reader, base, epoch, cipher, session, 0, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	padded, _ := extensionPaddedCount(100_000)
	wantBytes := extensionChallengeCount(padded) * 16
	material := deterministicBytes(wantBytes, 101)
	reader := &countingReader{reader: bytes.NewReader(material)}
	_, challenge, err := StartExtensionSender(reader, selected, delta, epoch, cipher, commitment)
	if err != nil {
		t.Fatal(err)
	}
	if reader.n != wantBytes || len(challenge.Chi) != extensionChallengeCount(padded) {
		t.Fatalf("challenge read=%d coefficients=%d, want bytes=%d coefficients=%d", reader.n, len(challenge.Chi), wantBytes, extensionChallengeCount(padded))
	}
	for i, coefficient := range challenge.Chi {
		if coefficient != labelFromBytes(material[i*16:(i+1)*16]) {
			t.Fatalf("chi[%d] was not sampled directly from the full random vector", i)
		}
	}
}

func BenchmarkKOS2Proof100K(b *testing.B) {
	padded, err := extensionPaddedCount(100_000)
	if err != nil {
		b.Fatal(err)
	}
	choices := make([]byte, padded/8)
	matrix := make([]byte, BaseOTCount*padded/8)
	chi := make([]Label, extensionChallengeCount(padded))
	if _, err := rand.Read(choices); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(matrix); err != nil {
		b.Fatal(err)
	}
	var encoded [16]byte
	for i := range chi {
		if _, err := rand.Read(encoded[:]); err != nil {
			b.Fatal(err)
		}
		chi[i] = labelFromBytes(encoded[:])
	}
	b.ReportAllocs()
	for b.Loop() {
		proof := repetitionReceiverProof(choices, matrix, padded, chi)
		otBenchmarkSink = proof.X.xor(proof.T[0])
	}
}

func BenchmarkKOS2Full100K(b *testing.B) {
	for b.Loop() {
		sender, receiver := benchmarkKOS2Extension(b, 100_000)
		otBenchmarkSink = sender[0].R0.xor(receiver[0].R)
	}
}

func BenchmarkBaseOTBatch128(b *testing.B) {
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		baseSender, setupMessage, err := StartBaseOTSender(rand.Reader, session)
		if err != nil {
			b.Fatal(err)
		}
		baseReceiver, choiceMessage, err := StartBaseOTReceiver(rand.Reader, session, setupMessage)
		if err != nil {
			b.Fatal(err)
		}
		cipherMessage, _, err := FinishBaseOTSender(baseSender, choiceMessage)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := FinishBaseOTReceiver(baseReceiver, cipherMessage); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTranspose100K(b *testing.B) {
	padded, err := extensionPaddedCount(100_000)
	if err != nil {
		b.Fatal(err)
	}
	byteRows := padded / 8
	matrix := make([]byte, BaseOTCount*byteRows)
	if _, err := rand.Read(matrix); err != nil {
		b.Fatal(err)
	}
	out := make([]Label, padded)
	b.ReportAllocs()
	b.SetBytes(int64(len(matrix)))
	for b.Loop() {
		transposeColumns(matrix, byteRows, out)
	}
	otBenchmarkSink = out[0]
}

func BenchmarkTMMO100K(b *testing.B) {
	const count = 100_000
	rows := make([]Label, count)
	var random [16]byte
	for i := range rows {
		if _, err := rand.Read(random[:]); err != nil {
			b.Fatal(err)
		}
		rows[i] = labelFromBytes(random[:])
	}
	block, err := aes.NewCipher(tmmoKey[:])
	if err != nil {
		b.Fatal(err)
	}
	var input, output [16]byte
	b.ReportAllocs()
	for b.Loop() {
		var sum Label
		for i, row := range rows {
			sum = sum.xor(tmmoHash(block, row, uint64(i), &input, &output))
		}
		otBenchmarkSink = sum
	}
}

var otBenchmarkSink Label

func runKOS2Extension(t testing.TB, count int, start uint64, receiverRNG, senderRNG io.Reader) ([]SenderOT, []ReceiverOT) {
	t.Helper()
	base, selected, delta := testBaseSeeds(t)
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := testEpoch(t)
	cipher := testCipherMessage(session)
	receiverState, commitment, receiver, err := StartExtensionReceiver(receiverRNG, base, epoch, cipher, session, start, count)
	if err != nil {
		t.Fatal(err)
	}
	commitmentBytes, err := MarshalExtensionCommitment(commitment)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err = UnmarshalExtensionCommitment(commitmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	senderState, challenge, err := StartExtensionSender(senderRNG, selected, delta, epoch, cipher, commitment)
	if err != nil {
		t.Fatal(err)
	}
	challengeBytes, err := MarshalExtensionChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err = UnmarshalExtensionChallenge(challengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := FinishExtensionReceiver(receiverState, challenge)
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, err := MarshalExtensionProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	proof, err = UnmarshalExtensionProof(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := FinishExtensionSender(senderState, proof)
	if err != nil {
		t.Fatal(err)
	}
	return sender, receiver
}

func benchmarkKOS2Extension(b *testing.B, count int) ([]SenderOT, []ReceiverOT) {
	return runKOS2Extension(b, count, 0, rand.Reader, rand.Reader)
}

func testBaseSeeds(t testing.TB) (base [BaseOTCount]BaseOTSeedPair, selected [BaseOTCount]Label, delta Label) {
	t.Helper()
	var data [BaseOTCount*32 + 16]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal(err)
	}
	off := 0
	for i := range base {
		base[i] = BaseOTSeedPair{Zero: labelFromBytes(data[off : off+16]), One: labelFromBytes(data[off+16 : off+32])}
		off += 32
	}
	delta = labelFromBytes(data[off:])
	if delta == (Label{}) {
		delta.D0 = 1
	}
	for i := range selected {
		selected[i] = base[i].Zero
		if deltaBit(delta, i) {
			selected[i] = base[i].One
		}
	}
	return base, selected, delta
}

func testCipherMessage(session [32]byte) []byte {
	cipher := make([]byte, baseCipherMessageSize)
	copy(cipher[:4], "BOT1")
	copy(cipher[4:36], session[:])
	return cipher
}

func testEpoch(t testing.TB) string {
	t.Helper()
	epoch, err := InitialExtensionEpoch("00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	return epoch
}

func assertMatchedOTs(t testing.TB, sender []SenderOT, receiver []ReceiverOT) {
	t.Helper()
	if len(sender) != len(receiver) {
		t.Fatalf("count mismatch: sender=%d receiver=%d", len(sender), len(receiver))
	}
	for i := range sender {
		want, other := sender[i].R0, sender[i].R1
		if receiver[i].Choice {
			want, other = other, want
		}
		if receiver[i].R != want || receiver[i].R == other || sender[i].Index != receiver[i].Index {
			t.Fatalf("OT %d did not match the selected indexed sender value", i)
		}
	}
}

func cloneChallenge(in *ExtensionChallenge) *ExtensionChallenge {
	out := *in
	out.Chi = append([]Label(nil), in.Chi...)
	return &out
}

func cloneExtensionCommitment(in ExtensionCommitment) ExtensionCommitment {
	in.U = append([]byte(nil), in.U...)
	return in
}

func deterministicBytes(size int, seed byte) []byte {
	out := make([]byte, size)
	value := uint32(seed)
	for i := range out {
		value = value*1664525 + 1013904223
		out[i] = byte(value >> 24)
	}
	return out
}

func testCountName(count int) string {
	return "n" + strconv.Itoa(count)
}

type countingReader struct {
	reader io.Reader
	n      int
}

func (r *countingReader) Read(dst []byte) (int, error) {
	n, err := r.reader.Read(dst)
	r.n += n
	return n, err
}
