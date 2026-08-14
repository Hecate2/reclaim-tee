package mpc

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
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
	values := []Label{
		{},
		{D0: 1},
		{D1: 1},
		{D0: 0x0123456789abcdef, D1: 0xfedcba9876543210},
	}
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
				left := gf128Mul(a, b.xor(c))
				right := gf128Mul(a, b).xor(gf128Mul(a, c))
				if left != right {
					t.Fatalf("multiplication is not distributive")
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

func TestKOSExtensionRoundTrip(t *testing.T) {
	for _, count := range []int{1, InputBits, 4097} {
		base, selected, delta := testBaseSeeds(t)
		session, err := NewExtensionSession(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		request, receiver, err := ExtendReceiver(rand.Reader, base, session, 9_000, count)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := MarshalExtensionRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := UnmarshalExtensionRequest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		sender, err := ExtendSender(selected, delta, decoded)
		if err != nil {
			t.Fatal(err)
		}
		if len(sender) != count || len(receiver) != count {
			t.Fatalf("count mismatch: sender=%d receiver=%d", len(sender), len(receiver))
		}
		for i := range count {
			want := sender[i].R0
			other := sender[i].R1
			if receiver[i].Choice {
				want, other = other, want
			}
			if receiver[i].R != want {
				t.Fatalf("count %d OT %d did not match selected sender value", count, i)
			}
			if receiver[i].R == other {
				t.Fatalf("count %d OT %d matched both sender values", count, i)
			}
			if sender[i].Index != 9_000+uint64(i) || receiver[i].Index != sender[i].Index {
				t.Fatalf("count %d OT %d index mismatch", count, i)
			}
		}
	}
}

func TestBaseOTAndKOSExtensionRoundTrip(t *testing.T) {
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	request, receiver, err := ExtendReceiver(rand.Reader, basePairs, session, 41, InputBits)
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
	sender, err := ExtendSender(selected, delta, request)
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

	wrongSession := session
	wrongSession[0] ^= 1
	if _, _, err := StartBaseOTReceiver(rand.Reader, wrongSession, setupMessage); err == nil {
		t.Fatal("accepted base OT setup from another session")
	}
}

func TestKOSExtensionRejectsTampering(t *testing.T) {
	base, selected, delta := testBaseSeeds(t)
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := ExtendReceiver(rand.Reader, base, session, 123, InputBits)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*ExtensionRequest)
	}{
		{"matrix", func(r *ExtensionRequest) { r.U[len(r.U)/2] ^= 1 }},
		{"proof-x", func(r *ExtensionRequest) { r.ProofX.D0 ^= 1 }},
		{"proof-t", func(r *ExtensionRequest) { r.ProofT.D1 ^= 1 }},
		{"session", func(r *ExtensionRequest) { r.SessionID[0] ^= 1 }},
		{"start-index", func(r *ExtensionRequest) { r.StartIndex++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyRequest := *request
			copyRequest.U = append([]byte(nil), request.U...)
			test.mutate(&copyRequest)
			if _, err := ExtendSender(selected, delta, &copyRequest); !errors.Is(err, errKOSCheck) {
				t.Fatalf("got %v, want KOS check failure", err)
			}
		})
	}

	encoded, err := MarshalExtensionRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalExtensionRequest(append(encoded, 0)); err == nil {
		t.Fatal("accepted trailing extension byte")
	}
	badCount := append([]byte(nil), encoded...)
	binary.BigEndian.PutUint32(badCount[44:48], 0)
	if _, err := UnmarshalExtensionRequest(badCount); err == nil {
		t.Fatal("accepted zero extension count")
	}
}

func BenchmarkKOSExtensionReceiver640(b *testing.B) {
	base, _, _ := testBaseSeeds(b)
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ExtendReceiver(rand.Reader, base, session, 0, InputBits); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKOSExtensionSender640(b *testing.B) {
	base, selected, delta := testBaseSeeds(b)
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	request, _, err := ExtendReceiver(rand.Reader, base, session, 0, InputBits)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := ExtendSender(selected, delta, request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKOSExtensionReceiver100K(b *testing.B) {
	base, _, _ := testBaseSeeds(b)
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ExtendReceiver(rand.Reader, base, session, 0, 100_000); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKOSExtensionSender100K(b *testing.B) {
	base, selected, delta := testBaseSeeds(b)
	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	request, _, err := ExtendReceiver(rand.Reader, base, session, 0, 100_000)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := ExtendSender(selected, delta, request); err != nil {
			b.Fatal(err)
		}
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

func BenchmarkKOSProof100K(b *testing.B) {
	padded, err := extensionPaddedCount(100_000)
	if err != nil {
		b.Fatal(err)
	}
	choices := make([]byte, padded/8)
	rows := make([]Label, padded)
	var random [16]byte
	for i := range rows {
		if _, err := rand.Read(random[:]); err != nil {
			b.Fatal(err)
		}
		rows[i] = labelFromBytes(random[:])
	}
	if _, err := rand.Read(choices); err != nil {
		b.Fatal(err)
	}
	seed := rows[0]
	b.ReportAllocs()
	for b.Loop() {
		x, proof := receiverProof(seed, choices, rows)
		otBenchmarkSink = x.xor(proof)
	}
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

func testBaseSeeds(t testing.TB) (base [BaseOTCount]BaseOTSeedPair, selected [BaseOTCount]Label, delta Label) {
	t.Helper()
	var data [BaseOTCount*32 + 16]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal(err)
	}
	off := 0
	for i := range base {
		base[i] = BaseOTSeedPair{
			Zero: labelFromBytes(data[off : off+16]),
			One:  labelFromBytes(data[off+16 : off+32]),
		}
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

func assertMatchedOTs(t testing.TB, sender []SenderOT, receiver []ReceiverOT) {
	t.Helper()
	if len(sender) != len(receiver) {
		t.Fatalf("sender count %d != receiver count %d", len(sender), len(receiver))
	}
	for i := range sender {
		want, other := sender[i].R0, sender[i].R1
		if receiver[i].Choice {
			want, other = other, want
		}
		if receiver[i].R != want || receiver[i].R == other {
			t.Fatalf("OT %d does not match its selected sender value", i)
		}
	}
}
