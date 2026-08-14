package mpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// BaseOTCount is the computational security parameter of the IKNP/KOS
	// extension and the number of public-key base OTs required per batch.
	BaseOTCount = 128

	// KOSCheckOTs is the number of sacrificial random OTs included in the
	// receiver-consistency check.
	KOSCheckOTs = 128

	maxExtensionOTs = 1 << 24
)

var (
	errKOSCheck = errors.New("mpc: KOS receiver consistency check failed")

	// A public, domain-separated fixed key for the TMMO correlation-robust
	// hash. Fixed-key AES is the construction used by libOTe's KOS path.
	tmmoKey = func() [16]byte {
		sum := sha256.Sum256([]byte("reclaim-tee/mpc/kos/tmmo/v1"))
		var key [16]byte
		copy(key[:], sum[:16])
		return key
	}()
)

// BaseOTSeedPair contains the two 128-bit seeds held by the OT-extension
// receiver after 128 base OTs. The extension sender learns one seed from each
// pair according to the corresponding bit of Delta.
type BaseOTSeedPair struct {
	Zero Label
	One  Label
}

// ExtensionRequest is the receiver-to-sender IKNP matrix correction and KOS
// proof. SessionID must have been sampled by the extension sender before this
// request is constructed.
type ExtensionRequest struct {
	SessionID   [32]byte
	StartIndex  uint64
	Count       uint32
	PaddedCount uint32
	U           []byte
	ProofX      Label
	ProofT      Label
}

// NewExtensionSession samples a sender-chosen session identifier for one OT
// extension batch.
func NewExtensionSession(rng io.Reader) ([32]byte, error) {
	var session [32]byte
	if rng == nil {
		return session, errors.New("mpc: nil randomness source")
	}
	if _, err := io.ReadFull(rng, session[:]); err != nil {
		return session, fmt.Errorf("mpc: read OT extension session: %w", err)
	}
	return session, nil
}

// ExtendReceiver creates count random OTs from 128 base seed pairs. It returns
// the matrix/proof sent to the extension sender and the receiver's compact pool
// entries. The caller must not commit the entries until the sender accepts the
// proof.
func ExtendReceiver(rng io.Reader, base [BaseOTCount]BaseOTSeedPair, sessionID [32]byte, startIndex uint64, count int) (*ExtensionRequest, []ReceiverOT, error) {
	defer clear(base[:])
	if rng == nil {
		return nil, nil, errors.New("mpc: nil randomness source")
	}
	padded, err := extensionPaddedCount(count)
	if err != nil {
		return nil, nil, err
	}
	byteRows := padded / 8

	choices := make([]byte, byteRows)
	defer clear(choices)
	if _, err := io.ReadFull(rng, choices); err != nil {
		return nil, nil, fmt.Errorf("mpc: read OT choices: %w", err)
	}
	tMatrix := make([]byte, BaseOTCount*byteRows)
	defer clear(tMatrix)
	u := make([]byte, BaseOTCount*byteRows)
	tmp := make([]byte, byteRows)
	defer clear(tmp)
	for col := 0; col < BaseOTCount; col++ {
		t0 := tMatrix[col*byteRows : (col+1)*byteRows]
		if err := expandSeed(base[col].Zero, sessionID, col, t0); err != nil {
			return nil, nil, fmt.Errorf("mpc: expand base seed %d/0: %w", col, err)
		}
		if err := expandSeed(base[col].One, sessionID, col, tmp); err != nil {
			return nil, nil, fmt.Errorf("mpc: expand base seed %d/1: %w", col, err)
		}
		ucol := u[col*byteRows : (col+1)*byteRows]
		for i := range ucol {
			ucol[i] = t0[i] ^ tmp[i] ^ choices[i]
		}
	}

	raw := make([]Label, padded)
	defer clear(raw)
	transposeColumns(tMatrix, byteRows, raw)
	request := &ExtensionRequest{
		SessionID: sessionID, StartIndex: startIndex, Count: uint32(count),
		PaddedCount: uint32(padded), U: u,
	}
	challenge, err := extensionChallenge(request)
	if err != nil {
		return nil, nil, err
	}
	request.ProofX, request.ProofT = receiverProof(challenge, choices, raw)

	receiver := make([]ReceiverOT, count)
	hasher, err := aes.NewCipher(tmmoKey[:])
	if err != nil {
		return nil, nil, err
	}
	var hashInput, hashOutput [16]byte
	for i := range receiver {
		choice := choices[i/8]&(1<<uint(i&7)) != 0
		receiver[i] = ReceiverOT{
			R: tmmoHash(hasher, raw[i], uint64(i), &hashInput, &hashOutput), Choice: choice,
			Index: startIndex + uint64(i),
		}
	}
	return request, receiver, nil
}

// ExtendSender verifies a KOS extension request and returns the sender's two
// independent random-OT labels. selected[i] is the base seed chosen by bit i
// of delta. No output is returned if the consistency proof fails.
func ExtendSender(selected [BaseOTCount]Label, delta Label, request *ExtensionRequest) ([]SenderOT, error) {
	defer func() {
		clear(selected[:])
		delta = Label{}
	}()
	if delta.D0 == 0 && delta.D1 == 0 {
		return nil, errors.New("mpc: zero OT correlation delta")
	}
	if request == nil {
		return nil, errors.New("mpc: nil OT extension request")
	}
	count := int(request.Count)
	padded, err := extensionPaddedCount(count)
	if err != nil {
		return nil, err
	}
	if int(request.PaddedCount) != padded {
		return nil, fmt.Errorf("mpc: padded OT count %d, want %d", request.PaddedCount, padded)
	}
	byteRows := padded / 8
	if len(request.U) != BaseOTCount*byteRows {
		return nil, fmt.Errorf("mpc: OT extension matrix length %d, want %d", len(request.U), BaseOTCount*byteRows)
	}

	qMatrix := make([]byte, BaseOTCount*byteRows)
	defer clear(qMatrix)
	for col := 0; col < BaseOTCount; col++ {
		qcol := qMatrix[col*byteRows : (col+1)*byteRows]
		if err := expandSeed(selected[col], request.SessionID, col, qcol); err != nil {
			return nil, fmt.Errorf("mpc: expand selected base seed %d: %w", col, err)
		}
		if deltaBit(delta, col) {
			ucol := request.U[col*byteRows : (col+1)*byteRows]
			for i := range qcol {
				qcol[i] ^= ucol[i]
			}
		}
	}

	raw := make([]Label, padded)
	defer clear(raw)
	transposeColumns(qMatrix, byteRows, raw)
	challenge, err := extensionChallenge(request)
	if err != nil {
		return nil, err
	}
	q := senderProof(challenge, raw)
	wantT := q.xor(gf128Mul(request.ProofX, delta))
	var wantBytes, proofBytes [16]byte
	wantT.put(wantBytes[:])
	request.ProofT.put(proofBytes[:])
	if subtle.ConstantTimeCompare(wantBytes[:], proofBytes[:]) != 1 {
		return nil, errKOSCheck
	}

	sender := make([]SenderOT, count)
	hasher, err := aes.NewCipher(tmmoKey[:])
	if err != nil {
		return nil, err
	}
	var hashInput, hashOutput [16]byte
	for i := range sender {
		q0 := raw[i]
		q1 := q0.xor(delta)
		sender[i] = SenderOT{
			R0:    tmmoHash(hasher, q0, uint64(i), &hashInput, &hashOutput),
			R1:    tmmoHash(hasher, q1, uint64(i), &hashInput, &hashOutput),
			Index: request.StartIndex + uint64(i),
		}
	}
	return sender, nil
}

func extensionPaddedCount(count int) (int, error) {
	if count <= 0 || count > maxExtensionOTs {
		return 0, fmt.Errorf("mpc: invalid OT extension count %d", count)
	}
	total := count + KOSCheckOTs
	return (total + BaseOTCount - 1) &^ (BaseOTCount - 1), nil
}

func expandSeed(seed Label, sessionID [32]byte, column int, dst []byte) error {
	var material [32 + 32 + 1 + 16]byte
	copy(material[:32], []byte("reclaim-tee/mpc/iknp/prg/v1"))
	copy(material[32:64], sessionID[:])
	material[64] = byte(column)
	seed.put(material[65:])
	derived := sha256.Sum256(material[:])
	var key [16]byte
	copy(key[:], derived[:16])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	var counter [16]byte
	for off, value := 0, uint64(0); off < len(dst); off, value = off+16, value+1 {
		binary.BigEndian.PutUint64(counter[8:], value)
		block.Encrypt(counter[:], counter[:])
		copy(dst[off:], counter[:])
		clear(counter[:])
	}
	return nil
}

func extensionChallenge(request *ExtensionRequest) (Label, error) {
	if request == nil {
		return Label{}, errors.New("mpc: nil OT extension request")
	}
	h := sha256.New()
	h.Write([]byte("reclaim-tee/mpc/kos/challenge/v1"))
	h.Write(request.SessionID[:])
	var metadata [16]byte
	binary.BigEndian.PutUint64(metadata[:8], request.StartIndex)
	binary.BigEndian.PutUint32(metadata[8:12], request.Count)
	binary.BigEndian.PutUint32(metadata[12:16], request.PaddedCount)
	h.Write(metadata[:])
	h.Write(request.U)
	sum := h.Sum(nil)
	return labelFromBytes(sum[:16]), nil
}

func receiverProof(seed Label, choices []byte, rows []Label) (x, t Label) {
	block := challengeCipher(seed)
	var counter [16]byte
	for i := range rows {
		chi := nextChallenge(block, uint64(i), &counter)
		t = t.xor(gf128Mul(chi, rows[i]))
		if choices[i/8]&(1<<uint(i&7)) != 0 {
			x = x.xor(chi)
		}
	}
	return x, t
}

func senderProof(seed Label, rows []Label) (q Label) {
	block := challengeCipher(seed)
	var counter [16]byte
	for i := range rows {
		chi := nextChallenge(block, uint64(i), &counter)
		q = q.xor(gf128Mul(chi, rows[i]))
	}
	return q
}

func challengeCipher(seed Label) cipher.Block {
	var key [16]byte
	seed.put(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	return block
}

func nextChallenge(block cipher.Block, index uint64, counter *[16]byte) Label {
	binary.BigEndian.PutUint64(counter[8:], index)
	block.Encrypt(counter[:], counter[:])
	result := labelFromBytes(counter[:])
	clear(counter[:])
	return result
}

// gf128MulGeneric multiplies in GF(2^128) with the polynomial
// x^128+x^7+x^2+x+1. It is the constant-time portable fallback.
func gf128MulGeneric(a, b Label) (z Label) {
	v := a
	for i := 0; i < 128; i++ {
		bit := (b.D0 >> uint(i&63)) & 1
		if i >= 64 {
			bit = (b.D1 >> uint(i-64)) & 1
		}
		mask := uint64(0) - bit
		z.D0 ^= v.D0 & mask
		z.D1 ^= v.D1 & mask
		carry := v.D1 >> 63
		v.D1 = v.D1<<1 | v.D0>>63
		v.D0 = v.D0<<1 ^ (uint64(0x87) & (uint64(0) - carry))
	}
	return z
}

func reduceGF128(lo, hi Label) Label {
	// Fold hi*x^128 with x^128 = x^7+x^2+x+1. The first fold can
	// overflow by seven bits; fold those bits once more.
	overflow := hi.D1>>63 ^ hi.D1>>62 ^ hi.D1>>57
	lo.D0 ^= hi.D0 ^ hi.D0<<1 ^ hi.D0<<2 ^ hi.D0<<7
	lo.D1 ^= hi.D1 ^
		hi.D1<<1 ^ hi.D0>>63 ^
		hi.D1<<2 ^ hi.D0>>62 ^
		hi.D1<<7 ^ hi.D0>>57
	lo.D0 ^= overflow ^ overflow<<1 ^ overflow<<2 ^ overflow<<7
	return lo
}

func tmmoHash(block cipher.Block, value Label, tweak uint64, input, encrypted *[16]byte) Label {
	value.put(input[:])
	block.Encrypt(encrypted[:], input[:])
	binary.BigEndian.PutUint64(input[8:], binary.BigEndian.Uint64(encrypted[8:])^tweak)
	binary.BigEndian.PutUint64(input[:8], binary.BigEndian.Uint64(encrypted[:8]))
	block.Encrypt(input[:], input[:])
	return labelFromBytes(input[:]).xor(labelFromBytes(encrypted[:]))
}

func deltaBit(delta Label, bit int) bool {
	if bit < 64 {
		return delta.D0&(uint64(1)<<uint(bit)) != 0
	}
	return delta.D1&(uint64(1)<<uint(bit-64)) != 0
}
