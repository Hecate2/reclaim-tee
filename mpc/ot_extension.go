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

	// KOSCheckOTs is the statistical security parameter and the number of
	// repetition-code check rows appended to every extension batch.
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

// ExtensionCommitment fixes the base-OT ciphertexts and IKNP matrix before
// the extension sender samples the interactive repetition-code challenge.
type ExtensionCommitment struct {
	SessionID   [32]byte
	StartIndex  uint64
	Count       uint32
	PaddedCount uint32
	EpochHash   [32]byte
	Transcript  [32]byte
	U           []byte
}

// ExtensionChallenge is the extension sender's full vector of independently
// sampled GF(2^128) coefficients. One coefficient covers each 128-row block
// preceding the final 128 repetition-code check rows.
type ExtensionChallenge struct {
	SessionID  [32]byte
	Commitment [32]byte
	Transcript [32]byte
	Chi        []Label
}

// ExtensionProof contains x and all 128 column checks from Figure 10 of the
// corrected KOS protocol. Compressing the column checks into one field element
// recreates the unsound original check and is deliberately unsupported.
type ExtensionProof struct {
	SessionID  [32]byte
	Transcript [32]byte
	X          Label
	T          [BaseOTCount]Label
}

// ExtensionReceiverState holds TEE_T's private IKNP matrix and choices between
// its commitment and the sender's unpredictable challenge. It is single-use.
type ExtensionReceiverState struct {
	commitment ExtensionCommitment
	choices    []byte
	tMatrix    []byte
	used       bool
}

// ExtensionSenderState holds TEE_K's private IKNP matrix and correlation until
// all 128 proof equations have been checked. It is single-use.
type ExtensionSenderState struct {
	commitment          ExtensionCommitment
	challengeTranscript [32]byte
	delta               Label
	qChecks             [BaseOTCount]Label
	rows                []Label
	used                bool
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

// StartExtensionReceiver creates the IKNP commitment and receiver OTs. The
// returned entries remain provisional until TEE_K accepts FinishExtensionSender
// and sends OTPrecomputeComplete.
func StartExtensionReceiver(
	rng io.Reader,
	base [BaseOTCount]BaseOTSeedPair,
	epoch string,
	cipherMessage []byte,
	sessionID [32]byte,
	startIndex uint64,
	count int,
) (*ExtensionReceiverState, *ExtensionCommitment, []ReceiverOT, error) {
	defer clear(base[:])
	if rng == nil {
		return nil, nil, nil, errors.New("mpc: nil randomness source")
	}
	if err := validateExtensionEpoch(epoch); err != nil {
		return nil, nil, nil, err
	}
	if err := validateBaseCipherForTranscript(cipherMessage, sessionID); err != nil {
		return nil, nil, nil, err
	}
	padded, err := extensionPaddedCount(count)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := checkedIndexEnd(startIndex, count); err != nil {
		return nil, nil, nil, err
	}
	byteRows := padded / 8

	choices := make([]byte, byteRows)
	if _, err := io.ReadFull(rng, choices); err != nil {
		clear(choices)
		return nil, nil, nil, fmt.Errorf("mpc: read OT choices: %w", err)
	}
	tMatrix := make([]byte, BaseOTCount*byteRows)
	u := make([]byte, BaseOTCount*byteRows)
	tmp := make([]byte, byteRows)
	defer clear(tmp)
	for col := 0; col < BaseOTCount; col++ {
		t0 := tMatrix[col*byteRows : (col+1)*byteRows]
		if err := expandSeed(base[col].Zero, sessionID, col, t0); err != nil {
			clear(choices)
			clear(tMatrix)
			clear(u)
			return nil, nil, nil, fmt.Errorf("mpc: expand base seed %d/0: %w", col, err)
		}
		if err := expandSeed(base[col].One, sessionID, col, tmp); err != nil {
			clear(choices)
			clear(tMatrix)
			clear(u)
			return nil, nil, nil, fmt.Errorf("mpc: expand base seed %d/1: %w", col, err)
		}
		ucol := u[col*byteRows : (col+1)*byteRows]
		for i := range ucol {
			ucol[i] = t0[i] ^ tmp[i] ^ choices[i]
		}
	}

	commitment := ExtensionCommitment{
		SessionID: sessionID, StartIndex: startIndex, Count: uint32(count),
		PaddedCount: uint32(padded), U: u, EpochHash: extensionEpochHash(epoch),
	}
	commitment.Transcript = extensionTranscript(cipherMessage, &commitment)

	raw := make([]Label, padded)
	defer clear(raw)
	transposeColumns(tMatrix, byteRows, raw)
	receiver, err := hashReceiverOTs(raw, choices, startIndex, count)
	if err != nil {
		clear(choices)
		clear(tMatrix)
		clear(u)
		return nil, nil, nil, err
	}
	state := &ExtensionReceiverState{commitment: extensionStateCommitment(commitment), choices: choices, tMatrix: tMatrix}
	return state, &commitment, receiver, nil
}

// StartExtensionSender validates the fixed BOT+U transcript, expands q, and
// only then samples the complete independent challenge vector.
func StartExtensionSender(
	rng io.Reader,
	selected [BaseOTCount]Label,
	delta Label,
	epoch string,
	cipherMessage []byte,
	commitment *ExtensionCommitment,
) (*ExtensionSenderState, *ExtensionChallenge, error) {
	defer func() {
		clear(selected[:])
		delta = Label{}
	}()
	if rng == nil {
		return nil, nil, errors.New("mpc: nil randomness source")
	}
	if delta == (Label{}) {
		return nil, nil, errors.New("mpc: zero OT correlation delta")
	}
	if err := validateExtensionCommitment(epoch, cipherMessage, commitment); err != nil {
		return nil, nil, err
	}
	byteRows := int(commitment.PaddedCount) / 8
	qMatrix := make([]byte, BaseOTCount*byteRows)
	for col := 0; col < BaseOTCount; col++ {
		qcol := qMatrix[col*byteRows : (col+1)*byteRows]
		if err := expandSeed(selected[col], commitment.SessionID, col, qcol); err != nil {
			clear(qMatrix)
			return nil, nil, fmt.Errorf("mpc: expand selected base seed %d: %w", col, err)
		}
		if deltaBit(delta, col) {
			ucol := commitment.U[col*byteRows : (col+1)*byteRows]
			for i := range qcol {
				qcol[i] ^= ucol[i]
			}
		}
	}

	chiCount := extensionChallengeCount(int(commitment.PaddedCount))
	random := make([]byte, chiCount*16)
	defer clear(random)
	if _, err := io.ReadFull(rng, random); err != nil {
		clear(qMatrix)
		return nil, nil, fmt.Errorf("mpc: read OT extension challenge: %w", err)
	}
	chi := make([]Label, chiCount)
	for i := range chi {
		chi[i] = labelFromBytes(random[i*16 : (i+1)*16])
	}
	challenge := &ExtensionChallenge{
		SessionID: commitment.SessionID, Commitment: commitment.Transcript, Chi: chi,
	}
	challenge.Transcript = extensionChallengeTranscript(challenge)
	checks := repetitionColumnChecks(qMatrix, int(commitment.PaddedCount), chi)
	rows := make([]Label, int(commitment.PaddedCount))
	transposeColumns(qMatrix, byteRows, rows)
	clear(qMatrix)
	state := &ExtensionSenderState{
		commitment: extensionStateCommitment(*commitment), challengeTranscript: challenge.Transcript,
		delta: delta, qChecks: checks, rows: rows,
	}
	return state, challenge, nil
}

// FinishExtensionReceiver consumes the fresh sender challenge and returns the
// literal repetition-code proof x,t_0,...,t_127.
func FinishExtensionReceiver(state *ExtensionReceiverState, challenge *ExtensionChallenge) (*ExtensionProof, error) {
	if state == nil {
		return nil, errors.New("mpc: nil OT extension receiver state")
	}
	if state.used {
		return nil, errors.New("mpc: OT extension receiver state already used")
	}
	state.used = true
	defer clearExtensionReceiverState(state)
	if err := validateExtensionChallenge(&state.commitment, challenge); err != nil {
		return nil, err
	}
	proof := repetitionReceiverProof(state.choices, state.tMatrix, int(state.commitment.PaddedCount), challenge.Chi)
	proof.SessionID = state.commitment.SessionID
	proof.Transcript = challenge.Transcript
	return &proof, nil
}

// FinishExtensionSender checks every repetition-code column equation before it
// derives any sender OT output. A failed proof returns no entries.
func FinishExtensionSender(state *ExtensionSenderState, proof *ExtensionProof) ([]SenderOT, error) {
	if state == nil {
		return nil, errors.New("mpc: nil OT extension sender state")
	}
	if state.used {
		return nil, errors.New("mpc: OT extension sender state already used")
	}
	state.used = true
	defer clearExtensionSenderState(state)
	if proof == nil {
		return nil, errors.New("mpc: nil OT extension proof")
	}
	if proof.SessionID != state.commitment.SessionID ||
		subtle.ConstantTimeCompare(proof.Transcript[:], state.challengeTranscript[:]) != 1 {
		return nil, errors.New("mpc: OT extension proof transcript mismatch")
	}
	if len(state.rows) != int(state.commitment.PaddedCount) {
		return nil, errors.New("mpc: OT extension sender proof state is incomplete")
	}
	for col := 0; col < BaseOTCount; col++ {
		q := state.qChecks[col]
		want := proof.T[col]
		if deltaBit(state.delta, col) {
			want = want.xor(proof.X)
		}
		var qBytes, wantBytes [16]byte
		q.put(qBytes[:])
		want.put(wantBytes[:])
		if subtle.ConstantTimeCompare(qBytes[:], wantBytes[:]) != 1 {
			return nil, errKOSCheck
		}
	}

	return hashSenderOTs(state)
}

func validateExtensionCommitment(epoch string, cipherMessage []byte, commitment *ExtensionCommitment) error {
	if commitment == nil {
		return errors.New("mpc: nil OT extension commitment")
	}
	if err := validateExtensionEpoch(epoch); err != nil {
		return err
	}
	if err := validateBaseCipherForTranscript(cipherMessage, commitment.SessionID); err != nil {
		return err
	}
	padded, err := extensionPaddedCount(int(commitment.Count))
	if err != nil {
		return err
	}
	if int(commitment.PaddedCount) != padded {
		return fmt.Errorf("mpc: padded OT count %d, want %d", commitment.PaddedCount, padded)
	}
	if _, err := checkedIndexEnd(commitment.StartIndex, int(commitment.Count)); err != nil {
		return err
	}
	wantU := BaseOTCount * padded / 8
	if len(commitment.U) != wantU {
		return fmt.Errorf("mpc: OT extension matrix length %d, want %d", len(commitment.U), wantU)
	}
	wantEpoch := extensionEpochHash(epoch)
	if subtle.ConstantTimeCompare(commitment.EpochHash[:], wantEpoch[:]) != 1 {
		return errors.New("mpc: OT extension epoch mismatch")
	}
	wantTranscript := extensionTranscript(cipherMessage, commitment)
	if subtle.ConstantTimeCompare(commitment.Transcript[:], wantTranscript[:]) != 1 {
		return errors.New("mpc: OT extension commitment transcript mismatch")
	}
	return nil
}

func validateBaseCipherForTranscript(cipherMessage []byte, sessionID [32]byte) error {
	if len(cipherMessage) != baseCipherMessageSize || string(cipherMessage[:4]) != "BOT1" {
		return errors.New("mpc: invalid base OT ciphertext message")
	}
	if subtle.ConstantTimeCompare(cipherMessage[4:36], sessionID[:]) != 1 {
		return errors.New("mpc: base OT ciphertext session mismatch")
	}
	return nil
}

func extensionTranscript(cipherMessage []byte, commitment *ExtensionCommitment) [32]byte {
	h := sha256.New()
	h.Write([]byte("reclaim-tee/mpc/kos/repetition/v2/transcript"))
	h.Write([]byte("KOC2"))
	h.Write(commitment.SessionID[:])
	var metadata [16]byte
	binary.BigEndian.PutUint64(metadata[:8], commitment.StartIndex)
	binary.BigEndian.PutUint32(metadata[8:12], commitment.Count)
	binary.BigEndian.PutUint32(metadata[12:16], commitment.PaddedCount)
	h.Write(metadata[:])
	h.Write(commitment.EpochHash[:])
	h.Write(cipherMessage)
	h.Write(commitment.U)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func extensionEpochHash(epoch string) [32]byte {
	h := sha256.New()
	h.Write([]byte("reclaim-tee/mpc/kos/repetition/v2/epoch"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(epoch)))
	h.Write(length[:])
	h.Write([]byte(epoch))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func validateExtensionChallenge(commitment *ExtensionCommitment, challenge *ExtensionChallenge) error {
	if challenge == nil {
		return errors.New("mpc: nil OT extension challenge")
	}
	if challenge.SessionID != commitment.SessionID ||
		subtle.ConstantTimeCompare(challenge.Commitment[:], commitment.Transcript[:]) != 1 {
		return errors.New("mpc: OT extension challenge transcript mismatch")
	}
	want := extensionChallengeCount(int(commitment.PaddedCount))
	if len(challenge.Chi) != want {
		return fmt.Errorf("mpc: OT extension challenge length %d, want %d", len(challenge.Chi), want)
	}
	wantTranscript := extensionChallengeTranscript(challenge)
	if subtle.ConstantTimeCompare(challenge.Transcript[:], wantTranscript[:]) != 1 {
		return errors.New("mpc: OT extension challenge hash mismatch")
	}
	return nil
}

func extensionChallengeTranscript(challenge *ExtensionChallenge) [32]byte {
	h := sha256.New()
	h.Write([]byte("reclaim-tee/mpc/kos/repetition/v2/challenge"))
	h.Write(challenge.SessionID[:])
	h.Write(challenge.Commitment[:])
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(challenge.Chi)))
	h.Write(count[:])
	var encoded [16]byte
	for _, coefficient := range challenge.Chi {
		coefficient.put(encoded[:])
		h.Write(encoded[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func extensionChallengeCount(padded int) int {
	return (padded - KOSCheckOTs) / 128
}

func repetitionReceiverProof(choices, matrix []byte, padded int, chi []Label) (proof ExtensionProof) {
	mainBytes := (padded - KOSCheckOTs) / 8
	proof.X = labelFromBytes(choices[mainBytes : mainBytes+16])
	for block, coefficient := range chi {
		off := block * 16
		proof.X = proof.X.xor(gf128Mul(labelFromBytes(choices[off:off+16]), coefficient))
	}
	proof.T = repetitionColumnChecks(matrix, padded, chi)
	return proof
}

func repetitionColumnChecks(matrix []byte, padded int, chi []Label) (checks [BaseOTCount]Label) {
	mainBytes := (padded - KOSCheckOTs) / 8
	byteRows := padded / 8
	for col := 0; col < BaseOTCount; col++ {
		column := matrix[col*byteRows : (col+1)*byteRows]
		check := labelFromBytes(column[mainBytes : mainBytes+16])
		for block, coefficient := range chi {
			off := block * 16
			check = check.xor(gf128Mul(labelFromBytes(column[off:off+16]), coefficient))
		}
		checks[col] = check
	}
	return checks
}

func hashReceiverOTs(raw []Label, choices []byte, startIndex uint64, count int) ([]ReceiverOT, error) {
	if _, err := checkedIndexEnd(startIndex, count); err != nil {
		return nil, err
	}
	receiver := make([]ReceiverOT, count)
	hasher, err := aes.NewCipher(tmmoKey[:])
	if err != nil {
		return nil, err
	}
	var hashInput, hashOutput [16]byte
	for i := range receiver {
		receiver[i] = ReceiverOT{
			R:      tmmoHash(hasher, raw[i], uint64(i), &hashInput, &hashOutput),
			Choice: choices[i/8]&(1<<uint(i&7)) != 0,
			Index:  startIndex + uint64(i),
		}
	}
	return receiver, nil
}

func hashSenderOTs(state *ExtensionSenderState) ([]SenderOT, error) {
	count := int(state.commitment.Count)
	if _, err := checkedIndexEnd(state.commitment.StartIndex, count); err != nil {
		return nil, err
	}
	sender := make([]SenderOT, count)
	hasher, err := aes.NewCipher(tmmoKey[:])
	if err != nil {
		return nil, err
	}
	var hashInput, hashOutput [16]byte
	for i := range sender {
		q0 := state.rows[i]
		q1 := q0.xor(state.delta)
		sender[i] = SenderOT{
			R0:    tmmoHash(hasher, q0, uint64(i), &hashInput, &hashOutput),
			R1:    tmmoHash(hasher, q1, uint64(i), &hashInput, &hashOutput),
			Index: state.commitment.StartIndex + uint64(i),
		}
	}
	return sender, nil
}

func extensionStateCommitment(in ExtensionCommitment) ExtensionCommitment {
	in.U = nil
	return in
}

func clearExtensionReceiverState(state *ExtensionReceiverState) {
	clear(state.choices)
	clear(state.tMatrix)
	clear(state.commitment.U)
	state.choices = nil
	state.tMatrix = nil
	state.commitment = ExtensionCommitment{}
}

func clearExtensionSenderState(state *ExtensionSenderState) {
	clear(state.qChecks[:])
	clear(state.rows)
	clear(state.commitment.U)
	state.rows = nil
	state.delta = Label{}
	state.challengeTranscript = [32]byte{}
	state.commitment = ExtensionCommitment{}
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
