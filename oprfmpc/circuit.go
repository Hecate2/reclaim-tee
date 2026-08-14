// Package oprfmpc implements AES-CMAC based OPRF using Garbled Circuits
//
// This implements a 2PC OPRF computing: AES-CMAC(keyShareK XOR keyShareT, data_K XOR data_T)
//
// Protocol with OT precomputation:
// - Precomputation: TEE_K and TEE_T create single-use random OT entries.
// - Online message 1: TEE_K sends the garbled circuit and output translation bits.
// - Online message 2: TEE_T sends random-OT choice corrections.
// - Online message 3: TEE_K sends correction-aware OT masks.
// - Online message 4: TEE_T sends the evaluated output labels.
//
// Properties:
// - TEE_K (Garbler) has: data share (up to 64 bytes), keyShareK (16 bytes)
// - TEE_T (Evaluator) has: data share (up to 64 bytes), keyShareT (16 bytes)
// - Neither party sees: the combined key or plaintext
// - Output: 16-byte CMAC tag (both parties), then SHA256 offline for 32 bytes
package oprfmpc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"filippo.io/nistec"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/ot"
)

// aesCMACCircuit holds the compiled AES-CMAC OPRF circuit
var aesCMACCircuit *circuit.Circuit

// Input size: 64 bytes data + 16 bytes key = 80 bytes = 640 bits per party
const cmacInputBitCount = 640

// AESCMACResult holds the result of AES-CMAC OPRF computation
type AESCMACResult struct {
	Output16 [16]byte // Raw 16-byte CMAC output
	Output32 [32]byte // SHA256(CMAC output) for 32-byte result
}

// MPCL source for AES-CMAC OPRF with XOR-shared inputs
const aesCMACSource = `
package main

import (
	"crypto/aes"
)

func leftShift(L [16]byte) [16]byte {
	var result [16]byte
	var carry byte = 0
	for i := 15; i >= 0; i-- {
		result[i] = (L[i] << 1) | carry
		carry = L[i] >> 7
	}
	var mask byte = 0 - (L[0] >> 7)
	result[15] ^= mask & 0x87
	return result
}

func main(gInput [80]byte, eInput [80]byte) []byte {
	var key [16]byte
	for i := 0; i < 16; i++ {
		key[i] = gInput[64+i] ^ eInput[64+i]
	}
	var data [64]byte
	for i := 0; i < 64; i++ {
		data[i] = gInput[i] ^ eInput[i]
	}
	var zero [16]byte
	L := aes.Block128(key, zero)
	K1 := leftShift(L)
	var M1, M2, M3, M4 [16]byte
	for i := 0; i < 16; i++ {
		M1[i] = data[i]
		M2[i] = data[16+i]
		M3[i] = data[32+i]
		M4[i] = data[48+i] ^ K1[i]
	}
	C := aes.Block128(key, M1)
	for i := 0; i < 16; i++ {
		C[i] ^= M2[i]
	}
	C = aes.Block128(key, C)
	for i := 0; i < 16; i++ {
		C[i] ^= M3[i]
	}
	C = aes.Block128(key, C)
	for i := 0; i < 16; i++ {
		C[i] ^= M4[i]
	}
	C = aes.Block128(key, C)
	return C[:]
}
`

func init() {
	params := utils.NewParams()
	params.OptPruneGates = true
	comp := compiler.New(params)
	inputSizes := [][]int{{640}, {640}}
	circ, _, err := comp.Compile(aesCMACSource, inputSizes)
	if err != nil {
		panic(fmt.Sprintf("failed to compile AES-CMAC OPRF circuit: %v", err))
	}
	aesCMACCircuit = circ
}

// CMACOnlinePayload is the message sent from garbler to evaluator in the online phase
type CMACOnlinePayload struct {
	SessionID          uint64
	Key                [32]byte     // Garbling key
	GarbledTables      [][]ot.Label // The garbled circuit tables
	GarblerInputs      []ot.Label   // Garbler's encoded input labels
	OutputTranslations []bool       // L0 permutation bits; never exposes both output labels
	OTStartIndex       int          // Starting index in precomputed OT pool

	// Set only by CMACGarblerOnline; slices above point into pooled scratch.
	// Caller MUST invoke Release after serializing to the wire.
	garbled *circuit.Garbled
}

// Returns pooled garble scratch to the circuit pool. Idempotent.
func (p *CMACOnlinePayload) Release() {
	if p == nil || p.garbled == nil {
		return
	}
	g := p.garbled
	p.garbled = nil
	p.GarbledTables = nil
	g.Release()
}

// CMACOnlineResult holds the evaluator's output
type CMACOnlineResult struct {
	CMACOutput   [16]byte   // 16-byte CMAC result
	OutputLabels []ot.Label // MANDATORY: actual output wire labels for garbler verification
}

// CMACGarblerOnlineSession holds garbler state for output verification
type CMACGarblerOnlineSession struct {
	SessionID           uint64
	ExpectedOutputWires []ot.Wire // Kept only by the garbler for output verification.

	mu                 sync.Mutex
	evaluatorWires     []ot.Wire
	otPads             []randomOTPair
	correctionsApplied bool
	outputVerified     bool
}

type randomOTPair struct {
	R0 ot.Label
	R1 ot.Label
}

// CMACEvaluatorOnlineSession holds the evaluator state between the choice-
// correction message and receipt of the corrected OT masks. It is single-use.
type CMACEvaluatorOnlineSession struct {
	SessionID uint64

	mu              sync.Mutex
	payload         *CMACOnlinePayload
	inputBits       []bool
	receiverEntries []*OTReceiverEntry
	evaluated       bool
}

var (
	errCMACNilRandom = errors.New("aes_cmac_oprf: randomness source must not be nil")
)

// Builds the online-phase payload using precomputed OT (640 entries / OPRF).
func CMACGarblerOnline(rng io.Reader, curve elliptic.Curve, garblerInput [80]byte, otEntries []*OTPoolEntry, otStartIndex int) (*CMACOnlinePayload, *CMACGarblerOnlineSession, error) {
	if rng == nil {
		return nil, nil, errCMACNilRandom
	}
	if len(otEntries) != cmacInputBitCount {
		return nil, nil, fmt.Errorf("need %d OT entries, got %d", cmacInputBitCount, len(otEntries))
	}
	if curve == nil || curve.Params().Name != otCurveName {
		return nil, nil, fmt.Errorf("unexpected OT curve")
	}
	for i, entry := range otEntries {
		if entry == nil {
			return nil, nil, fmt.Errorf("nil sender OT entry at i=%d", i)
		}
	}

	circ := aesCMACCircuit
	if circ.NumParties() != 2 {
		return nil, nil, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}

	// Generate session ID
	var sidBuf [8]byte
	if _, err := io.ReadFull(rng, sidBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to read session id: %w", err)
	}
	sessionID := binary.BigEndian.Uint64(sidBuf[:])

	// Generate garbling key
	var key [32]byte
	if _, err := io.ReadFull(rng, key[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to read garbling key: %w", err)
	}

	// Garble the circuit
	garbled, err := circ.Garble(rng, key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to garble circuit: %w", err)
	}

	// Extract garbler's input labels (first 640 wires)
	gBits := cmacInputBitCount
	bits := cmacBytesToBits(garblerInput[:])
	if len(bits) != gBits {
		return nil, nil, fmt.Errorf("garbler input mismatch: got %d bits want %d", len(bits), gBits)
	}

	garblerLabels := make([]ot.Label, gBits)
	for i := range gBits {
		garblerLabels[i] = circuit.LabelForBit(garbled.Wires[i], bits[i])
	}

	// Extract evaluator's wire labels (wires 640-1279)
	evaluatorWires := garbled.Wires[gBits : gBits+cmacInputBitCount]

	// Derive the sender's random-OT pads now, but do not mask the evaluator
	// labels until the evaluator returns c=d XOR b. Sending R0 XOR R1 would
	// reveal both pads to a receiver that already knows R_d.
	otPads := make([]randomOTPair, cmacInputBitCount)
	scratch := newNistecScratch()
	for i := range cmacInputBitCount {
		entry := otEntries[i]
		r0, r1, err := deriveRandomLabelsFromSetup(entry.SenderSetup, entry.ReceiverPoint, i, scratch)
		if err != nil {
			garbled.Release()
			return nil, nil, fmt.Errorf("random-OT pad derivation at i=%d: %w", i, err)
		}
		otPads[i] = randomOTPair{R0: r0, R1: r1}
	}

	// Keep the output wires on TEE_K. Send only each L0 permutation bit.
	outputs := circ.Outputs.Size()
	outputWires := make([]ot.Wire, outputs)
	start := int(circ.NumWires) - outputs
	copy(outputWires, garbled.Wires[start:])
	outputTranslations := make([]bool, outputs)
	for i, wire := range outputWires {
		outputTranslations[i] = wire.L0.S()
	}

	payload := &CMACOnlinePayload{
		SessionID:          sessionID,
		Key:                key,
		GarbledTables:      garbled.Gates,
		GarblerInputs:      garblerLabels,
		OutputTranslations: outputTranslations,
		OTStartIndex:       otStartIndex,
		garbled:            garbled,
	}

	session := &CMACGarblerOnlineSession{
		SessionID:           sessionID,
		ExpectedOutputWires: outputWires,
		evaluatorWires:      append([]ot.Wire(nil), evaluatorWires...),
		otPads:              otPads,
	}

	return payload, session, nil
}

// CMACGarblerApplyCorrections converts random OT into chosen OT. For each bit,
// c=d XOR b tells the sender whether to swap R0/R1 before masking L0/L1. Since
// d is uniform and single-use, c hides b from the sender. No pad delta is sent.
func CMACGarblerApplyCorrections(session *CMACGarblerOnlineSession, corrections []bool) ([]OTMask, error) {
	if session == nil {
		return nil, errors.New("nil garbler session")
	}
	if len(corrections) != cmacInputBitCount {
		return nil, fmt.Errorf("need %d choice corrections, got %d", cmacInputBitCount, len(corrections))
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.correctionsApplied {
		return nil, errors.New("choice corrections already applied")
	}
	if len(session.evaluatorWires) != cmacInputBitCount || len(session.otPads) != cmacInputBitCount {
		return nil, errors.New("garbler session has invalid OT state")
	}

	masks := make([]OTMask, cmacInputBitCount)
	for i := range cmacInputBitCount {
		pads := session.otPads[i]
		if corrections[i] {
			pads.R0, pads.R1 = pads.R1, pads.R0
		}
		wire := session.evaluatorWires[i]
		masks[i] = OTMask{
			M0: xorLabels(wire.L0, pads.R0),
			M1: xorLabels(wire.L1, pads.R1),
		}
	}

	session.correctionsApplied = true
	session.evaluatorWires = nil
	session.otPads = nil
	return masks, nil
}

// CMACEvaluatorPrepare binds the evaluator's actual input to its single-use
// random OT choices and returns the correction bits sent to the garbler.
func CMACEvaluatorPrepare(payload *CMACOnlinePayload, evaluatorInput [80]byte, receiverEntries []*OTReceiverEntry) (*CMACEvaluatorOnlineSession, []bool, error) {
	if payload == nil {
		return nil, nil, errors.New("nil payload")
	}
	if len(receiverEntries) != cmacInputBitCount {
		return nil, nil, fmt.Errorf("need %d receiver entries, got %d", cmacInputBitCount, len(receiverEntries))
	}
	if len(payload.OutputTranslations) != aesCMACCircuit.Outputs.Size() {
		return nil, nil, fmt.Errorf("need %d output translations, got %d", aesCMACCircuit.Outputs.Size(), len(payload.OutputTranslations))
	}

	// Convert evaluator input to bits (choice bits)
	bits := cmacBytesToBits(evaluatorInput[:])
	if len(bits) != cmacInputBitCount {
		return nil, nil, fmt.Errorf("evaluator input mismatch: got %d bits want %d", len(bits), cmacInputBitCount)
	}

	corrections := make([]bool, cmacInputBitCount)
	for i, entry := range receiverEntries {
		if entry == nil || len(entry.ReceiverBundle.Bits) != 1 || len(entry.ReceiverBundle.Scalars) != 1 ||
			entry.ReceiverBundle.Scalars[0] == nil || entry.SenderPublicPoint.X == nil || entry.SenderPublicPoint.Y == nil {
			return nil, nil, fmt.Errorf("invalid receiver OT entry at i=%d", i)
		}
		corrections[i] = entry.ReceiverBundle.Bits[0] != bits[i]
	}

	return &CMACEvaluatorOnlineSession{
		SessionID:       payload.SessionID,
		payload:         payload,
		inputBits:       bits,
		receiverEntries: append([]*OTReceiverEntry(nil), receiverEntries...),
	}, corrections, nil
}

// CMACEvaluatorOnline evaluates the garbled circuit after receiving the
// correction-aware masks from the garbler.
func CMACEvaluatorOnline(curve elliptic.Curve, session *CMACEvaluatorOnlineSession, masks []OTMask) (*CMACOnlineResult, error) {
	if session == nil {
		return nil, errors.New("nil evaluator session")
	}
	if len(masks) != cmacInputBitCount {
		return nil, fmt.Errorf("need %d OT masks, got %d", cmacInputBitCount, len(masks))
	}
	if curve == nil || curve.Params().Name != otCurveName {
		return nil, fmt.Errorf("unexpected OT curve")
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.evaluated {
		return nil, errors.New("evaluator session already used")
	}
	session.evaluated = true

	payload := session.payload
	bits := session.inputBits
	receiverEntries := session.receiverEntries
	circ := aesCMACCircuit

	// Recover only L_b from R_d and the correction-aware mask M_b.
	evaluatorLabels := make([]ot.Label, cmacInputBitCount)
	scratch := newNistecScratch()
	for i := range cmacInputBitCount {
		entry := receiverEntries[i]
		actualChoice := bits[i]
		receivedR, err := deriveReceivedLabelFromEntry(entry, i, scratch)
		if err != nil {
			return nil, fmt.Errorf("evaluator label derivation at i=%d: %w", i, err)
		}

		// Select the mask for the actual choice bit
		var chosenMask ot.Label
		if actualChoice {
			chosenMask = masks[i].M1
		} else {
			chosenMask = masks[i].M0
		}

		// The sender swapped pads when c=1, so M_b always uses R_d.
		evaluatorLabels[i] = xorLabels(receivedR, chosenMask)
	}

	// Build complete wire labels
	totalWires := int(circ.NumWires)
	wires := make([]ot.Label, totalWires)
	copy(wires[:cmacInputBitCount], payload.GarblerInputs)
	copy(wires[cmacInputBitCount:2*cmacInputBitCount], evaluatorLabels)

	// Evaluate the garbled circuit
	if err := circ.Eval(payload.Key[:], wires, payload.GarbledTables); err != nil {
		return nil, fmt.Errorf("circuit evaluation failed: %w", err)
	}

	// Decode with one permutation bit per output. Sending both output labels
	// would reveal the global Free-XOR offset.
	if len(payload.OutputTranslations) != circ.Outputs.Size() {
		return nil, fmt.Errorf("output translation mismatch: have %d want %d",
			len(payload.OutputTranslations), circ.Outputs.Size())
	}

	outputStart := int(circ.NumWires) - len(payload.OutputTranslations)
	outputBits := make([]bool, len(payload.OutputTranslations))
	outputLabels := make([]ot.Label, len(payload.OutputTranslations))

	for i := range payload.OutputTranslations {
		label := wires[outputStart+i]
		outputBits[i] = label.S() != payload.OutputTranslations[i]
		outputLabels[i] = label
	}

	// Convert output bits to bytes
	outputBytes := cmacBitsToBytes(outputBits)
	if len(outputBytes) != 16 {
		return nil, fmt.Errorf("unexpected output length %d", len(outputBytes))
	}

	var cmacOutput [16]byte
	copy(cmacOutput[:], outputBytes)

	return &CMACOnlineResult{
		CMACOutput:   cmacOutput,
		OutputLabels: outputLabels,
	}, nil
}

// CMACGarblerVerifyOutput verifies the evaluator's output labels and derives
// the CMAC bytes from them. Each label MUST equal L0 or L1; the bit is then
// 0 or 1. TEE_K trusts these derived bytes — not whatever CMAC bytes TEE_T
// also sends on the wire — so a malicious evaluator can't substitute the
// output without first forging a label collision.
func CMACGarblerVerifyOutput(session *CMACGarblerOnlineSession, outputLabels []ot.Label) ([16]byte, error) {
	var zero [16]byte
	if session == nil {
		return zero, errors.New("nil session")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.correctionsApplied {
		return zero, errors.New("choice corrections were not applied")
	}
	if session.outputVerified {
		return zero, errors.New("output already verified")
	}
	session.outputVerified = true
	if len(outputLabels) != len(session.ExpectedOutputWires) {
		return zero, fmt.Errorf("output label count mismatch: got %d, expected %d",
			len(outputLabels), len(session.ExpectedOutputWires))
	}
	if len(outputLabels) != 128 {
		return zero, fmt.Errorf("expected 128 output labels for 16-byte CMAC, got %d", len(outputLabels))
	}

	bits := make([]bool, len(outputLabels))
	for i, label := range outputLabels {
		wire := session.ExpectedOutputWires[i]
		switch {
		case label.Equal(wire.L0):
			bits[i] = false
		case label.Equal(wire.L1):
			bits[i] = true
		default:
			return zero, fmt.Errorf("output label %d verification failed: label does not match either L0 or L1", i)
		}
	}

	outBytes := cmacBitsToBytes(bits)
	var out [16]byte
	copy(out[:], outBytes)
	return out, nil
}

// Helper functions

func cmacBytesToBits(data []byte) []bool {
	bits := make([]bool, len(data)*8)
	for i, b := range data {
		for j := range 8 {
			bits[i*8+j] = (b>>j)&1 == 1
		}
	}
	return bits
}

func cmacBitsToBytes(bits []bool) []byte {
	bytes := make([]byte, (len(bits)+7)/8)
	for i, bit := range bits {
		if bit {
			bytes[i/8] |= 1 << (i % 8)
		}
	}
	return bytes
}

func packBits(bits []bool) []byte {
	packed := make([]byte, (len(bits)+7)/8)
	for i, bit := range bits {
		if bit {
			packed[i/8] |= 1 << (i % 8)
		}
	}
	return packed
}

func unpackBits(packed []byte, count int) []bool {
	bits := make([]bool, count)
	for i := range count {
		bits[i] = packed[i/8]&(1<<(i%8)) != 0
	}
	return bits
}

// PadZeros64 pads data with zeros to exactly 64 bytes.
func PadZeros64(data []byte, dataLen int) ([64]byte, error) {
	if dataLen > 64 {
		return [64]byte{}, fmt.Errorf("dataLen too large: %d > 64", dataLen)
	}
	if len(data) < dataLen {
		return [64]byte{}, fmt.Errorf("data slice too short: %d < %d", len(data), dataLen)
	}
	var padded [64]byte
	copy(padded[:dataLen], data[:dataLen])
	return padded, nil
}

// xorLabels XORs two labels
func xorLabels(a, b ot.Label) ot.Label {
	return ot.Label{
		D0: a.D0 ^ b.D0,
		D1: a.D1 ^ b.D1,
	}
}

// Reusable scratch for the 640-iteration ECDH pad loop. Mutated in place.
type nistecScratch struct {
	bPt, aPt, aAInvPt *nistec.P256Point
	r0Pt, r1Pt        *nistec.P256Point
	pointEnc          [65]byte // 0x04 || x32 || y32
	altEnc            [65]byte
	scalar            [32]byte
}

func newNistecScratch() *nistecScratch {
	return &nistecScratch{
		bPt:     nistec.NewP256Point(),
		aPt:     nistec.NewP256Point(),
		aAInvPt: nistec.NewP256Point(),
		r0Pt:    nistec.NewP256Point(),
		r1Pt:    nistec.NewP256Point(),
	}
}

// Writes (0x04 || x32 || y32) SEC 1 uncompressed encoding via FillBytes (no alloc).
func encodeUncompressedInto(out *[65]byte, x, y *big.Int) {
	out[0] = 0x04
	x.FillBytes(out[1:33])
	y.FillBytes(out[33:65])
}

// scalarToFixed32 writes the 32-byte big-endian encoding of s into out.
func scalarToFixed32(out *[32]byte, s *big.Int) {
	s.FillBytes(out[:])
}

// SHA256(x32 || y32 || index8 || selector1) -> ot.Label. K and T must agree.
func labelFromNistecPoint(p *nistec.P256Point, index int, selector byte) ot.Label {
	pb := p.Bytes()
	var buf [32 + 32 + 8 + 1]byte
	copy(buf[0:32], pb[1:33])
	copy(buf[32:64], pb[33:65])
	binary.BigEndian.PutUint64(buf[64:72], uint64(index))
	buf[72] = selector
	hash := sha256.Sum256(buf[:])
	return ot.Label{
		D0: binary.BigEndian.Uint64(hash[0:8]),
		D1: binary.BigEndian.Uint64(hash[8:16]),
	}
}

// CO OT sender: R0 = H(aB), R1 = H(R0 + (-aA)). Identity: a(B-A) = aB - aA.
func deriveRandomLabelsFromSetup(setup ot.COSenderSetup, receiverPoint ot.ECPoint, index int, s *nistecScratch) (r0, r1 ot.Label, err error) {
	encodeUncompressedInto(&s.pointEnc, receiverPoint.X, receiverPoint.Y)
	encodeUncompressedInto(&s.altEnc, setup.AaInvX, setup.AaInvY)
	scalarToFixed32(&s.scalar, setup.Scalar)

	if _, err = s.bPt.SetBytes(s.pointEnc[:]); err != nil {
		return r0, r1, fmt.Errorf("decode receiver point: %w", err)
	}
	if _, err = s.aAInvPt.SetBytes(s.altEnc[:]); err != nil {
		return r0, r1, fmt.Errorf("decode AaInv point: %w", err)
	}
	if _, err = s.r0Pt.ScalarMult(s.bPt, s.scalar[:]); err != nil {
		return r0, r1, fmt.Errorf("scalar mult B^a: %w", err)
	}
	s.r1Pt.Add(s.r0Pt, s.aAInvPt)

	r0 = labelFromNistecPoint(s.r0Pt, index, 0)
	r1 = labelFromNistecPoint(s.r1Pt, index, 1)
	return r0, r1, nil
}

// CO OT receiver: R = H(A^b). Matches sender's R0 (choice=0) or R1 (choice=1).
func deriveReceivedLabelFromEntry(entry *OTReceiverEntry, index int, s *nistecScratch) (ot.Label, error) {
	bundle := entry.ReceiverBundle
	choiceBit := bundle.Bits[0]

	encodeUncompressedInto(&s.pointEnc, entry.SenderPublicPoint.X, entry.SenderPublicPoint.Y)
	scalarToFixed32(&s.scalar, bundle.Scalars[0])

	if _, err := s.aPt.SetBytes(s.pointEnc[:]); err != nil {
		return ot.Label{}, fmt.Errorf("decode A point: %w", err)
	}
	if _, err := s.r0Pt.ScalarMult(s.aPt, s.scalar[:]); err != nil {
		return ot.Label{}, fmt.Errorf("scalar mult A^b: %w", err)
	}

	// Selector matches sender's derivation: 0 for R0, 1 for R1
	selector := byte(0)
	if choiceBit {
		selector = 1
	}

	return labelFromNistecPoint(s.r0Pt, index, selector), nil
}

// Serialization helpers for wire protocol

// deserializeLabel deserializes 16 bytes to a Label
func deserializeLabel(data []byte) ot.Label {
	return ot.Label{
		D0: binary.BigEndian.Uint64(data[0:8]),
		D1: binary.BigEndian.Uint64(data[8:16]),
	}
}

// One allocation; size known up front. OT masks are sent only after the
// evaluator's choice-correction message and are not part of this payload.
func SerializeOnlinePayload(p *CMACOnlinePayload) []byte {
	totalGateLabels := 0
	for _, gate := range p.GarbledTables {
		totalGateLabels += len(gate)
	}
	translationBytes := packBits(p.OutputTranslations)

	size := 8 + 32 + 4 + // sessionID + key + OTStartIndex
		4 + len(p.GarbledTables)*4 + totalGateLabels*16 + // gates: numGates + per-gate (numLabels + labels)
		4 + len(p.GarblerInputs)*16 + // garbler inputs
		4 + len(translationBytes) // output translation bit count + packed bits

	buf := make([]byte, size)
	off := 0

	binary.BigEndian.PutUint64(buf[off:off+8], p.SessionID)
	off += 8
	copy(buf[off:off+32], p.Key[:])
	off += 32
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(p.OTStartIndex))
	off += 4

	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(p.GarbledTables)))
	off += 4
	for _, gate := range p.GarbledTables {
		binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(gate)))
		off += 4
		for _, label := range gate {
			binary.BigEndian.PutUint64(buf[off:off+8], label.D0)
			binary.BigEndian.PutUint64(buf[off+8:off+16], label.D1)
			off += 16
		}
	}

	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(p.GarblerInputs)))
	off += 4
	for _, label := range p.GarblerInputs {
		binary.BigEndian.PutUint64(buf[off:off+8], label.D0)
		binary.BigEndian.PutUint64(buf[off+8:off+16], label.D1)
		off += 16
	}

	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(p.OutputTranslations)))
	off += 4
	copy(buf[off:], translationBytes)

	return buf
}

// DeserializeOnlinePayload deserializes bytes to CMACOnlinePayload
func DeserializeOnlinePayload(data []byte) (*CMACOnlinePayload, error) {
	// Minimum header: sessionID(8) + key(32) + otStartIndex(4) + numGates(4) = 48 bytes
	if len(data) < 48 {
		return nil, errors.New("data too short for online payload header")
	}

	offset := 0
	sessionID := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	var key [32]byte
	copy(key[:], data[offset:offset+32])
	offset += 32

	otStartIndex := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Garbled Tables
	if offset+4 > len(data) {
		return nil, errors.New("data too short for gate count")
	}
	numGates := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	// Must equal the compiled circuit's gate count — circ.Eval would
	// index garbled[i] for i in 0..circ.NumGates without bounds-checking.
	if int(numGates) != aesCMACCircuit.NumGates {
		return nil, fmt.Errorf("gate count mismatch: payload has %d, circuit has %d", numGates, aesCMACCircuit.NumGates)
	}
	gates := make([][]ot.Label, numGates)
	for i := range gates {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for label count at gate %d", i)
		}
		numLabels := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(numLabels)*16 > len(data) {
			return nil, fmt.Errorf("data too short for %d labels at gate %d", numLabels, i)
		}
		labels := make([]ot.Label, numLabels)
		for j := range labels {
			labels[j] = deserializeLabel(data[offset : offset+16])
			offset += 16
		}
		gates[i] = labels
	}

	// Garbler Inputs
	if offset+4 > len(data) {
		return nil, errors.New("data too short for garbler input count")
	}
	numGI := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if int(numGI) != cmacInputBitCount {
		return nil, fmt.Errorf("garbler input count mismatch: payload has %d, circuit needs %d", numGI, cmacInputBitCount)
	}

	if offset+int(numGI)*16 > len(data) {
		return nil, fmt.Errorf("data too short for %d garbler inputs", numGI)
	}
	garblerInputs := make([]ot.Label, numGI)
	for i := range garblerInputs {
		garblerInputs[i] = deserializeLabel(data[offset : offset+16])
		offset += 16
	}

	// Output translation bits
	if offset+4 > len(data) {
		return nil, errors.New("data too short for output translation count")
	}
	numTranslations := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if int(numTranslations) != aesCMACCircuit.Outputs.Size() {
		return nil, fmt.Errorf("output translation count mismatch: payload has %d, circuit has %d", numTranslations, aesCMACCircuit.Outputs.Size())
	}
	translationByteCount := (int(numTranslations) + 7) / 8
	if offset+translationByteCount > len(data) {
		return nil, fmt.Errorf("data too short for %d output translations", numTranslations)
	}
	outputTranslations := unpackBits(data[offset:offset+translationByteCount], int(numTranslations))
	offset += translationByteCount

	if offset != len(data) {
		return nil, fmt.Errorf("trailing bytes after output translations (%d)", len(data)-offset)
	}

	return &CMACOnlinePayload{
		SessionID:          sessionID,
		Key:                key,
		GarbledTables:      gates,
		GarblerInputs:      garblerInputs,
		OutputTranslations: outputTranslations,
		OTStartIndex:       int(otStartIndex),
	}, nil
}

// SerializeOutputLabels serializes output labels for transmission
func SerializeOutputLabels(labels []ot.Label) []byte {
	buf := make([]byte, 4+len(labels)*16)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(labels)))
	offset := 4
	for _, label := range labels {
		binary.BigEndian.PutUint64(buf[offset:offset+8], label.D0)
		binary.BigEndian.PutUint64(buf[offset+8:offset+16], label.D1)
		offset += 16
	}
	return buf
}

// DeserializeOutputLabels deserializes output labels
func DeserializeOutputLabels(data []byte) ([]ot.Label, error) {
	if len(data) < 4 {
		return nil, errors.New("data too short for label count")
	}

	count := binary.BigEndian.Uint32(data[0:4])

	expectedLen := uint64(4) + uint64(count)*16
	if uint64(len(data)) != expectedLen {
		return nil, fmt.Errorf("invalid output label encoding length %d for count %d", len(data), count)
	}

	labels := make([]ot.Label, count)
	offset := 4
	for i := range count {
		labels[i] = ot.Label{
			D0: binary.BigEndian.Uint64(data[offset : offset+8]),
			D1: binary.BigEndian.Uint64(data[offset+8 : offset+16]),
		}
		offset += 16
	}

	return labels, nil
}
