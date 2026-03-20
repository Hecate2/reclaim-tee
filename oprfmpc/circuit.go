// Package oprfmpc implements AES-CMAC based OPRF using Garbled Circuits
//
// This implements a 2PC OPRF computing: AES-CMAC(keyShareK XOR keyShareT, data_K XOR data_T)
//
// Properties:
// - TEE_K (Garbler) has: data share (up to 64 bytes), keyShareK (16 bytes)
// - TEE_T (Evaluator) has: data share (up to 64 bytes), keyShareT (16 bytes)
// - Neither party sees: the combined key or plaintext
// - Output: 16-byte CMAC tag (both parties), then SHA256 offline for 32 bytes
package oprfmpc

import (
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

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

// CMACRound1Payload is sent by garbler to evaluator
type CMACRound1Payload struct {
	SessionID uint64
	OT        CMACOTSetup
}

// CMACOTSetup contains the OT setup parameters
type CMACOTSetup struct {
	CurveName string
	A         ot.ECPoint
}

// CMACRound2Payload is sent by evaluator to garbler
type CMACRound2Payload struct {
	SessionID uint64
	CurveName string
	Choices   []ot.ECPoint
}

// CMACRound3Payload is sent by garbler to evaluator
type CMACRound3Payload struct {
	SessionID     uint64
	Ciphertexts   []ot.LabelCiphertext
	Key           [32]byte
	GarbledTables [][]ot.Label
	GarblerInputs []ot.Label
	OutputHints   []ot.Wire
}

// CMACGarblerSession holds garbler state between rounds
type CMACGarblerSession struct {
	SessionID   uint64
	SenderSetup ot.COSenderSetup
}

// CMACEvaluatorSession holds evaluator state between rounds
type CMACEvaluatorSession struct {
	SessionID    uint64
	ChoiceBundle ot.COChoiceBundle
}

var (
	errCMACNilRandom = errors.New("aes_cmac_oprf: randomness source must not be nil")
	errCMACNilCurve  = errors.New("aes_cmac_oprf: elliptic curve must not be nil")
)

// CMACGarblerRound1 initiates the protocol
func CMACGarblerRound1(rng io.Reader, curve elliptic.Curve) (CMACRound1Payload, *CMACGarblerSession, error) {
	if rng == nil {
		return CMACRound1Payload{}, nil, errCMACNilRandom
	}
	if curve == nil {
		return CMACRound1Payload{}, nil, errCMACNilCurve
	}

	setup, err := ot.GenerateCOSenderSetup(rng, curve)
	if err != nil {
		return CMACRound1Payload{}, nil, err
	}

	var sidBuf [8]byte
	if _, err := io.ReadFull(rng, sidBuf[:]); err != nil {
		return CMACRound1Payload{}, nil, fmt.Errorf("failed to read session id: %w", err)
	}
	sessionID := binary.BigEndian.Uint64(sidBuf[:])

	state := &CMACGarblerSession{
		SessionID:   sessionID,
		SenderSetup: setup,
	}

	payload := CMACRound1Payload{
		SessionID: sessionID,
		OT: CMACOTSetup{
			CurveName: setup.CurveName,
			A: ot.ECPoint{
				X: new(big.Int).Set(setup.Ax),
				Y: new(big.Int).Set(setup.Ay),
			},
		},
	}

	return payload, state, nil
}

// CMACEvaluatorRound2 processes round 1 and returns round 2
func CMACEvaluatorRound2(rng io.Reader, curve elliptic.Curve, msg CMACRound1Payload, input [80]byte) (CMACRound2Payload, *CMACEvaluatorSession, error) {
	if rng == nil {
		return CMACRound2Payload{}, nil, errCMACNilRandom
	}
	if curve == nil {
		return CMACRound2Payload{}, nil, errCMACNilCurve
	}

	circ := aesCMACCircuit
	if circ.NumParties() != 2 {
		return CMACRound2Payload{}, nil, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}

	state := &CMACEvaluatorSession{}
	if msg.OT.CurveName != curve.Params().Name {
		return CMACRound2Payload{}, nil, fmt.Errorf("curve mismatch: %s vs %s",
			msg.OT.CurveName, curve.Params().Name)
	}
	state.SessionID = msg.SessionID

	bits := cmacBytesToBits(input[:])
	if len(bits) != cmacInputBitCount {
		return CMACRound2Payload{}, nil, fmt.Errorf("evaluator input mismatch: got %d bits want %d",
			len(bits), cmacInputBitCount)
	}

	bundle, choices, err := ot.BuildCOChoices(rng, curve, msg.OT.A.X, msg.OT.A.Y, bits)
	if err != nil {
		return CMACRound2Payload{}, nil, err
	}
	state.ChoiceBundle = bundle

	return CMACRound2Payload{
		SessionID: msg.SessionID,
		CurveName: curve.Params().Name,
		Choices:   choices,
	}, state, nil
}

// CMACGarblerRound3 garbles the circuit and prepares round 3
func CMACGarblerRound3(rng io.Reader, curve elliptic.Curve, state *CMACGarblerSession, input [80]byte, req CMACRound2Payload) (CMACRound3Payload, error) {
	if rng == nil {
		return CMACRound3Payload{}, errCMACNilRandom
	}
	if state == nil || state.SenderSetup.Scalar == nil {
		return CMACRound3Payload{}, errors.New("aes_cmac_oprf: invalid garbler session")
	}
	if curve == nil {
		return CMACRound3Payload{}, errCMACNilCurve
	}

	circ := aesCMACCircuit
	if circ.NumParties() != 2 {
		return CMACRound3Payload{}, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}
	if req.SessionID != state.SessionID {
		return CMACRound3Payload{}, fmt.Errorf("session id mismatch: got %d want %d",
			req.SessionID, state.SessionID)
	}

	var key [32]byte
	if _, err := io.ReadFull(rng, key[:]); err != nil {
		return CMACRound3Payload{}, fmt.Errorf("failed to read garbling key: %w", err)
	}

	garbled, err := circ.Garble(rng, key[:])
	if err != nil {
		return CMACRound3Payload{}, err
	}

	gBits := cmacInputBitCount
	eBits := cmacInputBitCount
	bits := cmacBytesToBits(input[:])
	if len(bits) != gBits {
		return CMACRound3Payload{}, fmt.Errorf("garbler input mismatch: got %d bits want %d",
			len(bits), gBits)
	}

	garblerLabels := make([]ot.Label, gBits)
	for i := range gBits {
		garblerLabels[i] = circuit.LabelForBit(garbled.Wires[i], bits[i])
	}

	evaluatorWires := garbled.Wires[gBits : gBits+eBits]
	ciphertexts, err := ot.EncryptCOCiphertexts(curve, state.SenderSetup, req.Choices, evaluatorWires)
	if err != nil {
		return CMACRound3Payload{}, err
	}

	outputs := circ.Outputs.Size()
	outputHints := make([]ot.Wire, outputs)
	start := int(circ.NumWires) - outputs
	copy(outputHints, garbled.Wires[start:])

	return CMACRound3Payload{
		SessionID:     state.SessionID,
		Ciphertexts:   ciphertexts,
		Key:           key,
		GarbledTables: garbled.Gates,
		GarblerInputs: garblerLabels,
		OutputHints:   outputHints,
	}, nil
}

// CMACEvaluatorRound4 evaluates the garbled circuit
func CMACEvaluatorRound4(curve elliptic.Curve, state *CMACEvaluatorSession, msg CMACRound3Payload) ([16]byte, error) {
	var result [16]byte
	if state == nil || len(state.ChoiceBundle.Scalars) == 0 {
		return result, fmt.Errorf("invalid evaluator state for round 4")
	}
	if curve == nil {
		return result, errCMACNilCurve
	}
	if msg.SessionID != state.SessionID {
		return result, fmt.Errorf("session id mismatch: got %d want %d",
			msg.SessionID, state.SessionID)
	}

	labels, err := ot.DecryptCOCiphertexts(curve, state.ChoiceBundle, msg.Ciphertexts)
	if err != nil {
		return result, err
	}

	circ := aesCMACCircuit
	totalWires := int(circ.NumWires)
	wires := make([]ot.Label, totalWires)
	copy(wires[:cmacInputBitCount], msg.GarblerInputs)
	copy(wires[cmacInputBitCount:], labels)

	if err := circ.Eval(msg.Key[:], wires, msg.GarbledTables); err != nil {
		return result, err
	}

	if len(msg.OutputHints) != circ.Outputs.Size() {
		return result, fmt.Errorf("output hint mismatch: have %d want %d",
			len(msg.OutputHints), circ.Outputs.Size())
	}

	start := circ.NumWires - len(msg.OutputHints)
	outputBits := make([]bool, len(msg.OutputHints))
	for i := 0; i < len(msg.OutputHints); i++ {
		bit, err := circuit.BitFromLabel(msg.OutputHints[i], wires[start+i])
		if err != nil {
			return result, err
		}
		outputBits[i] = bit
	}

	bytes := cmacBitsToBytes(outputBits)
	if len(bytes) != 16 {
		return result, fmt.Errorf("unexpected output length %d", len(bytes))
	}

	copy(result[:], bytes)
	return result, nil
}

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

// Serialization helpers for wire protocol

// SerializeRound1 serializes CMACRound1Payload to bytes
func SerializeRound1(p CMACRound1Payload) []byte {
	// Format: sessionID(8) + curveNameLen(2) + curveName + ax(32) + ay(32)
	curveNameBytes := []byte(p.OT.CurveName)
	buf := make([]byte, 8+2+len(curveNameBytes)+32+32)
	binary.BigEndian.PutUint64(buf[0:8], p.SessionID)
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(curveNameBytes)))
	copy(buf[10:10+len(curveNameBytes)], curveNameBytes)
	offset := 10 + len(curveNameBytes)
	axBytes := p.OT.A.X.Bytes()
	ayBytes := p.OT.A.Y.Bytes()
	copy(buf[offset+32-len(axBytes):offset+32], axBytes)
	copy(buf[offset+64-len(ayBytes):offset+64], ayBytes)
	return buf
}

// DeserializeRound1 deserializes bytes to CMACRound1Payload
func DeserializeRound1(data []byte) (CMACRound1Payload, error) {
	if len(data) < 10 {
		return CMACRound1Payload{}, errors.New("data too short for round1")
	}
	sessionID := binary.BigEndian.Uint64(data[0:8])
	curveNameLen := binary.BigEndian.Uint16(data[8:10])
	if len(data) < 10+int(curveNameLen)+64 {
		return CMACRound1Payload{}, errors.New("data too short for round1 payload")
	}
	curveName := string(data[10 : 10+curveNameLen])
	offset := 10 + int(curveNameLen)
	ax := new(big.Int).SetBytes(data[offset : offset+32])
	ay := new(big.Int).SetBytes(data[offset+32 : offset+64])
	return CMACRound1Payload{
		SessionID: sessionID,
		OT: CMACOTSetup{
			CurveName: curveName,
			A:         ot.ECPoint{X: ax, Y: ay},
		},
	}, nil
}

// SerializeRound2 serializes CMACRound2Payload to bytes
func SerializeRound2(p CMACRound2Payload) []byte {
	// Format: sessionID(8) + curveNameLen(2) + curveName + numChoices(4) + choices(64 each)
	curveNameBytes := []byte(p.CurveName)
	buf := make([]byte, 8+2+len(curveNameBytes)+4+len(p.Choices)*64)
	binary.BigEndian.PutUint64(buf[0:8], p.SessionID)
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(curveNameBytes)))
	copy(buf[10:10+len(curveNameBytes)], curveNameBytes)
	offset := 10 + len(curveNameBytes)
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(p.Choices)))
	offset += 4
	for _, choice := range p.Choices {
		xBytes := choice.X.Bytes()
		yBytes := choice.Y.Bytes()
		copy(buf[offset+32-len(xBytes):offset+32], xBytes)
		copy(buf[offset+64-len(yBytes):offset+64], yBytes)
		offset += 64
	}
	return buf
}

// DeserializeRound2 deserializes bytes to CMACRound2Payload
func DeserializeRound2(data []byte) (CMACRound2Payload, error) {
	if len(data) < 14 {
		return CMACRound2Payload{}, errors.New("data too short for round2")
	}
	sessionID := binary.BigEndian.Uint64(data[0:8])
	curveNameLen := binary.BigEndian.Uint16(data[8:10])
	if len(data) < 10+int(curveNameLen)+4 {
		return CMACRound2Payload{}, errors.New("data too short for round2 header")
	}
	curveName := string(data[10 : 10+curveNameLen])
	offset := 10 + int(curveNameLen)
	numChoices := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if len(data) < offset+int(numChoices)*64 {
		return CMACRound2Payload{}, errors.New("data too short for round2 choices")
	}
	choices := make([]ot.ECPoint, numChoices)
	for i := range choices {
		x := new(big.Int).SetBytes(data[offset : offset+32])
		y := new(big.Int).SetBytes(data[offset+32 : offset+64])
		choices[i] = ot.ECPoint{X: x, Y: y}
		offset += 64
	}
	return CMACRound2Payload{
		SessionID: sessionID,
		CurveName: curveName,
		Choices:   choices,
	}, nil
}

// serializeLabel serializes a Label (two uint64s) to 16 bytes
func serializeLabel(l ot.Label) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], l.D0)
	binary.BigEndian.PutUint64(buf[8:16], l.D1)
	return buf
}

// deserializeLabel deserializes 16 bytes to a Label
func deserializeLabel(data []byte) ot.Label {
	return ot.Label{
		D0: binary.BigEndian.Uint64(data[0:8]),
		D1: binary.BigEndian.Uint64(data[8:16]),
	}
}

// SerializeRound3 serializes CMACRound3Payload to bytes
func SerializeRound3(p CMACRound3Payload) []byte {
	var buf []byte

	// Session ID + Key
	tmp := make([]byte, 8+32)
	binary.BigEndian.PutUint64(tmp[0:8], p.SessionID)
	copy(tmp[8:40], p.Key[:])
	buf = append(buf, tmp...)

	// Ciphertexts (each is Zero + One, each LabelData is 16 bytes)
	ctCountBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(ctCountBuf, uint32(len(p.Ciphertexts)))
	buf = append(buf, ctCountBuf...)
	for _, ct := range p.Ciphertexts {
		buf = append(buf, ct.Zero[:]...)
		buf = append(buf, ct.One[:]...)
	}

	// Garbled Tables (each gate is []Label)
	numGatesBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(numGatesBuf, uint32(len(p.GarbledTables)))
	buf = append(buf, numGatesBuf...)
	for _, gate := range p.GarbledTables {
		numLabelsBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(numLabelsBuf, uint32(len(gate)))
		buf = append(buf, numLabelsBuf...)
		for _, label := range gate {
			buf = append(buf, serializeLabel(label)...)
		}
	}

	// Garbler Inputs ([]Label)
	numGIBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(numGIBuf, uint32(len(p.GarblerInputs)))
	buf = append(buf, numGIBuf...)
	for _, label := range p.GarblerInputs {
		buf = append(buf, serializeLabel(label)...)
	}

	// Output Hints ([]Wire, each Wire has L0 and L1 Labels)
	numOHBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(numOHBuf, uint32(len(p.OutputHints)))
	buf = append(buf, numOHBuf...)
	for _, wire := range p.OutputHints {
		buf = append(buf, serializeLabel(wire.L0)...)
		buf = append(buf, serializeLabel(wire.L1)...)
	}

	return buf
}

// DeserializeRound3 deserializes bytes to CMACRound3Payload
func DeserializeRound3(data []byte) (CMACRound3Payload, error) {
	// Minimum header: sessionID(8) + key(32) + numCT(4) = 44 bytes
	if len(data) < 44 {
		return CMACRound3Payload{}, errors.New("data too short for round3 header")
	}

	offset := 0
	sessionID := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	var key [32]byte
	copy(key[:], data[offset:offset+32])
	offset += 32

	// Ciphertexts (each is 32 bytes: Zero[16] + One[16])
	if offset+4 > len(data) {
		return CMACRound3Payload{}, errors.New("data too short for ciphertext count")
	}
	numCT := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Bounds check for ciphertexts
	if offset+int(numCT)*32 > len(data) {
		return CMACRound3Payload{}, fmt.Errorf("data too short for %d ciphertexts: need %d bytes from offset %d, have %d",
			numCT, numCT*32, offset, len(data)-offset)
	}
	ciphertexts := make([]ot.LabelCiphertext, numCT)
	for i := range ciphertexts {
		var zero, one ot.LabelData
		copy(zero[:], data[offset:offset+16])
		copy(one[:], data[offset+16:offset+32])
		ciphertexts[i] = ot.LabelCiphertext{Zero: zero, One: one}
		offset += 32
	}

	// Garbled Tables
	if offset+4 > len(data) {
		return CMACRound3Payload{}, errors.New("data too short for gate count")
	}
	numGates := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	gates := make([][]ot.Label, numGates)
	for i := range gates {
		if offset+4 > len(data) {
			return CMACRound3Payload{}, fmt.Errorf("data too short for label count at gate %d", i)
		}
		numLabels := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		// Bounds check for labels
		if offset+int(numLabels)*16 > len(data) {
			return CMACRound3Payload{}, fmt.Errorf("data too short for %d labels at gate %d", numLabels, i)
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
		return CMACRound3Payload{}, errors.New("data too short for garbler input count")
	}
	numGI := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Bounds check for garbler inputs
	if offset+int(numGI)*16 > len(data) {
		return CMACRound3Payload{}, fmt.Errorf("data too short for %d garbler inputs", numGI)
	}
	garblerInputs := make([]ot.Label, numGI)
	for i := range garblerInputs {
		garblerInputs[i] = deserializeLabel(data[offset : offset+16])
		offset += 16
	}

	// Output Hints (each Wire is 32 bytes: L0[16] + L1[16])
	if offset+4 > len(data) {
		return CMACRound3Payload{}, errors.New("data too short for output hint count")
	}
	numOH := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Bounds check for output hints
	if offset+int(numOH)*32 > len(data) {
		return CMACRound3Payload{}, fmt.Errorf("data too short for %d output hints", numOH)
	}
	outputHints := make([]ot.Wire, numOH)
	for i := range outputHints {
		outputHints[i].L0 = deserializeLabel(data[offset : offset+16])
		outputHints[i].L1 = deserializeLabel(data[offset+16 : offset+32])
		offset += 32
	}

	return CMACRound3Payload{
		SessionID:     sessionID,
		Ciphertexts:   ciphertexts,
		Key:           key,
		GarbledTables: gates,
		GarblerInputs: garblerInputs,
		OutputHints:   outputHints,
	}, nil
}
