package mpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// SenderOT is one random OT held by the garbler. R0 and R1 are independent
// random labels produced by OT extension.
type SenderOT struct {
	R0    Label
	R1    Label
	Index uint64
}

// ReceiverOT is the matching random OT held by the evaluator. R equals R0 or
// R1 according to Choice; the other sender label is unknown to the evaluator.
type ReceiverOT struct {
	R      Label
	Index  uint64
	Choice bool
}

// OTMask converts a precomputed random OT into a chosen OT after the evaluator
// sends its one-time choice correction.
type OTMask struct {
	M0 Label
	M1 Label
}

// OnlinePayload is the garbler's first online message.
type OnlinePayload struct {
	SessionID          uint64
	Key                [16]byte
	Tables             []Label
	GarblerInputs      []Label
	OutputTranslations [OutputBits / 8]byte
	OTStartIndex       uint64

	garbled *garbled
}

// Release returns garbling scratch to the package pool. It is idempotent. The
// payload must not be read after Release.
func (p *OnlinePayload) Release() {
	if p == nil {
		return
	}
	garbled := p.garbled
	p.garbled = nil
	p.Key = [16]byte{}
	clear(p.Tables)
	p.Tables = nil
	clear(p.GarblerInputs)
	p.GarblerInputs = nil
	p.OutputTranslations = [OutputBits / 8]byte{}
	// Tables aliases garbled scratch. Clear every public alias before returning
	// that scratch to sync.Pool so another goroutine cannot reuse it while this
	// release is still writing through the old slice.
	if garbled != nil {
		garbled.release()
	}
}

// GarblerSession holds single-use state for corrections and output-label
// verification.
type GarblerSession struct {
	SessionID uint64

	mu             sync.Mutex
	evaluatorWires []wire
	otPads         []SenderOT
	outputWires    []wire
	corrected      bool
	verified       bool
}

// EvaluatorSession holds single-use state between the correction and mask
// messages.
type EvaluatorSession struct {
	SessionID uint64

	mu        sync.Mutex
	payload   *OnlinePayload
	inputBits [InputBits]bool
	ots       []ReceiverOT
	evaluated bool
}

// Destroy clears an abandoned garbler session. It is idempotent and makes the
// session unusable. Completed sessions are safe to destroy again.
func (s *GarblerSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.evaluatorWires)
	clear(s.otPads)
	clear(s.outputWires)
	s.evaluatorWires = nil
	s.otPads = nil
	s.outputWires = nil
	s.corrected = true
	s.verified = true
}

// Destroy clears an abandoned evaluator session. It is idempotent and makes
// the session unusable. Completed sessions are safe to destroy again.
func (s *EvaluatorSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.payload != nil {
		s.payload.Release()
	}
	s.payload = nil
	clear(s.inputBits[:])
	clear(s.ots)
	s.ots = nil
	s.evaluated = true
}

// OnlineResult is returned by the evaluator. The garbler must verify
// OutputLabels and derive the trusted CMAC with VerifyOutput.
type OnlineResult struct {
	CMACOutput   [16]byte
	OutputLabels []Label
}

// PadZeros64 copies dataLen bytes and zero-pads the result to the circuit's
// fixed four AES blocks.
func PadZeros64(data []byte, dataLen int) ([64]byte, error) {
	if dataLen < 0 || dataLen > 64 {
		return [64]byte{}, fmt.Errorf("mpc: data length %d is outside [0,64]", dataLen)
	}
	if len(data) < dataLen {
		return [64]byte{}, fmt.Errorf("mpc: data slice length %d is shorter than %d", len(data), dataLen)
	}
	var out [64]byte
	copy(out[:dataLen], data[:dataLen])
	return out, nil
}

// GarblerOnline creates the garbled AES-CMAC payload. OT labels are already
// materialized, so this function performs no elliptic-curve operations.
func GarblerOnline(rng io.Reader, garblerInput [80]byte, ots []SenderOT, otStartIndex uint64) (*OnlinePayload, *GarblerSession, error) {
	if rng == nil {
		return nil, nil, errors.New("mpc: nil randomness source")
	}
	if len(ots) != InputBits {
		return nil, nil, fmt.Errorf("mpc: need %d sender OTs, got %d", InputBits, len(ots))
	}
	if err := validateSenderOTIndices(ots, otStartIndex); err != nil {
		return nil, nil, err
	}
	e, err := defaultEngine()
	if err != nil {
		return nil, nil, err
	}

	var header [8 + 16]byte
	if _, err := io.ReadFull(rng, header[:]); err != nil {
		return nil, nil, fmt.Errorf("mpc: read online randomness: %w", err)
	}
	sessionID := binary.BigEndian.Uint64(header[:8])
	var key [16]byte
	copy(key[:], header[8:])
	g, err := e.garble(rng, &key)
	if err != nil {
		return nil, nil, fmt.Errorf("mpc: garble circuit: %w", err)
	}

	var bits [InputBits]bool
	bytesToBits(garblerInput[:], bits[:])
	garblerInputs := make([]Label, InputBits)
	for i, bit := range bits {
		if bit {
			garblerInputs[i] = g.wires[i].l1
		} else {
			garblerInputs[i] = g.wires[i].l0
		}
	}

	evaluatorWires := append([]wire(nil), g.wires[InputBits:2*InputBits]...)
	outputStart := e.numWires - OutputBits
	outputWires := append([]wire(nil), g.wires[outputStart:]...)
	var translations [OutputBits / 8]byte
	for i, w := range outputWires {
		if w.l0.permutationBit() {
			translations[i/8] |= 1 << (i % 8)
		}
	}

	payload := &OnlinePayload{
		SessionID: sessionID, Key: key, Tables: g.tables,
		GarblerInputs: garblerInputs, OutputTranslations: translations,
		OTStartIndex: otStartIndex, garbled: g,
	}
	session := &GarblerSession{
		SessionID: sessionID, evaluatorWires: evaluatorWires,
		otPads: append([]SenderOT(nil), ots...), outputWires: outputWires,
	}
	return payload, session, nil
}

// EvaluatorPrepare binds the evaluator input to its single-use random OT
// choices and returns c=d XOR b for each input bit.
func EvaluatorPrepare(payload *OnlinePayload, evaluatorInput [80]byte, ots []ReceiverOT) (*EvaluatorSession, []bool, error) {
	if payload == nil {
		return nil, nil, errors.New("mpc: nil online payload")
	}
	if len(ots) != InputBits {
		return nil, nil, fmt.Errorf("mpc: need %d receiver OTs, got %d", InputBits, len(ots))
	}
	if len(payload.GarblerInputs) != InputBits {
		return nil, nil, fmt.Errorf("mpc: garbler input label count %d", len(payload.GarblerInputs))
	}
	if err := validateReceiverOTIndices(ots, payload.OTStartIndex); err != nil {
		return nil, nil, err
	}

	var bits [InputBits]bool
	bytesToBits(evaluatorInput[:], bits[:])
	corrections := make([]bool, InputBits)
	for i := range corrections {
		corrections[i] = ots[i].Choice != bits[i]
	}
	return &EvaluatorSession{
		SessionID: payload.SessionID, payload: payload, inputBits: bits,
		ots: append([]ReceiverOT(nil), ots...),
	}, corrections, nil
}

// ApplyCorrections returns the correction-aware masks for the evaluator input
// labels. A session accepts exactly one correction vector.
func ApplyCorrections(session *GarblerSession, corrections []bool) ([]OTMask, error) {
	if session == nil {
		return nil, errors.New("mpc: nil garbler session")
	}
	if len(corrections) != InputBits {
		return nil, fmt.Errorf("mpc: need %d corrections, got %d", InputBits, len(corrections))
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.corrected {
		return nil, errors.New("mpc: corrections already applied")
	}
	if len(session.evaluatorWires) != InputBits || len(session.otPads) != InputBits {
		return nil, errors.New("mpc: invalid garbler session state")
	}

	masks := make([]OTMask, InputBits)
	for i := range masks {
		pads := session.otPads[i]
		if corrections[i] {
			pads.R0, pads.R1 = pads.R1, pads.R0
		}
		w := session.evaluatorWires[i]
		masks[i] = OTMask{M0: w.l0.xor(pads.R0), M1: w.l1.xor(pads.R1)}
	}
	session.corrected = true
	clear(session.evaluatorWires)
	clear(session.otPads)
	session.evaluatorWires = nil
	session.otPads = nil
	return masks, nil
}

// EvaluatorOnline recovers exactly one label per evaluator input wire and
// evaluates the garbled circuit. A session can be evaluated once.
func EvaluatorOnline(session *EvaluatorSession, masks []OTMask) (*OnlineResult, error) {
	if session == nil {
		return nil, errors.New("mpc: nil evaluator session")
	}
	if len(masks) != InputBits {
		return nil, fmt.Errorf("mpc: need %d OT masks, got %d", InputBits, len(masks))
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.evaluated {
		return nil, errors.New("mpc: evaluator session already used")
	}
	session.evaluated = true
	defer func() {
		clear(session.inputBits[:])
		clear(session.ots)
		session.ots = nil
		session.payload = nil
	}()
	if session.payload == nil || len(session.ots) != InputBits {
		return nil, errors.New("mpc: invalid evaluator session state")
	}

	e, err := defaultEngine()
	if err != nil {
		return nil, err
	}
	p := session.payload
	wires := e.evalPool.Get().([]Label)
	defer func() {
		clear(wires)
		e.evalPool.Put(wires)
	}()
	copy(wires[:InputBits], p.GarblerInputs)
	for i := range InputBits {
		mask := masks[i].M0
		if session.inputBits[i] {
			mask = masks[i].M1
		}
		wires[InputBits+i] = session.ots[i].R.xor(mask)
	}
	if err := e.evaluate(&p.Key, wires, p.Tables); err != nil {
		return nil, fmt.Errorf("mpc: evaluate circuit: %w", err)
	}

	outputStart := e.numWires - OutputBits
	result := &OnlineResult{OutputLabels: append([]Label(nil), wires[outputStart:]...)}
	var outputBits [OutputBits]bool
	for i, label := range result.OutputLabels {
		translation := p.OutputTranslations[i/8]&(1<<(i%8)) != 0
		outputBits[i] = label.permutationBit() != translation
	}
	bitsToBytes(outputBits[:], result.CMACOutput[:])
	return result, nil
}

// VerifyOutput verifies every output label and derives the trusted CMAC. A
// session accepts exactly one output.
func VerifyOutput(session *GarblerSession, labels []Label) ([16]byte, error) {
	var zero [16]byte
	if session == nil {
		return zero, errors.New("mpc: nil garbler session")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.corrected {
		return zero, errors.New("mpc: corrections not applied")
	}
	if session.verified {
		return zero, errors.New("mpc: output already verified")
	}
	session.verified = true
	defer func() {
		clear(session.outputWires)
		session.outputWires = nil
	}()
	if len(labels) != OutputBits || len(session.outputWires) != OutputBits {
		return zero, fmt.Errorf("mpc: need %d output labels, got %d", OutputBits, len(labels))
	}

	var bits [OutputBits]bool
	for i, label := range labels {
		w := session.outputWires[i]
		switch {
		case label.equal(w.l0):
		case label.equal(w.l1):
			bits[i] = true
		default:
			return zero, fmt.Errorf("mpc: output label %d is invalid", i)
		}
	}
	var out [16]byte
	bitsToBytes(bits[:], out[:])
	return out, nil
}

func validateSenderOTIndices(ots []SenderOT, start uint64) error {
	if _, err := checkedIndexEnd(start, len(ots)); err != nil {
		return err
	}
	for i := range ots {
		if ots[i].Index != start+uint64(i) {
			return fmt.Errorf("mpc: sender OT index %d: got %d want %d", i, ots[i].Index, start+uint64(i))
		}
	}
	return nil
}

func validateReceiverOTIndices(ots []ReceiverOT, start uint64) error {
	if _, err := checkedIndexEnd(start, len(ots)); err != nil {
		return err
	}
	for i := range ots {
		if ots[i].Index != start+uint64(i) {
			return fmt.Errorf("mpc: receiver OT index %d: got %d want %d", i, ots[i].Index, start+uint64(i))
		}
	}
	return nil
}
