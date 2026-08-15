package mpc

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"

	markot "github.com/markkurossi/mpc/ot"
)

const (
	compressedP256PointSize = 33
	baseSetupMessageSize    = 4 + 32 + compressedP256PointSize
	baseChoiceMessageSize   = 4 + 32 + BaseOTCount*compressedP256PointSize
	baseCipherMessageSize   = 4 + 32 + BaseOTCount*32
)

// BaseOTSenderState is the extension receiver's private state for one batch of
// Chou-Orlandi base OTs. It must be discarded after FinishBaseOTSender.
type BaseOTSenderState struct {
	session [32]byte
	setup   markot.COSenderSetup
	seeds   [BaseOTCount]BaseOTSeedPair
	used    bool
}

// BaseOTReceiverState is the extension sender's private state for one batch of
// Chou-Orlandi base OTs. It must be discarded after FinishBaseOTReceiver.
type BaseOTReceiverState struct {
	session [32]byte
	bundle  markot.COChoiceBundle
	delta   Label
	used    bool
}

// StartBaseOTSender creates 128 random seed pairs and the first base-OT
// message. The caller is the final OT-extension receiver.
func StartBaseOTSender(rng io.Reader, session [32]byte) (*BaseOTSenderState, []byte, error) {
	if rng == nil {
		return nil, nil, errors.New("mpc: nil randomness source")
	}
	curve := elliptic.P256()
	setup, err := markot.GenerateCOSenderSetup(rng, curve)
	if err != nil {
		return nil, nil, fmt.Errorf("mpc: generate base OT sender setup: %w", err)
	}
	state := &BaseOTSenderState{session: session, setup: setup}
	var seedBytes [32]byte
	for i := range state.seeds {
		if _, err := io.ReadFull(rng, seedBytes[:]); err != nil {
			return nil, nil, fmt.Errorf("mpc: read base OT seeds: %w", err)
		}
		pair := BaseOTSeedPair{Zero: labelFromBytes(seedBytes[:16]), One: labelFromBytes(seedBytes[16:])}
		if pair.Zero == pair.One {
			return nil, nil, fmt.Errorf("mpc: identical base OT seed pair at %d", i)
		}
		state.seeds[i] = pair
	}

	message := make([]byte, baseSetupMessageSize)
	copy(message[:4], "BOS1")
	copy(message[4:36], session[:])
	point := elliptic.MarshalCompressed(curve, setup.Ax, setup.Ay)
	copy(message[36:], point)
	return state, message, nil
}

// StartBaseOTReceiver consumes the sender setup, samples a nonzero extension
// correlation delta, and returns the 128 Chou-Orlandi choice points. The
// caller is the final OT-extension sender.
func StartBaseOTReceiver(rng io.Reader, session [32]byte, setupMessage []byte) (*BaseOTReceiverState, []byte, error) {
	if rng == nil {
		return nil, nil, errors.New("mpc: nil randomness source")
	}
	if len(setupMessage) != baseSetupMessageSize || string(setupMessage[:4]) != "BOS1" {
		return nil, nil, errors.New("mpc: invalid base OT setup message")
	}
	if string(setupMessage[4:36]) != string(session[:]) {
		return nil, nil, errors.New("mpc: base OT setup session mismatch")
	}
	curve := elliptic.P256()
	ax, ay := elliptic.UnmarshalCompressed(curve, setupMessage[36:])
	if ax == nil || ay == nil {
		return nil, nil, errors.New("mpc: invalid base OT sender point")
	}

	var deltaBytes [16]byte
	if _, err := io.ReadFull(rng, deltaBytes[:]); err != nil {
		return nil, nil, fmt.Errorf("mpc: read OT correlation delta: %w", err)
	}
	delta := labelFromBytes(deltaBytes[:])
	if delta == (Label{}) {
		return nil, nil, errors.New("mpc: zero OT correlation delta")
	}
	choices := make([]bool, BaseOTCount)
	for i := range choices {
		choices[i] = deltaBit(delta, i)
	}
	bundle, points, err := markot.BuildCOChoices(rng, curve, ax, ay, choices)
	if err != nil {
		return nil, nil, fmt.Errorf("mpc: build base OT choices: %w", err)
	}
	state := &BaseOTReceiverState{session: session, bundle: bundle, delta: delta}
	message := make([]byte, baseChoiceMessageSize)
	copy(message[:4], "BOC1")
	copy(message[4:36], session[:])
	off := 36
	for _, point := range points {
		encoded := elliptic.MarshalCompressed(curve, point.X, point.Y)
		copy(message[off:off+compressedP256PointSize], encoded)
		off += compressedP256PointSize
	}
	return state, message, nil
}

// FinishBaseOTSender consumes the 128 choice points and returns encrypted seed
// pairs plus the seed pairs needed by StartExtensionReceiver. It is single-use.
func FinishBaseOTSender(state *BaseOTSenderState, choiceMessage []byte) ([]byte, [BaseOTCount]BaseOTSeedPair, error) {
	var zero [BaseOTCount]BaseOTSeedPair
	if state == nil {
		return nil, zero, errors.New("mpc: nil base OT sender state")
	}
	if state.used {
		return nil, zero, errors.New("mpc: base OT sender state already used")
	}
	state.used = true
	defer clearBaseOTSenderState(state)
	if len(choiceMessage) != baseChoiceMessageSize || string(choiceMessage[:4]) != "BOC1" {
		return nil, zero, errors.New("mpc: invalid base OT choice message")
	}
	if string(choiceMessage[4:36]) != string(state.session[:]) {
		return nil, zero, errors.New("mpc: base OT choice session mismatch")
	}

	curve := elliptic.P256()
	points := make([]markot.ECPoint, BaseOTCount)
	off := 36
	for i := range points {
		x, y := elliptic.UnmarshalCompressed(curve, choiceMessage[off:off+compressedP256PointSize])
		if x == nil || y == nil {
			return nil, zero, fmt.Errorf("mpc: invalid base OT choice point %d", i)
		}
		points[i] = markot.ECPoint{X: x, Y: y}
		off += compressedP256PointSize
	}
	wires := make([]markot.Wire, BaseOTCount)
	for i, pair := range state.seeds {
		wires[i] = markot.Wire{L0: toMarkLabel(pair.Zero), L1: toMarkLabel(pair.One)}
	}
	ciphertexts, err := markot.EncryptCOCiphertexts(curve, state.setup, points, wires)
	if err != nil {
		return nil, zero, fmt.Errorf("mpc: encrypt base OT seeds: %w", err)
	}
	message := make([]byte, baseCipherMessageSize)
	copy(message[:4], "BOT1")
	copy(message[4:36], state.session[:])
	off = 36
	for _, ciphertext := range ciphertexts {
		copy(message[off:off+16], ciphertext.Zero[:])
		copy(message[off+16:off+32], ciphertext.One[:])
		off += 32
	}
	return message, state.seeds, nil
}

// FinishBaseOTReceiver decrypts the selected 128 seeds and returns them with
// the extension correlation delta. It is single-use.
func FinishBaseOTReceiver(state *BaseOTReceiverState, cipherMessage []byte) ([BaseOTCount]Label, Label, error) {
	var selected [BaseOTCount]Label
	if state == nil {
		return selected, Label{}, errors.New("mpc: nil base OT receiver state")
	}
	if state.used {
		return selected, Label{}, errors.New("mpc: base OT receiver state already used")
	}
	state.used = true
	defer clearBaseOTReceiverState(state)
	if len(cipherMessage) != baseCipherMessageSize || string(cipherMessage[:4]) != "BOT1" {
		return selected, Label{}, errors.New("mpc: invalid base OT ciphertext message")
	}
	if string(cipherMessage[4:36]) != string(state.session[:]) {
		return selected, Label{}, errors.New("mpc: base OT ciphertext session mismatch")
	}

	ciphertexts := make([]markot.LabelCiphertext, BaseOTCount)
	off := 36
	for i := range ciphertexts {
		copy(ciphertexts[i].Zero[:], cipherMessage[off:off+16])
		copy(ciphertexts[i].One[:], cipherMessage[off+16:off+32])
		off += 32
	}
	labels, err := markot.DecryptCOCiphertexts(elliptic.P256(), state.bundle, ciphertexts)
	if err != nil {
		return selected, Label{}, fmt.Errorf("mpc: decrypt base OT seeds: %w", err)
	}
	for i, label := range labels {
		selected[i] = fromMarkLabel(label)
	}
	return selected, state.delta, nil
}

func toMarkLabel(label Label) markot.Label {
	return markot.Label{D0: label.D0, D1: label.D1}
}

func fromMarkLabel(label markot.Label) Label {
	return Label{D0: label.D0, D1: label.D1}
}

func clearBaseOTSenderState(state *BaseOTSenderState) {
	if state == nil {
		return
	}
	clear(state.session[:])
	clear(state.seeds[:])
	if state.setup.Scalar != nil {
		state.setup.Scalar.SetInt64(0)
	}
	state.setup = markot.COSenderSetup{}
}

func clearBaseOTReceiverState(state *BaseOTReceiverState) {
	if state == nil {
		return
	}
	clear(state.session[:])
	state.delta = Label{}
	for _, scalar := range state.bundle.Scalars {
		if scalar != nil {
			scalar.SetInt64(0)
		}
	}
	clear(state.bundle.Bits)
	clear(state.bundle.Scalars)
	state.bundle = markot.COChoiceBundle{}
}
