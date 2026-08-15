package mpc

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	extensionEpochPrefix = "kos2:"
	maxEpochLength       = 256
)

type PrecomputePhase uint8

const (
	PrecomputePhaseUnknown PrecomputePhase = iota
	PrecomputePhaseBegin
	PrecomputePhaseBaseChoices
	PrecomputePhaseChallenge
)

type PrecomputeBegin struct {
	SessionID  [32]byte
	StartIndex uint64
	Count      uint32
	Epoch      string
}

// InitialExtensionEpoch marks a fresh pool as belonging to the corrected KOS2
// protocol. The caller supplies its existing cryptographically random nonce.
func InitialExtensionEpoch(nonce string) (string, error) {
	if nonce == "" {
		return "", errors.New("mpc: empty OT extension epoch nonce")
	}
	epoch := extensionEpochPrefix + nonce
	if err := validateExtensionEpoch(epoch); err != nil {
		return "", err
	}
	return epoch, nil
}

// ExtensionEpoch returns the pool epoch after a verified KOS2 extension batch.
// Both parties derive it from the public session identifier. The version prefix
// prevents a corrected peer from resuming a KOS1 pool.
func ExtensionEpoch(sessionID [32]byte) string {
	return extensionEpochPrefix + hex.EncodeToString(sessionID[:])
}

func validateExtensionEpoch(epoch string) error {
	if len(epoch) <= len(extensionEpochPrefix) || len(epoch) > maxEpochLength || !utf8.ValidString(epoch) {
		return errors.New("mpc: invalid OT extension epoch")
	}
	if epoch[:len(extensionEpochPrefix)] != extensionEpochPrefix {
		return errors.New("mpc: unsupported OT extension epoch version")
	}
	return nil
}

// IsCurrentExtensionEpoch reports whether an epoch belongs to KOS2. Resume
// callers use it to reject retained KOS1 pools without a downgrade attempt.
func IsCurrentExtensionEpoch(epoch string) bool {
	return validateExtensionEpoch(epoch) == nil
}

func PrecomputeRequestPhase(data []byte) PrecomputePhase {
	if len(data) < 4 {
		return PrecomputePhaseUnknown
	}
	switch string(data[:4]) {
	case "KOB2":
		return PrecomputePhaseBegin
	case "KBC2":
		return PrecomputePhaseBaseChoices
	case "KCH2":
		return PrecomputePhaseChallenge
	default:
		return PrecomputePhaseUnknown
	}
}

func MarshalPrecomputeBegin(begin PrecomputeBegin) ([]byte, error) {
	if _, err := extensionPaddedCount(int(begin.Count)); err != nil {
		return nil, err
	}
	if _, err := checkedIndexEnd(begin.StartIndex, int(begin.Count)); err != nil {
		return nil, err
	}
	if err := validateExtensionEpoch(begin.Epoch); err != nil {
		return nil, err
	}
	out := make([]byte, 4+32+8+4+2+len(begin.Epoch))
	copy(out[:4], "KOB2")
	copy(out[4:36], begin.SessionID[:])
	binary.BigEndian.PutUint64(out[36:44], begin.StartIndex)
	binary.BigEndian.PutUint32(out[44:48], begin.Count)
	binary.BigEndian.PutUint16(out[48:50], uint16(len(begin.Epoch)))
	copy(out[50:], begin.Epoch)
	return out, nil
}

func UnmarshalPrecomputeBegin(data []byte) (PrecomputeBegin, error) {
	var begin PrecomputeBegin
	if len(data) < 50 || string(data[:4]) != "KOB2" {
		return begin, errors.New("mpc: invalid OT precompute begin message")
	}
	epochLen := int(binary.BigEndian.Uint16(data[48:50]))
	if epochLen == 0 || len(data) != 50+epochLen {
		return begin, errors.New("mpc: invalid OT precompute begin epoch framing")
	}
	copy(begin.SessionID[:], data[4:36])
	begin.StartIndex = binary.BigEndian.Uint64(data[36:44])
	begin.Count = binary.BigEndian.Uint32(data[44:48])
	begin.Epoch = string(data[50:])
	if err := validateExtensionEpoch(begin.Epoch); err != nil {
		return PrecomputeBegin{}, err
	}
	if _, err := extensionPaddedCount(int(begin.Count)); err != nil {
		return PrecomputeBegin{}, err
	}
	if _, err := checkedIndexEnd(begin.StartIndex, int(begin.Count)); err != nil {
		return PrecomputeBegin{}, err
	}
	return begin, nil
}

func MarshalPrecomputeBaseSetup(session [32]byte, setup []byte) ([]byte, error) {
	if len(setup) != baseSetupMessageSize || string(setup[:4]) != "BOS1" || string(setup[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: invalid base OT setup for KOS2 frame")
	}
	out := make([]byte, 4+32+len(setup))
	copy(out[:4], "KBS2")
	copy(out[4:36], session[:])
	copy(out[36:], setup)
	return out, nil
}

func UnmarshalPrecomputeBaseSetup(data []byte, session [32]byte) ([]byte, error) {
	if len(data) != 4+32+baseSetupMessageSize || string(data[:4]) != "KBS2" || string(data[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: invalid KOS2 base OT setup frame")
	}
	setup := data[36:]
	if string(setup[:4]) != "BOS1" || string(setup[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: invalid nested base OT setup")
	}
	return append([]byte(nil), setup...), nil
}

func MarshalPrecomputeBaseChoices(session [32]byte, choices []byte) ([]byte, error) {
	if len(choices) != baseChoiceMessageSize || string(choices[:4]) != "BOC1" || string(choices[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: invalid base OT choices for KOS2 frame")
	}
	out := make([]byte, 4+32+len(choices))
	copy(out[:4], "KBC2")
	copy(out[4:36], session[:])
	copy(out[36:], choices)
	return out, nil
}

func UnmarshalPrecomputeBaseChoices(data []byte, session [32]byte) ([]byte, error) {
	if len(data) != 4+32+baseChoiceMessageSize || string(data[:4]) != "KBC2" || string(data[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: invalid KOS2 base OT choice frame")
	}
	choices := data[36:]
	if string(choices[:4]) != "BOC1" || string(choices[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: invalid nested base OT choices")
	}
	return append([]byte(nil), choices...), nil
}

func MarshalPrecomputeCommitment(cipherMessage []byte, commitment *ExtensionCommitment) ([]byte, error) {
	if commitment == nil {
		return nil, errors.New("mpc: nil OT extension commitment")
	}
	if err := validateBaseCipherForTranscript(cipherMessage, commitment.SessionID); err != nil {
		return nil, err
	}
	extension, err := MarshalExtensionCommitment(commitment)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+4+len(cipherMessage)+len(extension))
	copy(out[:4], "KOF2")
	binary.BigEndian.PutUint32(out[4:8], uint32(len(cipherMessage)))
	copy(out[8:8+len(cipherMessage)], cipherMessage)
	copy(out[8+len(cipherMessage):], extension)
	return out, nil
}

func UnmarshalPrecomputeCommitment(data []byte) ([]byte, *ExtensionCommitment, error) {
	if len(data) < 8 || string(data[:4]) != "KOF2" {
		return nil, nil, errors.New("mpc: invalid OT precompute commitment message")
	}
	cipherLen := int(binary.BigEndian.Uint32(data[4:8]))
	if cipherLen != baseCipherMessageSize || len(data) < 8+cipherLen {
		return nil, nil, errors.New("mpc: invalid base OT ciphertext framing")
	}
	commitment, err := UnmarshalExtensionCommitment(data[8+cipherLen:])
	if err != nil {
		return nil, nil, err
	}
	cipher := append([]byte(nil), data[8:8+cipherLen]...)
	if err := validateBaseCipherForTranscript(cipher, commitment.SessionID); err != nil {
		return nil, nil, err
	}
	return cipher, commitment, nil
}

// UnmarshalPrecomputeCommitmentFor validates the production batch metadata and
// exact encoded size before the generic decoder copies the fixed ciphertexts or
// IKNP matrix. Production handlers use this entry point for untrusted frames.
func UnmarshalPrecomputeCommitmentFor(data []byte, expected PrecomputeBegin) ([]byte, *ExtensionCommitment, error) {
	if err := ValidatePrecomputeCount(int(expected.Count)); err != nil {
		return nil, nil, err
	}
	if _, err := checkedIndexEnd(expected.StartIndex, int(expected.Count)); err != nil {
		return nil, nil, err
	}
	wantLen, err := PrecomputeCommitmentWireSize(int(expected.Count))
	if err != nil {
		return nil, nil, err
	}
	if len(data) != wantLen {
		return nil, nil, fmt.Errorf("mpc: OT precompute commitment length %d, want %d", len(data), wantLen)
	}
	const commitmentOffset = 8 + baseCipherMessageSize
	if string(data[:4]) != "KOF2" || int(binary.BigEndian.Uint32(data[4:8])) != baseCipherMessageSize || string(data[commitmentOffset:commitmentOffset+4]) != "KOC2" {
		return nil, nil, errors.New("mpc: invalid OT precompute commitment framing")
	}
	if string(data[commitmentOffset+4:commitmentOffset+36]) != string(expected.SessionID[:]) ||
		binary.BigEndian.Uint64(data[commitmentOffset+36:commitmentOffset+44]) != expected.StartIndex ||
		binary.BigEndian.Uint32(data[commitmentOffset+44:commitmentOffset+48]) != expected.Count {
		return nil, nil, errors.New("mpc: OT extension commitment metadata mismatch")
	}
	cipher, commitment, err := UnmarshalPrecomputeCommitment(data)
	if err != nil {
		return nil, nil, err
	}
	if commitment.SessionID != expected.SessionID || commitment.StartIndex != expected.StartIndex || commitment.Count != expected.Count {
		return nil, nil, errors.New("mpc: OT extension commitment metadata mismatch")
	}
	return cipher, commitment, nil
}

// UnmarshalExtensionChallengeFor validates the exact coefficient count, frame
// length, and session for the pending production batch before allocating Chi.
func UnmarshalExtensionChallengeFor(data []byte, session [32]byte, otCount int) (*ExtensionChallenge, error) {
	if err := ValidatePrecomputeCount(otCount); err != nil {
		return nil, err
	}
	wantLen, err := PrecomputeChallengeWireSize(otCount)
	if err != nil {
		return nil, err
	}
	if len(data) != wantLen {
		return nil, fmt.Errorf("mpc: OT extension challenge length %d, want %d", len(data), wantLen)
	}
	if string(data[:4]) != "KCH2" || string(data[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: OT extension challenge metadata mismatch")
	}
	padded, err := extensionPaddedCount(otCount)
	if err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(data[100:104]) != uint32(extensionChallengeCount(padded)) {
		return nil, errors.New("mpc: OT extension challenge coefficient count mismatch")
	}
	challenge, err := UnmarshalExtensionChallenge(data)
	if err != nil {
		return nil, err
	}
	if challenge.SessionID != session {
		return nil, errors.New("mpc: OT extension challenge metadata mismatch")
	}
	return challenge, nil
}

// UnmarshalExtensionProofFor validates the fixed frame and pending session
// before constructing the proof object used by the production sender handler.
func UnmarshalExtensionProofFor(data []byte, session [32]byte) (*ExtensionProof, error) {
	if len(data) != extensionProofSize || string(data[:4]) != "KPR2" || string(data[4:36]) != string(session[:]) {
		return nil, errors.New("mpc: invalid OT extension proof metadata")
	}
	return UnmarshalExtensionProof(data)
}

func PrecomputeCommitmentWireSize(count int) (int, error) {
	padded, err := extensionPaddedCount(count)
	if err != nil {
		return 0, err
	}
	return 8 + baseCipherMessageSize + extensionCommitmentHeaderSize + BaseOTCount*padded/8, nil
}

func PrecomputeChallengeWireSize(count int) (int, error) {
	padded, err := extensionPaddedCount(count)
	if err != nil {
		return 0, err
	}
	return extensionChallengeHeaderSize + extensionChallengeCount(padded)*16, nil
}

func PrecomputeProofWireSize() int {
	return extensionProofSize
}
