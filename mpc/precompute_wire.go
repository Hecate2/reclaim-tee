package mpc

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

type PrecomputePhase uint8

const (
	PrecomputePhaseUnknown PrecomputePhase = iota
	PrecomputePhaseBegin
	PrecomputePhaseBaseChoices
)

type PrecomputeBegin struct {
	SessionID  [32]byte
	StartIndex uint64
	Count      uint32
}

// ExtensionEpoch returns the pool epoch after a verified extension batch.
// Both parties derive it from the public session identifier. A lost commit
// message therefore causes the next resume attempt to fail closed.
func ExtensionEpoch(sessionID [32]byte) string {
	return hex.EncodeToString(sessionID[:])
}

func PrecomputeRequestPhase(data []byte) PrecomputePhase {
	if len(data) < 4 {
		return PrecomputePhaseUnknown
	}
	switch string(data[:4]) {
	case "KOB1":
		return PrecomputePhaseBegin
	case "BOC1":
		return PrecomputePhaseBaseChoices
	default:
		return PrecomputePhaseUnknown
	}
}

func MarshalPrecomputeBegin(begin PrecomputeBegin) ([]byte, error) {
	if _, err := extensionPaddedCount(int(begin.Count)); err != nil {
		return nil, err
	}
	out := make([]byte, 4+32+8+4)
	copy(out[:4], "KOB1")
	copy(out[4:36], begin.SessionID[:])
	binary.BigEndian.PutUint64(out[36:44], begin.StartIndex)
	binary.BigEndian.PutUint32(out[44:48], begin.Count)
	return out, nil
}

func UnmarshalPrecomputeBegin(data []byte) (PrecomputeBegin, error) {
	var begin PrecomputeBegin
	if len(data) != 48 || string(data[:4]) != "KOB1" {
		return begin, errors.New("mpc: invalid OT precompute begin message")
	}
	copy(begin.SessionID[:], data[4:36])
	begin.StartIndex = binary.BigEndian.Uint64(data[36:44])
	begin.Count = binary.BigEndian.Uint32(data[44:48])
	if _, err := extensionPaddedCount(int(begin.Count)); err != nil {
		return PrecomputeBegin{}, err
	}
	return begin, nil
}

func MarshalPrecomputeFinal(cipherMessage []byte, request *ExtensionRequest) ([]byte, error) {
	if len(cipherMessage) != baseCipherMessageSize {
		return nil, fmt.Errorf("mpc: base OT ciphertext length %d, want %d", len(cipherMessage), baseCipherMessageSize)
	}
	extension, err := MarshalExtensionRequest(request)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+4+len(cipherMessage)+len(extension))
	copy(out[:4], "KOF1")
	binary.BigEndian.PutUint32(out[4:8], uint32(len(cipherMessage)))
	copy(out[8:8+len(cipherMessage)], cipherMessage)
	copy(out[8+len(cipherMessage):], extension)
	return out, nil
}

func UnmarshalPrecomputeFinal(data []byte) ([]byte, *ExtensionRequest, error) {
	if len(data) < 8 || string(data[:4]) != "KOF1" {
		return nil, nil, errors.New("mpc: invalid OT precompute final message")
	}
	cipherLen := int(binary.BigEndian.Uint32(data[4:8]))
	if cipherLen != baseCipherMessageSize || len(data) < 8+cipherLen {
		return nil, nil, errors.New("mpc: invalid base OT ciphertext framing")
	}
	request, err := UnmarshalExtensionRequest(data[8+cipherLen:])
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), data[8:8+cipherLen]...), request, nil
}
