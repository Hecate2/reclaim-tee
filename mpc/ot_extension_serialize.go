package mpc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const extensionHeaderSize = 4 + 32 + 8 + 4 + 4 + 16 + 16

// MarshalExtensionRequest encodes the receiver's IKNP/KOS request.
func MarshalExtensionRequest(request *ExtensionRequest) ([]byte, error) {
	if request == nil {
		return nil, errors.New("mpc: nil OT extension request")
	}
	padded, err := extensionPaddedCount(int(request.Count))
	if err != nil {
		return nil, err
	}
	if int(request.PaddedCount) != padded {
		return nil, fmt.Errorf("mpc: padded OT count %d, want %d", request.PaddedCount, padded)
	}
	wantU := BaseOTCount * padded / 8
	if len(request.U) != wantU {
		return nil, fmt.Errorf("mpc: OT extension matrix length %d, want %d", len(request.U), wantU)
	}
	out := make([]byte, extensionHeaderSize+len(request.U))
	copy(out[:4], "KOS1")
	copy(out[4:36], request.SessionID[:])
	binary.BigEndian.PutUint64(out[36:44], request.StartIndex)
	binary.BigEndian.PutUint32(out[44:48], request.Count)
	binary.BigEndian.PutUint32(out[48:52], request.PaddedCount)
	request.ProofX.put(out[52:68])
	request.ProofT.put(out[68:84])
	copy(out[84:], request.U)
	return out, nil
}

// UnmarshalExtensionRequest decodes and bounds-checks an IKNP/KOS request.
func UnmarshalExtensionRequest(data []byte) (*ExtensionRequest, error) {
	if len(data) < extensionHeaderSize {
		return nil, errors.New("mpc: OT extension request is too short")
	}
	if string(data[:4]) != "KOS1" {
		return nil, errors.New("mpc: unsupported OT extension request version")
	}
	count := int(binary.BigEndian.Uint32(data[44:48]))
	padded, err := extensionPaddedCount(count)
	if err != nil {
		return nil, err
	}
	encodedPadded := int(binary.BigEndian.Uint32(data[48:52]))
	if encodedPadded != padded {
		return nil, fmt.Errorf("mpc: padded OT count %d, want %d", encodedPadded, padded)
	}
	wantLen := extensionHeaderSize + BaseOTCount*padded/8
	if len(data) != wantLen {
		return nil, fmt.Errorf("mpc: OT extension request length %d, want %d", len(data), wantLen)
	}
	request := &ExtensionRequest{
		StartIndex: uint64(binary.BigEndian.Uint64(data[36:44])),
		Count:      uint32(count), PaddedCount: uint32(padded),
		ProofX: labelFromBytes(data[52:68]),
		ProofT: labelFromBytes(data[68:84]),
		U:      append([]byte(nil), data[84:]...),
	}
	copy(request.SessionID[:], data[4:36])
	return request, nil
}
