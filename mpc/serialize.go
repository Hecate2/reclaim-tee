package mpc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	payloadMagic      = "MPC1"
	payloadHeaderSize = 4 + 8 + 16 + 8 + 4
)

// MarshalOnlinePayload encodes the fixed circuit without legacy per-gate
// length words. The table count is validated by the receiver.
func MarshalOnlinePayload(p *OnlinePayload) ([]byte, error) {
	if p == nil {
		return nil, errors.New("mpc: nil online payload")
	}
	e, err := defaultEngine()
	if err != nil {
		return nil, err
	}
	if len(p.Tables) != e.tableCount {
		return nil, fmt.Errorf("mpc: table count %d, want %d", len(p.Tables), e.tableCount)
	}
	if len(p.GarblerInputs) != InputBits {
		return nil, fmt.Errorf("mpc: garbler input count %d, want %d", len(p.GarblerInputs), InputBits)
	}

	size := payloadHeaderSize + len(p.Tables)*16 + InputBits*16 + len(p.OutputTranslations)
	out := make([]byte, size)
	copy(out[:4], payloadMagic)
	binary.BigEndian.PutUint64(out[4:12], p.SessionID)
	copy(out[12:28], p.Key[:])
	binary.BigEndian.PutUint64(out[28:36], p.OTStartIndex)
	binary.BigEndian.PutUint32(out[36:40], uint32(len(p.Tables)))
	off := payloadHeaderSize
	for _, label := range p.Tables {
		label.put(out[off : off+16])
		off += 16
	}
	for _, label := range p.GarblerInputs {
		label.put(out[off : off+16])
		off += 16
	}
	copy(out[off:], p.OutputTranslations[:])
	return out, nil
}

// UnmarshalOnlinePayload decodes and validates an online payload.
func UnmarshalOnlinePayload(data []byte) (*OnlinePayload, error) {
	e, err := defaultEngine()
	if err != nil {
		return nil, err
	}
	if len(data) < payloadHeaderSize {
		return nil, errors.New("mpc: online payload is too short")
	}
	if string(data[:4]) != payloadMagic {
		return nil, errors.New("mpc: unsupported online payload version")
	}
	tableCount := int(binary.BigEndian.Uint32(data[36:40]))
	if tableCount != e.tableCount {
		return nil, fmt.Errorf("mpc: table count %d, want %d", tableCount, e.tableCount)
	}
	expected := payloadHeaderSize + tableCount*16 + InputBits*16 + OutputBits/8
	if len(data) != expected {
		return nil, fmt.Errorf("mpc: online payload length %d, want %d", len(data), expected)
	}

	p := &OnlinePayload{
		SessionID:     binary.BigEndian.Uint64(data[4:12]),
		OTStartIndex:  binary.BigEndian.Uint64(data[28:36]),
		Tables:        make([]Label, tableCount),
		GarblerInputs: make([]Label, InputBits),
	}
	copy(p.Key[:], data[12:28])
	off := payloadHeaderSize
	for i := range p.Tables {
		p.Tables[i] = labelFromBytes(data[off : off+16])
		off += 16
	}
	for i := range p.GarblerInputs {
		p.GarblerInputs[i] = labelFromBytes(data[off : off+16])
		off += 16
	}
	copy(p.OutputTranslations[:], data[off:])
	return p, nil
}

// OnlinePayloadSize returns the exact byte size of this package's fixed
// AES-CMAC online payload.
func OnlinePayloadSize() (int, error) {
	e, err := defaultEngine()
	if err != nil {
		return 0, err
	}
	return payloadHeaderSize + e.tableCount*16 + InputBits*16 + OutputBits/8, nil
}
