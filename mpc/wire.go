package mpc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func MarshalChoiceCorrections(corrections []bool) ([]byte, error) {
	if len(corrections) != InputBits {
		return nil, fmt.Errorf("mpc: need %d choice corrections, got %d", InputBits, len(corrections))
	}
	out := make([]byte, InputBits/8)
	bitsToBytes(corrections, out)
	return out, nil
}

func UnmarshalChoiceCorrections(data []byte) ([]bool, error) {
	if len(data) != InputBits/8 {
		return nil, fmt.Errorf("mpc: choice correction length %d, want %d", len(data), InputBits/8)
	}
	out := make([]bool, InputBits)
	bytesToBits(data, out)
	return out, nil
}

func MarshalOTMasks(masks []OTMask) ([]byte, error) {
	if len(masks) != InputBits {
		return nil, fmt.Errorf("mpc: need %d OT masks, got %d", InputBits, len(masks))
	}
	out := make([]byte, 4+len(masks)*32)
	binary.BigEndian.PutUint32(out[:4], uint32(len(masks)))
	off := 4
	for _, mask := range masks {
		mask.M0.put(out[off : off+16])
		mask.M1.put(out[off+16 : off+32])
		off += 32
	}
	return out, nil
}

func UnmarshalOTMasks(data []byte) ([]OTMask, error) {
	if len(data) < 4 {
		return nil, errors.New("mpc: OT mask encoding is too short")
	}
	count := int(binary.BigEndian.Uint32(data[:4]))
	if count != InputBits || len(data) != 4+count*32 {
		return nil, fmt.Errorf("mpc: invalid OT mask encoding length %d for count %d", len(data), count)
	}
	out := make([]OTMask, count)
	off := 4
	for i := range out {
		out[i] = OTMask{M0: labelFromBytes(data[off : off+16]), M1: labelFromBytes(data[off+16 : off+32])}
		off += 32
	}
	return out, nil
}

func MarshalOutputLabels(labels []Label) ([]byte, error) {
	if len(labels) != OutputBits {
		return nil, fmt.Errorf("mpc: need %d output labels, got %d", OutputBits, len(labels))
	}
	out := make([]byte, 4+len(labels)*16)
	binary.BigEndian.PutUint32(out[:4], uint32(len(labels)))
	off := 4
	for _, label := range labels {
		label.put(out[off : off+16])
		off += 16
	}
	return out, nil
}

func UnmarshalOutputLabels(data []byte) ([]Label, error) {
	if len(data) < 4 {
		return nil, errors.New("mpc: output label encoding is too short")
	}
	count := int(binary.BigEndian.Uint32(data[:4]))
	if count != OutputBits || len(data) != 4+count*16 {
		return nil, fmt.Errorf("mpc: invalid output label encoding length %d for count %d", len(data), count)
	}
	out := make([]Label, count)
	off := 4
	for i := range out {
		out[i] = labelFromBytes(data[off : off+16])
		off += 16
	}
	return out, nil
}
