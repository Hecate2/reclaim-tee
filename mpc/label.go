// Package mpc implements the two-party AES-CMAC OPRF used by the paired TEEs.
package mpc

import "encoding/binary"

// Label is a 128-bit garbled-circuit wire label.
//
// D0 contains the permutation bit in its most-significant bit. The layout is
// intentionally explicit so labels have a stable 16-byte wire encoding.
type Label struct {
	D0 uint64
	D1 uint64
}

type wire struct {
	l0 Label
	l1 Label
}

func (l Label) xor(r Label) Label {
	return Label{D0: l.D0 ^ r.D0, D1: l.D1 ^ r.D1}
}

func (l Label) equal(r Label) bool {
	return l.D0 == r.D0 && l.D1 == r.D1
}

func (l Label) permutationBit() bool {
	return l.D0>>63 != 0
}

func (l Label) withPermutationBit(set bool) Label {
	if set {
		l.D0 |= uint64(1) << 63
	} else {
		l.D0 &^= uint64(1) << 63
	}
	return l
}

func (l Label) put(dst []byte) {
	binary.BigEndian.PutUint64(dst[:8], l.D0)
	binary.BigEndian.PutUint64(dst[8:16], l.D1)
}

func labelFromBytes(src []byte) Label {
	return Label{
		D0: binary.BigEndian.Uint64(src[:8]),
		D1: binary.BigEndian.Uint64(src[8:16]),
	}
}
