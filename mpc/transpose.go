package mpc

import (
	"encoding/binary"
	"math/bits"
)

// transposeColumns converts a 128-by-N column-major bit matrix to N labels.
// N must be a multiple of 128 and byteRows must equal N/8.
func transposeColumns(matrix []byte, byteRows int, dst []Label) {
	var block [BaseOTCount]Label
	for row := 0; row < len(dst); row += BaseOTCount {
		byteOffset := row / 8
		for col := range BaseOTCount {
			src := matrix[col*byteRows+byteOffset:]
			block[col] = Label{
				D0: binary.LittleEndian.Uint64(src[:8]),
				D1: binary.LittleEndian.Uint64(src[8:16]),
			}
		}
		transpose128(&block)
		copy(dst[row:row+BaseOTCount], block[:])
	}
}

// transpose128 decomposes the matrix into four 64-by-64 quadrants. Each
// quadrant uses the six-pass in-place delta-swap transpose from Hacker's
// Delight.
func transpose128(data *[BaseOTCount]Label) {
	var a, b, c, d [64]uint64
	for i := range 64 {
		a[i], b[i] = data[i].D0, data[i].D1
		c[i], d[i] = data[64+i].D0, data[64+i].D1
	}
	transpose64(&a)
	transpose64(&b)
	transpose64(&c)
	transpose64(&d)
	for i := range 64 {
		j := 63 - i
		data[i] = Label{D0: bits.Reverse64(a[j]), D1: bits.Reverse64(c[j])}
		data[64+i] = Label{D0: bits.Reverse64(b[j]), D1: bits.Reverse64(d[j])}
	}
}

func transpose64(data *[64]uint64) {
	mask := uint64(0x00000000ffffffff)
	for width := 32; width != 0; {
		for k := 0; k < 64; k = (k + width + 1) &^ width {
			t := (data[k] ^ data[k+width]>>uint(width)) & mask
			data[k] ^= t
			data[k+width] ^= t << uint(width)
		}
		width >>= 1
		if width != 0 {
			mask ^= mask << uint(width)
		}
	}
}
