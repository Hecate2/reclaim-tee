package mpc

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func TestCircuitShape(t *testing.T) {
	e, err := defaultEngine()
	if err != nil {
		t.Fatal(err)
	}

	var xor, xnor, and, inv int
	depth := make([]int, e.numWires)
	maxDepth := 0
	for _, g := range e.gates {
		d := depth[g.in0]
		if depth[g.in1] > d {
			d = depth[g.in1]
		}
		switch g.op {
		case opXOR:
			xor++
		case opXNOR:
			xnor++
		case opAND:
			and++
			if g.in0 == g.in1 {
				t.Fatalf("AND gate has duplicate input wire %d", g.in0)
			}
			d++
		case opINV:
			inv++
		}
		depth[g.out] = d
		if d > maxDepth {
			maxDepth = d
		}
	}

	if got, want := len(e.gates), 184_496; got != want {
		t.Fatalf("gate count %d, want %d", got, want)
	}
	if xor != 152_477 || xnor != 11 || and != 32_007 || inv != 1 {
		t.Fatalf("gate shape XOR=%d XNOR=%d AND=%d INV=%d", xor, xnor, and, inv)
	}
	if maxDepth != 240 {
		t.Fatalf("nonlinear depth %d, want 240", maxDepth)
	}
	if size, err := OnlinePayloadSize(); err != nil {
		t.Fatal(err)
	} else if size != 1_034_536 {
		t.Fatalf("online payload size %d, want 1034536", size)
	}
}

func TestFixedAESMatchesCryptoAES(t *testing.T) {
	for test := 0; test < 1_000; test++ {
		var key [16]byte
		var blocks4 [64]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(blocks4[:]); err != nil {
			t.Fatal(err)
		}
		want := blocks4
		standard, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off < len(want); off += aes.BlockSize {
			standard.Encrypt(want[off:off+aes.BlockSize], want[off:off+aes.BlockSize])
		}
		fixed, err := newFixedAES(&key)
		if err != nil {
			t.Fatal(err)
		}
		got4 := blocks4
		fixed.encrypt4(&got4)
		if !bytes.Equal(got4[:], want[:]) {
			t.Fatalf("four-block AES mismatch in case %d", test)
		}
		got2 := *(*[32]byte)(blocks4[:32])
		fixed.encrypt2(&got2)
		if !bytes.Equal(got2[:], want[:32]) {
			t.Fatalf("two-block AES mismatch in case %d", test)
		}

		// Exercise the portable path even when this test runs on an AES-NI host.
		fixed.accelerated = false
		fallback4 := blocks4
		fixed.encrypt4(&fallback4)
		if !bytes.Equal(fallback4[:], want[:]) {
			t.Fatalf("portable four-block AES mismatch in case %d", test)
		}
	}
}

func TestHalfHashInputUsesFieldDoubling(t *testing.T) {
	withoutTopBit := Label{D0: 0x0123456789abcdef, D1: 0xfedcba9876543210}
	withTopBit := withoutTopBit
	withTopBit.D0 |= uint64(1) << 63
	if halfHashInput(withoutTopBit, 7) == halfHashInput(withTopBit, 7) {
		t.Fatal("half-gate hash input discarded the top label bit")
	}

	got := halfHashInput(Label{D0: uint64(1) << 63}, 0)
	if got != (Label{D1: 0x87}) {
		t.Fatalf("field doubling reduction = %v, want {0 0x87}", got)
	}
}

func BenchmarkFixedAESFourBlocks(b *testing.B) {
	var key [16]byte
	var blocks [64]byte
	if _, err := rand.Read(key[:]); err != nil {
		b.Fatal(err)
	}
	fixed, err := newFixedAES(&key)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(64)
	for b.Loop() {
		fixed.encrypt4(&blocks)
	}
}

func BenchmarkCryptoAESFourBlocks(b *testing.B) {
	var key [16]byte
	var blocks [64]byte
	if _, err := rand.Read(key[:]); err != nil {
		b.Fatal(err)
	}
	standard, err := aes.NewCipher(key[:])
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(64)
	for b.Loop() {
		for off := 0; off < len(blocks); off += aes.BlockSize {
			standard.Encrypt(blocks[off:off+aes.BlockSize], blocks[off:off+aes.BlockSize])
		}
	}
}
