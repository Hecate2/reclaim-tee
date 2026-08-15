package mpc

import (
	"errors"
	"fmt"
	"io"
	"sync"

	markcircuit "github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
)

const (
	// InputBits is the number of bits contributed by each party.
	InputBits = 80 * 8
	// OutputBits is the size of the AES-CMAC result.
	OutputBits = 16 * 8
)

// This is the same circuit source as the legacy oprfmpc package. Compiling it
// once per process avoids hand-maintained AES gate lists. Only the compact
// execution plan below is used in the online path.
const aesCMACSource = `
package main

import (
	"crypto/aes"
)

func leftShift(L [16]byte) [16]byte {
	var result [16]byte
	var carry byte
	for i := 15; i >= 0; i-- {
		result[i] = (L[i] << 1) | carry
		carry = L[i] >> 7
	}
	var mask byte = 0 - (L[0] >> 7)
	result[15] ^= mask & 0x87
	return result
}

func main(gInput [80]byte, eInput [80]byte) []byte {
	var key [16]byte
	for i := 0; i < 16; i++ {
		key[i] = gInput[64+i] ^ eInput[64+i]
	}
	var data [64]byte
	for i := 0; i < 64; i++ {
		data[i] = gInput[i] ^ eInput[i]
	}
	var zero [16]byte
	L := aes.Block128(key, zero)
	K1 := leftShift(L)
	var M1, M2, M3, M4 [16]byte
	for i := 0; i < 16; i++ {
		M1[i] = data[i]
		M2[i] = data[16+i]
		M3[i] = data[32+i]
		M4[i] = data[48+i] ^ K1[i]
	}
	C := aes.Block128(key, M1)
	for i := 0; i < 16; i++ { C[i] ^= M2[i] }
	C = aes.Block128(key, C)
	for i := 0; i < 16; i++ { C[i] ^= M3[i] }
	C = aes.Block128(key, C)
	for i := 0; i < 16; i++ { C[i] ^= M4[i] }
	C = aes.Block128(key, C)
	return C[:]
}
`

type operation uint8

const (
	opXOR operation = iota
	opXNOR
	opAND
	opINV
)

type gate struct {
	in0   uint32
	in1   uint32
	out   uint32
	table uint32
	op    operation
}

type engine struct {
	gates      []gate
	numWires   int
	tableCount int
	pool       sync.Pool
	evalPool   sync.Pool
}

type garbleScratch struct {
	wires  []wire
	tables []Label
	random []byte
}

type garbled struct {
	wires   []wire
	tables  []Label
	scratch *garbleScratch
	owner   *engine
}

func (g *garbled) release() {
	if g == nil || g.owner == nil {
		return
	}
	clearGarbleScratch(g.scratch)
	g.owner.pool.Put(g.scratch)
	g.owner = nil
	g.scratch = nil
	g.wires = nil
	g.tables = nil
}

func clearGarbleScratch(scratch *garbleScratch) {
	if scratch == nil {
		return
	}
	clear(scratch.wires)
	clear(scratch.tables)
	clear(scratch.random)
}

var (
	engineOnce sync.Once
	cmacEngine *engine
	engineErr  error
)

func defaultEngine() (*engine, error) {
	engineOnce.Do(func() {
		params := utils.NewParams()
		params.OptPruneGates = true
		comp := compiler.New(params)
		compiled, _, err := comp.Compile(aesCMACSource, [][]int{{InputBits}, {InputBits}})
		if err != nil {
			engineErr = fmt.Errorf("compile AES-CMAC circuit: %w", err)
			return
		}
		cmacEngine, engineErr = newEngine(compiled)
	})
	return cmacEngine, engineErr
}

// Initialize compiles and validates the fixed circuit before the service
// accepts online work. Later calls are constant-time sync.Once lookups.
func Initialize() error {
	_, err := defaultEngine()
	return err
}

func newEngine(compiled *markcircuit.Circuit) (*engine, error) {
	if compiled == nil {
		return nil, errors.New("nil compiled circuit")
	}
	if compiled.NumParties() != 2 || compiled.Inputs.Size() != 2*InputBits || compiled.Outputs.Size() != OutputBits {
		return nil, fmt.Errorf("unexpected circuit shape: parties=%d inputs=%d outputs=%d",
			compiled.NumParties(), compiled.Inputs.Size(), compiled.Outputs.Size())
	}

	e := &engine{
		gates:    make([]gate, len(compiled.Gates)),
		numWires: compiled.NumWires,
	}
	for i, src := range compiled.Gates {
		dst := gate{in0: uint32(src.Input0), in1: uint32(src.Input1), out: uint32(src.Output)}
		switch src.Op {
		case markcircuit.XOR:
			dst.op = opXOR
		case markcircuit.XNOR:
			dst.op = opXNOR
		case markcircuit.AND:
			dst.op = opAND
			dst.table = uint32(e.tableCount)
			e.tableCount += 2
		case markcircuit.INV:
			dst.op = opINV
			dst.table = uint32(e.tableCount)
			e.tableCount++
		default:
			return nil, fmt.Errorf("unsupported circuit operation %s at gate %d", src.Op, i)
		}
		e.gates[i] = dst
	}

	e.pool.New = func() any {
		return &garbleScratch{
			wires:  make([]wire, e.numWires),
			tables: make([]Label, e.tableCount),
			random: make([]byte, 16+(2*InputBits)*16),
		}
	}
	e.evalPool.New = func() any {
		return make([]Label, e.numWires)
	}
	return e, nil
}

func (e *engine) garble(rng io.Reader, key *[16]byte) (*garbled, error) {
	if rng == nil {
		return nil, errors.New("nil randomness source")
	}
	block, err := newFixedAES(key)
	if err != nil {
		return nil, err
	}

	scratch := e.pool.Get().(*garbleScratch)
	if _, err := io.ReadFull(rng, scratch.random); err != nil {
		clearGarbleScratch(scratch)
		e.pool.Put(scratch)
		return nil, fmt.Errorf("read garbling randomness: %w", err)
	}
	random := scratch.random
	r := labelFromBytes(random[:16]).withPermutationBit(true)
	off := 16
	for i := 0; i < 2*InputBits; i++ {
		l0 := labelFromBytes(random[off : off+16])
		off += 16
		scratch.wires[i] = wire{l0: l0, l1: l0.xor(r)}
	}

	var hashBuf [64]byte
	var tweak uint32
	for i := range e.gates {
		g := e.gates[i]
		a := scratch.wires[g.in0]
		switch g.op {
		case opXOR, opXNOR:
			b := scratch.wires[g.in1]
			l0 := a.l0.xor(b.l0)
			l1 := l0.xor(r)
			if g.op == opXNOR {
				l0, l1 = l1, l0
			}
			scratch.wires[g.out] = wire{l0: l0, l1: l1}

		case opAND:
			b := scratch.wires[g.in1]
			pa, pb := a.l0.permutationBit(), b.l0.permutationBit()
			ha0, ha1, hb0, hb1 := halfHash4(block, a.l0, a.l1, b.l0, b.l1, tweak, tweak+1, &hashBuf)
			tweak += 2

			tg := ha0.xor(ha1)
			if pb {
				tg = tg.xor(r)
			}
			wg0 := ha0
			if pa {
				wg0 = wg0.xor(tg)
			}

			te := hb0.xor(hb1).xor(a.l0)
			we0 := hb0
			if pb {
				we0 = we0.xor(te).xor(a.l0)
			}

			l0 := wg0.xor(we0)
			scratch.wires[g.out] = wire{l0: l0, l1: l0.xor(r)}
			scratch.tables[g.table] = tg
			scratch.tables[g.table+1] = te

		case opINV:
			// Preserve the legacy row-reduced unary-gate construction. The
			// compiler emits one INV gate for this circuit.
			p0 := a.l0.permutationBit()
			h0 := unaryHash(block, a.l0, tweak, hashBuf[:16])
			h1 := unaryHash(block, a.l1, tweak, hashBuf[:16])
			tweak++

			var table [2]Label
			if p0 {
				table[1], table[0] = h0, h1
			} else {
				table[0], table[1] = h0, h1
			}
			l0, l1 := table[0], table[0]
			if p0 {
				l1 = l1.xor(r)
			} else {
				l0 = l0.xor(r)
			}
			if p0 {
				table[0] = table[0].xor(l0)
				table[1] = table[1].xor(l1)
			} else {
				table[0] = table[0].xor(l1)
				table[1] = table[1].xor(l0)
			}
			scratch.wires[g.out] = wire{l0: l0, l1: l1}
			scratch.tables[g.table] = table[1]
		}
	}

	return &garbled{
		wires: scratch.wires, tables: scratch.tables,
		scratch: scratch, owner: e,
	}, nil
}

func (e *engine) evaluate(key *[16]byte, wires []Label, tables []Label) error {
	if len(wires) != e.numWires {
		return fmt.Errorf("wire count mismatch: got %d want %d", len(wires), e.numWires)
	}
	if len(tables) != e.tableCount {
		return fmt.Errorf("garbled table count mismatch: got %d want %d", len(tables), e.tableCount)
	}
	block, err := newFixedAES(key)
	if err != nil {
		return err
	}

	var hashBuf [32]byte
	var tweak uint32
	for i := range e.gates {
		g := e.gates[i]
		a := wires[g.in0]
		switch g.op {
		case opXOR, opXNOR:
			wires[g.out] = a.xor(wires[g.in1])
		case opAND:
			b := wires[g.in1]
			wg, we := halfHash2(block, a, wires[g.in1], tweak, tweak+1, &hashBuf)
			tweak += 2
			if a.permutationBit() {
				wg = wg.xor(tables[g.table])
			}
			if b.permutationBit() {
				we = we.xor(tables[g.table+1]).xor(a)
			}
			wires[g.out] = wg.xor(we)
		case opINV:
			var row Label
			if a.permutationBit() {
				row = tables[g.table]
			}
			wires[g.out] = unaryHash(block, a, tweak, hashBuf[:16]).xor(row)
			tweak++
		}
	}
	return nil
}

func halfHashInput(x Label, tweak uint32) Label {
	carry := x.D0 >> 63
	return Label{
		D0: x.D0<<1 | x.D1>>63,
		D1: x.D1<<1 ^ (uint64(0x87) & (uint64(0) - carry)) ^ uint64(tweak),
	}
}

// halfHash4 computes four H(x,t) values through one four-way AES-NI call.
func halfHash4(block *fixedAES, x0, x1, x2, x3 Label, tweak01, tweak23 uint32, buf *[64]byte) (Label, Label, Label, Label) {
	k0 := halfHashInput(x0, tweak01)
	k1 := halfHashInput(x1, tweak01)
	k2 := halfHashInput(x2, tweak23)
	k3 := halfHashInput(x3, tweak23)
	k0.put(buf[0:16])
	k1.put(buf[16:32])
	k2.put(buf[32:48])
	k3.put(buf[48:64])
	block.encrypt4(buf)
	return labelFromBytes(buf[0:16]).xor(k0), labelFromBytes(buf[16:32]).xor(k1),
		labelFromBytes(buf[32:48]).xor(k2), labelFromBytes(buf[48:64]).xor(k3)
}

func halfHash2(block *fixedAES, x0, x1 Label, tweak0, tweak1 uint32, buf *[32]byte) (Label, Label) {
	k0 := halfHashInput(x0, tweak0)
	k1 := halfHashInput(x1, tweak1)
	k0.put(buf[0:16])
	k1.put(buf[16:32])
	block.encrypt2(buf)
	return labelFromBytes(buf[0:16]).xor(k0), labelFromBytes(buf[16:32]).xor(k1)
}

// unaryHash preserves the legacy row-reduced unary gate.
func unaryHash(block *fixedAES, a Label, tweak uint32, buf []byte) Label {
	k := halfHashInput(a, tweak)
	k.put(buf)
	block.fallback.Encrypt(buf, buf)
	return labelFromBytes(buf).xor(k)
}

func bytesToBits(data []byte, dst []bool) {
	for i, b := range data {
		for bit := 0; bit < 8; bit++ {
			dst[i*8+bit] = b&(1<<bit) != 0
		}
	}
}

func bitsToBytes(bits []bool, dst []byte) {
	clear(dst)
	for i, bit := range bits {
		if bit {
			dst[i/8] |= 1 << (i % 8)
		}
	}
}
