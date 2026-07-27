// Package oprfmpc implements AES-CMAC based OPRF using Garbled Circuits
package oprfmpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"filippo.io/nistec"
	"github.com/markkurossi/mpc/ot"
)

// compressedPointLen is the SEC1 compressed P-256 point size: 1 parity byte
// (0x02 even / 0x03 odd Y) + 32-byte big-endian X. Half the raw X||Y size;
// Y is recovered on decode from the curve equation.
const compressedPointLen = 33

// Both halves pin elliptic.P256(), so any other wire value means the peer
// disagrees about the group and its points must not be decoded.
const otCurveName = "P-256"

func checkOTCurveName(name string) error {
	if name != otCurveName {
		return fmt.Errorf("unexpected OT curve %q, want %q", name, otCurveName)
	}
	return nil
}

// compressPoint encodes (x, y) as a 33-byte SEC1 compressed P-256 point.
func compressPoint(x, y *big.Int) []byte {
	out := make([]byte, compressedPointLen)
	out[0] = 0x02 | byte(y.Bit(0))
	x.FillBytes(out[1:])
	return out
}

// decompressPoint recovers (x, y) from a 33-byte compressed P-256 point.
// nistec.SetBytes does the modular sqrt and rejects off-curve encodings.
func decompressPoint(b []byte) (x, y *big.Int, err error) {
	p, err := nistec.NewP256Point().SetBytes(b)
	if err != nil {
		return nil, nil, fmt.Errorf("decompress P-256 point: %w", err)
	}
	u := p.Bytes() // 0x04 || X(32) || Y(32)
	return new(big.Int).SetBytes(u[1:33]), new(big.Int).SetBytes(u[33:65]), nil
}

// OT Pool configuration constants
const (
	// OTPoolInitialSize is the initial number of OTs to precompute
	// 100,000 OTs = ~156 OPRFs = ~52 sessions (at 3 OPRFs/session average)
	OTPoolInitialSize = 100000

	// OTPoolExtendSize is the number of OTs to add when extending
	// Extends by 50,000 to restore pool to full capacity
	OTPoolExtendSize = 50000

	// OTPoolWatermark is the threshold below which extension is triggered
	// 50,000 remaining = ~78 OPRFs = ~26 sessions buffer while extend completes
	OTPoolWatermark = 50000

	// OTsPerOPRF is the number of OTs consumed per OPRF operation
	// 80 bytes input = 640 bits = 640 OTs
	OTsPerOPRF = 640
)

// OTPoolEntry holds a single precomputed OT for the garbler (TEE_K)
type OTPoolEntry struct {
	SenderSetup   ot.COSenderSetup // Garbler's random setup (contains scalar, A point)
	ReceiverPoint ot.ECPoint       // Receiver's choice point B (needed for ECDH derivation)
	Index         int              // Position in pool
	Used          bool             // Whether consumed
}

// OTPool manages precomputed OT entries for the garbler (TEE_K)
type OTPool struct {
	mu            sync.Mutex
	entries       []*OTPoolEntry
	nextIndex     int  // Next unused entry
	totalCount    int  // Total entries allocated
	usedCount     int  // Consumed entries
	extendPending bool // Whether extend is in progress
}

// NewOTPool creates a new OT pool with the given capacity
func NewOTPool(capacity int) *OTPool {
	return &OTPool{
		entries:    make([]*OTPoolEntry, 0, capacity),
		nextIndex:  0,
		totalCount: 0,
		usedCount:  0,
	}
}

// Reserve reserves count OT entries from the pool
// Returns the start index and the reserved entries
func (p *OTPool) Reserve(count int) (startIndex int, entries []*OTPoolEntry, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextIndex+count > p.totalCount {
		return 0, nil, fmt.Errorf("insufficient OT entries: need %d, have %d available",
			count, p.totalCount-p.nextIndex)
	}

	startIndex = p.nextIndex
	entries = make([]*OTPoolEntry, count)

	for i := range count {
		entry := p.entries[p.nextIndex+i]
		if entry.Used {
			return 0, nil, fmt.Errorf("OT entry %d already used (corruption detected)", p.nextIndex+i)
		}
		entry.Used = true
		entries[i] = entry
	}

	p.nextIndex += count
	p.usedCount += count

	return startIndex, entries, nil
}

// NeedsExtend returns true if the pool needs extension
func (p *OTPool) NeedsExtend() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	available := p.totalCount - p.usedCount
	return available <= OTPoolWatermark && !p.extendPending
}

// SetExtendPending marks that an extend operation is in progress
func (p *OTPool) SetExtendPending(pending bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.extendPending = pending
}

// IsExtendPending returns whether an extend operation is in progress
func (p *OTPool) IsExtendPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.extendPending
}

// Available returns the number of available (unused) OT entries
func (p *OTPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalCount - p.usedCount
}

// TotalCount returns the total number of entries in the pool
func (p *OTPool) TotalCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalCount
}

// NextIndex returns the next unreserved entry index. Sent to TEE_T on resume
// so it can confirm its retained pool still covers what TEE_K will reserve.
func (p *OTPool) NextIndex() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nextIndex
}

// Clear resets the pool, clearing all entries
// Called on disconnect to prevent replay attacks
func (p *OTPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries = nil
	p.nextIndex = 0
	p.totalCount = 0
	p.usedCount = 0
	p.extendPending = false
}

// AddEntry adds a single entry to the pool (used during two-phase OT setup)
func (p *OTPool) AddEntry(entry *OTPoolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, entry)
	p.totalCount++
}

// OTReceiverEntry holds a single precomputed OT for the evaluator (TEE_T)
type OTReceiverEntry struct {
	// ReceiverBundle stores the receiver's secrets for later decryption
	ReceiverBundle ot.COChoiceBundle
	// SenderPublicPoint stores sender's public point A for ECDH derivation
	SenderPublicPoint ot.ECPoint
	Index             int
	Used              bool
}

// OTReceiverPool manages precomputed OT entries for the evaluator (TEE_T).
//
// Consumption is by ABSOLUTE INDEX (the sender, TEE_K, picks the index via
// its own Reserve and tells TEE_T over the wire). The previous "monotonic
// nextIndex" guard was unsound under concurrent sessions: each session has
// its own per-session WS connection to TEE_T, so OPRF online messages
// across sessions arrive in arbitrary order — sometimes higher indices
// land first. The actual replay defense is the per-entry Used flag.
type OTReceiverPool struct {
	mu         sync.Mutex
	entries    []*OTReceiverEntry
	totalCount int // Total entries allocated
	usedCount  int // Consumed entries
}

// NewOTReceiverPool creates a new OT receiver pool with the given capacity
func NewOTReceiverPool(capacity int) *OTReceiverPool {
	return &OTReceiverPool{
		entries:    make([]*OTReceiverEntry, 0, capacity),
		totalCount: 0,
		usedCount:  0,
	}
}

// AddEntries adds precomputed receiver entries to the pool
func (p *OTReceiverPool) AddEntries(entries []*OTReceiverEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, entry := range entries {
		entry.Index = p.totalCount + i
	}
	p.entries = append(p.entries, entries...)
	p.totalCount += len(entries)
}

// Consume retrieves entries from the pool at the given absolute index.
// Returns an error if the range is out of bounds or any entry is already
// used. Order-independent — concurrent OPRF online messages from different
// sessions can arrive at TEE_T in any order; only the per-entry Used flag
// guards against replay/double-consume.
func (p *OTReceiverPool) Consume(startIndex int, count int) ([]*OTReceiverEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if startIndex < 0 || count <= 0 {
		return nil, fmt.Errorf("invalid OT range: startIndex=%d count=%d", startIndex, count)
	}
	if startIndex+count > p.totalCount {
		return nil, fmt.Errorf("insufficient OT entries: need %d at index %d, have %d total",
			count, startIndex, p.totalCount)
	}

	// Validate all entries are unused BEFORE mutating any — keeps the pool
	// consistent if a partial range is already used (no half-consumed state).
	for i := range count {
		if p.entries[startIndex+i].Used {
			return nil, fmt.Errorf("OT entry %d already used (replay)", startIndex+i)
		}
	}

	entries := make([]*OTReceiverEntry, count)
	for i := range count {
		entry := p.entries[startIndex+i]
		entry.Used = true
		entries[i] = entry
	}
	p.usedCount += count

	return entries, nil
}

// Available returns the number of available (unused) OT entries
func (p *OTReceiverPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalCount - p.usedCount
}

// TotalCount returns the total number of entries in the pool
func (p *OTReceiverPool) TotalCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalCount
}

// Clear resets the pool, clearing all entries
func (p *OTReceiverPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries = nil
	p.totalCount = 0
	p.usedCount = 0
}

// Serialization helpers for bulk OT data

// SenderPublicSetup is what crosses the K→T wire — public point A only.
// The sender's secret scalar `a` and the derived -aA stay on TEE_K, never
// in a struct that gets serialized.
type SenderPublicSetup struct {
	CurveName string
	Ax, Ay    *big.Int
}

// Wire format: curveNameLen(2) + curveName + A(33, compressed) = ~35 B/entry.
func SerializeBulkCOSenderSetup(setups []ot.COSenderSetup) []byte {
	if len(setups) == 0 {
		return nil
	}

	buf := make([]byte, 4, 4+len(setups)*40)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(setups)))

	for _, setup := range setups {
		curveNameBytes := []byte(setup.CurveName)

		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(curveNameBytes)))
		buf = append(buf, lenBuf...)
		buf = append(buf, curveNameBytes...)

		buf = append(buf, compressPoint(setup.Ax, setup.Ay)...)
	}

	return buf
}

func DeserializeBulkCOSenderSetup(data []byte) ([]SenderPublicSetup, error) {
	if len(data) < 4 {
		return nil, errors.New("data too short for count")
	}

	count := binary.BigEndian.Uint32(data[0:4])
	offset := 4

	// Min per entry: 2 (curveNameLen) + 0 (curveName) + 33 (compressed A).
	minBytesPerEntry := 2 + compressedPointLen
	maxPossibleEntries := (len(data) - 4) / minBytesPerEntry
	if int(count) > maxPossibleEntries {
		return nil, fmt.Errorf("invalid count %d: data can hold at most %d entries", count, maxPossibleEntries)
	}

	setups := make([]SenderPublicSetup, count)

	for i := range count {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("data too short for curve name length at entry %d", i)
		}
		curveNameLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		if offset+int(curveNameLen)+compressedPointLen > len(data) {
			return nil, fmt.Errorf("data too short for entry %d", i)
		}

		curveName := string(data[offset : offset+int(curveNameLen)])
		offset += int(curveNameLen)

		if err := checkOTCurveName(curveName); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}

		ax, ay, err := decompressPoint(data[offset : offset+compressedPointLen])
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		setups[i] = SenderPublicSetup{CurveName: curveName, Ax: ax, Ay: ay}
		offset += compressedPointLen
	}

	return setups, nil
}

// OTReceiverData holds the data needed for receiver-side OT reconstruction
// This is sent from TEE_T to TEE_K during precomputation response
type OTReceiverData struct {
	CurveName string
	Ax        *big.Int     // Sender's A.x (copied from sender setup)
	Ay        *big.Int     // Sender's A.y
	Points    []ot.ECPoint // Choice points B[i]
}

// SerializeBulkOTReceiverData serializes receiver data for transmission.
// Format: curveNameLen(2) + curveName + A(33) + count(4) + points(33 each), all
// points SEC1-compressed.
func SerializeBulkOTReceiverData(data *OTReceiverData) []byte {
	curveNameBytes := []byte(data.CurveName)
	buf := make([]byte, 0, 2+len(curveNameBytes)+compressedPointLen+4+len(data.Points)*compressedPointLen)

	// Curve name
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(curveNameBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, curveNameBytes...)

	// A point (compressed)
	buf = append(buf, compressPoint(data.Ax, data.Ay)...)

	// Points count
	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, uint32(len(data.Points)))
	buf = append(buf, countBuf...)

	// Points (compressed)
	for _, pt := range data.Points {
		buf = append(buf, compressPoint(pt.X, pt.Y)...)
	}

	return buf
}

// DeserializeBulkOTReceiverData deserializes receiver data
func DeserializeBulkOTReceiverData(data []byte) (*OTReceiverData, error) {
	if len(data) < 2 {
		return nil, errors.New("data too short")
	}

	offset := 0

	// Curve name
	curveNameLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// header after curve name = A(33) + count(4).
	if offset+int(curveNameLen)+compressedPointLen+4 > len(data) {
		return nil, errors.New("data too short for header")
	}

	curveName := string(data[offset : offset+int(curveNameLen)])
	offset += int(curveNameLen)

	if err := checkOTCurveName(curveName); err != nil {
		return nil, err
	}

	// A point (compressed)
	ax, ay, err := decompressPoint(data[offset : offset+compressedPointLen])
	if err != nil {
		return nil, fmt.Errorf("A point: %w", err)
	}
	offset += compressedPointLen

	// Points count
	pointCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Bounds check: prevent integer overflow and memory exhaustion.
	// Each compressed point is 33 bytes.
	maxPossiblePoints := (len(data) - offset) / compressedPointLen
	if int(pointCount) > maxPossiblePoints {
		return nil, fmt.Errorf("invalid point count %d: data can hold at most %d points", pointCount, maxPossiblePoints)
	}

	points := make([]ot.ECPoint, pointCount)
	for i := range pointCount {
		px, py, err := decompressPoint(data[offset : offset+compressedPointLen])
		if err != nil {
			return nil, fmt.Errorf("point %d: %w", i, err)
		}
		points[i] = ot.ECPoint{X: px, Y: py}
		offset += compressedPointLen
	}

	return &OTReceiverData{
		CurveName: curveName,
		Ax:        ax,
		Ay:        ay,
		Points:    points,
	}, nil
}

// DualMask holds the masks for derandomized OT
// M0 = L0 XOR R0, M1 = L1 XOR R1
// Delta = R0 XOR R1 (needed when precomputed choice != actual input)
// Where (L0, L1) are the actual input wire labels and (R0, R1) are precomputed random labels
type DualMask struct {
	M0    ot.Label // Mask for 0-label
	M1    ot.Label // Mask for 1-label
	Delta ot.Label // R0 XOR R1 for correction when precomputed choice != actual input
}

// SerializeDualMasks serializes dual masks for transmission
// Each DualMask is 48 bytes (3 x 16-byte labels: M0, M1, Delta)
func SerializeDualMasks(masks []DualMask) []byte {
	buf := make([]byte, 4+len(masks)*48)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(masks)))

	offset := 4
	for _, mask := range masks {
		binary.BigEndian.PutUint64(buf[offset:offset+8], mask.M0.D0)
		binary.BigEndian.PutUint64(buf[offset+8:offset+16], mask.M0.D1)
		binary.BigEndian.PutUint64(buf[offset+16:offset+24], mask.M1.D0)
		binary.BigEndian.PutUint64(buf[offset+24:offset+32], mask.M1.D1)
		binary.BigEndian.PutUint64(buf[offset+32:offset+40], mask.Delta.D0)
		binary.BigEndian.PutUint64(buf[offset+40:offset+48], mask.Delta.D1)
		offset += 48
	}

	return buf
}

// DeserializeDualMasks deserializes dual masks
func DeserializeDualMasks(data []byte) ([]DualMask, error) {
	if len(data) < 4 {
		return nil, errors.New("data too short for mask count")
	}

	count := binary.BigEndian.Uint32(data[0:4])

	// Bounds check: prevent integer overflow and memory exhaustion
	// Each mask is 48 bytes, max possible entries = (len(data) - 4) / 48
	maxPossibleMasks := (len(data) - 4) / 48
	if int(count) > maxPossibleMasks {
		return nil, fmt.Errorf("invalid mask count %d: data can hold at most %d masks", count, maxPossibleMasks)
	}

	masks := make([]DualMask, count)
	offset := 4

	for i := range count {
		masks[i] = DualMask{
			M0: ot.Label{
				D0: binary.BigEndian.Uint64(data[offset : offset+8]),
				D1: binary.BigEndian.Uint64(data[offset+8 : offset+16]),
			},
			M1: ot.Label{
				D0: binary.BigEndian.Uint64(data[offset+16 : offset+24]),
				D1: binary.BigEndian.Uint64(data[offset+24 : offset+32]),
			},
			Delta: ot.Label{
				D0: binary.BigEndian.Uint64(data[offset+32 : offset+40]),
				D1: binary.BigEndian.Uint64(data[offset+40 : offset+48]),
			},
		}
		offset += 48
	}

	return masks, nil
}
