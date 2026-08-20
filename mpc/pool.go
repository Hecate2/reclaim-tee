package mpc

import (
	"errors"
	"fmt"
	"sync"
)

const (
	OTPoolInitialSize = 100_000
	OTPoolExtendSize  = 50_000
	OTPoolWatermark   = 50_000
	OTsPerOPRF        = InputBits

	// MaxPrecomputeOTs is the application protocol limit. The generic IKNP
	// primitive supports larger batches, but production only creates the
	// 100,000-entry initial pool and 50,000-entry refills.
	MaxPrecomputeOTs = OTPoolInitialSize
)

// ValidatePrecomputeCount applies the production TEE protocol limit before a
// caller creates a session, mutates pool state, or allocates extension data.
func ValidatePrecomputeCount(count int) error {
	if count <= 0 || count > MaxPrecomputeOTs {
		return fmt.Errorf("mpc: unsupported OT precompute count %d (maximum %d)", count, MaxPrecomputeOTs)
	}
	return nil
}

// SenderPool is the garbler's compact, append-only random-OT pool.
type SenderPool struct {
	mu          sync.Mutex
	entries     []SenderOT
	baseIndex   uint64
	nextIndex   uint64
	extendClaim *SenderExtendClaim
}

// SenderExtendClaim is an opaque, single-owner lease for one pool extension.
// A pool clear invalidates the claim; delayed owners cannot release a newer
// claim because ownership is compared by exact pointer identity.
type SenderExtendClaim struct{ marker byte }

func NewSenderPool(capacity int) *SenderPool {
	return &SenderPool{entries: make([]SenderOT, 0, capacity)}
}

func (p *SenderPool) totalLocked() (uint64, error) {
	total, err := checkedIndexEnd(p.baseIndex, len(p.entries))
	if err != nil || p.nextIndex < p.baseIndex || p.nextIndex > total {
		return 0, errors.New("mpc: invalid sender pool frontier")
	}
	return total, nil
}

// Add appends a verified extension batch. Indices must continue the pool.
func (p *SenderPool) Add(entries []SenderOT) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateAddLocked(entries); err != nil {
		return err
	}
	p.entries = appendWithWipedGrowth(p.entries, entries)
	return nil
}

// ValidateAdd checks that entries can be appended at the exact cumulative
// frontier without changing the pool. Protocol handlers use it before sending
// an irreversible completion acknowledgment; Add repeats the same validation
// when the batch is committed locally.
func (p *SenderPool) ValidateAdd(entries []SenderOT) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validateAddLocked(entries)
}

func (p *SenderPool) validateAddLocked(entries []SenderOT) error {
	start, err := p.totalLocked()
	if err != nil {
		return err
	}
	if _, err := checkedIndexEnd(start, len(entries)); err != nil {
		return err
	}
	if err := validateSenderOTIndices(entries, start); err != nil {
		return err
	}
	return nil
}

// Reserve atomically consumes the next count sender entries.
func (p *SenderPool) Reserve(count int) (uint64, []SenderOT, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if count <= 0 {
		return 0, nil, fmt.Errorf("mpc: invalid OT reservation count %d", count)
	}
	if p.nextIndex < p.baseIndex {
		return 0, nil, errors.New("mpc: invalid sender pool index state")
	}
	total, err := p.totalLocked()
	if err != nil {
		return 0, nil, err
	}
	end, err := checkedIndexEnd(p.nextIndex, count)
	if err != nil {
		return 0, nil, err
	}
	if end > total {
		return 0, nil, fmt.Errorf("mpc: insufficient sender OTs: need %d, available %d", count, total-p.nextIndex)
	}
	start := p.nextIndex
	offset := int(start - p.baseIndex)
	result := append([]SenderOT(nil), p.entries[offset:offset+count]...)
	clear(p.entries[offset : offset+count])
	p.nextIndex = end
	p.compactConsumed()
	return start, result, nil
}

func (p *SenderPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLocked()
	p.extendClaim = nil
}

// ClearForExtendFailure clears the pool only while the caller still owns the
// exact failed extension. The claim remains held until the caller performs its
// failure recovery, so a replacement refill cannot occupy the gap.
func (p *SenderPool) ClearForExtendFailure(claim *SenderExtendClaim) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if claim == nil || p.extendClaim != claim {
		return false
	}
	p.clearLocked()
	return true
}

func (p *SenderPool) clearLocked() {
	clear(p.entries)
	p.entries = p.entries[:0]
	p.baseIndex = 0
	p.nextIndex = 0
}

func (p *SenderPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total, err := p.totalLocked()
	if err != nil {
		return 0
	}
	return int(total - p.nextIndex)
}

func (p *SenderPool) TotalCount() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	total, err := p.totalLocked()
	if err != nil {
		return 0
	}
	return total
}

func (p *SenderPool) NextIndex() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nextIndex
}

func (p *SenderPool) NeedsExtend() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	total, err := p.totalLocked()
	if err != nil {
		return false
	}
	return int(total-p.nextIndex) < OTPoolWatermark && p.extendClaim == nil
}

// ClaimExtendIfNeeded atomically claims ownership of the next low-watermark
// extension. Callers must release this exact token if they fail before
// publishing an in-flight extension request.
func (p *SenderPool) ClaimExtendIfNeeded() *SenderExtendClaim {
	p.mu.Lock()
	defer p.mu.Unlock()
	total, err := p.totalLocked()
	if err != nil {
		return nil
	}
	available := int(total - p.nextIndex)
	if available >= OTPoolWatermark || p.extendClaim != nil {
		return nil
	}
	claim := &SenderExtendClaim{}
	p.extendClaim = claim
	return claim
}

func (p *SenderPool) IsExtendPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.extendClaim != nil
}

func (p *SenderPool) OwnsExtendClaim(claim *SenderExtendClaim) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return claim != nil && p.extendClaim == claim
}

// ReleaseExtendClaim releases only the exact claim supplied by its owner.
func (p *SenderPool) ReleaseExtendClaim(claim *SenderExtendClaim) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if claim == nil || p.extendClaim != claim {
		return false
	}
	p.extendClaim = nil
	return true
}

// InvalidateExtendClaim revokes any claimant captured before a pool lifecycle
// transition. Exact release semantics keep a delayed claimant from affecting a
// replacement claim.
func (p *SenderPool) InvalidateExtendClaim() {
	p.mu.Lock()
	p.extendClaim = nil
	p.mu.Unlock()
}

func (p *SenderPool) compactConsumed() {
	consumed := p.nextIndex - p.baseIndex
	if consumed < OTPoolWatermark && consumed < uint64(len(p.entries))/2 {
		return
	}
	consumedCount := int(consumed)
	remaining := copy(p.entries, p.entries[consumedCount:])
	clear(p.entries[remaining:])
	p.entries = p.entries[:remaining]
	p.baseIndex = p.nextIndex
}

// ReceiverPool is the evaluator's matching compact random-OT pool. It accepts
// disjoint ranges in any order because online sessions use separate
// connections. The used slice rejects replays and partial overlaps.
type ReceiverPool struct {
	mu             sync.Mutex
	entries        []ReceiverOT
	used           []bool
	baseIndex      uint64
	highWater      uint64
	availableCount int
}

func NewReceiverPool(capacity int) *ReceiverPool {
	return &ReceiverPool{entries: make([]ReceiverOT, 0, capacity)}
}

func (p *ReceiverPool) totalLocked() (uint64, error) {
	total, err := checkedIndexEnd(p.baseIndex, len(p.entries))
	if err != nil || len(p.used) != len(p.entries) || p.availableCount < 0 || p.availableCount > len(p.entries) || p.highWater < p.baseIndex || p.highWater > total {
		return 0, errors.New("mpc: invalid receiver pool frontier")
	}
	return total, nil
}

func (p *ReceiverPool) Add(entries []ReceiverOT) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	start, err := p.totalLocked()
	if err != nil {
		return err
	}
	if _, err := checkedIndexEnd(start, len(entries)); err != nil {
		return err
	}
	if err := validateReceiverOTIndices(entries, start); err != nil {
		return err
	}
	p.entries = appendWithWipedGrowth(p.entries, entries)
	p.used = append(p.used, make([]bool, len(entries))...)
	p.availableCount += len(entries)
	return nil
}

// appendWithWipedGrowth mirrors append while ensuring that a reallocation
// does not leave secret entries in the abandoned backing array.
func appendWithWipedGrowth[T any](dst, src []T) []T {
	if len(src) <= cap(dst)-len(dst) {
		oldLen := len(dst)
		dst = dst[:oldLen+len(src)]
		copy(dst[oldLen:], src)
		return dst
	}

	needed := len(dst) + len(src)
	newCap := needed
	if cap(dst) <= int(^uint(0)>>1)/2 && cap(dst)*2 > newCap {
		newCap = cap(dst) * 2
	}
	next := make([]T, needed, newCap)
	copy(next, dst)
	copy(next[len(dst):], src)
	if cap(dst) != 0 {
		clear(dst[:cap(dst)])
	}
	return next
}

// Consume returns one unused absolute range. It accepts out-of-order ranges
// and validates the complete range before it changes the pool.
func (p *ReceiverPool) Consume(start uint64, count int) ([]ReceiverOT, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateConsumableLocked(start, count); err != nil {
		return nil, err
	}
	end, _ := checkedIndexEnd(start, count)
	offset := int(start - p.baseIndex)
	result := append([]ReceiverOT(nil), p.entries[offset:offset+count]...)
	for i := offset; i < offset+count; i++ {
		p.used[i] = true
	}
	clear(p.entries[offset : offset+count])
	p.availableCount -= count
	if end > p.highWater {
		p.highWater = end
	}
	p.compactConsumed()
	return result, nil
}

// ValidateConsumable checks whether a range in the currently committed pool is
// unused without consuming it. TEE_T uses this while deciding whether an
// online request that crosses into the current pending batch may wait for the
// existing completion message.
func (p *ReceiverPool) ValidateConsumable(start uint64, count int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validateConsumableLocked(start, count)
}

func (p *ReceiverPool) validateConsumableLocked(start uint64, count int) error {
	if count <= 0 {
		return fmt.Errorf("mpc: invalid OT consume count %d", count)
	}
	if start < p.baseIndex {
		return fmt.Errorf("mpc: receiver OT range starts before retained index %d", p.baseIndex)
	}
	total, err := p.totalLocked()
	if err != nil {
		return err
	}
	end, err := checkedIndexEnd(start, count)
	if err != nil || end > total {
		if err != nil {
			return err
		}
		return fmt.Errorf("mpc: insufficient receiver OTs: need through %d, total %d", end, total)
	}
	offset := int(start - p.baseIndex)
	for i := offset; i < offset+count; i++ {
		if p.used[i] {
			return fmt.Errorf("mpc: receiver OT index %d already used", start+uint64(i-offset))
		}
	}
	return nil
}

// AdvanceTo discards every entry below the sender's reservation frontier after
// a reconnect. It rejects a frontier below any range already consumed here.
func (p *ReceiverPool) AdvanceTo(next uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	total, err := p.totalLocked()
	if err != nil {
		return err
	}
	if next < p.highWater || next > total {
		return fmt.Errorf("mpc: receiver OT resume index %d outside [%d,%d]", next, p.highWater, total)
	}
	end := int(next - p.baseIndex)
	for i := range end {
		if !p.used[i] {
			p.used[i] = true
			p.availableCount--
		}
	}
	clear(p.entries[:end])
	p.highWater = next
	p.compactConsumed()
	return nil
}

func (p *ReceiverPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.entries)
	p.entries = p.entries[:0]
	clear(p.used)
	p.used = p.used[:0]
	p.baseIndex = 0
	p.highWater = 0
	p.availableCount = 0
}

func (p *ReceiverPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.totalLocked(); err != nil {
		return 0
	}
	return p.availableCount
}

func (p *ReceiverPool) TotalCount() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	total, err := p.totalLocked()
	if err != nil {
		return 0
	}
	return total
}

func (p *ReceiverPool) NextIndex() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.highWater
}

func (p *ReceiverPool) compactConsumed() {
	consumed := 0
	for consumed < len(p.used) && p.used[consumed] {
		consumed++
	}
	if consumed < OTPoolWatermark && consumed < len(p.entries)/2 {
		return
	}
	remaining := copy(p.entries, p.entries[consumed:])
	clear(p.entries[remaining:])
	p.entries = p.entries[:remaining]
	copy(p.used, p.used[consumed:])
	clear(p.used[remaining:])
	p.used = p.used[:remaining]
	p.baseIndex += uint64(consumed)
}

func ValidatePoolAgreement(sender *SenderPool, receiver *ReceiverPool) error {
	if sender == nil || receiver == nil {
		return errors.New("mpc: nil OT pool")
	}
	if sender.TotalCount() != receiver.TotalCount() || sender.NextIndex() != receiver.NextIndex() {
		return errors.New("mpc: sender and receiver OT pools disagree")
	}
	return nil
}
