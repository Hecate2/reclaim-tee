package mpc

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPoolGrowthWipesAbandonedSecretBacking(t *testing.T) {
	senderBacking := []SenderOT{{R0: Label{D0: 1}, R1: Label{D1: 2}, Index: 0}}
	sender := &SenderPool{entries: senderBacking, baseIndex: 0, nextIndex: 0}
	if err := sender.Add([]SenderOT{{R0: Label{D0: 3}, R1: Label{D1: 4}, Index: 1}}); err != nil {
		t.Fatal(err)
	}
	if senderBacking[0] != (SenderOT{}) {
		t.Fatal("sender pool growth left secrets in the old backing array")
	}
	if len(sender.entries) != 2 || sender.entries[0].Index != 0 || sender.entries[1].Index != 1 {
		t.Fatal("sender pool growth changed committed entries")
	}

	receiverBacking := []ReceiverOT{{R: Label{D0: 5}, Index: 0, Choice: true}}
	receiver := &ReceiverPool{
		entries: receiverBacking, used: []bool{false}, baseIndex: 0, highWater: 0, availableCount: 1,
	}
	if err := receiver.Add([]ReceiverOT{{R: Label{D0: 6}, Index: 1}}); err != nil {
		t.Fatal(err)
	}
	if receiverBacking[0] != (ReceiverOT{}) {
		t.Fatal("receiver pool growth left secrets in the old backing array")
	}
	if len(receiver.entries) != 2 || receiver.entries[0].Index != 0 || receiver.entries[1].Index != 1 {
		t.Fatal("receiver pool growth changed committed entries")
	}
}

func TestPoolsConsumeCompactAndExtend(t *testing.T) {
	const initial = OTPoolInitialSize
	senderEntries := indexedSenderOTs(0, initial)
	receiverEntries := indexedReceiverOTs(0, initial)
	sender := NewSenderPool(initial)
	receiver := NewReceiverPool(initial)
	if err := sender.Add(senderEntries); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Add(receiverEntries); err != nil {
		t.Fatal(err)
	}

	senderBatch, receiverBatch := consumeMatchingBatch(t, sender, receiver, 0, OTPoolWatermark)
	if senderBatch[0].Index != 0 || receiverBatch[0].Index != 0 {
		t.Fatal("pool returned the wrong first index")
	}
	if sender.baseIndex != OTPoolWatermark || receiver.baseIndex != OTPoolWatermark {
		t.Fatalf("pools did not compact: sender=%d receiver=%d", sender.baseIndex, receiver.baseIndex)
	}
	if sender.TotalCount() != initial || receiver.TotalCount() != initial {
		t.Fatal("compaction changed the total generated count")
	}

	if err := sender.Add(indexedSenderOTs(initial, OTPoolExtendSize)); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Add(indexedReceiverOTs(initial, OTPoolExtendSize)); err != nil {
		t.Fatal(err)
	}
	if sender.TotalCount() != initial+OTPoolExtendSize || receiver.TotalCount() != initial+OTPoolExtendSize {
		t.Fatal("extension total is incorrect")
	}
	if err := ValidatePoolAgreement(sender, receiver); err != nil {
		t.Fatal(err)
	}

	claimPool := NewSenderPool(OTPoolWatermark - 1)
	if err := claimPool.Add(indexedSenderOTs(0, OTPoolWatermark-1)); err != nil {
		t.Fatal(err)
	}
	claim := claimPool.ClaimExtendIfNeeded()
	if claim == nil {
		t.Fatal("failed to claim sender extension")
	}
	if !claimPool.IsExtendPending() {
		t.Fatal("extend-pending flag was not set")
	}
	if !claimPool.ReleaseExtendClaim(claim) {
		t.Fatal("sender extension claim was not released")
	}
	sender.Clear()
	receiver.Clear()
	if sender.TotalCount() != 0 || receiver.TotalCount() != 0 || sender.NextIndex() != 0 || receiver.NextIndex() != 0 {
		t.Fatal("clear did not reset pool indices")
	}
}

func TestSenderPoolHighFrontierExactEndAndOverflowAreAtomic(t *testing.T) {
	base := uint64(math.MaxUint64 - 3)
	entries := indexedSenderOTs(base, 3)
	pool := &SenderPool{entries: entries, baseIndex: base, nextIndex: base}

	if got := pool.TotalCount(); got != math.MaxUint64 {
		t.Fatalf("total=%d, want %d", got, uint64(math.MaxUint64))
	}
	start, reserved, err := pool.Reserve(3)
	if err != nil {
		t.Fatal(err)
	}
	if start != base || len(reserved) != 3 || pool.NextIndex() != math.MaxUint64 || pool.TotalCount() != math.MaxUint64 {
		t.Fatalf("exact-end reserve start=%d len=%d next=%d total=%d", start, len(reserved), pool.NextIndex(), pool.TotalCount())
	}

	beforeBase, beforeNext, beforeLen := pool.baseIndex, pool.nextIndex, len(pool.entries)
	if _, _, err := pool.Reserve(1); err == nil {
		t.Fatal("reserved past the exhausted uint64 frontier")
	}
	if pool.baseIndex != beforeBase || pool.nextIndex != beforeNext || len(pool.entries) != beforeLen {
		t.Fatal("overflowing reserve mutated sender pool")
	}
	if err := pool.Add([]SenderOT{{Index: math.MaxUint64}}); err == nil {
		t.Fatal("appended an OT at the exhausted uint64 frontier")
	}
	if pool.baseIndex != beforeBase || pool.nextIndex != beforeNext || len(pool.entries) != beforeLen {
		t.Fatal("overflowing append mutated sender pool")
	}
}

func TestReceiverPoolHighFrontierExactEndAndOverflowAreAtomic(t *testing.T) {
	base := uint64(math.MaxUint64 - 3)
	entries := indexedReceiverOTs(base, 3)
	pool := &ReceiverPool{
		entries: entries, used: make([]bool, len(entries)), baseIndex: base,
		highWater: base, availableCount: len(entries),
	}

	if got := pool.TotalCount(); got != math.MaxUint64 {
		t.Fatalf("total=%d, want %d", got, uint64(math.MaxUint64))
	}
	consumed, err := pool.Consume(base, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(consumed) != 3 || pool.NextIndex() != math.MaxUint64 || pool.TotalCount() != math.MaxUint64 || pool.Available() != 0 {
		t.Fatalf("exact-end consume len=%d next=%d total=%d available=%d", len(consumed), pool.NextIndex(), pool.TotalCount(), pool.Available())
	}

	beforeBase, beforeHigh, beforeLen := pool.baseIndex, pool.highWater, len(pool.entries)
	if _, err := pool.Consume(math.MaxUint64, 1); err == nil {
		t.Fatal("consumed past the exhausted uint64 frontier")
	}
	if pool.baseIndex != beforeBase || pool.highWater != beforeHigh || len(pool.entries) != beforeLen || pool.Available() != 0 {
		t.Fatal("overflowing consume mutated receiver pool")
	}
	if err := pool.Add([]ReceiverOT{{Index: math.MaxUint64}}); err == nil {
		t.Fatal("appended an OT at the exhausted uint64 frontier")
	}
	if pool.baseIndex != beforeBase || pool.highWater != beforeHigh || len(pool.entries) != beforeLen || pool.Available() != 0 {
		t.Fatal("overflowing append mutated receiver pool")
	}
}

func TestPoolInvariantViolationsFailClosedWithoutMutation(t *testing.T) {
	sender := &SenderPool{entries: indexedSenderOTs(10, 1), baseIndex: 10, nextIndex: 9}
	if err := sender.Add([]SenderOT{{Index: 11}}); err == nil {
		t.Fatal("sender append accepted next index below base")
	}
	if _, _, err := sender.Reserve(1); err == nil {
		t.Fatal("sender reserve accepted next index below base")
	}
	if len(sender.entries) != 1 || sender.baseIndex != 10 || sender.nextIndex != 9 {
		t.Fatal("invalid sender state was mutated")
	}

	receiver := &ReceiverPool{
		entries: indexedReceiverOTs(10, 1), baseIndex: 10, highWater: 10, availableCount: 1,
	}
	if err := receiver.Add([]ReceiverOT{{Index: 11}}); err == nil {
		t.Fatal("receiver append accepted mismatched entry/used slices")
	}
	if _, err := receiver.Consume(10, 1); err == nil {
		t.Fatal("receiver consume accepted mismatched entry/used slices")
	}
	if err := receiver.AdvanceTo(10); err == nil {
		t.Fatal("receiver resume accepted mismatched entry/used slices")
	}
	if len(receiver.entries) != 1 || len(receiver.used) != 0 || receiver.baseIndex != 10 || receiver.highWater != 10 || receiver.availableCount != 1 {
		t.Fatal("invalid receiver state was mutated")
	}
}

func FuzzCheckedOTIndexEnd(f *testing.F) {
	f.Add(uint64(0), uint32(1))
	f.Add(uint64(math.MaxUint32), uint32(100_000))
	f.Add(uint64(math.MaxUint64), uint32(1))
	f.Fuzz(func(t *testing.T, start uint64, count uint32) {
		end, err := CheckedOTIndexEnd(start, int(count))
		fits := uint64(count) <= math.MaxUint64-start
		if fits {
			if err != nil || end < start || end-start != uint64(count) {
				t.Fatalf("start=%d count=%d end=%d err=%v", start, count, end, err)
			}
			return
		}
		if err == nil {
			t.Fatalf("accepted overflowing start=%d count=%d end=%d", start, count, end)
		}
	})
}

func TestPoolRejectsReplayOverlapAndInvalidAppend(t *testing.T) {
	sender := NewSenderPool(8)
	receiver := NewReceiverPool(8)
	if err := sender.Add(indexedSenderOTs(1, 2)); err == nil {
		t.Fatal("sender accepted a skipped append index")
	}
	if err := receiver.Add(indexedReceiverOTs(1, 2)); err == nil {
		t.Fatal("receiver accepted a skipped append index")
	}
	if err := sender.Add(indexedSenderOTs(0, 8)); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Add(indexedReceiverOTs(0, 8)); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Consume(4, 2); err != nil {
		t.Fatalf("receiver rejected an out-of-order range: %v", err)
	}
	if _, err := receiver.Consume(0, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Consume(4, 1); err == nil {
		t.Fatal("receiver accepted a replayed consume index")
	}
	if _, err := receiver.Consume(1, 2); err == nil {
		t.Fatal("receiver accepted a partially overlapping range")
	}
	if _, err := receiver.Consume(2, 2); err != nil {
		t.Fatalf("overlap failure partially consumed the range: %v", err)
	}
	if err := receiver.AdvanceTo(5); err == nil {
		t.Fatal("receiver accepted a resume rewind")
	}
	if err := receiver.AdvanceTo(9); err == nil {
		t.Fatal("receiver accepted a resume index beyond the pool")
	}
	if err := receiver.AdvanceTo(8); err != nil {
		t.Fatal(err)
	}
	if receiver.Available() != 0 || receiver.NextIndex() != 8 {
		t.Fatal("resume did not discard every sender-reserved entry")
	}
}

func TestReceiverPoolCompactsAfterOutOfOrderConsume(t *testing.T) {
	receiver := NewReceiverPool(64)
	if err := receiver.Add(indexedReceiverOTs(0, 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Consume(32, 32); err != nil {
		t.Fatal(err)
	}
	if receiver.baseIndex != 0 {
		t.Fatal("receiver compacted across an unused prefix")
	}
	if _, err := receiver.Consume(0, 32); err != nil {
		t.Fatal(err)
	}
	if receiver.baseIndex != 64 || receiver.TotalCount() != 64 || receiver.Available() != 0 {
		t.Fatal("receiver did not compact the completed out-of-order ranges")
	}
}

func TestPoolReturnsOwnedBatches(t *testing.T) {
	sender := NewSenderPool(1)
	receiver := NewReceiverPool(1)
	senderEntry := indexedSenderOTs(0, 1)
	receiverEntry := indexedReceiverOTs(0, 1)
	senderEntry[0].R0.D0 = 7
	receiverEntry[0].R.D0 = 9
	if err := sender.Add(senderEntry); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Add(receiverEntry); err != nil {
		t.Fatal(err)
	}
	senderBatch, receiverBatch := consumeMatchingBatch(t, sender, receiver, 0, 1)
	sender.Clear()
	receiver.Clear()
	if senderBatch[0].R0.D0 != 7 || receiverBatch[0].R.D0 != 9 {
		t.Fatal("pool clear modified an already returned batch")
	}
}

func TestSenderPoolConcurrentRefillClaimHasOneOwner(t *testing.T) {
	pool := NewSenderPool(OTPoolWatermark - 1)
	if err := pool.Add(indexedSenderOTs(0, OTPoolWatermark-1)); err != nil {
		t.Fatal(err)
	}
	var claims atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if pool.ClaimExtendIfNeeded() != nil {
				claims.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := claims.Load(); got != 1 {
		t.Fatalf("refill claims = %d, want 1", got)
	}
	if !pool.IsExtendPending() {
		t.Fatal("winning refill claim was not retained")
	}
}

func TestSenderPoolOldClaimCannotReleaseReplacementAcrossClear(t *testing.T) {
	pool := NewSenderPool(OTPoolWatermark - 1)
	if err := pool.Add(indexedSenderOTs(0, OTPoolWatermark-1)); err != nil {
		t.Fatal(err)
	}
	oldClaim := pool.ClaimExtendIfNeeded()
	if oldClaim == nil {
		t.Fatal("failed to acquire old extension claim")
	}

	pool.Clear()
	if err := pool.Add(indexedSenderOTs(0, OTPoolWatermark-1)); err != nil {
		t.Fatal(err)
	}
	replacementClaim := pool.ClaimExtendIfNeeded()
	if replacementClaim == nil || replacementClaim == oldClaim {
		t.Fatal("failed to acquire unique replacement extension claim")
	}
	if pool.ReleaseExtendClaim(oldClaim) {
		t.Fatal("stale extension owner released replacement claim")
	}
	if !pool.OwnsExtendClaim(replacementClaim) {
		t.Fatal("replacement extension claim was lost")
	}
}

func TestResumeReconcilesRejectedOnlineReservationAndAllowsExtension(t *testing.T) {
	const initial = 2 * OTsPerOPRF
	sender := NewSenderPool(initial)
	receiver := NewReceiverPool(initial)
	if err := sender.Add(indexedSenderOTs(0, initial)); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Add(indexedReceiverOTs(0, initial)); err != nil {
		t.Fatal(err)
	}

	// The sender reserved the first range, but the peer rejected the online
	// message before consuming it. Resume advances the receiver to the exact
	// sender frontier and makes the abandoned prefix compactable.
	if _, _, err := sender.Reserve(OTsPerOPRF); err != nil {
		t.Fatal(err)
	}
	if err := receiver.AdvanceTo(sender.NextIndex()); err != nil {
		t.Fatal(err)
	}
	if receiver.baseIndex != OTsPerOPRF || len(receiver.entries) != OTsPerOPRF {
		t.Fatalf("receiver prefix retained after reconciliation: base=%d retained=%d", receiver.baseIndex, len(receiver.entries))
	}

	if _, _, err := sender.Reserve(OTsPerOPRF); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Consume(OTsPerOPRF, OTsPerOPRF); err != nil {
		t.Fatal(err)
	}
	if receiver.baseIndex != initial || len(receiver.entries) != 0 {
		t.Fatalf("receiver did not compact successful range: base=%d retained=%d", receiver.baseIndex, len(receiver.entries))
	}

	if err := sender.Add(indexedSenderOTs(initial, OTPoolExtendSize)); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Add(indexedReceiverOTs(initial, OTPoolExtendSize)); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePoolAgreement(sender, receiver); err != nil {
		t.Fatal(err)
	}
	if sender.Available() != OTPoolExtendSize || receiver.Available() != OTPoolExtendSize {
		t.Fatal("reconciled pools did not accept the next extension")
	}
}

func consumeMatchingBatch(t *testing.T, sender *SenderPool, receiver *ReceiverPool, start uint64, count int) ([]SenderOT, []ReceiverOT) {
	t.Helper()
	senderStart, senderBatch, err := sender.Reserve(count)
	if err != nil {
		t.Fatal(err)
	}
	if senderStart != start {
		t.Fatalf("sender start %d, want %d", senderStart, start)
	}
	receiverBatch, err := receiver.Consume(start, count)
	if err != nil {
		t.Fatal(err)
	}
	return senderBatch, receiverBatch
}

func indexedSenderOTs(start uint64, count int) []SenderOT {
	entries := make([]SenderOT, count)
	for i := range entries {
		entries[i].Index = start + uint64(i)
	}
	return entries
}

func indexedReceiverOTs(start uint64, count int) []ReceiverOT {
	entries := make([]ReceiverOT, count)
	for i := range entries {
		entries[i].Index = start + uint64(i)
	}
	return entries
}
