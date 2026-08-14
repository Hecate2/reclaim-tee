package mpc

import (
	"sync"
	"sync/atomic"
	"testing"
)

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
