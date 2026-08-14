package mpc

import "testing"

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

	sender.SetExtendPending(true)
	if !sender.IsExtendPending() {
		t.Fatal("extend-pending flag was not set")
	}
	sender.SetExtendPending(false)
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
