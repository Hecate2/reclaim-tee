package oprfmpc

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

func TestOTPool_NewPool(t *testing.T) {
	pool := NewOTPool(100)
	if pool == nil {
		t.Fatal("NewOTPool returned nil")
	}
	if pool.Available() != 0 {
		t.Errorf("expected 0 available, got %d", pool.Available())
	}
	// Empty pool does need extend (available = 0 <= OTPoolWatermark)
	if !pool.NeedsExtend() {
		t.Error("empty pool should need extend")
	}
}

func TestOTPool_AddEntry(t *testing.T) {
	pool := NewOTPool(100)
	curve := elliptic.P256()

	// Generate a test entry
	setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
	if err != nil {
		t.Fatalf("failed to create sender setup: %v", err)
	}

	entry := &OTPoolEntry{
		SenderSetup: setup,
		Index:       0,
		Used:        false,
	}
	pool.AddEntry(entry)

	if pool.Available() != 1 {
		t.Errorf("expected 1 available, got %d", pool.Available())
	}
}

func TestOTPool_Reserve(t *testing.T) {
	pool := NewOTPool(100)
	curve := elliptic.P256()

	// Add 10 entries
	for i := 0; i < 10; i++ {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			t.Fatalf("failed to create sender setup: %v", err)
		}
		entry := &OTPoolEntry{
			SenderSetup: setup,
			Index:       i,
			Used:        false,
		}
		pool.AddEntry(entry)
	}

	// Reserve 5 entries
	startIdx, entries, err := pool.Reserve(5)
	if err != nil {
		t.Fatalf("failed to reserve: %v", err)
	}
	if startIdx != 0 {
		t.Errorf("expected start index 0, got %d", startIdx)
	}
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}
	if pool.Available() != 5 {
		t.Errorf("expected 5 available after reserve, got %d", pool.Available())
	}

	// Reserve 5 more
	startIdx, entries, err = pool.Reserve(5)
	if err != nil {
		t.Fatalf("failed to reserve: %v", err)
	}
	if startIdx != 5 {
		t.Errorf("expected start index 5, got %d", startIdx)
	}
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}
	if pool.Available() != 0 {
		t.Errorf("expected 0 available after second reserve, got %d", pool.Available())
	}

	// Try to reserve more than available
	_, _, err = pool.Reserve(1)
	if err == nil {
		t.Error("expected error when reserving from empty pool")
	}
}

func TestOTPool_NeedsExtend(t *testing.T) {
	// The OTPoolWatermark is fixed at 10000
	// A pool needs extend when available <= 10000
	// We need to test with a larger pool to test the watermark logic properly
	pool := NewOTPool(OTPoolInitialSize)
	curve := elliptic.P256()

	// Add entries above watermark (we'll add 15000 to be above 10000 watermark)
	testSize := OTPoolWatermark + 5000
	for i := 0; i < testSize; i++ {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			t.Fatalf("failed to create sender setup: %v", err)
		}
		entry := &OTPoolEntry{
			SenderSetup: setup,
			Index:       i,
			Used:        false,
		}
		pool.AddEntry(entry)
	}

	// Should not need extend initially (15000 > 10000 watermark)
	if pool.NeedsExtend() {
		t.Errorf("pool should not need extend at %d available", pool.Available())
	}

	// Reserve entries to drop below watermark
	reserveCount := 5001 // Leave 9999, which is <= 10000 watermark
	_, _, err := pool.Reserve(reserveCount)
	if err != nil {
		t.Fatalf("failed to reserve: %v", err)
	}

	// Now should need extend (9999 <= 10000 watermark)
	if !pool.NeedsExtend() {
		t.Errorf("pool should need extend at %d available", pool.Available())
	}
}

func TestOTPool_Clear(t *testing.T) {
	pool := NewOTPool(100)
	curve := elliptic.P256()

	// Add entries
	for i := 0; i < 10; i++ {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			t.Fatalf("failed to create sender setup: %v", err)
		}
		entry := &OTPoolEntry{
			SenderSetup: setup,
			Index:       i,
			Used:        false,
		}
		pool.AddEntry(entry)
	}

	pool.Clear()

	if pool.Available() != 0 {
		t.Errorf("expected 0 available after clear, got %d", pool.Available())
	}
}

func TestOTReceiverPool_Basic(t *testing.T) {
	pool := NewOTReceiverPool(100)
	if pool == nil {
		t.Fatal("NewOTReceiverPool returned nil")
	}
	if pool.Available() != 0 {
		t.Errorf("expected 0 available, got %d", pool.Available())
	}
}

func TestOTReceiverPool_AddEntries(t *testing.T) {
	pool := NewOTReceiverPool(100)

	// Add some entries with empty bundles (we need real bundles)
	curve := elliptic.P256()
	entries := make([]*OTReceiverEntry, 10)
	for i := range entries {
		// Generate a real sender setup to build choices from
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			t.Fatalf("failed to create sender setup: %v", err)
		}

		// Build choice for this OT
		bundle, _, err := ot.BuildCOChoices(rand.Reader, curve, setup.Ax, setup.Ay, []bool{false})
		if err != nil {
			t.Fatalf("failed to build choice: %v", err)
		}

		entries[i] = &OTReceiverEntry{
			ReceiverBundle: bundle,
			Index:          i,
			Used:           false,
		}
	}
	pool.AddEntries(entries)

	if pool.Available() != 10 {
		t.Errorf("expected 10 available, got %d", pool.Available())
	}
}

func TestOTReceiverPool_Consume(t *testing.T) {
	pool := NewOTReceiverPool(100)
	curve := elliptic.P256()

	// Add some entries with real bundles
	entries := make([]*OTReceiverEntry, 10)
	for i := range entries {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			t.Fatalf("failed to create sender setup: %v", err)
		}

		bundle, _, err := ot.BuildCOChoices(rand.Reader, curve, setup.Ax, setup.Ay, []bool{i%2 == 0})
		if err != nil {
			t.Fatalf("failed to build choice: %v", err)
		}

		entries[i] = &OTReceiverEntry{
			ReceiverBundle: bundle,
			Index:          i,
			Used:           false,
		}
	}
	pool.AddEntries(entries)

	// Consume entries starting at index 0
	consumed, err := pool.Consume(0, 5)
	if err != nil {
		t.Fatalf("failed to consume: %v", err)
	}
	if len(consumed) != 5 {
		t.Errorf("expected 5 consumed, got %d", len(consumed))
	}

	// Verify all consumed entries are marked used
	for i, entry := range consumed {
		if !entry.Used {
			t.Errorf("entry %d should be marked used", i)
		}
	}

	// Try to consume same entries again - should fail
	_, err = pool.Consume(0, 5)
	if err == nil {
		t.Error("expected error when consuming already used entries")
	}

	// Consume remaining entries
	consumed, err = pool.Consume(5, 5)
	if err != nil {
		t.Fatalf("failed to consume remaining: %v", err)
	}
	if len(consumed) != 5 {
		t.Errorf("expected 5 consumed, got %d", len(consumed))
	}
}

func TestDualMaskSerialization(t *testing.T) {
	// Create labels using proper Label type
	masks := []DualMask{
		{M0: createLabel(0x01, 0x02, 0x03), M1: createLabel(0x04, 0x05, 0x06), Delta: createLabel(0x07, 0x08, 0x09)},
		{M0: createLabel(0x11, 0x12, 0x13), M1: createLabel(0x14, 0x15, 0x16), Delta: createLabel(0x17, 0x18, 0x19)},
	}

	serialized := SerializeDualMasks(masks)
	if len(serialized) == 0 {
		t.Fatal("serialized dual masks is empty")
	}

	deserialized, err := DeserializeDualMasks(serialized)
	if err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	if len(deserialized) != len(masks) {
		t.Fatalf("expected %d masks, got %d", len(masks), len(deserialized))
	}

	for i := range masks {
		if !labelsEqual(deserialized[i].M0, masks[i].M0) {
			t.Errorf("mask %d M0 mismatch", i)
		}
		if !labelsEqual(deserialized[i].M1, masks[i].M1) {
			t.Errorf("mask %d M1 mismatch", i)
		}
		if !labelsEqual(deserialized[i].Delta, masks[i].Delta) {
			t.Errorf("mask %d Delta mismatch", i)
		}
	}
}

// Helper function to create a Label for testing
func createLabel(d0, d1, d2 byte) ot.Label {
	return ot.Label{
		D0: uint64(d0)<<56 | uint64(d1)<<48 | uint64(d2)<<40,
		D1: 0,
	}
}

// Helper function to compare labels
func labelsEqual(a, b ot.Label) bool {
	return a == b
}
