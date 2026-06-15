package oprfmpc

import "testing"

// TestPoolResumeContinuity proves that a resume (which mutates neither pool)
// leaves sender/receiver consumption consistent for a NON-ZERO counter:
// TEE_K keeps reserving from where it left off, TEE_T keeps consuming at the
// absolute indices TEE_K dictates, and already-consumed entries stay protected.
func TestPoolResumeContinuity(t *testing.T) {
	const total = 100
	sender := NewOTPool(total)
	receiver := NewOTReceiverPool(total)
	for range total {
		sender.AddEntry(&OTPoolEntry{})
	}
	rEntries := make([]*OTReceiverEntry, total)
	for i := range rEntries {
		rEntries[i] = &OTReceiverEntry{}
	}
	receiver.AddEntries(rEntries)

	// Pre-disconnect: consume 50 OTs. TEE_K reserves [0,50); TEE_T consumes the
	// matching absolute indices.
	start, _, err := sender.Reserve(50)
	if err != nil || start != 0 {
		t.Fatalf("pre-reserve: start=%d err=%v, want start=0", start, err)
	}
	if _, err := receiver.Consume(0, 50); err != nil {
		t.Fatalf("pre-consume [0,50): %v", err)
	}

	// --- resume happens here: neither pool is touched (counter = 50) ---

	// Post-resume: TEE_K must continue at index 50, not rewind to 0.
	start2, _, err := sender.Reserve(10)
	if err != nil {
		t.Fatalf("post-reserve: %v", err)
	}
	if start2 != 50 {
		t.Fatalf("counter rewound across resume: post-reserve start=%d, want 50", start2)
	}
	if _, err := receiver.Consume(50, 10); err != nil {
		t.Fatalf("post-consume [50,60): %v", err)
	}

	// Replay guard survives the resume: a previously consumed index must still
	// be rejected (Used flags retained, not reset).
	if _, err := receiver.Consume(40, 5); err == nil {
		t.Fatal("expected replay error re-consuming [40,45) after resume, got nil")
	}

	// Sanity: nothing double-reserved on the sender side either.
	if got := sender.Available(); got != total-60 {
		t.Fatalf("sender available=%d, want %d", got, total-60)
	}
}
