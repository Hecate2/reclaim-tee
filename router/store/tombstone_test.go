package store

import (
	"testing"
	"time"
)

func TestMemoryStore_Tombstone(t *testing.T) {
	s := NewMemoryStore()
	ctx := t.Context()
	now := time.Unix(1_700_000_000, 0)

	if err := s.Tombstone(ctx, "pair-A", now.Add(5*time.Minute)); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}

	// Present and unexpired.
	got, err := s.IsTombstoned(ctx, "pair-A", now.Add(time.Second))
	if err != nil || !got {
		t.Fatalf("expected tombstoned, got %v err=%v", got, err)
	}
	// Unknown id.
	got, _ = s.IsTombstoned(ctx, "pair-B", now)
	if got {
		t.Fatal("unknown pair should not be tombstoned")
	}
	// Expired → false, and lazily removed.
	got, _ = s.IsTombstoned(ctx, "pair-A", now.Add(6*time.Minute))
	if got {
		t.Fatal("expired tombstone should not be contained")
	}
	if _, ok := s.tombstones["pair-A"]; ok {
		t.Fatal("expired tombstone should be swept on read")
	}
}
