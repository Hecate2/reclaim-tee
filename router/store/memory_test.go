package store

import (
	"errors"
	"sync"
	"testing"
)

func TestMemoryStore_GetMissing(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.GetPair(t.Context(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_UpsertRoundTrip(t *testing.T) {
	s := NewMemoryStore()
	p := &Pair{ID: "p1", TEEKAddr: "10.0.0.1:443"}
	if err := s.UpsertPair(t.Context(), p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.GetPair(t.Context(), "p1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TEEKAddr != "10.0.0.1:443" {
		t.Fatalf("addr round-trip: %+v", got)
	}
}

func TestMemoryStore_DefensiveCopyOnRead(t *testing.T) {
	// Mutating a returned Pair must not affect what's in the store.
	s := NewMemoryStore()
	_ = s.UpsertPair(t.Context(), &Pair{ID: "p1", TEEKAddr: "original"})
	got, _ := s.GetPair(t.Context(), "p1")
	got.TEEKAddr = "tampered"
	got2, _ := s.GetPair(t.Context(), "p1")
	if got2.TEEKAddr != "original" {
		t.Fatalf("defensive copy failed: store mutated to %q", got2.TEEKAddr)
	}
}

func TestMemoryStore_DefensiveCopyOnWrite(t *testing.T) {
	// Mutating a Pair after upserting it must not affect what's in the store.
	s := NewMemoryStore()
	p := &Pair{ID: "p1", TEEKAddr: "original"}
	_ = s.UpsertPair(t.Context(), p)
	p.TEEKAddr = "tampered"
	got, _ := s.GetPair(t.Context(), "p1")
	if got.TEEKAddr != "original" {
		t.Fatalf("defensive copy failed: store mutated to %q", got.TEEKAddr)
	}
}

func TestMemoryStore_DeleteMissing(t *testing.T) {
	s := NewMemoryStore()
	err := s.DeletePair(t.Context(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_List(t *testing.T) {
	s := NewMemoryStore()
	_ = s.UpsertPair(t.Context(), &Pair{ID: "p1"})
	_ = s.UpsertPair(t.Context(), &Pair{ID: "p2"})
	pairs, err := s.ListPairs(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	// Sanity check under -race. 100 concurrent upserts and reads must not
	// produce data races or panics.
	s := NewMemoryStore()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			id := "p"
			_ = s.UpsertPair(t.Context(), &Pair{ID: id, ActiveSessions: i})
			_, _ = s.GetPair(t.Context(), id)
			_, _ = s.ListPairs(t.Context())
		})
	}
	wg.Wait()
}

// N concurrent MutatePair calls each increment ActiveSessions. With proper
// serialization the final value equals N — no lost updates.
func TestMemoryStore_MutatePair_NoLostUpdates(t *testing.T) {
	s := NewMemoryStore()
	const id = "p"
	if _, err := s.MutatePair(t.Context(), id, func(p *Pair, exists bool) error {
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const N = 200
	var wg sync.WaitGroup
	for range N {
		wg.Go(func() {
			_, _ = s.MutatePair(t.Context(), id, func(p *Pair, exists bool) error {
				p.ActiveSessions++
				return nil
			})
		})
	}
	wg.Wait()

	p, err := s.GetPair(t.Context(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if p.ActiveSessions != N {
		t.Fatalf("ActiveSessions = %d, want %d (lost updates)", p.ActiveSessions, N)
	}
}

// MutatePair fn returning an error must NOT write.
func TestMemoryStore_MutatePair_AbortDoesNotWrite(t *testing.T) {
	s := NewMemoryStore()
	const id = "p"
	if _, err := s.MutatePair(t.Context(), id, func(p *Pair, exists bool) error {
		p.ActiveSessions = 42
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	wantErr := errors.New("abort")
	_, err := s.MutatePair(t.Context(), id, func(p *Pair, exists bool) error {
		p.ActiveSessions = 99
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected abort error, got %v", err)
	}
	p, _ := s.GetPair(t.Context(), id)
	if p.ActiveSessions != 42 {
		t.Fatalf("ActiveSessions = %d, want 42 (abort failed to roll back)", p.ActiveSessions)
	}
}

// DeletePairIf must not delete if fn returns an error.
func TestMemoryStore_DeletePairIf(t *testing.T) {
	s := NewMemoryStore()
	const id = "p"
	if err := s.UpsertPair(t.Context(), &Pair{ID: id, ActiveSessions: 5}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	refuse := errors.New("not safe")
	err := s.DeletePairIf(t.Context(), id, func(p *Pair) error {
		if p.ActiveSessions > 0 {
			return refuse
		}
		return nil
	})
	if !errors.Is(err, refuse) {
		t.Fatalf("expected refuse, got %v", err)
	}
	if _, err := s.GetPair(t.Context(), id); err != nil {
		t.Fatalf("pair was deleted despite predicate refusing: %v", err)
	}

	// Now drain to zero and try again.
	if _, err := s.MutatePair(t.Context(), id, func(p *Pair, exists bool) error {
		p.ActiveSessions = 0
		return nil
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := s.DeletePairIf(t.Context(), id, func(p *Pair) error {
		if p.ActiveSessions > 0 {
			return refuse
		}
		return nil
	}); err != nil {
		t.Fatalf("delete-after-drain: %v", err)
	}
	if _, err := s.GetPair(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
