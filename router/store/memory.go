package store

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-process implementation of Store, used for local
// development and tests. The production deployment uses a Firestore-backed
// Store that is added later.
type MemoryStore struct {
	mu         sync.RWMutex
	pairs      map[string]*Pair
	digests    map[string]struct{}
	tombstones map[string]time.Time // pair_id -> expiry
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		pairs:      make(map[string]*Pair),
		digests:    make(map[string]struct{}),
		tombstones: make(map[string]time.Time),
	}
}

func (s *MemoryStore) Tombstone(_ context.Context, pairID string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tombstones[pairID] = until
	return nil
}

func (s *MemoryStore) IsTombstoned(_ context.Context, pairID string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tombstones[pairID]
	if !ok {
		return false, nil
	}
	if !now.Before(exp) {
		delete(s.tombstones, pairID)
		return false, nil
	}
	return true, nil
}

func (s *MemoryStore) GetPair(_ context.Context, id string) (*Pair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pairs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return new(*p), nil
}

func (s *MemoryStore) UpsertPair(_ context.Context, p *Pair) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pairs[p.ID] = new(*p)
	return nil
}

func (s *MemoryStore) ListPairs(_ context.Context) ([]*Pair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Pair, 0, len(s.pairs))
	for _, p := range s.pairs {
		out = append(out, new(*p))
	}
	return out, nil
}

func (s *MemoryStore) DeletePair(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pairs[id]; !ok {
		return ErrNotFound
	}
	delete(s.pairs, id)
	return nil
}

func (s *MemoryStore) MutatePair(_ context.Context, id string, fn func(p *Pair, exists bool) error) (*Pair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.pairs[id]
	var p Pair
	if ok {
		p = *cur
	} else {
		p.ID = id
	}
	if err := fn(&p, ok); err != nil {
		return nil, err
	}
	s.pairs[id] = &p
	return new(p), nil
}

func (s *MemoryStore) DeletePairIf(_ context.Context, id string, fn func(*Pair) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.pairs[id]
	if !ok {
		return ErrNotFound
	}
	if err := fn(new(*cur)); err != nil {
		return err
	}
	delete(s.pairs, id)
	return nil
}

func (s *MemoryStore) ListDigests(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.digests))
	for d := range s.digests {
		out = append(out, d)
	}
	return out, nil
}

func (s *MemoryStore) AddDigest(_ context.Context, digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.digests[digest] = struct{}{}
	return nil
}

func (s *MemoryStore) RemoveDigest(_ context.Context, digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.digests, digest)
	return nil
}
