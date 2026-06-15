package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a Pair lookup or delete targets an unknown ID.
var ErrNotFound = errors.New("pair not found")

// Store is the persistence interface for the pair registry. The router
// holds no in-process state of its own; everything observable lives here.
//
// Implementations must be safe for concurrent use.
type Store interface {
	GetPair(ctx context.Context, id string) (*Pair, error)
	UpsertPair(ctx context.Context, p *Pair) error
	ListPairs(ctx context.Context) ([]*Pair, error)
	DeletePair(ctx context.Context, id string) error

	// Atomic read-modify-write. fn receives a non-nil *Pair (zero with ID
	// set when !exists) and is called inside a serialized critical section
	// or Firestore transaction. fn mutates p in place; return nil to commit,
	// non-nil to abort without writing. Returns the committed pair (or the
	// abort error).
	MutatePair(ctx context.Context, id string, fn func(p *Pair, exists bool) error) (*Pair, error)

	// Atomic conditional delete. fn inspects the current pair; return nil
	// to commit the delete, non-nil to abort (that error is returned).
	// Returns ErrNotFound if the pair is absent before fn runs.
	DeletePairIf(ctx context.Context, id string, fn func(*Pair) error) error

	// Approved-image-digest allowlist. Source of truth lives in the store
	// so that admin-API mutations survive router restarts (the env-var
	// seed in config is only consulted on first boot when the store is
	// empty). All three operations are idempotent.
	ListDigests(ctx context.Context) ([]string, error)
	AddDigest(ctx context.Context, digest string) error
	RemoveDigest(ctx context.Context, digest string) error

	// Tombstones record recently-retired pair_ids so a still-running TEE
	// can't re-register one after /dead. Shared via the store so the guard
	// holds across router replicas. Tombstone records pairID with an expiry;
	// IsTombstoned reports whether it's present and not yet expired.
	Tombstone(ctx context.Context, pairID string, until time.Time) error
	IsTombstoned(ctx context.Context, pairID string, now time.Time) (bool, error)
}
