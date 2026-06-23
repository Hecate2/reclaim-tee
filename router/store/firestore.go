package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FirestoreCollection is the Firestore collection name for pair records.
const FirestoreCollection = "pairs"

// firestoreDigestCollection holds the approved-image-digest allowlist.
// Doc ID = the digest itself (sha256:... — no Firestore-illegal chars).
// The doc body is empty placeholder; existence is the only signal.
const firestoreDigestCollection = "approved_digests"

// firestoreTombstoneCollection holds recently-retired pair_ids. Doc ID =
// pair_id; body carries the expiry. Read on /register, written on /dead.
const firestoreTombstoneCollection = "tombstones"

type tombstoneDoc struct {
	Expiry time.Time `firestore:"expiry"`
}

// FirestoreStore implements Store against Firestore Native mode.
//
// Documents are keyed by pair_id. Field names are tagged explicitly so a Go
// struct rename doesn't silently shift the on-disk schema.
type FirestoreStore struct {
	client *firestore.Client
}

// NewFirestoreStore builds a FirestoreStore bound to the named GCP project.
// databaseID selects a named Firestore database; empty means "(default)".
func NewFirestoreStore(ctx context.Context, projectID, databaseID string) (*FirestoreStore, error) {
	var client *firestore.Client
	var err error
	if databaseID == "" {
		client, err = firestore.NewClient(ctx, projectID)
	} else {
		client, err = firestore.NewClientWithDatabase(ctx, projectID, databaseID)
	}
	if err != nil {
		return nil, fmt.Errorf("firestore client: %w", err)
	}
	return &FirestoreStore{client: client}, nil
}

// Close releases the Firestore client. Safe to defer in main().
func (s *FirestoreStore) Close() error {
	return s.client.Close()
}

func (s *FirestoreStore) GetPair(ctx context.Context, id string) (*Pair, error) {
	snap, err := s.client.Collection(FirestoreCollection).Doc(id).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("firestore get: %w", err)
	}
	var doc pairDoc
	if err := snap.DataTo(&doc); err != nil {
		return nil, fmt.Errorf("decode pair doc: %w", err)
	}
	return doc.toPair(snap.Ref.ID), nil
}

func (s *FirestoreStore) UpsertPair(ctx context.Context, p *Pair) error {
	_, err := s.client.Collection(FirestoreCollection).Doc(p.ID).Set(ctx, fromPair(p))
	if err != nil {
		return fmt.Errorf("firestore upsert: %w", err)
	}
	return nil
}

func (s *FirestoreStore) MutatePair(ctx context.Context, id string, fn func(p *Pair, exists bool) error) (*Pair, error) {
	ref := s.client.Collection(FirestoreCollection).Doc(id)
	var result *Pair
	err := s.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(ref)
		var p Pair
		exists := true
		switch {
		case status.Code(err) == codes.NotFound:
			exists = false
			p.ID = id
		case err != nil:
			return fmt.Errorf("firestore tx get: %w", err)
		default:
			var doc pairDoc
			if err := snap.DataTo(&doc); err != nil {
				return fmt.Errorf("decode pair doc: %w", err)
			}
			p = *doc.toPair(id)
		}
		if err := fn(&p, exists); err != nil {
			return err
		}
		if err := tx.Set(ref, fromPair(&p)); err != nil {
			return fmt.Errorf("firestore tx set: %w", err)
		}
		result = &p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *FirestoreStore) DeletePairIf(ctx context.Context, id string, fn func(*Pair) error) error {
	ref := s.client.Collection(FirestoreCollection).Doc(id)
	return s.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(ref)
		if status.Code(err) == codes.NotFound {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("firestore tx get: %w", err)
		}
		var doc pairDoc
		if err := snap.DataTo(&doc); err != nil {
			return fmt.Errorf("decode pair doc: %w", err)
		}
		p := doc.toPair(id)
		if err := fn(p); err != nil {
			return err
		}
		if err := tx.Delete(ref); err != nil {
			return fmt.Errorf("firestore tx delete: %w", err)
		}
		return nil
	})
}

func (s *FirestoreStore) ListPairs(ctx context.Context) ([]*Pair, error) {
	it := s.client.Collection(FirestoreCollection).Documents(ctx)
	defer it.Stop()

	var pairs []*Pair
	for {
		snap, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("firestore list: %w", err)
		}
		var doc pairDoc
		if err := snap.DataTo(&doc); err != nil {
			return nil, fmt.Errorf("decode pair doc %q: %w", snap.Ref.ID, err)
		}
		pairs = append(pairs, doc.toPair(snap.Ref.ID))
	}
	return pairs, nil
}

// DeletePair preserves the interface contract by checking existence first.
// Firestore's Delete is idempotent by default; without this read we'd never
// return ErrNotFound and admin /dead would always 204 even for typos.
func (s *FirestoreStore) DeletePair(ctx context.Context, id string) error {
	ref := s.client.Collection(FirestoreCollection).Doc(id)
	if _, err := ref.Get(ctx); err != nil {
		if status.Code(err) == codes.NotFound {
			return ErrNotFound
		}
		return fmt.Errorf("firestore precheck: %w", err)
	}
	if _, err := ref.Delete(ctx); err != nil {
		return fmt.Errorf("firestore delete: %w", err)
	}
	return nil
}

func (s *FirestoreStore) ListDigests(ctx context.Context) ([]string, error) {
	it := s.client.Collection(firestoreDigestCollection).Documents(ctx)
	defer it.Stop()
	var digests []string
	for {
		snap, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("firestore list digests: %w", err)
		}
		digests = append(digests, snap.Ref.ID)
	}
	return digests, nil
}

func (s *FirestoreStore) AddDigest(ctx context.Context, digest string) error {
	// Empty body — existence of the doc IS the entry. Set is idempotent;
	// re-adding an already-present digest is a no-op.
	_, err := s.client.Collection(firestoreDigestCollection).Doc(digest).Set(ctx, map[string]any{})
	if err != nil {
		return fmt.Errorf("firestore add digest: %w", err)
	}
	return nil
}

func (s *FirestoreStore) RemoveDigest(ctx context.Context, digest string) error {
	// Idempotent: deleting a missing doc is not an error here. Operators
	// retrying a fleet drain shouldn't see 404s for digests that some
	// concurrent op already removed.
	_, err := s.client.Collection(firestoreDigestCollection).Doc(digest).Delete(ctx)
	if err != nil {
		return fmt.Errorf("firestore remove digest: %w", err)
	}
	return nil
}

// pairDoc is the Firestore on-disk schema for a Pair. Decoupled from the
// in-memory Pair so the persistence schema can evolve independently of the
// in-process model. ID is excluded — Firestore uses the document key.
type pairDoc struct {
	TEEKAddr        string `firestore:"teek_addr"`
	TEETAddr        string `firestore:"teet_addr"`
	TEEKImageDigest string `firestore:"teek_image_digest"`
	TEETImageDigest string `firestore:"teet_image_digest"`
	Region          string `firestore:"region"`
	AttestationType string `firestore:"attestation_type"`

	LastHeartbeatK         time.Time `firestore:"last_heartbeat_k"`
	LastHeartbeatT         time.Time `firestore:"last_heartbeat_t"`
	ControlHealthyK        bool      `firestore:"control_healthy_k"`
	ControlHealthyT        bool      `firestore:"control_healthy_t"`
	OTReadyK               bool      `firestore:"ot_ready_k"`
	OTReadyT               bool      `firestore:"ot_ready_t"`
	ControlUnhealthySinceK time.Time `firestore:"control_unhealthy_since_k"`
	ControlUnhealthySinceT time.Time `firestore:"control_unhealthy_since_t"`
	OTUnreadySinceK        time.Time `firestore:"ot_unready_since_k"`
	OTUnreadySinceT        time.Time `firestore:"ot_unready_since_t"`
	ActiveSessions         int       `firestore:"active_sessions"`

	Draining     bool      `firestore:"draining"`
	RegisteredAt time.Time `firestore:"registered_at"`
	ReadyAt      time.Time `firestore:"ready_at"`
}

func fromPair(p *Pair) pairDoc {
	return pairDoc{
		TEEKAddr:               p.TEEKAddr,
		TEETAddr:               p.TEETAddr,
		TEEKImageDigest:        p.TEEKImageDigest,
		TEETImageDigest:        p.TEETImageDigest,
		Region:                 p.Region,
		AttestationType:        p.AttestationType,
		LastHeartbeatK:         p.LastHeartbeatK,
		LastHeartbeatT:         p.LastHeartbeatT,
		ControlHealthyK:        p.ControlHealthyK,
		ControlHealthyT:        p.ControlHealthyT,
		OTReadyK:               p.OTReadyK,
		OTReadyT:               p.OTReadyT,
		ControlUnhealthySinceK: p.ControlUnhealthySinceK,
		ControlUnhealthySinceT: p.ControlUnhealthySinceT,
		OTUnreadySinceK:        p.OTUnreadySinceK,
		OTUnreadySinceT:        p.OTUnreadySinceT,
		ActiveSessions:         p.ActiveSessions,
		Draining:               p.Draining,
		RegisteredAt:           p.RegisteredAt,
		ReadyAt:                p.ReadyAt,
	}
}

func (d pairDoc) toPair(id string) *Pair {
	return &Pair{
		ID:                     id,
		TEEKAddr:               d.TEEKAddr,
		TEETAddr:               d.TEETAddr,
		TEEKImageDigest:        d.TEEKImageDigest,
		TEETImageDigest:        d.TEETImageDigest,
		Region:                 d.Region,
		AttestationType:        d.AttestationType,
		LastHeartbeatK:         d.LastHeartbeatK,
		LastHeartbeatT:         d.LastHeartbeatT,
		ControlHealthyK:        d.ControlHealthyK,
		ControlHealthyT:        d.ControlHealthyT,
		OTReadyK:               d.OTReadyK,
		OTReadyT:               d.OTReadyT,
		ControlUnhealthySinceK: d.ControlUnhealthySinceK,
		ControlUnhealthySinceT: d.ControlUnhealthySinceT,
		OTUnreadySinceK:        d.OTUnreadySinceK,
		OTUnreadySinceT:        d.OTUnreadySinceT,
		ActiveSessions:         d.ActiveSessions,
		Draining:               d.Draining,
		RegisteredAt:           d.RegisteredAt,
		ReadyAt:                d.ReadyAt,
	}
}

func (s *FirestoreStore) Tombstone(ctx context.Context, pairID string, until time.Time) error {
	_, err := s.client.Collection(firestoreTombstoneCollection).Doc(pairID).Set(ctx, tombstoneDoc{Expiry: until})
	if err != nil {
		return fmt.Errorf("firestore tombstone: %w", err)
	}
	return nil
}

func (s *FirestoreStore) IsTombstoned(ctx context.Context, pairID string, now time.Time) (bool, error) {
	ref := s.client.Collection(firestoreTombstoneCollection).Doc(pairID)
	snap, err := ref.Get(ctx)
	if status.Code(err) == codes.NotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("firestore is-tombstoned: %w", err)
	}
	var doc tombstoneDoc
	if err := snap.DataTo(&doc); err != nil {
		return false, fmt.Errorf("decode tombstone doc: %w", err)
	}
	if !now.Before(doc.Expiry) {
		_, _ = ref.Delete(ctx) // best-effort lazy cleanup of an expired tombstone
		return false, nil
	}
	return true, nil
}
