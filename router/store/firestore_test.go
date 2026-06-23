package store

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestPairDocRoundTrip is a pure-function test that doesn't need any
// Firestore connection. It guarantees the on-disk schema mapping doesn't
// silently drop or rename a field.
func TestPairDocRoundTrip(t *testing.T) {
	original := &Pair{
		ID:                     "pair-id",
		TEEKAddr:               "10.0.0.1:443",
		TEETAddr:               "10.0.0.2:443",
		TEEKImageDigest:        "sha256:k",
		TEETImageDigest:        "sha256:t",
		Region:                 "asia-south2",
		LastHeartbeatK:         time.Unix(100, 0).UTC(),
		LastHeartbeatT:         time.Unix(200, 0).UTC(),
		ControlHealthyK:        true,
		ControlHealthyT:        false,
		OTReadyK:               true,
		OTReadyT:               false,
		ControlUnhealthySinceK: time.Unix(150, 0).UTC(),
		ControlUnhealthySinceT: time.Unix(250, 0).UTC(),
		OTUnreadySinceK:        time.Unix(300, 0).UTC(),
		OTUnreadySinceT:        time.Unix(350, 0).UTC(),
		ActiveSessions:         7,
		Draining:               true,
		RegisteredAt:           time.Unix(50, 0).UTC(),
		ReadyAt:                time.Unix(75, 0).UTC(),
	}

	roundTripped := fromPair(original).toPair(original.ID)
	if *roundTripped != *original {
		t.Fatalf("round trip mismatch:\n  want: %+v\n  got:  %+v", original, roundTripped)
	}
}

// TestFirestore_Integration runs against the Firestore emulator if available.
// Start the emulator with:
//
//	gcloud emulators firestore start --host-port=localhost:8085
//	export FIRESTORE_EMULATOR_HOST=localhost:8085
//
// Without FIRESTORE_EMULATOR_HOST, the test skips.
func TestFirestore_Integration(t *testing.T) {
	if os.Getenv("FIRESTORE_EMULATOR_HOST") == "" {
		t.Skip("FIRESTORE_EMULATOR_HOST not set; skipping integration test")
	}
	ctx := t.Context()
	store, err := NewFirestoreStore(ctx, "test-project", "")
	if err != nil {
		t.Fatalf("new firestore store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const id = "00000000-0000-0000-0000-00000000aaaa"
	t.Cleanup(func() { _ = store.DeletePair(ctx, id) })

	// Get of missing → ErrNotFound.
	if _, err := store.GetPair(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Upsert + Get round-trip.
	want := &Pair{
		ID:             id,
		TEEKAddr:       "10.0.0.1:443",
		TEETAddr:       "10.0.0.2:443",
		Region:         "asia-south2",
		LastHeartbeatK: time.Now().Truncate(time.Microsecond),
		ActiveSessions: 3,
	}
	if err := store.UpsertPair(ctx, want); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := store.GetPair(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TEEKAddr != want.TEEKAddr || got.ActiveSessions != want.ActiveSessions {
		t.Fatalf("get mismatch: got=%+v want=%+v", got, want)
	}

	// List finds the doc.
	pairs, err := store.ListPairs(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, p := range pairs {
		if p.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatal("upserted doc not found in ListPairs")
	}

	// Delete of present → nil; subsequent Get → ErrNotFound.
	if err := store.DeletePair(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.GetPair(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-delete get: expected ErrNotFound, got %v", err)
	}

	// Delete of missing → ErrNotFound (interface contract).
	if err := store.DeletePair(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: expected ErrNotFound, got %v", err)
	}
}
