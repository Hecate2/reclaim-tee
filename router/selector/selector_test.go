package selector

import (
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
)

const (
	staleness        = 15 * time.Second
	controlUnhealthy = 30 * time.Second
	otNotReady       = 60 * time.Second
)

var now = time.Now()

func readyPair(id string) *store.Pair {
	return &store.Pair{
		ID:       id,
		TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
		LastHeartbeatK: now, LastHeartbeatT: now,
		ControlHealthyK: true, ControlHealthyT: true,
		OTReadyK: true, OTReadyT: true,
	}
}

func TestPickReadyPair_EmptyPool(t *testing.T) {
	_, err := PickReadyPair(nil, now, staleness, controlUnhealthy, otNotReady)
	if !errors.Is(err, ErrNoReadyPairs) {
		t.Fatalf("expected ErrNoReadyPairs, got %v", err)
	}
}

func TestPickReadyPair_NoReady(t *testing.T) {
	// All pairs are in non-Ready states.
	pairs := []*store.Pair{
		{ID: "registering", TEEKAddr: "10.0.0.1:443"}, // only K registered
		{ID: "dead",
			TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
			LastHeartbeatK: now.Add(-1 * time.Hour),
		},
		{ID: "draining", Draining: true,
			TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
			LastHeartbeatK: now, LastHeartbeatT: now,
		},
	}
	_, err := PickReadyPair(pairs, now, staleness, controlUnhealthy, otNotReady)
	if !errors.Is(err, ErrNoReadyPairs) {
		t.Fatalf("expected ErrNoReadyPairs, got %v", err)
	}
}

func TestPickReadyPair_SingleReady(t *testing.T) {
	p := readyPair("only")
	picked, err := PickReadyPair([]*store.Pair{p}, now, staleness, controlUnhealthy, otNotReady)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if picked.ID != "only" {
		t.Fatalf("picked %q", picked.ID)
	}
}

func TestPickReadyPair_SkipsNonReady(t *testing.T) {
	// One ready + one draining + one dead. Must always pick the ready one.
	ready := readyPair("ready")
	pairs := []*store.Pair{
		{ID: "dead",
			TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
			LastHeartbeatK: now.Add(-1 * time.Hour),
		},
		ready,
		{ID: "draining", Draining: true,
			TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
			LastHeartbeatK: now, LastHeartbeatT: now,
		},
	}
	for range 20 {
		picked, err := PickReadyPair(pairs, now, staleness, controlUnhealthy, otNotReady)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID != "ready" {
			t.Fatalf("expected 'ready', got %q", picked.ID)
		}
	}
}

func TestPickReadyPair_MultipleReady_DistributesOverTime(t *testing.T) {
	// With several Ready pairs and many picks, every pair should be selected
	// at least once. This is a probabilistic check on uniform-random selection.
	pairs := []*store.Pair{
		readyPair("a"), readyPair("b"), readyPair("c"),
	}
	seen := map[string]int{}
	for range 200 {
		picked, err := PickReadyPair(pairs, now, staleness, controlUnhealthy, otNotReady)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		seen[picked.ID]++
	}
	for _, id := range []string{"a", "b", "c"} {
		if seen[id] == 0 {
			t.Fatalf("pair %q was never picked across 200 calls", id)
		}
	}
}

func TestPickReadyPair_DoesNotMutateInput(t *testing.T) {
	// PickReadyPair must not reorder or truncate the caller's slice.
	pairs := []*store.Pair{
		readyPair("a"), readyPair("b"), readyPair("c"),
	}
	originalLen := len(pairs)
	originalIDs := []string{pairs[0].ID, pairs[1].ID, pairs[2].ID}
	_, _ = PickReadyPair(pairs, now, staleness, controlUnhealthy, otNotReady)
	if len(pairs) != originalLen {
		t.Fatalf("input slice length changed: %d -> %d", originalLen, len(pairs))
	}
	for i, id := range originalIDs {
		if pairs[i].ID != id {
			t.Fatalf("input slice reordered: pos %d was %q, now %q", i, id, pairs[i].ID)
		}
	}
}
