package selector

import (
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/geo"
	"github.com/reclaimprotocol/reclaim-tee/router/store"
)

const (
	staleness        = 15 * time.Second
	controlUnhealthy = 30 * time.Second
	otNotReady       = 60 * time.Second
)

var now = time.Now()

// acceptAll = a current client that can verify every migration generation.
var acceptAll = []string{"cs", "sev-snp", "secure-boot"}

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
	_, err := PickReadyPair(nil, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
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
	_, err := PickReadyPair(pairs, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
	if !errors.Is(err, ErrNoReadyPairs) {
		t.Fatalf("expected ErrNoReadyPairs, got %v", err)
	}
}

func TestPickReadyPair_SingleReady(t *testing.T) {
	p := readyPair("only")
	picked, err := PickReadyPair([]*store.Pair{p}, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
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
		picked, err := PickReadyPair(pairs, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
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
		picked, err := PickReadyPair(pairs, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
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
	_, _ = PickReadyPair(pairs, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
	if len(pairs) != originalLen {
		t.Fatalf("input slice length changed: %d -> %d", originalLen, len(pairs))
	}
	for i, id := range originalIDs {
		if pairs[i].ID != id {
			t.Fatalf("input slice reordered: pos %d was %q, now %q", i, id, pairs[i].ID)
		}
	}
}

func readyPairTyped(id, attType string) *store.Pair {
	p := readyPair(id)
	p.AttestationType = attType
	return p
}

func TestPickReadyPair_GatesByAttestationType(t *testing.T) {
	snp := readyPairTyped("snp", "sev-snp")
	pairs := []*store.Pair{
		readyPairTyped("cs", "cs"),
		snp,
		readyPair("legacy"), // no AttestationType -> treated as CS
	}

	// CS-only client must never be handed the SEV-SNP pair.
	for range 50 {
		picked, err := PickReadyPair(pairs, []string{"cs"}, now, staleness, controlUnhealthy, otNotReady, nil)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID == "snp" {
			t.Fatalf("CS-only client was handed the SEV-SNP pair")
		}
	}

	// SEV-SNP-only client gets only the SEV-SNP pair.
	for range 50 {
		picked, err := PickReadyPair(pairs, []string{"sev-snp"}, now, staleness, controlUnhealthy, otNotReady, nil)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID != "snp" {
			t.Fatalf("SEV-SNP client got %q, want snp", picked.ID)
		}
	}

	// CS-only client with only SEV-SNP pairs available => nothing allocatable.
	_, err := PickReadyPair([]*store.Pair{snp}, []string{"cs"}, now, staleness, controlUnhealthy, otNotReady, nil)
	if !errors.Is(err, ErrNoReadyPairs) {
		t.Fatalf("expected ErrNoReadyPairs for CS client vs SNP-only pool, got %v", err)
	}
}

func TestPickReadyPair_PrefersSNPWhenClientSupportsIt(t *testing.T) {
	snp := readyPairTyped("snp", "sev-snp")
	pairs := []*store.Pair{
		readyPairTyped("cs1", "cs"),
		readyPair("cs2"), // untyped -> CS
		snp,
	}
	// Client accepts BOTH cs+snp: must always get the SNP pair when one is
	// ready, so CS capacity is reserved for genuinely legacy clients.
	for range 100 {
		picked, err := PickReadyPair(pairs, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID != "snp" {
			t.Fatalf("SNP-capable client got %q, want snp (SNP must win over CS)", picked.ID)
		}
	}

	// Fallback: no SNP pair ready => SNP-capable client is still served a CS pair.
	csOnly := []*store.Pair{readyPairTyped("cs1", "cs"), readyPair("cs2")}
	if _, err := PickReadyPair(csOnly, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil); err != nil {
		t.Fatalf("SNP-capable client must fall back to CS when no SNP ready: %v", err)
	}

	// SNP preference overrides geo: an Asia client with a NEAR CS pair and a
	// FAR SNP pair must still get the SNP pair (this is what stops SNP clients
	// from being geo-routed onto the CS pair).
	nearCS := readyPairTyped("nearCS", "cs")
	nearCS.TEEKRegion, nearCS.TEETRegion = "asia-south1", "asia-south1"
	farSNP := readyPairTyped("farSNP", "sev-snp")
	farSNP.TEEKRegion, farSNP.TEETRegion = "us-central1", "us-east-2"
	mumbai := &geo.LatLon{Lat: 19.0, Lon: 72.8}
	for range 50 {
		picked, err := PickReadyPair([]*store.Pair{nearCS, farSNP}, acceptAll, now, staleness, controlUnhealthy, otNotReady, mumbai)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID != "farSNP" {
			t.Fatalf("SNP-capable Asia client got %q, want farSNP (SNP preference must beat geo)", picked.ID)
		}
	}
}

func TestPickReadyPair_PrefersSecureBootThenFallsBack(t *testing.T) {
	secure := readyPairTyped("secure", "secure-boot")
	sev2 := readyPairTyped("sev2", "sev-snp")
	cs := readyPairTyped("cs", "cs")

	for range 50 {
		picked, err := PickReadyPair([]*store.Pair{cs, sev2, secure}, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID != "secure" {
			t.Fatalf("current client got %q, want secure", picked.ID)
		}
	}

	oldClient := []string{"cs", "sev-snp"}
	for range 50 {
		picked, err := PickReadyPair([]*store.Pair{cs, sev2, secure}, oldClient, now, staleness, controlUnhealthy, otNotReady, nil)
		if err != nil {
			t.Fatalf("old-client pick: %v", err)
		}
		if picked.ID != "sev2" {
			t.Fatalf("old client got %q, want sev2", picked.ID)
		}
	}

	secureOnly := []string{"secure-boot"}
	picked, err := PickReadyPair([]*store.Pair{cs, sev2, secure}, secureOnly, now, staleness, controlUnhealthy, otNotReady, nil)
	if err != nil || picked.ID != "secure" {
		t.Fatalf("secure-only pick = %v, %v; want secure", picked, err)
	}
}

func TestPickReadyPair_GeoAffinity(t *testing.T) {
	near := readyPair("near")
	near.TEEKRegion, near.TEETRegion = "asia-south1", "asia-south1"
	far := readyPair("far")
	far.TEEKRegion, far.TEETRegion = "us-central1", "us-east-2"
	pairs := []*store.Pair{far, near}
	mumbai := &geo.LatLon{Lat: 19.0, Lon: 72.8}

	// A located client must always get the nearer (asia-south1) pair.
	for range 50 {
		picked, err := PickReadyPair(pairs, acceptAll, now, staleness, controlUnhealthy, otNotReady, mumbai)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID != "near" {
			t.Fatalf("located client got %q, want near", picked.ID)
		}
	}

	// No client location => random fallback; must still return a ready pair.
	if _, err := PickReadyPair(pairs, acceptAll, now, staleness, controlUnhealthy, otNotReady, nil); err != nil {
		t.Fatalf("nil-geo fallback: %v", err)
	}

	// A geo-located pair is preferred over a pair whose regions are unknown.
	unloc := readyPair("unloc")
	for range 50 {
		picked, err := PickReadyPair([]*store.Pair{unloc, near}, acceptAll, now, staleness, controlUnhealthy, otNotReady, mumbai)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if picked.ID != "near" {
			t.Fatalf("located client got %q, want the geo-located pair", picked.ID)
		}
	}
}
