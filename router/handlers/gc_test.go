package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

func gcTestServer(t *testing.T) *Server {
	t.Helper()
	st := store.NewMemoryStore()
	allowlist, err := auth.NewAllowlist(t.Context(), st, []string{"sha256:fake"}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	t.Cleanup(allowlist.Stop)
	return &Server{
		Store:     st,
		Logger:    zap.NewNop(),
		Allowlist: allowlist,
		Config: &config.Config{
			HeartbeatStaleness: 15 * time.Second,
		},
	}
}

func putPair(t *testing.T, s *Server, id string, hbAge time.Duration) {
	t.Helper()
	now := time.Now()
	_, err := s.Store.MutatePair(t.Context(), id, func(p *store.Pair, _ bool) error {
		p.TEEKAddr = "10.0.0.1:443"
		p.TEETAddr = "10.0.0.2:443"
		p.LastHeartbeatK = now.Add(-hbAge)
		p.LastHeartbeatT = now.Add(-hbAge)
		return nil
	})
	if err != nil {
		t.Fatalf("seed pair: %v", err)
	}
}

func TestStaleRowGC_DeletesPairWithBothHeartbeatsStale(t *testing.T) {
	s := gcTestServer(t)
	putPair(t, s, "old", 5*time.Minute)
	putPair(t, s, "fresh", 5*time.Second)

	threshold := time.Duration(staleRowGCMultiplier) * s.Config.HeartbeatStaleness
	s.sweepStaleRows(context.Background(), threshold)

	if _, err := s.Store.GetPair(t.Context(), "old"); err == nil {
		t.Fatal("stale pair should have been GC'd")
	}
	if _, err := s.Store.GetPair(t.Context(), "fresh"); err != nil {
		t.Fatalf("fresh pair should survive GC: %v", err)
	}
}

func TestStaleRowGC_IgnoresHalfRegisteredPair(t *testing.T) {
	s := gcTestServer(t)
	now := time.Now()
	_, err := s.Store.MutatePair(t.Context(), "half", func(p *store.Pair, _ bool) error {
		p.TEEKAddr = "10.0.0.1:443"
		// TEETAddr deliberately empty — T side hasn't registered yet.
		p.LastHeartbeatK = now.Add(-5 * time.Minute)
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	threshold := time.Duration(staleRowGCMultiplier) * s.Config.HeartbeatStaleness
	s.sweepStaleRows(context.Background(), threshold)

	if _, err := s.Store.GetPair(t.Context(), "half"); err != nil {
		t.Fatalf("half-registered pair should not be GC'd: %v", err)
	}
}

func TestStaleRowGC_RecoveryRacesDoNotDelete(t *testing.T) {
	s := gcTestServer(t)
	putPair(t, s, "recovering", 5*time.Minute)

	// Simulate the precondition failing: between list and delete the pair's
	// heartbeats refreshed (e.g. K side reconnected). The GC's DeletePairIf
	// re-checks staleness; sweep should leave the row alone.
	threshold := time.Duration(staleRowGCMultiplier) * s.Config.HeartbeatStaleness
	_, _ = s.Store.MutatePair(t.Context(), "recovering", func(p *store.Pair, _ bool) error {
		p.LastHeartbeatK = time.Now()
		p.LastHeartbeatT = time.Now()
		return nil
	})

	s.sweepStaleRows(context.Background(), threshold)

	if _, err := s.Store.GetPair(t.Context(), "recovering"); err != nil {
		t.Fatalf("recovered pair should survive GC: %v", err)
	}
}
