package handlers

import (
	"context"
	"errors"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

// staleRowGCMultiplier × HeartbeatStaleness is the threshold past which a
// pair with no recent heartbeats from either side is considered gone for
// good. Generous on purpose — transient network blips shouldn't trigger.
const staleRowGCMultiplier = 10

// staleRowGCInterval is how often the background sweep runs.
const staleRowGCInterval = 30 * time.Second

var errGCPreconditionMissed = errors.New("pair recovered before GC could delete it")

// RunStaleRowGC sweeps the Store periodically and deletes pair rows whose
// K AND T last_heartbeat are both older than staleRowGCMultiplier × the
// configured HeartbeatStaleness. Catches orphans from killed VMs, retired
// pairs that resurrected via re-register before tombstones expired,
// and anything else that left a stale row behind.
func (s *Server) RunStaleRowGC(ctx context.Context) {
	threshold := time.Duration(staleRowGCMultiplier) * s.Config.HeartbeatStaleness
	s.Logger.Info("stale-row GC starting",
		zap.Duration("interval", staleRowGCInterval),
		zap.Duration("threshold", threshold))

	ticker := time.NewTicker(staleRowGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepStaleRows(ctx, threshold)
		}
	}
}

func (s *Server) sweepStaleRows(ctx context.Context, threshold time.Duration) {
	pairs, err := s.Store.ListPairs(ctx)
	if err != nil {
		s.Logger.Warn("stale-row GC: list pairs failed", zap.Error(err))
		return
	}
	now := time.Now()
	for _, p := range pairs {
		if !bothHeartbeatsStale(p, now, threshold) {
			continue
		}
		err := s.Store.DeletePairIf(ctx, p.ID, func(cur *store.Pair) error {
			if !bothHeartbeatsStale(cur, time.Now(), threshold) {
				return errGCPreconditionMissed
			}
			return nil
		})
		if errors.Is(err, errGCPreconditionMissed) {
			continue
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.Logger.Warn("stale-row GC: delete failed",
				zap.String("pair_id", p.ID), zap.Error(err))
			continue
		}
		s.Logger.Info("stale-row GC: deleted",
			zap.String("pair_id", p.ID),
			zap.String("teek_addr", p.TEEKAddr),
			zap.String("teet_addr", p.TEETAddr),
			zap.Time("last_hb_k", p.LastHeartbeatK),
			zap.Time("last_hb_t", p.LastHeartbeatT))
	}
}

// bothHeartbeatsStale checks that BOTH sides are silent beyond threshold.
// A row with one side never registered (e.g. registering pair mid-creation)
// is treated as not-stale to avoid GC racing with a half-registered pair.
func bothHeartbeatsStale(p *store.Pair, now time.Time, threshold time.Duration) bool {
	if p.TEEKAddr == "" || p.TEETAddr == "" {
		return false
	}
	return now.Sub(p.LastHeartbeatK) > threshold && now.Sub(p.LastHeartbeatT) > threshold
}
