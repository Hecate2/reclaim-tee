// Package selector picks a ready pair to allocate to a new client session.
// Phase A: uniform random over ready pairs. Phase B (later) adds geo-affinity.
package selector

import (
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
)

// ErrNoReadyPairs is returned when no pair is currently allocatable.
var ErrNoReadyPairs = errors.New("no ready pairs available")

// PickReadyPair filters pairs to those whose EffectiveStatus is Ready and
// returns one chosen uniformly at random.
func PickReadyPair(
	pairs []*store.Pair,
	now time.Time,
	heartbeatStaleness, controlUnhealthy, otNotReady time.Duration,
) (*store.Pair, error) {
	ready := make([]*store.Pair, 0, len(pairs))
	for _, p := range pairs {
		if p.EffectiveStatus(now, heartbeatStaleness, controlUnhealthy, otNotReady) == store.StatusReady {
			ready = append(ready, p)
		}
	}
	if len(ready) == 0 {
		return nil, ErrNoReadyPairs
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(ready))))
	if err != nil {
		return nil, err
	}
	return ready[n.Int64()], nil
}
