// Package selector picks a ready pair to allocate to a new client session.
// Phase A: uniform random over ready pairs. Phase B (later) adds geo-affinity.
package selector

import (
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

// ErrNoReadyPairs is returned when no pair is currently allocatable.
var ErrNoReadyPairs = errors.New("no ready pairs available")

// PairAttestationType is a pair's attestation type, defaulting an unset value
// (legacy pairs registered before the field existed) to CS.
func PairAttestationType(p *store.Pair) string {
	if p.AttestationType == "" {
		return shared.AttestationTypeCS
	}
	return p.AttestationType
}

// PickReadyPair filters pairs to those whose EffectiveStatus is Ready AND whose
// attestation type the client accepts, then returns one chosen uniformly at
// random. accepts must be non-empty: the handler defaults a missing list to
// {cs} so a legacy (CS-only) client is never handed an SEV-SNP pair it can't
// verify.
func PickReadyPair(
	pairs []*store.Pair,
	accepts []string,
	now time.Time,
	heartbeatStaleness, controlUnhealthy, otNotReady time.Duration,
) (*store.Pair, error) {
	ready := make([]*store.Pair, 0, len(pairs))
	for _, p := range pairs {
		if p.EffectiveStatus(now, heartbeatStaleness, controlUnhealthy, otNotReady) != store.StatusReady {
			continue
		}
		if !accepted(accepts, PairAttestationType(p)) {
			continue
		}
		ready = append(ready, p)
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

func accepted(accepts []string, t string) bool {
	for _, a := range accepts {
		if a == t {
			return true
		}
	}
	return false
}
