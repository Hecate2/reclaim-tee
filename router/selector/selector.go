// Package selector picks a ready pair to allocate to a new client session:
// ready + attestation-type-accepted, preferring Secure Boot then SEV-SNP for
// capable clients (so older capacity is reserved for legacy clients), then geo-nearest
// to the client (falling back to uniform random when geo is unavailable).
package selector

import (
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	"slices"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/geo"
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
// clientLoc is the client's location from the LB geo header; nil (unknown)
// keeps the prior uniform-random behavior. When known, pairs whose TEEs we can
// geo-locate are preferred nearest-first (max-distance bottleneck), with a
// random tie-break among equally-near pairs for load balancing; pairs with
// unknown geo are used only when no geo-located pair is available.
func PickReadyPair(
	pairs []*store.Pair,
	accepts []string,
	now time.Time,
	heartbeatStaleness, controlUnhealthy, otNotReady time.Duration,
	clientLoc *geo.LatLon,
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

	// Prefer the newest mutually supported generation. During expansion a new
	// client chooses Secure Boot, falls back to SEV2, then CS. Old clients never
	// list Secure Boot, so they cannot be allocated a pair they cannot verify.
	for _, preferred := range []string{shared.AttestationTypeSecureBoot, shared.AttestationTypeSEVSNP} {
		if !accepted(accepts, preferred) {
			continue
		}
		only := make([]*store.Pair, 0, len(ready))
		for _, p := range ready {
			if PairAttestationType(p) == preferred {
				only = append(only, p)
			}
		}
		if len(only) > 0 {
			ready = only
			break
		}
	}

	if clientLoc != nil {
		var nearest []*store.Pair
		best := math.MaxFloat64
		for _, p := range ready {
			kr, tr := pairRegions(p)
			d, ok := geo.PairDistanceKm(clientLoc.Lat, clientLoc.Lon, kr, tr)
			if !ok {
				continue
			}
			if d < best-1 { // a closer region wins outright
				best, nearest = d, []*store.Pair{p}
			} else if d <= best+1 { // same region (identical centroid) -> tie
				nearest = append(nearest, p)
			}
		}
		if len(nearest) > 0 {
			return pickRandom(nearest)
		}
	}
	return pickRandom(ready)
}

// pairRegions returns each TEE's cloud region, falling back to a live lookup
// from the TEE's stored IP when the cached field is empty. This geo-locates
// pairs that registered before region tracking existed, with no re-register.
func pairRegions(p *store.Pair) (teek, teet string) {
	teek, teet = p.TEEKRegion, p.TEETRegion
	if teek == "" {
		teek = geo.RegionForIP(p.TEEKAddr)
	}
	if teet == "" {
		teet = geo.RegionForIP(p.TEETAddr)
	}
	return teek, teet
}

func pickRandom(pairs []*store.Pair) (*store.Pair, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pairs))))
	if err != nil {
		return nil, err
	}
	return pairs[n.Int64()], nil
}

func accepted(accepts []string, t string) bool {
	return slices.Contains(accepts, t)
}
