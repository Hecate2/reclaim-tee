package auth

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

// allowlistReloadInterval is how often the in-memory digest cache is
// refreshed from the store. Short enough that admin-API mutations on
// one Cloud Run instance propagate to the others within ops timescale,
// long enough that Firestore read load stays trivial.
const allowlistReloadInterval = 30 * time.Second

// Allowlist is the set of approved TEE image digests. Source of truth
// is the underlying Store; an in-memory cache backs the Contains hot
// path so /register doesn't pay a Firestore round-trip per call.
//
// Constructed via NewAllowlist, which:
//   - reads the current set from the store
//   - if empty AND a seed was provided, writes the seed and uses it
//   - starts a background goroutine that reloads from the store every
//     allowlistReloadInterval, picking up changes made by other router
//     instances
//
// Add/Remove write through to the store synchronously and update the
// in-memory cache atomically with the write.
type Allowlist struct {
	store  store.Store
	logger *zap.Logger

	mu      sync.RWMutex
	digests map[string]struct{}

	stop chan struct{}
}

// NewAllowlist constructs an Allowlist backed by store. If the store
// is empty AND seed is non-empty, the seed is written before the cache
// is populated — this is the "first boot" path where the env var hands
// over operating authority to the store.
//
// Background reload starts before returning so callers don't have to
// remember to start it.
func NewAllowlist(ctx context.Context, st store.Store, seed []string, logger *zap.Logger) (*Allowlist, error) {
	a := &Allowlist{
		store:   st,
		logger:  logger,
		digests: make(map[string]struct{}),
		stop:    make(chan struct{}),
	}
	if err := a.bootstrap(ctx, seed); err != nil {
		return nil, err
	}
	go a.runReloadLoop()
	return a, nil
}

func (a *Allowlist) bootstrap(ctx context.Context, seed []string) error {
	current, err := a.store.ListDigests(ctx)
	if err != nil {
		return fmt.Errorf("allowlist bootstrap: list digests: %w", err)
	}
	if len(current) == 0 && len(seed) > 0 {
		a.logger.Info("Allowlist empty in store; seeding from env var",
			zap.Int("seed_count", len(seed)))
		for _, d := range seed {
			if err := a.store.AddDigest(ctx, d); err != nil {
				return fmt.Errorf("allowlist bootstrap: seed digest %q: %w", d, err)
			}
		}
		current = slices.Clone(seed)
	}
	a.setCache(current)
	a.logger.Info("Allowlist loaded", zap.Int("count", len(current)))
	return nil
}

// Stop terminates the reload goroutine. Safe to call multiple times;
// the channel close is guarded by the goroutine's exit path.
func (a *Allowlist) Stop() {
	select {
	case <-a.stop:
		// already closed
	default:
		close(a.stop)
	}
}

func (a *Allowlist) runReloadLoop() {
	t := time.NewTicker(allowlistReloadInterval)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			current, err := a.store.ListDigests(ctx)
			cancel()
			if err != nil {
				a.logger.Warn("Allowlist reload failed; keeping last cache", zap.Error(err))
				continue
			}
			a.setCache(current)
		}
	}
}

func (a *Allowlist) setCache(digests []string) {
	next := make(map[string]struct{}, len(digests))
	for _, d := range digests {
		next[d] = struct{}{}
	}
	a.mu.Lock()
	a.digests = next
	a.mu.Unlock()
}

// Contains reports whether digest is in the in-memory cache. Does not
// hit the store. Cache may be up to allowlistReloadInterval stale.
func (a *Allowlist) Contains(digest string) bool {
	a.mu.RLock()
	_, ok := a.digests[digest]
	a.mu.RUnlock()
	return ok
}

// List returns a snapshot of the current cached digests. Order is
// undefined; caller may sort.
func (a *Allowlist) List() []string {
	a.mu.RLock()
	out := make([]string, 0, len(a.digests))
	for d := range a.digests {
		out = append(out, d)
	}
	a.mu.RUnlock()
	return out
}

// Add writes digest to the store and updates the cache. Idempotent.
func (a *Allowlist) Add(ctx context.Context, digest string) error {
	if err := a.store.AddDigest(ctx, digest); err != nil {
		return err
	}
	a.mu.Lock()
	a.digests[digest] = struct{}{}
	a.mu.Unlock()
	return nil
}

// Remove deletes digest from the store and updates the cache. Idempotent.
func (a *Allowlist) Remove(ctx context.Context, digest string) error {
	if err := a.store.RemoveDigest(ctx, digest); err != nil {
		return err
	}
	a.mu.Lock()
	delete(a.digests, digest)
	a.mu.Unlock()
	return nil
}
