package hub

import (
	"errors"
	"fmt"
	"sync"
)

// ErrTooManyInflight means the tenant already has as many jobs running as the
// Hub will run for it at the same time.
var ErrTooManyInflight = errors.New("tenant has too many jobs in flight")

// MaxFlightTenants bounds how many tenants one limiter tracks at once. Like
// MaxQuotaTenants it exists because the tenant name is attacker-influenced in
// open mode, but it binds far more loosely: an entry is dropped the moment its
// count returns to zero, so the table holds only tenants that have something
// running right now, and its size is already bounded by the number of jobs in
// flight. The cap therefore only ever bites on a Hub genuinely serving that
// many tenants at once.
const MaxFlightTenants = 1 << 16

// flightLimiter bounds how many jobs one tenant may have in flight at once.
//
// It is the fairness control for a shared provider, and it has to live in the
// Hub because nothing below it knows who anyone is. The TEE pools provider
// connections per (provider, host) and holds a slot for every connection it
// keeps — idle or busy — until its idle window expires; tenants are a Hub
// concept the TEE never sees (a job's tenant is not in the JobSpec, so it is
// not attested either). Under that layout a single tenant can take every slot a
// shared provider has and leave everyone else queued behind it for as long as
// its requests keep arriving. Bounding each tenant's share at the only layer
// that can tell tenants apart is what makes the pool's capacity shared rather
// than first-come-wins.
//
// The bound is on concurrency, not on rate: a tenant may run as many jobs as it
// likes over time, just not more than its share at one instant. A streaming
// session counts for as long as it is open, which is deliberate — a session
// holds a provider connection for the whole time it lasts, so it is exactly the
// shape of job that can starve the others, and it is why closing the session
// (not returning from the call that opened it) is what returns the slot.
//
// Sharing one count between requests and sessions is also deliberate: they draw
// on the same pool, so a tenant running its full share of sessions and its full
// share of requests would occupy twice the share the control promises.
type flightLimiter struct {
	maxPerTenant int
	maxTenants   int

	mu  sync.Mutex
	per map[string]int
}

// newFlightLimiter returns a limiter allowing maxPerTenant concurrent jobs per
// tenant and tracking at most maxTenants tenants at once. maxPerTenant must be
// at least 1: a zero there would refuse everything, which is spelled by not
// configuring a limiter at all.
func newFlightLimiter(maxPerTenant, maxTenants int) *flightLimiter {
	if maxTenants < 1 {
		maxTenants = MaxFlightTenants
	}
	return &flightLimiter{
		maxPerTenant: maxPerTenant,
		maxTenants:   maxTenants,
		per:          make(map[string]int),
	}
}

// acquire reserves one in-flight slot for the tenant and reports whether it got
// one. A nil limiter admits everything, which is how "no bound configured" is
// spelled — the same opt-out shape as a nil Quota — so callers never need to
// check for one.
func (f *flightLimiter) acquire(tenant string) bool {
	if f == nil {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	n := f.per[tenant]
	if n >= f.maxPerTenant {
		return false
	}
	// A tenant with nothing running is a new entry, so the table bound applies
	// here and nowhere else. A full table is refused rather than evicted: an
	// eviction would erase some other tenant's count and hand it a fresh
	// allowance, which is a way to exceed the bound by outrunning the sweep —
	// the same reasoning the quota table's full-table path follows. Entries
	// leave at zero (see release), so a table that is merely stale cannot fill.
	if n == 0 && f.maxTenants > 0 && len(f.per) >= f.maxTenants {
		return false
	}
	f.per[tenant] = n + 1
	return true
}

// release returns one in-flight slot. The entry is dropped at zero so a table
// of tenants that have finished everything cannot accumulate.
func (f *flightLimiter) release(tenant string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	switch n := f.per[tenant]; {
	case n <= 1:
		delete(f.per, tenant)
	default:
		f.per[tenant] = n - 1
	}
}

// active reports how many jobs the tenant has in flight. It exists for tests
// and operators; enforcement never reads it.
func (f *flightLimiter) active(tenant string) int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.per[tenant]
}

// beginJob admits one job against every tenant-scoped control and returns the
// spend handle pairing the job's two reserved resources: the in-flight slot
// and the prepaid hold. Every caller that starts a job must hold the returned
// handle for as long as the job runs and end it with settle or release;
// forgetting it leaks the tenant's allowance, so the shape is deliberately
// "one call, one defer".
//
// Order matters: the in-flight slot is taken before the money hold and the
// quota are consulted, and both are given back if either refuses. A request
// that is turned away on funds or rate is not running, so it must not leave
// the tenant holding concurrency it cannot use — one refused call could
// otherwise hold a slot for as long as its caller's context lives. The money
// hold is taken before the quota for the same reason the cumulative spend
// cap it replaced was checked first: a tenant with no money is going to be refused either
// way, and it must not also burn a rate-limit slot.
func (h *Hub) beginJob(tenant string) (*jobSpend, error) {
	if !h.flight.acquire(tenant) {
		return nil, fmt.Errorf("%w: tenant %q", ErrTooManyInflight, tenant)
	}
	if h.accounts != nil {
		if err := h.accounts.Hold(tenant, h.maxJob); err != nil {
			h.flight.release(tenant)
			return nil, err
		}
	}
	if err := h.admitTenant(tenant); err != nil {
		h.flight.release(tenant)
		if h.accounts != nil {
			h.accounts.ReleaseHold(tenant, h.maxJob)
		}
		return nil, err
	}
	return &jobSpend{
		accounts:     h.accounts,
		flight:       h.flight,
		tenant:       tenant,
		hold:         h.maxJob,
		holdActive:   h.accounts != nil,
		flightActive: true,
	}, nil
}

// jobSpend pairs one job's admission with its two exits. The in-flight slot
// is given back exactly once, at release; the money hold is consumed exactly
// once, by whichever comes first — settle (the job billed) or release (it did
// not). Settle after release is legal and charges anyway: a watchdog-closed
// session releases its hold before its truncated receipt is priced, and the
// service was still delivered, so the charge is due even though the hold is
// gone. Release after settle is the normal request path (the deferred release
// of a settled job) and touches neither the hold nor the balance again.
type jobSpend struct {
	accounts *Accounts
	flight   *flightLimiter
	tenant   string
	hold     uint64

	mu           sync.Mutex
	holdActive   bool
	flightActive bool
}

// settle converts the job's hold into the buyer's charge (or, when the hold
// was already released, bills the buyer directly). Persistence failures are
// accounted fail-closed inside Accounts; the delivery already happened, so
// there is nothing the caller could roll back.
func (s *jobSpend) settle(price uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.accounts == nil {
		return
	}
	if s.holdActive {
		s.holdActive = false
		_ = s.accounts.Settle(s.tenant, s.hold, price)
		return
	}
	_ = s.accounts.Charge(s.tenant, price)
}

// release gives back the in-flight slot and any hold not yet settled. It is
// idempotent: the deferred release of a settled job, and the Close of a
// session whose watchdog already fired, both land here as no-ops.
func (s *jobSpend) release() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.flight != nil && s.flightActive {
		s.flightActive = false
		s.flight.release(s.tenant)
	}
	if s.accounts != nil && s.holdActive {
		s.holdActive = false
		s.accounts.ReleaseHold(s.tenant, s.hold)
	}
}

// flightConn ties a session's in-flight slot and its money hold to the
// session's lifetime.
//
// A session is admitted like any other job, but it does not finish when the
// call that opened it returns — it runs until the connection closes. Releasing
// the slot there (a plain defer) would let a caller run unbounded sessions by
// opening them in a loop, each one holding a provider connection the bound
// believed was free. Handing the slot to the connection instead makes the two
// lifetimes the same thing, and Close idempotent so the relay and the timeout
// watchdog can both close it. The money hold rides along for the same
// lifetime: it is consumed by settle (see runRealtime) or given back here,
// whichever comes first.
type flightConn struct {
	SessionConn
	spend *jobSpend
	once  sync.Once
}

// newFlightConn returns conn that returns its tenant's slot and unsettled
// hold when closed.
func newFlightConn(conn SessionConn, spend *jobSpend) SessionConn {
	return &flightConn{SessionConn: conn, spend: spend}
}

// Close ends the session and gives back its in-flight slot and any unsettled
// hold. The release runs exactly once however many times Close is called.
func (c *flightConn) Close() error {
	err := c.SessionConn.Close()
	c.once.Do(c.spend.release)
	return err
}
