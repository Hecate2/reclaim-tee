package store

import "time"

// Status is the lifecycle state a pair is observed to be in. It is computed
// from raw observations + operator intent, not stored — see EffectiveStatus.
type Status string

const (
	StatusRegistering Status = "registering"
	StatusReady       Status = "ready"
	StatusDegraded    Status = "degraded"
	StatusDraining    Status = "draining"
	StatusDead        Status = "dead"
)

// Role identifies which member of a pair a record or heartbeat refers to.
type Role string

const (
	RoleK Role = "K"
	RoleT Role = "T"
)

// Pair is the registry record for a single TEE_K + TEE_T pair.
//
// Each side reports independently via /register and /heartbeat, so observations
// from K and T are tracked separately. Effective lifecycle status is computed
// via EffectiveStatus from these observations plus the sticky Draining flag.
//
// The *UnhealthySince timestamps record the moment a side first reported an
// unhealthy observation that hasn't yet been cleared. They drive the
// "sustained for >Nseconds" semantics specified in the architecture plan:
// a single transient false reading does not flip the pair to Degraded.
type Pair struct {
	ID              string
	TEEKAddr        string
	TEETAddr        string
	TEEKImageDigest string
	TEETImageDigest string
	Region          string

	// AttestationType is "cs" or "sev-snp", set at /register. Empty on pairs
	// registered before the field existed -> treated as CS. Used by /allocate
	// to match a pair only to clients that can verify its attestation.
	AttestationType string

	// Per-side observations updated by /heartbeat (and seeded by /register).
	LastHeartbeatK         time.Time
	LastHeartbeatT         time.Time
	ControlHealthyK        bool
	ControlHealthyT        bool
	OTReadyK               bool
	OTReadyT               bool
	ControlUnhealthySinceK time.Time // zero = currently healthy from K's view
	ControlUnhealthySinceT time.Time
	OTUnreadySinceK        time.Time // zero = currently ready from K's view
	OTUnreadySinceT        time.Time
	ActiveSessions         int

	// Operator intent — sticky once set by admin /drain.
	Draining bool

	// Lifecycle markers.
	RegisteredAt time.Time
	ReadyAt      time.Time // zero = never reached Ready; used to distinguish
	//             Registering from Degraded
}

// EffectiveStatus derives the current lifecycle status from observations and
// thresholds. A pair is Ready only when both sides have registered, both
// heartbeats are fresh, and the unhealthy-since timestamps for control and
// OT are either zero or within their respective thresholds.
//
// A never-been-Ready pair that's still bringing up OT shows as Registering,
// not Degraded — even though it shares the "something is not yet healthy"
// state with Degraded. ReadyAt is what disambiguates the two.
func (p *Pair) EffectiveStatus(
	now time.Time,
	heartbeatStaleness, controlUnhealthy, otNotReady time.Duration,
) Status {
	if p.Draining {
		if p.heartbeatsStale(now, heartbeatStaleness) {
			return StatusDead
		}
		return StatusDraining
	}
	if p.TEEKAddr == "" || p.TEETAddr == "" {
		return StatusRegistering
	}
	if p.heartbeatsStale(now, heartbeatStaleness) {
		return StatusDead
	}
	// A fresh pair where both sides have registered but neither has yet
	// sent a heartbeat with ControlHealthy + OTReady true is still warming
	// up — the duration-based checks below would say "Ready" because the
	// *UnhealthySince timestamps were just seeded to `now`. Require explicit
	// positive signal from both sides at least once before the selector
	// considers the pair allocatable.
	allHealthy := p.ControlHealthyK && p.ControlHealthyT && p.OTReadyK && p.OTReadyT
	if !allHealthy && p.ReadyAt.IsZero() {
		return StatusRegistering
	}
	controlBad := durationExceeded(p.ControlUnhealthySinceK, now, controlUnhealthy) ||
		durationExceeded(p.ControlUnhealthySinceT, now, controlUnhealthy)
	otBad := durationExceeded(p.OTUnreadySinceK, now, otNotReady) ||
		durationExceeded(p.OTUnreadySinceT, now, otNotReady)
	if controlBad || otBad {
		if p.ReadyAt.IsZero() {
			return StatusRegistering
		}
		return StatusDegraded
	}
	return StatusReady
}

// heartbeatsStale returns true if either registered side's last heartbeat is
// older than the staleness threshold. Sides that haven't registered are skipped.
func (p *Pair) heartbeatsStale(now time.Time, staleness time.Duration) bool {
	if p.TEEKAddr != "" && now.Sub(p.LastHeartbeatK) > staleness {
		return true
	}
	if p.TEETAddr != "" && now.Sub(p.LastHeartbeatT) > staleness {
		return true
	}
	return false
}

// durationExceeded reports whether the duration between `since` and `now`
// has reached the threshold. A zero `since` means "currently healthy" and
// always returns false.
func durationExceeded(since, now time.Time, threshold time.Duration) bool {
	if since.IsZero() {
		return false
	}
	return now.Sub(since) >= threshold
}
