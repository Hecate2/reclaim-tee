package store

import (
	"testing"
	"time"
)

// effectiveStatusCase captures one EffectiveStatus scenario; expressed as
// "build a Pair, evaluate at `at`, expect `want`."
type effectiveStatusCase struct {
	name string
	p    Pair
	at   time.Time
	want Status
}

const (
	staleness        = 15 * time.Second
	controlUnhealthy = 30 * time.Second
	otNotReady       = 60 * time.Second
)

var t0 = time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)

func TestEffectiveStatus(t *testing.T) {
	cases := []effectiveStatusCase{
		{
			name: "only K registered → Registering",
			p:    Pair{TEEKAddr: "10.0.0.1:443"},
			at:   t0,
			want: StatusRegistering,
		},
		{
			name: "only T registered → Registering",
			p:    Pair{TEETAddr: "10.0.0.2:443"},
			at:   t0,
			want: StatusRegistering,
		},
		{
			name: "both registered, all healthy → Ready",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0, LastHeartbeatT: t0,
				ControlHealthyK: true, ControlHealthyT: true,
				OTReadyK: true, OTReadyT: true,
			},
			at:   t0,
			want: StatusReady,
		},
		{
			// Right after /register: heartbeats freshly seeded, but the
			// bools are still false because no heartbeat has fired yet.
			// Must NOT be Ready — selector would otherwise allocate a pair
			// whose TEEs haven't even finished OT precompute.
			name: "both registered, no heartbeat yet → Registering",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0, LastHeartbeatT: t0,
				// bools all false, ReadyAt zero
			},
			at:   t0,
			want: StatusRegistering,
		},
		{
			name: "K heartbeat stale → Dead",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0.Add(-1 * time.Minute), LastHeartbeatT: t0,
				ControlHealthyK: true, ControlHealthyT: true,
				OTReadyK: true, OTReadyT: true,
			},
			at:   t0,
			want: StatusDead,
		},
		{
			name: "control unhealthy within threshold → still Ready (sustained semantics)",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0, LastHeartbeatT: t0,
				ControlHealthyK: false, ControlHealthyT: true,
				ControlUnhealthySinceK: t0.Add(-10 * time.Second), // < 30s threshold
				OTReadyK:               true, OTReadyT: true,
				ReadyAt: t0.Add(-1 * time.Minute), // was Ready before
			},
			at:   t0,
			want: StatusReady,
		},
		{
			name: "control unhealthy past threshold + was Ready → Degraded",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0, LastHeartbeatT: t0,
				ControlHealthyK: false, ControlHealthyT: true,
				ControlUnhealthySinceK: t0.Add(-31 * time.Second), // > 30s threshold
				OTReadyK:               true, OTReadyT: true,
				ReadyAt: t0.Add(-1 * time.Minute),
			},
			at:   t0,
			want: StatusDegraded,
		},
		{
			name: "control unhealthy past threshold + never Ready → Registering",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0, LastHeartbeatT: t0,
				ControlHealthyK: false, ControlHealthyT: true,
				ControlUnhealthySinceK: t0.Add(-31 * time.Second),
				OTReadyK:               true, OTReadyT: true,
				// ReadyAt zero
			},
			at:   t0,
			want: StatusRegistering,
		},
		{
			name: "OT not ready past threshold + was Ready → Degraded",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0, LastHeartbeatT: t0,
				ControlHealthyK: true, ControlHealthyT: true,
				OTReadyK: true, OTReadyT: false,
				OTUnreadySinceT: t0.Add(-61 * time.Second), // > 60s threshold
				ReadyAt:         t0.Add(-2 * time.Minute),
			},
			at:   t0,
			want: StatusDegraded,
		},
		{
			name: "Draining + heartbeats fresh → Draining",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0, LastHeartbeatT: t0,
				Draining: true,
			},
			at:   t0,
			want: StatusDraining,
		},
		{
			name: "Draining + heartbeats stale → Dead",
			p: Pair{
				TEEKAddr: "10.0.0.1:443", TEETAddr: "10.0.0.2:443",
				LastHeartbeatK: t0.Add(-1 * time.Minute), LastHeartbeatT: t0,
				Draining: true,
			},
			at:   t0,
			want: StatusDead,
		},
		{
			name: "heartbeatsStale only checks registered sides",
			p: Pair{
				TEEKAddr: "10.0.0.1:443",
				// T never registered; T's zero heartbeat should not count as stale.
				LastHeartbeatK: t0,
			},
			at:   t0,
			want: StatusRegistering, // because T not registered
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.p.EffectiveStatus(tc.at, staleness, controlUnhealthy, otNotReady)
			if got != tc.want {
				t.Fatalf("EffectiveStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDurationExceeded(t *testing.T) {
	cases := []struct {
		name      string
		since     time.Time
		now       time.Time
		threshold time.Duration
		want      bool
	}{
		{"zero since → false", time.Time{}, t0, time.Second, false},
		{"under threshold → false", t0.Add(-1 * time.Second), t0, time.Second * 2, false},
		{"exactly threshold → true", t0.Add(-2 * time.Second), t0, time.Second * 2, true},
		{"over threshold → true", t0.Add(-3 * time.Second), t0, time.Second * 2, true},
		{"threshold zero, any non-zero since → true", t0.Add(-1 * time.Nanosecond), t0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := durationExceeded(tc.since, tc.now, tc.threshold); got != tc.want {
				t.Fatalf("durationExceeded = %v, want %v", got, tc.want)
			}
		})
	}
}
