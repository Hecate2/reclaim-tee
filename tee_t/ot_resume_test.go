package main

import (
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
)

// poolWith returns a receiver pool holding n entries (TotalCount == n).
func poolWith(n int) *oprfmpc.OTReceiverPool {
	p := oprfmpc.NewOTReceiverPool(n)
	entries := make([]*oprfmpc.OTReceiverEntry, n)
	for i := range entries {
		entries[i] = &oprfmpc.OTReceiverEntry{}
	}
	p.AddEntries(entries)
	return p
}

func TestCanResumeOTPool(t *testing.T) {
	const epoch = "epoch-abc"

	cases := []struct {
		name      string
		state     *OTReceiverState
		reqEpoch  string
		nextIndex uint32
		want      bool
	}{
		{
			name:      "accept: ready, matching epoch, index within pool",
			state:     &OTReceiverState{pool: poolWith(100), ready: true, epoch: epoch},
			reqEpoch:  epoch,
			nextIndex: 40,
			want:      true,
		},
		{
			name:      "accept: nextIndex equals total (boundary)",
			state:     &OTReceiverState{pool: poolWith(100), ready: true, epoch: epoch},
			reqEpoch:  epoch,
			nextIndex: 100,
			want:      true,
		},
		{
			name:      "deny: no receiver state (TEE_T restarted)",
			state:     nil,
			reqEpoch:  epoch,
			nextIndex: 0,
			want:      false,
		},
		{
			name:      "deny: pool not ready (mid-precompute)",
			state:     &OTReceiverState{pool: poolWith(100), ready: false, epoch: epoch},
			reqEpoch:  epoch,
			nextIndex: 10,
			want:      false,
		},
		{
			name:      "deny: epoch mismatch (different pool instance)",
			state:     &OTReceiverState{pool: poolWith(100), ready: true, epoch: epoch},
			reqEpoch:  "epoch-other",
			nextIndex: 10,
			want:      false,
		},
		{
			name:      "deny: empty stored epoch never matches",
			state:     &OTReceiverState{pool: poolWith(100), ready: true, epoch: ""},
			reqEpoch:  "",
			nextIndex: 10,
			want:      false,
		},
		{
			name:      "deny: nextIndex past pool length (TEE_K ahead of TEE_T)",
			state:     &OTReceiverState{pool: poolWith(100), ready: true, epoch: epoch},
			reqEpoch:  epoch,
			nextIndex: 101,
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			teet := &TEET{otReceiverState: tc.state}
			if got := teet.canResumeOTPool(tc.reqEpoch, tc.nextIndex); got != tc.want {
				t.Fatalf("canResumeOTPool(%q, %d) = %v, want %v", tc.reqEpoch, tc.nextIndex, got, tc.want)
			}
		})
	}
}
