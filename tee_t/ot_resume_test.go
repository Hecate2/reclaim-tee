package main

import (
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
)

// poolWith returns a receiver pool holding n entries (TotalCount == n).
func poolWith(n int) *mpc.ReceiverPool {
	p := mpc.NewReceiverPool(n)
	entries := make([]mpc.ReceiverOT, n)
	for i := range entries {
		entries[i].Index = uint64(i)
	}
	if err := p.Add(entries); err != nil {
		panic(err)
	}
	return p
}

func TestResumeOTPool(t *testing.T) {
	const epoch = "epoch-abc"

	cases := []struct {
		name      string
		state     *OTReceiverState
		reqEpoch  string
		nextIndex uint32
		want      bool
	}{
		{
			name:      "accept: ready, matching epoch, sender ahead within pool",
			state:     &OTReceiverState{pool: poolWith(100), ready: true, epoch: epoch},
			reqEpoch:  epoch,
			nextIndex: 40,
			want:      true,
		},
		{
			name: "deny: receiver ahead of sender",
			state: func() *OTReceiverState {
				pool := poolWith(100)
				if _, err := pool.Consume(0, 50); err != nil {
					panic(err)
				}
				return &OTReceiverState{pool: pool, ready: true, epoch: epoch}
			}(),
			reqEpoch:  epoch,
			nextIndex: 40,
			want:      false,
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
			got := teet.resumeOTPool(tc.reqEpoch, tc.nextIndex)
			if got != tc.want {
				t.Fatalf("resumeOTPool(%q, %d) = %v, want %v", tc.reqEpoch, tc.nextIndex, got, tc.want)
			}
			if got && tc.state.pool.NextIndex() != uint64(tc.nextIndex) {
				t.Fatalf("receiver next index %d, want %d", tc.state.pool.NextIndex(), tc.nextIndex)
			}
		})
	}
}
