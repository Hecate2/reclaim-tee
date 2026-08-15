package main

import (
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestSupersededCompleteResultCannotAbortReplacementPrecompute(t *testing.T) {
	tests := []struct {
		name    string
		sendErr error
	}{
		{name: "delayed complete send error", sendErr: errors.New("delayed complete write failed")},
		{name: "delayed post-send finalization", sendErr: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := shared.NewNopLogger()
			state := NewOTPrecomputeState()
			teek := &TEEK{logger: logger, otPrecomputeState: state}
			cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
			teek.connManager = cm
			control, generation := installAckTestControl(cm, shared.NewWSConnection(nil))

			if err := state.pool.Add([]mpc.SenderOT{{Index: 0}}); err != nil {
				t.Fatalf("seed sender pool: %v", err)
			}
			oldClaim := state.pool.ClaimExtendIfNeeded()
			if oldClaim == nil {
				t.Fatal("claim old extension")
			}
			paused := make(chan struct{})
			resume := make(chan struct{})
			oldPending := &senderPrecompute{
				startIndex: 1, done: make(chan error, 1),
				controlConn: control, controlGeneration: generation,
				extendClaim: oldClaim,
				sendComplete: func(uint64) error {
					close(paused)
					<-resume
					return test.sendErr
				},
			}
			state.mu.Lock()
			state.ready = true
			state.pending = oldPending
			state.mu.Unlock()

			oldResult := make(chan error, 1)
			go func() {
				oldResult <- teek.completeSenderPrecompute(state, oldPending, []mpc.SenderOT{{Index: 1}})
			}()
			select {
			case <-paused:
			case <-time.After(time.Second):
				t.Fatal("old Complete path did not reach the deterministic pause")
			}
			state.mu.Lock()
			state.pool.InvalidateExtendClaim()
			replacementClaim := state.pool.ClaimExtendIfNeeded()
			if replacementClaim == nil {
				state.mu.Unlock()
				t.Fatal("claim replacement extension")
			}
			replacement := &senderPrecompute{
				startIndex: 1, done: make(chan error, 1),
				controlConn: control, controlGeneration: generation,
				extendClaim:  replacementClaim,
				sendComplete: func(uint64) error { return nil },
			}
			state.pending = replacement
			state.mu.Unlock()
			close(resume)

			select {
			case err := <-oldResult:
				if err == nil {
					t.Fatal("superseded Complete path unexpectedly succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("superseded Complete path did not return")
			}
			state.mu.Lock()
			gotPending := state.pending
			gotReady := state.ready
			state.mu.Unlock()
			if gotPending != replacement {
				t.Fatal("old Complete result cleared the replacement pending batch")
			}
			if !gotReady || !state.pool.IsExtendPending() {
				t.Fatal("old Complete result changed replacement readiness")
			}
			if got := state.pool.TotalCount(); got != 1 {
				t.Fatalf("old Complete result changed replacement pool: total=%d want=1", got)
			}
			select {
			case err := <-replacement.done:
				t.Fatalf("old Complete result signaled replacement batch: %v", err)
			default:
			}

			if err := teek.completeSenderPrecompute(state, replacement, []mpc.SenderOT{{Index: 1}}); err != nil {
				t.Fatalf("complete replacement precompute: %v", err)
			}
			select {
			case err := <-replacement.done:
				if err != nil {
					t.Fatalf("replacement completion signal: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("replacement precompute did not signal completion")
			}
			state.mu.Lock()
			gotPending = state.pending
			gotReady = state.ready
			state.mu.Unlock()
			if gotPending != nil || !gotReady || state.pool.IsExtendPending() {
				t.Fatal("replacement precompute did not complete cleanly")
			}
			if got := state.pool.TotalCount(); got != 2 {
				t.Fatalf("replacement pool total=%d want=2", got)
			}
		})
	}
}
