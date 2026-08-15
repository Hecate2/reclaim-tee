package main

import (
	"math"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestSendOTPrecomputeCompletePreservesHighPoolSize(t *testing.T) {
	conn, messages := newKOS2SenderCaptureWebSocket(t)
	teek := &TEEK{logger: shared.NewNopLogger()}
	teek.connManager = NewTEETConnectionManager(teek, "ws://example.invalid", teek.logger)
	_, generation := installAckTestControl(teek.connManager, conn)
	pending := &senderPrecompute{controlConn: conn, controlGeneration: generation}
	want := uint64(math.MaxUint32 + 1)

	if err := teek.sendOTPrecomputeComplete(pending, want); err != nil {
		t.Fatal(err)
	}
	envelope := receiveKOS2SenderEnvelope(t, messages)
	if got := envelope.GetOtPrecomputeComplete().GetPoolSize(); got != want {
		t.Fatalf("pool_size=%d, want %d", got, want)
	}
}

func TestCompleteSenderPrecomputeRejectsUint64FrontierOverflowBeforeSend(t *testing.T) {
	called := false
	pending := &senderPrecompute{
		startIndex: math.MaxUint64,
		sendComplete: func(uint64) error {
			called = true
			return nil
		},
	}
	state := NewOTPrecomputeState()
	teek := &TEEK{connManager: &TEETConnectionManager{}, otPrecomputeState: state}

	err := teek.completeSenderPrecompute(state, pending, []mpc.SenderOT{{Index: math.MaxUint64}})
	if err == nil || !strings.Contains(err.Error(), "overflows uint64") {
		t.Fatalf("overflow error=%v", err)
	}
	if called {
		t.Fatal("sent OTPrecomputeComplete for an overflowing frontier")
	}
	if state.pool.TotalCount() != 0 || state.pool.Available() != 0 || state.pending != nil || state.ready {
		t.Fatal("overflowing completion mutated sender state")
	}
}

func TestCompleteSenderPrecomputeValidatesExactEntriesBeforeSend(t *testing.T) {
	tests := []struct {
		name    string
		entries []mpc.SenderOT
	}{
		{name: "skipped", entries: []mpc.SenderOT{{Index: 0}, {Index: 2}}},
		{name: "repeated", entries: []mpc.SenderOT{{Index: 0}, {Index: 0}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			pending := &senderPrecompute{
				startIndex: 0, isInitial: true, done: make(chan error, 1),
				sendComplete: func(uint64) error {
					called = true
					return nil
				},
			}
			state := NewOTPrecomputeState()
			state.pending = pending
			teek := &TEEK{connManager: &TEETConnectionManager{}, otPrecomputeState: state}

			err := teek.completeSenderPrecompute(state, pending, tc.entries)
			if err == nil || !strings.Contains(err.Error(), "invalid OT sender completion batch") {
				t.Fatalf("invalid entries error=%v", err)
			}
			if called {
				t.Fatal("sent OTPrecomputeComplete before validating exact entries")
			}
			if state.pool.TotalCount() != 0 || state.pool.Available() != 0 || state.pending != nil || state.ready {
				t.Fatal("invalid initial completion did not terminalize and clear sender state")
			}
			select {
			case terminalErr := <-pending.done:
				if terminalErr == nil || !strings.Contains(terminalErr.Error(), "invalid OT sender completion batch") {
					t.Fatalf("terminal error=%v", terminalErr)
				}
			default:
				t.Fatal("invalid initial completion did not signal its waiter")
			}
		})
	}
}

func TestInvalidRefillCompletionPreservesCommittedPoolAndRecoversClaim(t *testing.T) {
	state := NewOTPrecomputeState()
	state.ready = true
	const committed = 1_000
	if err := state.pool.Add(accountingSenderOTs(0, committed)); err != nil {
		t.Fatal(err)
	}
	claim := state.pool.ClaimExtendIfNeeded()
	if claim == nil {
		t.Fatal("claim refill")
	}
	called := false
	pending := &senderPrecompute{
		startIndex: committed, extendClaim: claim, done: make(chan error, 1),
		sendComplete: func(uint64) error {
			called = true
			return nil
		},
	}
	state.pending = pending
	teek := &TEEK{connManager: &TEETConnectionManager{}, otPrecomputeState: state, logger: shared.NewNopLogger()}

	err := teek.completeSenderPrecompute(state, pending, []mpc.SenderOT{{Index: committed}, {Index: committed}})
	if err == nil || !strings.Contains(err.Error(), "invalid OT sender completion batch") {
		t.Fatalf("invalid refill error=%v", err)
	}
	if called {
		t.Fatal("sent completion for invalid refill entries")
	}
	if state.pending != nil || !state.ready || state.inconsistent {
		t.Fatalf("refill terminal state pending=%t ready=%t inconsistent=%t", state.pending != nil, state.ready, state.inconsistent)
	}
	if state.pool.TotalCount() != committed || state.pool.Available() != committed {
		t.Fatalf("committed pool changed: total=%d available=%d", state.pool.TotalCount(), state.pool.Available())
	}
	if state.pool.OwnsExtendClaim(claim) || state.pool.IsExtendPending() {
		t.Fatal("invalid refill retained its extension claim")
	}
	select {
	case terminalErr := <-pending.done:
		if terminalErr == nil || !strings.Contains(terminalErr.Error(), "invalid OT sender completion batch") {
			t.Fatalf("terminal error=%v", terminalErr)
		}
	default:
		t.Fatal("invalid refill did not signal its waiter")
	}
	replacement := state.pool.ClaimExtendIfNeeded()
	if replacement == nil {
		t.Fatal("released refill claim could not be reacquired")
	}
	if !state.pool.ReleaseExtendClaim(replacement) {
		t.Fatal("replacement refill claim could not be released")
	}
}
