package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
)

func TestFailPendingPrecomputeDestroysIdleProtocolState(t *testing.T) {
	state := NewOTPrecomputeState()
	pending := &senderPrecompute{
		session:      [32]byte{1},
		baseReceiver: new(mpc.BaseOTReceiverState),
		extension:    new(mpc.ExtensionSenderState),
		phase:        senderPrecomputeAwaitProof,
		done:         make(chan error, 1),
	}
	state.pending = pending
	teek := &TEEK{otPrecomputeState: state}
	wantErr := errors.New("injected terminal failure")

	if !teek.failPendingPrecompute(state, pending, wantErr) {
		t.Fatal("failed to terminalize exact pending precompute")
	}
	if state.pending != nil || pending.session != ([32]byte{}) || pending.baseReceiver != nil || pending.extension != nil {
		t.Fatal("terminalized sender precompute retained protocol state")
	}
	select {
	case got := <-pending.done:
		if !errors.Is(got, wantErr) {
			t.Fatalf("terminal signal error = %v, want %v", got, wantErr)
		}
	default:
		t.Fatal("terminalized sender precompute did not signal its waiter")
	}
}

func TestCompleteSenderPrecomputeClearsProvisionalEntries(t *testing.T) {
	state, pending, teek := newCompletionTestState(t, 0, true)
	entries := []mpc.SenderOT{{Index: 0}}
	pending.sendComplete = func(uint64) error { return nil }

	if err := teek.completeSenderPrecompute(state, pending, entries); err != nil {
		t.Fatal(err)
	}
	if entries[0] != (mpc.SenderOT{}) {
		t.Fatal("sender completion retained provisional OT entries")
	}
	if state.pool.TotalCount() != 1 {
		t.Fatalf("committed sender pool total = %d, want 1", state.pool.TotalCount())
	}
}

func newCompletionTestState(t *testing.T, start uint64, initial bool) (*OTPrecomputeState, *senderPrecompute, *TEEK) {
	t.Helper()
	state := NewOTPrecomputeState()
	connManager := &TEETConnectionManager{}
	pending := &senderPrecompute{
		session:     [32]byte{1},
		startIndex:  start,
		isInitial:   initial,
		controlConn: nil,
		extendClaim: nil,
		done:        make(chan error, 1),
		phase:       senderPrecomputeProcessingProof,
	}
	state.pending = pending
	connManager.controlConn = pending.controlConn
	teek := &TEEK{otPrecomputeState: state, connManager: connManager}
	if !initial {
		t.Fatal("test helper currently supports initial completion only")
	}
	return state, pending, teek
}

func TestDestroyedBaseOTStateReportsSingleUse(t *testing.T) {
	state := new(mpc.BaseOTSenderState)
	state.Destroy()
	_, _, err := mpc.FinishBaseOTSender(state, nil)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("destroyed base OT state error = %v", err)
	}
}

func TestGarblerSessionRemovalPreservesReplacement(t *testing.T) {
	stale := new(mpc.GarblerSession)
	current := new(mpc.GarblerSession)
	state := &TEEKSessionState{GarblerOnlineSessions: map[int]*mpc.GarblerSession{3: current}}

	if state.RemoveGarblerOnlineSession(3, stale) {
		t.Fatal("stale cleanup removed replacement garbler session")
	}
	if got, ok := state.GetGarblerOnlineSession(3); !ok || got != current {
		t.Fatal("stale cleanup changed current garbler session")
	}
	if got, ok := state.TakeGarblerOnlineSession(3); !ok || got != current {
		t.Fatal("final output did not take exact garbler session")
	}
	if _, ok := state.GetGarblerOnlineSession(3); ok {
		t.Fatal("taken garbler session remained published")
	}
}

func TestSessionTeardownDestroysPublishedGarblerSessions(t *testing.T) {
	session := new(mpc.GarblerSession)
	state := &TEEKSessionState{GarblerOnlineSessions: map[int]*mpc.GarblerSession{1: session}}
	state.DestroyOPRFSessions()
	state.DestroyOPRFSessions()

	if state.GarblerOnlineSessions != nil {
		t.Fatal("session teardown retained garbler session map")
	}
	if _, err := mpc.ApplyCorrections(session, make([]bool, mpc.InputBits)); err == nil || !strings.Contains(err.Error(), "already applied") {
		t.Fatalf("session teardown left garbler session usable: %v", err)
	}
}
