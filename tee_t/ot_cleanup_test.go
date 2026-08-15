package main

import (
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestFinishReceiverPrecomputeClearsIdleProtocolState(t *testing.T) {
	entries := []mpc.ReceiverOT{{R: mpc.Label{D0: 1}, Index: 0, Choice: true}}
	pending := &receiverPrecompute{
		baseSender: new(mpc.BaseOTSenderState),
		extension:  new(mpc.ExtensionReceiverState),
		entries:    entries,
		phase:      receiverPrecomputeAwaitComplete,
		done:       make(chan struct{}),
	}

	finishReceiverPrecompute(pending, receiverPrecomputeAborted)
	finishReceiverPrecompute(pending, receiverPrecomputeCommitted)

	if pending.outcome != receiverPrecomputeAborted || pending.baseSender != nil || pending.extension != nil || pending.entries != nil {
		t.Fatal("terminalized receiver precompute retained protocol state")
	}
	if entries[0] != (mpc.ReceiverOT{}) {
		t.Fatal("terminalized receiver precompute retained provisional entries")
	}
	select {
	case <-pending.done:
	default:
		t.Fatal("terminalized receiver precompute did not signal its waiter")
	}
}

func TestMalformedBaseChoicesDestroyProcessingState(t *testing.T) {
	baseSender := new(mpc.BaseOTSenderState)
	begin := mpc.PrecomputeBegin{Count: 1, Epoch: mpc.ExtensionEpoch([32]byte{1})}
	pending := &receiverPrecompute{
		begin: begin, isInitial: true, controlGeneration: 7, baseSender: baseSender,
		phase: receiverPrecomputeAwaitBaseChoices, done: make(chan struct{}),
	}
	state := &OTReceiverState{epoch: begin.Epoch, pending: pending}
	teet := &TEET{otReceiverState: state, logger: shared.NewNopLogger()}
	err := teet.handleOTPrecomputeChoices(newReceiverTestWebSocket(t), 7, directControlStateLease, &teeproto.OTPrecomputeRequest{
		Count: 1, IsInitial: true, Epoch: begin.Epoch, OtSenderSetup: []byte("invalid"),
	})
	if err == nil {
		t.Fatal("accepted malformed base OT choices")
	}
	if _, _, err := mpc.FinishBaseOTSender(baseSender, nil); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("malformed choices retained base OT state: %v", err)
	}
	if state.pending != nil || pending.outcome != receiverPrecomputeAborted {
		t.Fatal("malformed choices did not abort its pending receiver batch")
	}
}

func TestPendingEvaluatorRemovalPreservesReplacement(t *testing.T) {
	stale := &pendingOPRFEvaluation{Session: new(mpc.EvaluatorSession)}
	current := &pendingOPRFEvaluation{Session: new(mpc.EvaluatorSession)}
	state := &TEETSessionState{PendingOPRF: map[int]*pendingOPRFEvaluation{4: current}}

	if state.RemovePendingOPRF(4, stale) {
		t.Fatal("stale cleanup removed replacement evaluator session")
	}
	if got, ok := state.TakePendingOPRF(4); !ok || got != current {
		t.Fatal("round 3 did not take exact evaluator session")
	}
	if _, ok := state.TakePendingOPRF(4); ok {
		t.Fatal("taken evaluator session remained published")
	}
}

func TestSessionTeardownDestroysPublishedEvaluatorSessions(t *testing.T) {
	session := new(mpc.EvaluatorSession)
	payload := &mpc.OnlinePayload{Key: [16]byte{1}, GarblerInputs: []mpc.Label{{D0: 2}}}
	state := &TEETSessionState{PendingOPRF: map[int]*pendingOPRFEvaluation{1: {Session: session, Payload: payload}}}
	state.DestroyOPRFSessions()
	state.DestroyOPRFSessions()

	if state.PendingOPRF != nil {
		t.Fatal("session teardown retained evaluator session map")
	}
	if payload.Key != ([16]byte{}) || payload.GarblerInputs != nil {
		t.Fatal("session teardown retained evaluator payload")
	}
	if _, err := mpc.EvaluatorOnline(session, make([]mpc.OTMask, mpc.InputBits)); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("session teardown left evaluator session usable: %v", err)
	}
}
