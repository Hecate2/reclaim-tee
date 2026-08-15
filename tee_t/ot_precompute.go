package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type receiverPrecompute struct {
	begin             mpc.PrecomputeBegin
	isInitial         bool
	controlGeneration uint64
	baseSender        *mpc.BaseOTSenderState
	extension         *mpc.ExtensionReceiverState
	entries           []mpc.ReceiverOT
	phase             receiverPrecomputePhase
	done              chan struct{}
	outcome           receiverPrecomputeOutcome
}

type receiverPrecomputePhase uint8

const (
	receiverPrecomputeAwaitBaseChoices receiverPrecomputePhase = iota
	receiverPrecomputeProcessingChoices
	receiverPrecomputeAwaitChallenge
	receiverPrecomputeProcessingChallenge
	receiverPrecomputeAwaitComplete
)

type receiverPrecomputeOutcome uint8

type controlStateLease func(func() error) error

const (
	receiverPrecomputeInProgress receiverPrecomputeOutcome = iota
	receiverPrecomputeCommitted
	receiverPrecomputeAborted
)

type OTReceiverState struct {
	pool    *mpc.ReceiverPool
	ready   bool
	epoch   string
	pending *receiverPrecompute
}

func NewOTReceiverState() *OTReceiverState {
	return &OTReceiverState{pool: mpc.NewReceiverPool(mpc.OTPoolInitialSize)}
}

// handleOTPrecomputeRequest handles all KOS2 request phases carried by the
// existing protobuf request bytes.
func (t *TEET) handleOTPrecomputeRequest(conn *shared.WSConnection, generation uint64, lease controlStateLease, msg *teeproto.OTPrecomputeRequest) error {
	switch mpc.PrecomputeRequestPhase(msg.GetOtSenderSetup()) {
	case mpc.PrecomputePhaseBegin:
		return t.handleOTPrecomputeBegin(conn, generation, lease, msg)
	case mpc.PrecomputePhaseBaseChoices:
		return t.handleOTPrecomputeChoices(conn, generation, lease, msg)
	case mpc.PrecomputePhaseChallenge:
		return t.handleOTPrecomputeChallenge(conn, generation, lease, msg)
	default:
		return fmt.Errorf("unknown OT precompute request phase")
	}
}

func (t *TEET) handleOTPrecomputeBegin(conn *shared.WSConnection, generation uint64, lease controlStateLease, msg *teeproto.OTPrecomputeRequest) error {
	begin, err := mpc.UnmarshalPrecomputeBegin(msg.GetOtSenderSetup())
	if err != nil {
		return err
	}
	if err := mpc.ValidatePrecomputeCount(int(begin.Count)); err != nil {
		return err
	}
	if _, err := mpc.CheckedOTIndexEnd(begin.StartIndex, int(begin.Count)); err != nil {
		return err
	}
	if begin.Count != msg.GetCount() || begin.Epoch != msg.GetEpoch() {
		return fmt.Errorf("OT precompute begin metadata mismatch")
	}
	if err := mpc.Initialize(); err != nil {
		return fmt.Errorf("initialize MPC circuit: %w", err)
	}

	var state *OTReceiverState
	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		state = t.otReceiverState
		if msg.GetIsInitial() {
			if state != nil {
				state.pool.Clear()
				finishReceiverPrecompute(state.pending, receiverPrecomputeAborted)
				state.pending = nil
				state.ready = false
			}
			state = NewOTReceiverState()
			state.epoch = msg.GetEpoch()
			t.otReceiverState = state
		} else if state == nil || !state.ready {
			return fmt.Errorf("OT receiver pool is not ready for extension")
		}
		if state.pending != nil {
			return fmt.Errorf("OT precomputation already in progress")
		}
		if begin.StartIndex != state.pool.TotalCount() {
			return fmt.Errorf("OT extension start index %d, want %d", begin.StartIndex, state.pool.TotalCount())
		}
		if !msg.GetIsInitial() && msg.GetEpoch() != state.epoch {
			return fmt.Errorf("OT extension epoch mismatch")
		}
		return nil
	}); err != nil {
		return err
	}

	baseSender, setupMessage, err := mpc.StartBaseOTSender(rand.Reader, begin.SessionID)
	if err != nil {
		return err
	}
	pending := &receiverPrecompute{
		begin: begin, isInitial: msg.GetIsInitial(), controlGeneration: generation, baseSender: baseSender,
		done: make(chan struct{}),
	}
	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		if t.otReceiverState != state || state.pending != nil {
			return fmt.Errorf("OT receiver state changed during base setup")
		}
		state.pending = pending
		return nil
	}); err != nil {
		return err
	}

	setupFrame, err := mpc.MarshalPrecomputeBaseSetup(begin.SessionID, setupMessage)
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	if err := t.sendOTPrecomputeResponse(conn, msg.GetCount(), setupFrame); err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	return nil
}

func (t *TEET) handleOTPrecomputeChoices(conn *shared.WSConnection, generation uint64, lease controlStateLease, msg *teeproto.OTPrecomputeRequest) error {
	var state *OTReceiverState
	var pending *receiverPrecompute
	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		state = t.otReceiverState
		if state == nil || state.pending == nil {
			return fmt.Errorf("unexpected base OT choice message")
		}
		pending = state.pending
		if pending.controlGeneration != generation {
			return fmt.Errorf("base OT choice control generation mismatch")
		}
		if int(msg.GetCount()) != int(pending.begin.Count) || msg.GetIsInitial() != pending.isInitial || msg.GetEpoch() != state.epoch {
			return fmt.Errorf("base OT choice metadata mismatch")
		}
		if pending.phase != receiverPrecomputeAwaitBaseChoices {
			return fmt.Errorf("unexpected base OT choice phase %d", pending.phase)
		}
		pending.phase = receiverPrecomputeProcessingChoices
		return nil
	}); err != nil {
		return err
	}

	started := time.Now()
	choiceMessage, err := mpc.UnmarshalPrecomputeBaseChoices(msg.GetOtSenderSetup(), pending.begin.SessionID)
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	cipherMessage, basePairs, err := mpc.FinishBaseOTSender(pending.baseSender, choiceMessage)
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	extension, commitment, entries, err := mpc.StartExtensionReceiver(
		rand.Reader, basePairs, state.epoch, cipherMessage,
		pending.begin.SessionID, pending.begin.StartIndex, int(pending.begin.Count),
	)
	clear(basePairs[:])
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	commitmentMessage, err := mpc.MarshalPrecomputeCommitment(cipherMessage, commitment)
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}

	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		if t.otReceiverState != state || state.pending != pending || pending.controlGeneration != generation || pending.phase != receiverPrecomputeProcessingChoices {
			return fmt.Errorf("OT receiver state changed during extension")
		}
		pending.extension = extension
		pending.entries = entries
		pending.phase = receiverPrecomputeAwaitChallenge
		return nil
	}); err != nil {
		return err
	}

	if err := t.sendOTPrecomputeResponse(conn, msg.GetCount(), commitmentMessage); err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	t.logger.Info("Generated KOS2 receiver commitment", zap.Uint32("count", msg.GetCount()), zap.Duration("duration", time.Since(started)))
	return nil
}

func (t *TEET) handleOTPrecomputeChallenge(conn *shared.WSConnection, generation uint64, lease controlStateLease, msg *teeproto.OTPrecomputeRequest) error {
	var state *OTReceiverState
	var pending *receiverPrecompute
	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		state = t.otReceiverState
		if state == nil || state.pending == nil {
			return fmt.Errorf("unexpected OT extension challenge")
		}
		pending = state.pending
		if pending.controlGeneration != generation || int(msg.GetCount()) != int(pending.begin.Count) || msg.GetIsInitial() != pending.isInitial || msg.GetEpoch() != state.epoch {
			return fmt.Errorf("OT extension challenge metadata mismatch")
		}
		if pending.phase != receiverPrecomputeAwaitChallenge || pending.extension == nil || len(pending.entries) == 0 {
			return fmt.Errorf("unexpected OT extension challenge phase %d", pending.phase)
		}
		pending.phase = receiverPrecomputeProcessingChallenge
		return nil
	}); err != nil {
		return err
	}

	challenge, err := mpc.UnmarshalExtensionChallengeFor(msg.GetOtSenderSetup(), pending.begin.SessionID, int(pending.begin.Count))
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	proof, err := mpc.FinishExtensionReceiver(pending.extension, challenge)
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	proofMessage, err := mpc.MarshalExtensionProof(proof)
	if err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}

	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		if t.otReceiverState != state || state.pending != pending || pending.controlGeneration != generation || pending.phase != receiverPrecomputeProcessingChallenge {
			return fmt.Errorf("OT receiver state changed while proving extension")
		}
		pending.phase = receiverPrecomputeAwaitComplete
		return nil
	}); err != nil {
		return err
	}
	if err := t.sendOTPrecomputeResponse(conn, msg.GetCount(), proofMessage); err != nil {
		t.clearPendingReceiverPrecompute(state, pending)
		return err
	}
	return nil
}

func (t *TEET) sendOTPrecomputeResponse(conn *shared.WSConnection, count uint32, payload []byte) error {
	env := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeResponse{OtPrecomputeResponse: &teeproto.OTPrecomputeResponse{
			Count: count, OtReceiverData: payload,
		}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal OT precompute response: %w", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("send OT precompute response: %w", err)
	}
	return nil
}

// handleOTPrecomputeComplete commits the receiver entries only after TEE_K
// has verified the KOS proof and acknowledged the batch.
func (t *TEET) handleOTPrecomputeComplete(generation uint64, lease controlStateLease, msg *teeproto.OTPrecomputeComplete) error {
	return lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		state := t.otReceiverState
		if state == nil || state.pending == nil || len(state.pending.entries) == 0 {
			return fmt.Errorf("unexpected OT precompute completion")
		}
		if state.pending.controlGeneration != generation {
			return fmt.Errorf("OT precompute completion control generation mismatch")
		}
		if state.pending.phase != receiverPrecomputeAwaitComplete {
			return fmt.Errorf("unexpected OT precompute completion phase %d", state.pending.phase)
		}
		expectedTotal, err := mpc.CheckedOTIndexEnd(state.pool.TotalCount(), len(state.pending.entries))
		if err != nil {
			return err
		}
		if msg.GetPoolSize() != expectedTotal {
			return fmt.Errorf("OT pool total mismatch: peer=%d local=%d", msg.GetPoolSize(), expectedTotal)
		}
		if err := state.pool.Add(state.pending.entries); err != nil {
			return err
		}
		pending := state.pending
		state.epoch = mpc.ExtensionEpoch(pending.begin.SessionID)
		state.pending = nil
		state.ready = true
		t.otReady.Store(true)
		finishReceiverPrecompute(pending, receiverPrecomputeCommitted)
		t.logger.Info("Committed KOS receiver batch", zap.Int("pool_available", state.pool.Available()))
		return nil
	})
}

func (t *TEET) isOTReceiverPoolReady() bool {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	return t.otReceiverState != nil && t.otReceiverState.ready
}

func (t *TEET) consumeOTReceiverEntries(ctx context.Context, startIndex uint64, count int) ([]mpc.ReceiverOT, error) {
	return t.consumeOTReceiverEntriesWithWait(ctx, startIndex, count, waitForReceiverPrecompute)
}

func (t *TEET) consumeOTReceiverEntriesWithWait(
	ctx context.Context,
	startIndex uint64,
	count int,
	wait func(context.Context, <-chan struct{}) error,
) ([]mpc.ReceiverOT, error) {
	return t.consumeOTReceiverEntriesWithWaitAndLease(ctx, startIndex, count, wait, func(mutate func() error) error {
		return mutate()
	})
}

func (t *TEET) consumeOTReceiverEntriesForIdentity(
	identity *teetSessionIdentity,
	ctx context.Context,
	startIndex uint64,
	count int,
	wait func(context.Context, <-chan struct{}) error,
) ([]mpc.ReceiverOT, error) {
	if err := identity.ensureCurrent(); err != nil {
		return nil, err
	}
	if identity.beforeOTReceiverConsume != nil {
		identity.beforeOTReceiverConsume()
	}
	if t.connManager == nil {
		return nil, fmt.Errorf("TEE_K connection manager is not initialized")
	}
	return t.consumeOTReceiverEntriesWithWaitAndLease(ctx, startIndex, count, wait, func(mutate func() error) error {
		return t.connManager.withCurrentSessionControlState(identity, mutate)
	})
}

func (t *TEET) consumeOTReceiverEntriesWithWaitAndLease(
	ctx context.Context,
	startIndex uint64,
	count int,
	wait func(context.Context, <-chan struct{}) error,
	lease controlStateLease,
) ([]mpc.ReceiverOT, error) {
	var state *OTReceiverState
	var pending *receiverPrecompute
	var done <-chan struct{}
	var entries []mpc.ReceiverOT
	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		state = t.otReceiverState
		if state == nil {
			return fmt.Errorf("OT receiver state not initialized")
		}

		var err error
		pending, err = pendingReceiverCompletionForRange(state, startIndex, count)
		if err != nil {
			return err
		}
		if pending == nil {
			if !state.ready {
				return fmt.Errorf("OT receiver pool not ready")
			}
			entries, err = state.pool.Consume(startIndex, count)
			return err
		}
		done = pending.done
		return nil
	}); err != nil {
		return nil, err
	}
	if pending == nil {
		return entries, nil
	}

	// OTPrecomputeComplete arrives on the control connection while the online
	// request arrives on a per-session connection. Bind the request to these
	// exact state and batch pointers before dropping the mutex for the wait.
	if err := wait(ctx, done); err != nil {
		return nil, fmt.Errorf("OT receiver precompute wait canceled: %w", err)
	}

	// Waiting releases both locks. Reacquire the exact generation lease and
	// receiver-state lock before the irreversible single-use consume.
	if err := lease(func() error {
		t.otReceiverStateMu.Lock()
		defer t.otReceiverStateMu.Unlock()
		if t.otReceiverState != state {
			return fmt.Errorf("OT receiver state changed while waiting for precompute")
		}
		if pending.outcome != receiverPrecomputeCommitted {
			return fmt.Errorf("OT receiver precompute did not commit")
		}
		var err error
		entries, err = state.pool.Consume(startIndex, count)
		return err
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

func waitForReceiverPrecompute(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// pendingReceiverCompletionForRange returns the exact pending batch only when
// the current request is wholly covered by the committed pool plus that batch.
// Any committed prefix must still be unused.
// t.otReceiverStateMu must be held by the caller.
func pendingReceiverCompletionForRange(state *OTReceiverState, startIndex uint64, count int) (*receiverPrecompute, error) {
	if count <= 0 {
		return nil, nil
	}
	end, err := mpc.CheckedOTIndexEnd(startIndex, count)
	if err != nil {
		return nil, nil
	}
	committedTotal := state.pool.TotalCount()
	if end <= committedTotal {
		return nil, nil
	}
	pending := state.pending
	if pending == nil || pending.done == nil || len(pending.entries) == 0 || pending.begin.StartIndex != committedTotal {
		return nil, nil
	}
	pendingEnd, err := mpc.CheckedOTIndexEnd(pending.begin.StartIndex, len(pending.entries))
	if err != nil || startIndex > pendingEnd || end > pendingEnd {
		return nil, nil
	}
	if startIndex < committedTotal {
		committedCount := int(committedTotal - startIndex)
		if err := state.pool.ValidateConsumable(startIndex, committedCount); err != nil {
			return nil, err
		}
	}
	return pending, nil
}

func (t *TEET) clearPendingReceiverPrecompute(expectedState *OTReceiverState, expectedPending *receiverPrecompute) {
	t.otReceiverStateMu.Lock()
	if t.otReceiverState == expectedState && expectedState != nil && expectedState.pending == expectedPending {
		finishReceiverPrecompute(expectedPending, receiverPrecomputeAborted)
		expectedState.pending = nil
	}
	t.otReceiverStateMu.Unlock()
}

func (t *TEET) clearOTReceiverPool() {
	t.otReceiverStateMu.Lock()
	if t.otReceiverState != nil {
		t.otReceiverState.pool.Clear()
		finishReceiverPrecompute(t.otReceiverState.pending, receiverPrecomputeAborted)
		t.otReceiverState.pending = nil
		t.otReceiverState.ready = false
	}
	t.otReceiverStateMu.Unlock()
	t.otReady.Store(false)
	t.logger.Info("Cleared OT receiver pool")
}

func (t *TEET) suspendOTReceiverPoolForReconnect() {
	t.otReceiverStateMu.Lock()
	state := t.otReceiverState
	ready := state != nil && state.ready
	epoch := ""
	if state != nil {
		epoch = state.epoch
		finishReceiverPrecompute(state.pending, receiverPrecomputeAborted)
		state.pending = nil
	}
	t.otReceiverStateMu.Unlock()
	if ready {
		t.logger.Info("Retained OT receiver pool across disconnect for resume", zap.String("epoch", epoch))
		return
	}
	t.clearOTReceiverPool()
}

// finishReceiverPrecompute records one pending batch's terminal result before
// waking its waiters. All callers hold t.otReceiverStateMu.
func finishReceiverPrecompute(pending *receiverPrecompute, outcome receiverPrecomputeOutcome) {
	if pending == nil || pending.outcome != receiverPrecomputeInProgress {
		return
	}
	pending.outcome = outcome
	if pending.done != nil {
		close(pending.done)
	}
}

func (t *TEET) resumeOTPool(epoch string, nextIndex uint64) bool {
	if !mpc.IsCurrentExtensionEpoch(epoch) {
		return false
	}
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	if t.otReceiverState == nil || !t.otReceiverState.ready || t.otReceiverState.pending != nil || t.otReceiverState.epoch == "" || t.otReceiverState.epoch != epoch {
		return false
	}
	return t.otReceiverState.pool.AdvanceTo(nextIndex) == nil
}

func (t *TEET) handleOTResumeRequest(conn *shared.WSConnection, lease controlStateLease, msg *teeproto.OTResumeRequest) error {
	accepted := false
	if err := lease(func() error {
		accepted = t.resumeOTPool(msg.GetEpoch(), msg.GetNextIndex())
		if accepted {
			t.otReady.Store(true)
		}
		return nil
	}); err != nil {
		return err
	}
	env := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtResumeResponse{OtResumeResponse: &teeproto.OTResumeResponse{Accepted: accepted}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal OT resume response: %w", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("send OT resume response: %w", err)
	}
	return nil
}
