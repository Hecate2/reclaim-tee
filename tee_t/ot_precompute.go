package main

import (
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
	begin      mpc.PrecomputeBegin
	isInitial  bool
	baseSender *mpc.BaseOTSenderState
	entries    []mpc.ReceiverOT
	finalizing bool
}

type OTReceiverState struct {
	pool    *mpc.ReceiverPool
	ready   bool
	epoch   string
	pending *receiverPrecompute
}

func NewOTReceiverState() *OTReceiverState {
	return &OTReceiverState{pool: mpc.NewReceiverPool(mpc.OTPoolInitialSize)}
}

// handleOTPrecomputeRequest handles both phases carried by the existing
// protobuf request. KOB1 begins a fresh-base-OT KOS batch; BOC1 supplies the
// 128 base-OT choices.
func (t *TEET) handleOTPrecomputeRequest(conn *shared.WSConnection, msg *teeproto.OTPrecomputeRequest) error {
	switch mpc.PrecomputeRequestPhase(msg.GetOtSenderSetup()) {
	case mpc.PrecomputePhaseBegin:
		return t.handleOTPrecomputeBegin(conn, msg)
	case mpc.PrecomputePhaseBaseChoices:
		return t.handleOTPrecomputeChoices(conn, msg)
	default:
		return fmt.Errorf("unknown OT precompute request phase")
	}
}

func (t *TEET) handleOTPrecomputeBegin(conn *shared.WSConnection, msg *teeproto.OTPrecomputeRequest) error {
	begin, err := mpc.UnmarshalPrecomputeBegin(msg.GetOtSenderSetup())
	if err != nil {
		return err
	}
	if begin.Count != msg.GetCount() {
		return fmt.Errorf("OT precompute count mismatch: payload=%d protobuf=%d", begin.Count, msg.GetCount())
	}
	if msg.GetEpoch() == "" {
		return fmt.Errorf("OT precompute epoch is empty")
	}
	if err := mpc.Initialize(); err != nil {
		return fmt.Errorf("initialize MPC circuit: %w", err)
	}

	t.otReceiverStateMu.Lock()
	state := t.otReceiverState
	if msg.GetIsInitial() {
		if state != nil {
			state.pool.Clear()
			state.pending = nil
			state.ready = false
		}
		state = NewOTReceiverState()
		state.epoch = msg.GetEpoch()
		t.otReceiverState = state
	} else if state == nil || !state.ready {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("OT receiver pool is not ready for extension")
	}
	if state.pending != nil {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("OT precomputation already in progress")
	}
	if begin.StartIndex != uint64(state.pool.TotalCount()) {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("OT extension start index %d, want %d", begin.StartIndex, state.pool.TotalCount())
	}
	if !msg.GetIsInitial() && msg.GetEpoch() != state.epoch {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("OT extension epoch mismatch")
	}
	t.otReceiverStateMu.Unlock()

	baseSender, setupMessage, err := mpc.StartBaseOTSender(rand.Reader, begin.SessionID)
	if err != nil {
		return err
	}
	pending := &receiverPrecompute{begin: begin, isInitial: msg.GetIsInitial(), baseSender: baseSender}
	t.otReceiverStateMu.Lock()
	if t.otReceiverState != state || state.pending != nil {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("OT receiver state changed during base setup")
	}
	state.pending = pending
	t.otReceiverStateMu.Unlock()

	if err := t.sendOTPrecomputeResponse(conn, msg.GetCount(), setupMessage); err != nil {
		t.clearPendingReceiverPrecompute(state)
		return err
	}
	return nil
}

func (t *TEET) handleOTPrecomputeChoices(conn *shared.WSConnection, msg *teeproto.OTPrecomputeRequest) error {
	t.otReceiverStateMu.Lock()
	state := t.otReceiverState
	if state == nil || state.pending == nil {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("unexpected base OT choice message")
	}
	pending := state.pending
	if int(msg.GetCount()) != int(pending.begin.Count) || msg.GetIsInitial() != pending.isInitial || msg.GetEpoch() != state.epoch {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("base OT choice metadata mismatch")
	}
	if pending.finalizing {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("duplicate base OT choice message")
	}
	pending.finalizing = true
	t.otReceiverStateMu.Unlock()

	started := time.Now()
	cipherMessage, basePairs, err := mpc.FinishBaseOTSender(pending.baseSender, msg.GetOtSenderSetup())
	if err != nil {
		t.clearPendingReceiverPrecompute(state)
		return err
	}
	request, entries, err := mpc.ExtendReceiver(rand.Reader, basePairs, pending.begin.SessionID, pending.begin.StartIndex, int(pending.begin.Count))
	clear(basePairs[:])
	if err != nil {
		t.clearPendingReceiverPrecompute(state)
		return err
	}
	finalMessage, err := mpc.MarshalPrecomputeFinal(cipherMessage, request)
	if err != nil {
		t.clearPendingReceiverPrecompute(state)
		return err
	}

	t.otReceiverStateMu.Lock()
	if t.otReceiverState != state || state.pending != pending {
		t.otReceiverStateMu.Unlock()
		return fmt.Errorf("OT receiver state changed during extension")
	}
	pending.entries = entries
	t.otReceiverStateMu.Unlock()

	if err := t.sendOTPrecomputeResponse(conn, msg.GetCount(), finalMessage); err != nil {
		t.clearPendingReceiverPrecompute(state)
		return err
	}
	t.logger.Info("Generated KOS receiver batch", zap.Uint32("count", msg.GetCount()), zap.Duration("duration", time.Since(started)))
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
func (t *TEET) handleOTPrecomputeComplete(msg *teeproto.OTPrecomputeComplete) error {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	state := t.otReceiverState
	if state == nil || state.pending == nil || len(state.pending.entries) == 0 {
		return fmt.Errorf("unexpected OT precompute completion")
	}
	expectedTotal := state.pool.TotalCount() + len(state.pending.entries)
	if int(msg.GetPoolSize()) != expectedTotal {
		return fmt.Errorf("OT pool total mismatch: peer=%d local=%d", msg.GetPoolSize(), expectedTotal)
	}
	if err := state.pool.Add(state.pending.entries); err != nil {
		return err
	}
	state.epoch = mpc.ExtensionEpoch(state.pending.begin.SessionID)
	state.pending = nil
	state.ready = true
	t.otReady.Store(true)
	t.logger.Info("Committed KOS receiver batch", zap.Int("pool_available", state.pool.Available()))
	return nil
}

func (t *TEET) isOTReceiverPoolReady() bool {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	return t.otReceiverState != nil && t.otReceiverState.ready
}

func (t *TEET) consumeOTReceiverEntries(startIndex uint64, count int) ([]mpc.ReceiverOT, error) {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	if t.otReceiverState == nil {
		return nil, fmt.Errorf("OT receiver state not initialized")
	}
	if !t.otReceiverState.ready {
		return nil, fmt.Errorf("OT receiver pool not ready")
	}
	return t.otReceiverState.pool.Consume(startIndex, count)
}

func (t *TEET) clearPendingReceiverPrecompute(expected *OTReceiverState) {
	t.otReceiverStateMu.Lock()
	if t.otReceiverState == expected && expected != nil {
		expected.pending = nil
	}
	t.otReceiverStateMu.Unlock()
}

func (t *TEET) clearOTReceiverPool() {
	t.otReceiverStateMu.Lock()
	if t.otReceiverState != nil {
		t.otReceiverState.pool.Clear()
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
		state.pending = nil
	}
	t.otReceiverStateMu.Unlock()
	if ready {
		t.logger.Info("Retained OT receiver pool across disconnect for resume", zap.String("epoch", epoch))
		return
	}
	t.clearOTReceiverPool()
}

func (t *TEET) resumeOTPool(epoch string, nextIndex uint32) bool {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	if t.otReceiverState == nil || !t.otReceiverState.ready || t.otReceiverState.epoch == "" || t.otReceiverState.epoch != epoch {
		return false
	}
	return t.otReceiverState.pool.AdvanceTo(uint64(nextIndex)) == nil
}

func (t *TEET) handleOTResumeRequest(conn *shared.WSConnection, msg *teeproto.OTResumeRequest) error {
	accepted := t.resumeOTPool(msg.GetEpoch(), msg.GetNextIndex())
	if accepted {
		t.otReady.Store(true)
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
