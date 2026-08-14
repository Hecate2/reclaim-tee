package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type senderPrecompute struct {
	session      [32]byte
	count        int
	startIndex   uint64
	isInitial    bool
	baseReceiver *mpc.BaseOTReceiverState
	finalizing   bool
	done         chan error
}

// OTPrecomputeState holds the compact random-OT pool and one in-flight KOS
// extension batch for the shared TEE_T connection.
type OTPrecomputeState struct {
	mu         sync.Mutex
	pool       *mpc.SenderPool
	ready      bool
	epoch      string
	resumeChan chan bool
	pending    *senderPrecompute
}

func NewOTPrecomputeState() *OTPrecomputeState {
	return &OTPrecomputeState{
		pool:       mpc.NewSenderPool(mpc.OTPoolInitialSize),
		resumeChan: make(chan bool, 1),
	}
}

// performOTPrecomputation runs one fresh-base-OT malicious IKNP/KOS batch and
// blocks until TEE_T has committed the matching receiver entries.
func (t *TEEK) performOTPrecomputation(count int, isInitial bool) error {
	t.logger.Info("Starting KOS OT precomputation", zap.Int("count", count), zap.Bool("is_initial", isInitial))
	if count <= 0 || uint64(count) > math.MaxUint32 {
		return fmt.Errorf("invalid OT precomputation count %d", count)
	}
	if err := mpc.Initialize(); err != nil {
		return fmt.Errorf("initialize MPC circuit: %w", err)
	}
	if t.otPrecomputeState == nil {
		t.otPrecomputeState = NewOTPrecomputeState()
	}
	state := t.otPrecomputeState

	state.mu.Lock()
	if state.pending != nil {
		state.mu.Unlock()
		return fmt.Errorf("OT precomputation already in progress")
	}
	if isInitial {
		state.epoch = uuid.NewString()
		state.pool.Clear()
		state.ready = false
	} else {
		if !state.ready {
			state.mu.Unlock()
			return fmt.Errorf("cannot extend: OT pool not ready")
		}
		if state.pool.IsExtendPending() {
			state.mu.Unlock()
			t.logger.Debug("OT extend already pending, skipping")
			return nil
		}
		state.pool.SetExtendPending(true)
	}
	startIndex := uint64(state.pool.TotalCount())
	if startIndex > math.MaxUint32 || uint64(count) > math.MaxUint32-startIndex {
		state.pool.SetExtendPending(false)
		state.mu.Unlock()
		return fmt.Errorf("OT pool index exceeds protobuf uint32 range")
	}
	session, err := mpc.NewExtensionSession(rand.Reader)
	if err != nil {
		state.pool.SetExtendPending(false)
		state.mu.Unlock()
		return err
	}
	begin := mpc.PrecomputeBegin{SessionID: session, StartIndex: startIndex, Count: uint32(count)}
	beginData, err := mpc.MarshalPrecomputeBegin(begin)
	if err != nil {
		state.pool.SetExtendPending(false)
		state.mu.Unlock()
		return err
	}
	state.pending = &senderPrecompute{
		session: session, count: count, startIndex: startIndex, isInitial: isInitial,
		done: make(chan error, 1),
	}
	pending := state.pending
	epoch := state.epoch
	state.mu.Unlock()

	if t.connManager == nil {
		t.failPendingPrecompute(fmt.Errorf("connection manager not initialized"))
		return fmt.Errorf("connection manager not initialized")
	}
	conn := t.connManager.GetControlConnection()
	if conn == nil {
		t.failPendingPrecompute(fmt.Errorf("no TEE_T control connection available"))
		return fmt.Errorf("no TEE_T control connection available")
	}
	if err := t.sendOTPrecomputeRequest(conn, count, isInitial, epoch, beginData); err != nil {
		t.failPendingPrecompute(err)
		return err
	}

	select {
	case err := <-pending.done:
		if err != nil {
			return fmt.Errorf("OT precomputation failed: %w", err)
		}
		t.logger.Info("KOS OT precomputation completed", zap.Int("pool_available", state.pool.Available()))
		return nil
	case <-time.After(60 * time.Second):
		err := fmt.Errorf("OT precomputation timed out")
		t.failPendingPrecompute(err)
		return err
	}
}

func (t *TEEK) sendOTPrecomputeRequest(conn interface {
	WriteMessage(int, []byte) error
}, count int, isInitial bool, epoch string, payload []byte) error {
	env := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeRequest{OtPrecomputeRequest: &teeproto.OTPrecomputeRequest{
			Count: uint32(count), OtSenderSetup: payload, IsInitial: isInitial, Epoch: epoch,
		}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal OT precompute request: %w", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("send OT precompute request: %w", err)
	}
	return nil
}

// handleOTPrecomputeResponse advances the two-response base-OT/KOS state
// machine. The first response contains A; the second contains base ciphertexts
// and the extension proof.
func (t *TEEK) handleOTPrecomputeResponse(msg *teeproto.OTPrecomputeResponse) error {
	state := t.otPrecomputeState
	if state == nil {
		return fmt.Errorf("OT precompute state not initialized")
	}
	state.mu.Lock()
	pending := state.pending
	if pending == nil {
		state.mu.Unlock()
		return fmt.Errorf("unexpected OT precompute response")
	}
	if int(msg.GetCount()) != pending.count {
		err := fmt.Errorf("OT count mismatch: got %d want %d", msg.GetCount(), pending.count)
		state.mu.Unlock()
		t.failPendingPrecompute(err)
		return err
	}

	if pending.baseReceiver == nil {
		baseReceiver, choices, err := mpc.StartBaseOTReceiver(rand.Reader, pending.session, msg.GetOtReceiverData())
		if err != nil {
			state.mu.Unlock()
			t.failPendingPrecompute(err)
			return err
		}
		pending.baseReceiver = baseReceiver
		count, initial, epoch := pending.count, pending.isInitial, state.epoch
		state.mu.Unlock()

		if t.connManager == nil {
			err := fmt.Errorf("connection manager not initialized")
			t.failPendingPrecompute(err)
			return err
		}
		conn := t.connManager.GetControlConnection()
		if conn == nil {
			err := fmt.Errorf("no TEE_T control connection available")
			t.failPendingPrecompute(err)
			return err
		}
		if err := t.sendOTPrecomputeRequest(conn, count, initial, epoch, choices); err != nil {
			t.failPendingPrecompute(err)
			return err
		}
		return nil
	}
	if pending.finalizing {
		state.mu.Unlock()
		return fmt.Errorf("duplicate OT precompute final response")
	}
	pending.finalizing = true
	state.mu.Unlock()

	ciphertexts, request, err := mpc.UnmarshalPrecomputeFinal(msg.GetOtReceiverData())
	if err != nil {
		t.failPendingPrecompute(err)
		return err
	}
	if request.SessionID != pending.session || request.StartIndex != pending.startIndex || int(request.Count) != pending.count {
		err := fmt.Errorf("OT extension response metadata mismatch")
		t.failPendingPrecompute(err)
		return err
	}
	selected, delta, err := mpc.FinishBaseOTReceiver(pending.baseReceiver, ciphertexts)
	if err != nil {
		t.failPendingPrecompute(err)
		return err
	}
	entries, err := mpc.ExtendSender(selected, delta, request)
	clear(selected[:])
	delta = mpc.Label{}
	if err != nil {
		t.failPendingPrecompute(err)
		return err
	}

	state.mu.Lock()
	if state.pending != pending || state.pool.TotalCount() != int(pending.startIndex) {
		state.mu.Unlock()
		err := fmt.Errorf("OT sender state changed during extension")
		t.failPendingPrecompute(err)
		return err
	}
	expectedTotal := pending.startIndex + uint64(len(entries))
	state.mu.Unlock()

	// TEE_T commits its pending receiver entries on this acknowledgment. The
	// total generated count does not change when online sessions reserve OTs.
	if err := t.sendOTPrecomputeComplete(uint32(expectedTotal)); err != nil {
		state.mu.Lock()
		state.ready = false
		state.pool.Clear()
		state.pending = nil
		state.pool.SetExtendPending(false)
		state.mu.Unlock()
		t.otReady.Store(false)
		signalSenderPrecompute(pending, err)
		return err
	}

	state.mu.Lock()
	if state.pending != pending || state.pool.TotalCount() != int(pending.startIndex) {
		state.ready = false
		state.pool.Clear()
		state.pending = nil
		state.mu.Unlock()
		t.otReady.Store(false)
		err := fmt.Errorf("OT sender state changed before local commit")
		signalSenderPrecompute(pending, err)
		return err
	}
	if err := state.pool.Add(entries); err != nil {
		state.ready = false
		state.pool.Clear()
		state.pending = nil
		state.mu.Unlock()
		t.otReady.Store(false)
		signalSenderPrecompute(pending, err)
		return err
	}
	wasInitial := pending.isInitial
	state.epoch = mpc.ExtensionEpoch(pending.session)
	state.pending = nil
	state.pool.SetExtendPending(false)
	if wasInitial {
		state.ready = true
	}
	state.mu.Unlock()
	t.otReady.Store(true)
	signalSenderPrecompute(pending, nil)
	return nil
}

func signalSenderPrecompute(pending *senderPrecompute, err error) {
	if pending == nil {
		return
	}
	select {
	case pending.done <- err:
	default:
	}
}

func (t *TEEK) failPendingPrecompute(err error) {
	state := t.otPrecomputeState
	if state == nil {
		return
	}
	state.mu.Lock()
	pending := state.pending
	state.pending = nil
	state.pool.SetExtendPending(false)
	state.mu.Unlock()
	signalSenderPrecompute(pending, err)
}

func (t *TEEK) sendOTPrecomputeComplete(poolSize uint32) error {
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}
	conn := t.connManager.GetControlConnection()
	if conn == nil {
		return fmt.Errorf("no TEE_T control connection available")
	}
	env := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeComplete{OtPrecomputeComplete: &teeproto.OTPrecomputeComplete{PoolSize: poolSize}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal OT precompute complete: %w", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("send OT precompute complete: %w", err)
	}
	return nil
}

func (t *TEEK) isOTPoolReady() bool {
	if t.otPrecomputeState == nil {
		return false
	}
	t.otPrecomputeState.mu.Lock()
	defer t.otPrecomputeState.mu.Unlock()
	return t.otPrecomputeState.ready
}

func (t *TEEK) reserveOTEntries(count int) (uint64, []mpc.SenderOT, error) {
	if t.otPrecomputeState == nil {
		return 0, nil, fmt.Errorf("OT pool not initialized")
	}
	state := t.otPrecomputeState
	state.mu.Lock()
	if !state.ready {
		state.mu.Unlock()
		return 0, nil, fmt.Errorf("OT pool not ready")
	}
	start, entries, err := state.pool.Reserve(count)
	needsExtend := err == nil && state.pool.NeedsExtend()
	state.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	if needsExtend {
		go func() {
			if err := t.performOTPrecomputation(mpc.OTPoolExtendSize, false); err != nil {
				t.logger.Error("Failed to extend OT pool", zap.Error(err))
			}
		}()
	}
	return start, entries, nil
}

func (t *TEEK) clearOTPool() {
	if t.otPrecomputeState == nil {
		return
	}
	state := t.otPrecomputeState
	state.mu.Lock()
	pending := state.pending
	state.pool.Clear()
	state.pending = nil
	state.ready = false
	state.mu.Unlock()
	signalSenderPrecompute(pending, fmt.Errorf("OT precomputation aborted while clearing pool"))
	t.otReady.Store(false)
	t.logger.Info("Cleared OT pool due to disconnect")
}

func (t *TEEK) suspendOTPoolForReconnect() {
	if t.otPrecomputeState == nil {
		return
	}
	state := t.otPrecomputeState
	state.mu.Lock()
	ready := state.ready
	if ready {
		pending := state.pending
		state.pending = nil
		state.pool.SetExtendPending(false)
		epoch := state.epoch
		state.mu.Unlock()
		signalSenderPrecompute(pending, fmt.Errorf("OT precomputation interrupted by disconnect"))
		t.logger.Info("Retained OT pool across disconnect for resume", zap.String("epoch", epoch))
		return
	}
	state.mu.Unlock()
	t.clearOTPool()
}

func (t *TEEK) hasResumablePool() bool {
	if t.otPrecomputeState == nil {
		return false
	}
	t.otPrecomputeState.mu.Lock()
	defer t.otPrecomputeState.mu.Unlock()
	return t.otPrecomputeState.ready && t.otPrecomputeState.epoch != "" && t.otPrecomputeState.pool.Available() > 0
}

func (t *TEEK) tryResumeOTPool() (bool, error) {
	if t.connManager == nil {
		return false, fmt.Errorf("connection manager not initialized")
	}
	conn := t.connManager.GetControlConnection()
	if conn == nil {
		return false, fmt.Errorf("no TEE_T control connection available")
	}
	state := t.otPrecomputeState
	state.mu.Lock()
	epoch := state.epoch
	nextIndex := state.pool.NextIndex()
	state.mu.Unlock()
	if nextIndex > math.MaxUint32 {
		return false, fmt.Errorf("OT resume index exceeds protobuf uint32 range")
	}
	select {
	case <-state.resumeChan:
	default:
	}
	env := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtResumeRequest{OtResumeRequest: &teeproto.OTResumeRequest{
			Epoch: epoch, NextIndex: uint32(nextIndex),
		}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return false, fmt.Errorf("marshal OT resume request: %w", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return false, fmt.Errorf("send OT resume request: %w", err)
	}
	select {
	case accepted := <-state.resumeChan:
		return accepted, nil
	case <-time.After(10 * time.Second):
		return false, fmt.Errorf("OT resume timed out")
	}
}

func (t *TEEK) handleOTResumeResponse(msg *teeproto.OTResumeResponse) error {
	if t.otPrecomputeState == nil {
		return fmt.Errorf("OT pool not initialized")
	}
	select {
	case t.otPrecomputeState.resumeChan <- msg.GetAccepted():
	default:
	}
	return nil
}
