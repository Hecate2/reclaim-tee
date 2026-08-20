package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"
	"uuid"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

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
	extension    *mpc.ExtensionSenderState
	phase        senderPrecomputePhase
	done         chan error

	controlConn       *shared.WSConnection
	controlGeneration uint64
	extendClaim       *mpc.SenderExtendClaim

	// sendComplete is a request-local synchronization/error hook for
	// deterministic ownership tests. Production leaves it nil.
	sendComplete          func(uint64) error
	beforeStateValidation func()
}

type senderPrecomputePhase uint8

const (
	senderPrecomputeAwaitBaseSetup senderPrecomputePhase = iota
	senderPrecomputeAwaitCommitment
	senderPrecomputeProcessingCommitment
	senderPrecomputeAwaitProof
	senderPrecomputeProcessingProof
)

type senderResumeResult struct {
	controlConn       *shared.WSConnection
	controlGeneration uint64
	accepted          bool
}

// OTPrecomputeState holds the compact random-OT pool and one in-flight KOS
// extension batch for the shared TEE_T connection.
type OTPrecomputeState struct {
	mu            sync.Mutex
	pool          *mpc.SenderPool
	ready         bool
	inconsistent  bool
	epoch         string
	resumeChan    chan senderResumeResult
	resumePending *controlConnectionToken
	pending       *senderPrecompute
}

func NewOTPrecomputeState() *OTPrecomputeState {
	return &OTPrecomputeState{
		pool:       mpc.NewSenderPool(mpc.OTPoolInitialSize),
		resumeChan: make(chan senderResumeResult, 1),
	}
}

// performOTPrecomputation runs one fresh-base-OT malicious IKNP/KOS batch and
// blocks until TEE_T has committed the matching receiver entries.
func (t *TEEK) performOTPrecomputation(count int, isInitial bool) error {
	return t.performOTPrecomputationWithClaim(count, isInitial, nil, nil)
}

func (t *TEEK) performClaimedOTExtension(count int, claim *mpc.SenderExtendClaim, origin *controlConnectionToken) error {
	return t.performOTPrecomputationWithClaim(count, false, claim, origin)
}

func (t *TEEK) performOTPrecomputationWithClaim(count int, isInitial bool, claim *mpc.SenderExtendClaim, expectedOrigin *controlConnectionToken) error {
	if err := mpc.ValidatePrecomputeCount(count); err != nil {
		return err
	}
	if !isInitial {
		if claim == nil {
			return fmt.Errorf("OT extension has no ownership claim")
		}
	} else if claim != nil || expectedOrigin != nil {
		return fmt.Errorf("initial OT precomputation cannot use an extension claim")
	}
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}
	origin := expectedOrigin
	if origin == nil {
		var err error
		origin, err = t.connManager.currentAttestedControlToken()
		if err != nil {
			return err
		}
	}
	// Validate the cumulative frontier while holding the same ownership locks
	// used by setup. This must happen before session/epoch randomness is read.
	t.connManager.mu.RLock()
	if t.connManager.controlConn != origin.conn || t.connManager.controlGeneration != origin.generation {
		t.connManager.mu.RUnlock()
		return fmt.Errorf("TEE_T control connection changed before OT precomputation preflight")
	}
	state := t.otPrecomputeState
	if state == nil {
		if !isInitial {
			t.connManager.mu.RUnlock()
			return fmt.Errorf("OT refill claim has no sender pool")
		}
		state = NewOTPrecomputeState()
	}
	state.mu.Lock()
	if state.pending != nil {
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		return fmt.Errorf("OT precomputation already in progress")
	}
	startIndex := uint64(0)
	if !isInitial {
		if !state.ready {
			state.mu.Unlock()
			t.connManager.mu.RUnlock()
			return fmt.Errorf("cannot extend: OT pool not ready")
		}
		if !state.pool.OwnsExtendClaim(claim) {
			state.mu.Unlock()
			t.connManager.mu.RUnlock()
			return fmt.Errorf("OT refill claim was lost before preflight")
		}
		startIndex = state.pool.TotalCount()
	}
	_, frontierErr := mpc.CheckedOTIndexEnd(startIndex, count)
	state.mu.Unlock()
	t.connManager.mu.RUnlock()
	if frontierErr != nil {
		return frontierErr
	}

	t.logger.Info("Starting KOS OT precomputation", zap.Int("count", count), zap.Bool("is_initial", isInitial))
	if err := mpc.Initialize(); err != nil {
		return fmt.Errorf("initialize MPC circuit: %w", err)
	}
	rng := t.otPrecomputeRandom
	if rng == nil {
		rng = rand.Reader
	}
	session, initialEpoch, err := newSenderPrecomputeIdentity(rng, startIndex, count, isInitial)
	if err != nil {
		return err
	}
	pending := &senderPrecompute{
		session: session, count: count, isInitial: isInitial,
		done: make(chan error, 1), controlConn: origin.conn, controlGeneration: origin.generation,
		extendClaim: claim,
	}
	// Make control validation and all initial pool mutations one short atomic
	// ownership step. A superseded goroutine must not clear a replacement pool
	// after capturing an older control token.
	t.connManager.mu.Lock()
	if t.connManager.controlConn != origin.conn || t.connManager.controlGeneration != origin.generation {
		t.connManager.mu.Unlock()
		return fmt.Errorf("TEE_T control connection changed before OT precomputation setup")
	}
	state.mu.Lock()
	if t.otPrecomputeState == nil {
		if !isInitial {
			state.mu.Unlock()
			t.connManager.mu.Unlock()
			return fmt.Errorf("OT refill state disappeared after preflight")
		}
		t.otPrecomputeState = state
	} else if t.otPrecomputeState != state {
		state.mu.Unlock()
		t.connManager.mu.Unlock()
		return fmt.Errorf("OT precompute state changed after preflight")
	}
	if state.pending != nil {
		state.mu.Unlock()
		t.connManager.mu.Unlock()
		return fmt.Errorf("OT precomputation already in progress")
	}
	if isInitial {
		state.epoch = initialEpoch
		state.pool.Clear()
		state.ready = false
		t.publishOTReadyLocked(state)
	} else {
		if !state.ready {
			state.mu.Unlock()
			t.connManager.mu.Unlock()
			return fmt.Errorf("cannot extend: OT pool not ready")
		}
		if !state.pool.OwnsExtendClaim(claim) {
			state.mu.Unlock()
			t.connManager.mu.Unlock()
			return fmt.Errorf("OT refill claim was lost before setup")
		}
	}
	currentStart := state.pool.TotalCount()
	if isInitial {
		currentStart = 0
	}
	if currentStart != startIndex {
		state.mu.Unlock()
		t.connManager.mu.Unlock()
		return fmt.Errorf("OT pool frontier changed after preflight: got %d want %d", currentStart, startIndex)
	}
	if _, err := mpc.CheckedOTIndexEnd(currentStart, count); err != nil {
		state.mu.Unlock()
		t.connManager.mu.Unlock()
		return err
	}
	pending.startIndex = currentStart
	begin := mpc.PrecomputeBegin{SessionID: session, StartIndex: startIndex, Count: uint32(count), Epoch: state.epoch}
	beginData, err := mpc.MarshalPrecomputeBegin(begin)
	if err != nil {
		state.mu.Unlock()
		t.connManager.mu.Unlock()
		return err
	}
	state.pending = pending
	epoch := state.epoch
	state.mu.Unlock()
	t.connManager.mu.Unlock()

	if !t.connManager.isCurrentControlConnection(pending.controlConn, pending.controlGeneration) {
		err := fmt.Errorf("TEE_T control connection changed before OT precomputation request")
		t.failPendingPrecompute(state, pending, err)
		return err
	}
	if err := t.sendOTPrecomputeRequest(pending.controlConn, count, isInitial, epoch, beginData); err != nil {
		t.failPendingPrecompute(state, pending, err)
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
		t.failPendingPrecompute(state, pending, err)
		return err
	}
}

func newSenderPrecomputeIdentity(rng io.Reader, startIndex uint64, count int, isInitial bool) ([32]byte, string, error) {
	var session [32]byte
	if _, err := mpc.CheckedOTIndexEnd(startIndex, count); err != nil {
		return session, "", err
	}
	var err error
	session, err = mpc.NewExtensionSession(rng)
	if err != nil {
		return session, "", err
	}
	if !isInitial {
		return session, "", nil
	}
	epochNonce, err := newV4UUIDFromReader(rng)
	if err != nil {
		return session, "", fmt.Errorf("sample initial OT extension epoch: %w", err)
	}
	epoch, err := mpc.InitialExtensionEpoch(epochNonce.String())
	if err != nil {
		return session, "", err
	}
	return session, epoch, nil
}

// newV4UUIDFromReader preserves deterministic and injectable randomness for
// OT precomputation while using the standard library UUID type.
func newV4UUIDFromReader(r io.Reader) (uuid.UUID, error) {
	var id uuid.UUID
	if _, err := io.ReadFull(r, id[:]); err != nil {
		return uuid.Nil(), err
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
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

// handleOTPrecomputeResponse advances the three-response KOS2 state machine:
// base setup, fixed BOT+U commitment, then the repetition-code proof.
func (t *TEEK) handleOTPrecomputeResponse(conn *shared.WSConnection, generation uint64, msg *teeproto.OTPrecomputeResponse) error {
	state := t.otPrecomputeState
	if state == nil {
		return fmt.Errorf("OT precompute state not initialized")
	}
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	// Take the locks in the same order as control teardown. The lease covers
	// only identity inspection/state reservation, never curve work or writes.
	t.connManager.mu.RLock()
	if t.connManager.controlConn != conn || t.connManager.controlGeneration != generation {
		t.connManager.mu.RUnlock()
		return fmt.Errorf("OT precompute response control connection is no longer current")
	}
	state.mu.Lock()
	pending := state.pending
	if pending == nil {
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		return fmt.Errorf("unexpected OT precompute response")
	}
	if pending.controlConn != conn || pending.controlGeneration != generation {
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		return fmt.Errorf("OT precompute response belongs to a superseded control connection")
	}
	if int(msg.GetCount()) != pending.count {
		err := fmt.Errorf("OT count mismatch: got %d want %d", msg.GetCount(), pending.count)
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		t.failPendingPrecompute(state, pending, err)
		return err
	}

	switch pending.phase {
	case senderPrecomputeAwaitBaseSetup:
		pending.phase = senderPrecomputeAwaitCommitment
		session := pending.session
		state.mu.Unlock()
		t.connManager.mu.RUnlock()

		setup, err := mpc.UnmarshalPrecomputeBaseSetup(msg.GetOtReceiverData(), session)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		baseReceiver, choices, err := mpc.StartBaseOTReceiver(rand.Reader, session, setup)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		baseReceiverOwned := true
		defer func() {
			if baseReceiverOwned {
				baseReceiver.Destroy()
			}
		}()
		choiceFrame, err := mpc.MarshalPrecomputeBaseChoices(session, choices)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}

		// Publish the base-OT result only while the exact originating control
		// and pending request are still current.
		t.connManager.mu.RLock()
		controlCurrent := t.connManager.controlConn == conn && t.connManager.controlGeneration == generation
		state.mu.Lock()
		if !controlCurrent || state.pending != pending || pending.controlConn != conn || pending.controlGeneration != generation || pending.baseReceiver != nil || pending.phase != senderPrecomputeAwaitCommitment {
			state.mu.Unlock()
			t.connManager.mu.RUnlock()
			return fmt.Errorf("OT sender state changed during base OT")
		}
		pending.baseReceiver = baseReceiver
		baseReceiverOwned = false
		count, initial, epoch := pending.count, pending.isInitial, state.epoch
		state.mu.Unlock()
		t.connManager.mu.RUnlock()

		if !t.connManager.isCurrentControlConnection(conn, generation) {
			err := fmt.Errorf("TEE_T control connection changed before OT precomputation continuation")
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		if err := t.sendOTPrecomputeRequest(conn, count, initial, epoch, choiceFrame); err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		return nil

	case senderPrecomputeAwaitCommitment:
		pending.phase = senderPrecomputeProcessingCommitment
		baseReceiver := pending.baseReceiver
		session := pending.session
		startIndex := pending.startIndex
		count := pending.count
		epoch := state.epoch
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		defer baseReceiver.Destroy()

		expected := mpc.PrecomputeBegin{SessionID: session, StartIndex: startIndex, Count: uint32(count), Epoch: epoch}
		ciphertexts, commitment, err := mpc.UnmarshalPrecomputeCommitmentFor(msg.GetOtReceiverData(), expected)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		selected, delta, err := mpc.FinishBaseOTReceiver(baseReceiver, ciphertexts)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		extension, challenge, err := mpc.StartExtensionSender(rand.Reader, selected, delta, epoch, ciphertexts, commitment)
		clear(selected[:])
		delta = mpc.Label{}
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		extensionOwned := true
		defer func() {
			if extensionOwned {
				extension.Destroy()
			}
		}()
		challengeFrame, err := mpc.MarshalExtensionChallenge(challenge)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}

		t.connManager.mu.RLock()
		controlCurrent := t.connManager.controlConn == conn && t.connManager.controlGeneration == generation
		state.mu.Lock()
		if !controlCurrent || state.pending != pending || pending.controlConn != conn || pending.controlGeneration != generation || pending.phase != senderPrecomputeProcessingCommitment {
			state.mu.Unlock()
			t.connManager.mu.RUnlock()
			return fmt.Errorf("OT sender state changed while preparing KOS2 challenge")
		}
		pending.extension = extension
		extensionOwned = false
		pending.phase = senderPrecomputeAwaitProof
		initial := pending.isInitial
		state.mu.Unlock()
		t.connManager.mu.RUnlock()

		if err := t.sendOTPrecomputeRequest(conn, count, initial, epoch, challengeFrame); err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		return nil

	case senderPrecomputeAwaitProof:
		pending.phase = senderPrecomputeProcessingProof
		extension := pending.extension
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		defer extension.Destroy()
		proof, err := mpc.UnmarshalExtensionProofFor(msg.GetOtReceiverData(), pending.session)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		entries, err := mpc.FinishExtensionSender(extension, proof)
		if err != nil {
			t.failPendingPrecompute(state, pending, err)
			return err
		}
		return t.completeSenderPrecompute(state, pending, entries)

	default:
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		return fmt.Errorf("unexpected OT precompute response phase %d", pending.phase)
	}
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

func (t *TEEK) completeSenderPrecompute(state *OTPrecomputeState, pending *senderPrecompute, entries []mpc.SenderOT) error {
	defer clear(entries)
	if state == nil || pending == nil || t.connManager == nil {
		return fmt.Errorf("OT precompute identity is incomplete")
	}
	expectedTotal, err := mpc.CheckedOTIndexEnd(pending.startIndex, len(entries))
	if err != nil {
		return err
	}

	// Validate the exact control and pending request atomically before the
	// irreversible Complete acknowledgment. Do not retain the lease while the
	// network write can block.
	t.connManager.mu.RLock()
	if pending.beforeStateValidation != nil {
		pending.beforeStateValidation()
	}
	controlCurrent := t.connManager.controlConn == pending.controlConn && t.connManager.controlGeneration == pending.controlGeneration
	state.mu.Lock()
	claimCurrent := pending.isInitial || state.pool.OwnsExtendClaim(pending.extendClaim)
	stateCurrent := t.otPrecomputeState == state && state.pending == pending && claimCurrent && state.pool.TotalCount() == pending.startIndex
	var addErr error
	if stateCurrent {
		addErr = state.pool.ValidateAdd(entries)
	}
	state.mu.Unlock()
	t.connManager.mu.RUnlock()
	if !controlCurrent || !stateCurrent {
		err := fmt.Errorf("OT sender state changed during extension")
		t.failPendingPrecomputeAndClear(state, pending, err)
		return err
	}
	if addErr != nil {
		err := fmt.Errorf("invalid OT sender completion batch: %w", addErr)
		if pending.isInitial {
			t.failPendingPrecomputeAndClear(state, pending, err)
			return err
		}
		if t.failPendingPrecompute(state, pending, err) {
			t.recoverFailedClaimedOTExtension(pending.extendClaim, &controlConnectionToken{
				conn: pending.controlConn, generation: pending.controlGeneration,
			}, err)
		}
		return err
	}

	sendComplete := pending.sendComplete
	if sendComplete == nil {
		sendComplete = func(poolSize uint64) error {
			return t.sendOTPrecomputeComplete(pending, poolSize)
		}
	}
	if err := sendComplete(expectedTotal); err != nil {
		t.failPendingPrecomputeAndClear(state, pending, err)
		return err
	}

	// Commit locally under the short control-generation lease. This closes the
	// window where a successful old-generation Complete write could append to a
	// replacement pool after the connection was superseded.
	t.connManager.mu.RLock()
	controlCurrent = t.connManager.controlConn == pending.controlConn && t.connManager.controlGeneration == pending.controlGeneration
	state.mu.Lock()
	claimCurrent = pending.isInitial || state.pool.OwnsExtendClaim(pending.extendClaim)
	if !controlCurrent || t.otPrecomputeState != state || state.pending != pending || !claimCurrent || state.pool.TotalCount() != pending.startIndex {
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		err := fmt.Errorf("OT sender state changed before local commit")
		t.failPendingPrecomputeAndClear(state, pending, err)
		return err
	}
	if err := state.pool.Add(entries); err != nil {
		if pending.isInitial {
			state.pool.Clear()
		} else if !state.pool.ClearForExtendFailure(pending.extendClaim) {
			state.mu.Unlock()
			t.connManager.mu.RUnlock()
			ownershipErr := fmt.Errorf("OT refill ownership changed after append failure: %w", err)
			signalSenderPrecompute(pending, ownershipErr)
			return ownershipErr
		}
		state.ready = false
		state.pending = nil
		t.publishOTReadyLocked(state)
		state.mu.Unlock()
		t.connManager.mu.RUnlock()
		signalSenderPrecompute(pending, err)
		return err
	}
	wasInitial := pending.isInitial
	state.epoch = mpc.ExtensionEpoch(pending.session)
	state.pending = nil
	if !wasInitial {
		state.pool.ReleaseExtendClaim(pending.extendClaim)
	}
	if wasInitial {
		state.ready = true
		state.inconsistent = false
	}
	t.publishOTReadyLocked(state)
	state.mu.Unlock()
	t.connManager.mu.RUnlock()
	signalSenderPrecompute(pending, nil)
	return nil
}

func (t *TEEK) failPendingPrecompute(state *OTPrecomputeState, expected *senderPrecompute, err error) bool {
	if state == nil || expected == nil || t.otPrecomputeState != state {
		return false
	}
	state.mu.Lock()
	if t.otPrecomputeState != state || state.pending != expected {
		state.mu.Unlock()
		return false
	}
	state.pending = nil
	state.mu.Unlock()
	destroyIdleSenderPrecompute(expected)
	signalSenderPrecompute(expected, err)
	return true
}

func (t *TEEK) failPendingPrecomputeAndClear(state *OTPrecomputeState, expected *senderPrecompute, err error) bool {
	if state == nil || expected == nil || t.otPrecomputeState != state {
		return false
	}
	state.mu.Lock()
	if t.otPrecomputeState != state || state.pending != expected {
		state.mu.Unlock()
		return false
	}
	if expected.isInitial {
		state.pool.Clear()
	} else if !state.pool.ClearForExtendFailure(expected.extendClaim) {
		state.mu.Unlock()
		return false
	}
	state.ready = false
	state.pending = nil
	t.publishOTReadyLocked(state)
	state.mu.Unlock()
	destroyIdleSenderPrecompute(expected)
	signalSenderPrecompute(expected, err)
	return true
}

// destroyIdleSenderPrecompute clears state only when no handler can be using
// it outside the state lock. Processing phases consume and clear their own
// base/extension state before they return.
func destroyIdleSenderPrecompute(pending *senderPrecompute) {
	if pending == nil {
		return
	}
	switch pending.phase {
	case senderPrecomputeProcessingCommitment, senderPrecomputeProcessingProof:
		return
	}
	pending.baseReceiver.Destroy()
	pending.baseReceiver = nil
	pending.extension.Destroy()
	pending.extension = nil
	clear(pending.session[:])
}

func (t *TEEK) sendOTPrecomputeComplete(pending *senderPrecompute, poolSize uint64) error {
	if t.connManager == nil || pending == nil || pending.controlConn == nil {
		return fmt.Errorf("connection manager not initialized")
	}
	if !t.connManager.isCurrentControlConnection(pending.controlConn, pending.controlGeneration) {
		return fmt.Errorf("TEE_T control connection changed before OT precompute completion")
	}
	env := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeComplete{OtPrecomputeComplete: &teeproto.OTPrecomputeComplete{PoolSize: poolSize}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal OT precompute complete: %w", err)
	}
	if err := pending.controlConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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
	return otPoolUsableLocked(t.otPrecomputeState)
}

func otPoolUsableLocked(state *OTPrecomputeState) bool {
	return state != nil && state.ready && !state.inconsistent && state.pool.Available() >= mpc.OTsPerOPRF
}

// publishOTReadyLocked stores readiness while state.mu still serializes the
// pool mutation that produced it. This prevents an older computation from
// publishing after a newer reservation, refill, or lifecycle transition.
func (t *TEEK) publishOTReadyLocked(state *OTPrecomputeState) bool {
	usable := otPoolUsableLocked(state)
	t.otReady.Store(usable)
	return usable
}

type senderRefillStarter func(int, *mpc.SenderExtendClaim, *controlConnectionToken)

// reserveOTEntriesForSession validates the exact session/control identity,
// reserves sender OTs, and publishes the receiver-confirmation reservation
// under one control-generation lease. Lock order is cm -> OT state -> session
// OPRF state -> sender pool.
func (t *TEEK) reserveOTEntriesForSession(identity *teekSessionIdentity, sessionState *TEEKSessionState, rangeIndex, count int) (uint64, []mpc.SenderOT, *senderOTReservation, error) {
	return t.reserveOTEntriesForSessionWithRefill(identity, sessionState, rangeIndex, count, t.startClaimedOTExtension)
}

func (t *TEEK) reserveOTEntriesForSessionWithRefill(identity *teekSessionIdentity, sessionState *TEEKSessionState, rangeIndex, count int, startRefill senderRefillStarter) (uint64, []mpc.SenderOT, *senderOTReservation, error) {
	if t.connManager == nil || t.otPrecomputeState == nil || identity == nil || sessionState == nil {
		return 0, nil, nil, fmt.Errorf("OT reservation identity is incomplete")
	}
	cm := t.connManager
	state := t.otPrecomputeState
	cm.mu.RLock()
	if err := cm.validateSessionConnectionLocked(identity.sessionConn); err != nil {
		cm.mu.RUnlock()
		return 0, nil, nil, err
	}
	if identity.session != sessionState.session {
		cm.mu.RUnlock()
		return 0, nil, nil, fmt.Errorf("OPRF session state was superseded")
	}
	state.mu.Lock()
	if !state.ready || state.inconsistent {
		state.mu.Unlock()
		cm.mu.RUnlock()
		return 0, nil, nil, fmt.Errorf("OT pool not ready")
	}

	sessionState.oprfMu.Lock()
	if sessionState.OTReservations[rangeIndex] != nil {
		sessionState.oprfMu.Unlock()
		state.mu.Unlock()
		cm.mu.RUnlock()
		return 0, nil, nil, fmt.Errorf("OT reservation already exists for range %d", rangeIndex)
	}
	start, entries, reserveErr := state.pool.Reserve(count)
	claim := state.pool.ClaimExtendIfNeeded()
	var reservation *senderOTReservation
	if reserveErr == nil {
		reservation = &senderOTReservation{
			startIndex: start, controlConn: identity.sessionConn.controlConn,
			controlGeneration: identity.sessionConn.controlGeneration,
		}
		if sessionState.OTReservations == nil {
			sessionState.OTReservations = make(map[int]*senderOTReservation)
		}
		sessionState.OTReservations[rangeIndex] = reservation
	}
	sessionState.oprfMu.Unlock()
	if t.beforeReserveOTReadyPublish != nil {
		t.beforeReserveOTReadyPublish()
	}
	t.publishOTReadyLocked(state)
	state.mu.Unlock()
	origin := &controlConnectionToken{conn: identity.sessionConn.controlConn, generation: identity.sessionConn.controlGeneration}
	cm.mu.RUnlock()

	if claim != nil {
		if startRefill == nil {
			err := fmt.Errorf("OT refill callback is nil")
			if reserveErr == nil {
				t.abandonOTReservation(sessionState, rangeIndex, reservation)
			}
			t.recoverFailedClaimedOTExtension(claim, origin, err)
			return 0, nil, nil, err
		} else {
			startRefill(mpc.OTPoolExtendSize, claim, origin)
		}
	}
	if reserveErr != nil {
		return 0, nil, nil, reserveErr
	}
	return start, entries, reservation, nil
}

func (t *TEEK) startClaimedOTExtension(count int, claim *mpc.SenderExtendClaim, origin *controlConnectionToken) {
	go func() {
		if err := t.performClaimedOTExtension(count, claim, origin); err != nil {
			t.logger.Error("Failed to extend OT pool", zap.Error(err))
			t.recoverFailedClaimedOTExtension(claim, origin, err)
		}
	}()
}

// recoverFailedClaimedOTExtension restores service when enough committed OTs
// remain. If fewer than one circuit remain, it closes only the exact control
// generation that owned the failed refill so reconnect/resume can reconcile.
func (t *TEEK) recoverFailedClaimedOTExtension(claim *mpc.SenderExtendClaim, origin *controlConnectionToken, cause error) bool {
	if t.otPrecomputeState == nil {
		return false
	}
	state := t.otPrecomputeState
	if t.connManager == nil || origin == nil || origin.conn == nil {
		state.mu.Lock()
		state.pool.ReleaseExtendClaim(claim)
		t.publishOTReadyLocked(state)
		state.mu.Unlock()
		return false
	}
	cm := t.connManager
	cm.mu.Lock()
	state.mu.Lock()
	if !state.pool.ReleaseExtendClaim(claim) {
		state.mu.Unlock()
		cm.mu.Unlock()
		return false
	}
	if cm.controlConn != origin.conn || cm.controlGeneration != origin.generation {
		state.mu.Unlock()
		cm.mu.Unlock()
		return false
	}
	usable := state.ready && !state.inconsistent && state.pool.Available() >= mpc.OTsPerOPRF
	if !usable {
		state.inconsistent = true
	}
	t.publishOTReadyLocked(state)
	state.mu.Unlock()
	if usable {
		cm.mu.Unlock()
		return false
	}
	t.controlHealthy.Store(false)
	cm.mu.Unlock()
	t.logger.Warn("OT refill failed with no usable circuit remaining; reconnecting exact control", zap.Error(cause))
	_ = origin.conn.Close()
	return true
}

func (t *TEEK) reconcileAbandonedOTReservation(reservation *senderOTReservation) bool {
	if reservation == nil || reservation.controlConn == nil || t.connManager == nil || t.otPrecomputeState == nil {
		return false
	}
	cm := t.connManager
	state := t.otPrecomputeState
	cm.mu.Lock()
	if cm.controlConn != reservation.controlConn || cm.controlGeneration != reservation.controlGeneration {
		cm.mu.Unlock()
		return false
	}
	state.mu.Lock()
	state.inconsistent = true
	t.publishOTReadyLocked(state)
	state.mu.Unlock()
	t.controlHealthy.Store(false)
	cm.mu.Unlock()
	_ = reservation.controlConn.Close()
	return true
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
	state.inconsistent = false
	state.resumePending = nil
	t.publishOTReadyLocked(state)
	state.mu.Unlock()
	destroyIdleSenderPrecompute(pending)
	signalSenderPrecompute(pending, fmt.Errorf("OT precomputation aborted while clearing pool"))
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
		state.pool.InvalidateExtendClaim()
		epoch := state.epoch
		t.publishOTReadyLocked(state)
		state.mu.Unlock()
		destroyIdleSenderPrecompute(pending)
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
	return t.otPrecomputeState.ready && mpc.IsCurrentExtensionEpoch(t.otPrecomputeState.epoch) && t.otPrecomputeState.pool.Available() > 0
}

// ensureResumedOTPoolUsable repairs a retained pool before readiness is
// advertised. A sub-circuit remainder cannot satisfy even one OPRF, so its
// refill completes synchronously on the resumed control connection.
func (t *TEEK) ensureResumedOTPoolUsable() error {
	origin, err := t.connManager.currentAttestedControlToken()
	if err != nil {
		return err
	}
	return t.ensureResumedOTPoolUsableWithRefill(
		origin,
		func(refillCount int, claim *mpc.SenderExtendClaim, refillOrigin *controlConnectionToken) error {
			return t.performClaimedOTExtension(refillCount, claim, refillOrigin)
		},
		t.startClaimedOTExtension,
	)
}

func (t *TEEK) ensureResumedOTPoolUsableWithRefill(origin *controlConnectionToken, runRefill func(int, *mpc.SenderExtendClaim, *controlConnectionToken) error, startRefill senderRefillStarter) error {
	if t.otPrecomputeState == nil {
		return fmt.Errorf("OT pool not initialized")
	}
	state := t.otPrecomputeState
	state.mu.Lock()
	available := state.pool.Available()
	if available >= mpc.OTPoolWatermark {
		t.publishOTReadyLocked(state)
		state.mu.Unlock()
		return nil
	}
	claim := state.pool.ClaimExtendIfNeeded()
	t.publishOTReadyLocked(state)
	state.mu.Unlock()
	if claim == nil {
		return fmt.Errorf("OT refill is already pending after resume")
	}
	if available < mpc.OTsPerOPRF {
		if runRefill == nil {
			state.mu.Lock()
			state.pool.ReleaseExtendClaim(claim)
			t.publishOTReadyLocked(state)
			state.mu.Unlock()
			return fmt.Errorf("synchronous OT refill callback is nil")
		}
		err := runRefill(mpc.OTPoolExtendSize, claim, origin)
		if err != nil {
			state.mu.Lock()
			state.pool.ReleaseExtendClaim(claim)
			t.publishOTReadyLocked(state)
			state.mu.Unlock()
		}
		return err
	}
	if startRefill == nil {
		state.mu.Lock()
		state.pool.ReleaseExtendClaim(claim)
		t.publishOTReadyLocked(state)
		state.mu.Unlock()
		return fmt.Errorf("asynchronous OT refill callback is nil")
	}
	startRefill(mpc.OTPoolExtendSize, claim, origin)
	return nil
}

func (t *TEEK) tryResumeOTPool() (bool, error) {
	if t.connManager == nil {
		return false, fmt.Errorf("connection manager not initialized")
	}
	origin, err := t.connManager.currentAttestedControlToken()
	if err != nil {
		return false, err
	}
	state := t.otPrecomputeState
	state.mu.Lock()
	epoch := state.epoch
	nextIndex := state.pool.NextIndex()
	if !mpc.IsCurrentExtensionEpoch(epoch) {
		state.mu.Unlock()
		return false, fmt.Errorf("OT pool uses an unsupported protocol epoch")
	}
	if state.resumePending != nil {
		state.mu.Unlock()
		return false, fmt.Errorf("OT resume already pending")
	}
	state.resumePending = origin
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		if state.resumePending == origin {
			state.resumePending = nil
		}
		state.mu.Unlock()
	}()
	select {
	case <-state.resumeChan:
	default:
	}
	env := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtResumeRequest{OtResumeRequest: &teeproto.OTResumeRequest{
			Epoch: epoch, NextIndex: nextIndex,
		}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return false, fmt.Errorf("marshal OT resume request: %w", err)
	}
	if err := origin.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return false, fmt.Errorf("send OT resume request: %w", err)
	}
	select {
	case result := <-state.resumeChan:
		if result.controlConn != origin.conn || result.controlGeneration != origin.generation {
			return false, fmt.Errorf("OT resume response belongs to a superseded control connection")
		}
		if result.accepted {
			if !t.connManager.isCurrentControlConnection(origin.conn, origin.generation) {
				return false, fmt.Errorf("OT resume control connection changed before commit")
			}
			state.mu.Lock()
			state.inconsistent = false
			t.publishOTReadyLocked(state)
			state.mu.Unlock()
		}
		return result.accepted, nil
	case <-time.After(10 * time.Second):
		return false, fmt.Errorf("OT resume timed out")
	}
}

func (t *TEEK) handleOTResumeResponse(conn *shared.WSConnection, generation uint64, msg *teeproto.OTResumeResponse) error {
	if t.otPrecomputeState == nil {
		return fmt.Errorf("OT pool not initialized")
	}
	state := t.otPrecomputeState
	state.mu.Lock()
	pending := state.resumePending
	state.mu.Unlock()
	if pending == nil || pending.conn != conn || pending.generation != generation {
		return fmt.Errorf("unexpected OT resume response")
	}
	select {
	case state.resumeChan <- senderResumeResult{controlConn: conn, controlGeneration: generation, accepted: msg.GetAccepted()}:
	default:
	}
	return nil
}
