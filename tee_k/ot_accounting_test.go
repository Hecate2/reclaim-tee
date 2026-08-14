package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

func TestResumedPoolWithExactRemainderRefillsBeforeReady(t *testing.T) {
	state := NewOTPrecomputeState()
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTPoolInitialSize)); err != nil {
		t.Fatal(err)
	}
	for range 156 {
		if _, _, err := state.pool.Reserve(mpc.OTsPerOPRF); err != nil {
			t.Fatal(err)
		}
	}
	if got := state.pool.Available(); got != 160 {
		t.Fatalf("resume remainder = %d, want 160", got)
	}
	teek := &TEEK{otPrecomputeState: state, logger: shared.NewNopLogger()}
	var calls int
	origin := &controlConnectionToken{}
	err := teek.ensureResumedOTPoolUsableWithRefill(origin, func(count int, claim *mpc.SenderExtendClaim, refillOrigin *controlConnectionToken) error {
		calls++
		if refillOrigin != origin {
			t.Fatal("synchronous refill lost exact control origin")
		}
		if count != mpc.OTPoolExtendSize {
			t.Fatalf("refill count = %d, want %d", count, mpc.OTPoolExtendSize)
		}
		if !state.pool.OwnsExtendClaim(claim) {
			t.Fatal("synchronous refill did not own the claim")
		}
		if err := state.pool.Add(accountingSenderOTs(mpc.OTPoolInitialSize, count)); err != nil {
			return err
		}
		if !state.pool.ReleaseExtendClaim(claim) {
			t.Fatal("synchronous refill did not release its exact claim")
		}
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("synchronous refills = %d, want 1", calls)
	}
	if got := state.pool.Available(); got != 160+mpc.OTPoolExtendSize {
		t.Fatalf("available after refill = %d", got)
	}
	if !teek.isOTPoolReady() {
		t.Fatal("refilled resumed pool was not usable")
	}
}

func TestConcurrentReservationsStartExactlyOneRefill(t *testing.T) {
	teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
	state := teek.otPrecomputeState
	state.ready = true
	const initial = 60_000
	if err := state.pool.Add(accountingSenderOTs(0, initial)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.pool.Reserve(11_000); err != nil {
		t.Fatal(err)
	}
	sessionState, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}
	var starts atomic.Int32
	var badCount atomic.Bool
	var failures atomic.Int32
	claimResult := make(chan *mpc.SenderExtendClaim, 1)
	var wg sync.WaitGroup
	for rangeIndex := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, err := teek.reserveOTEntriesForSessionWithRefill(identity, sessionState, rangeIndex, 1, func(count int, claim *mpc.SenderExtendClaim, origin *controlConnectionToken) {
				if count != mpc.OTPoolExtendSize {
					badCount.Store(true)
				}
				if origin.conn != sessionConn.controlConn || origin.generation != sessionConn.controlGeneration {
					badCount.Store(true)
				}
				starts.Add(1)
				claimResult <- claim
			})
			if err != nil {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("reservation failures = %d", failures.Load())
	}
	if badCount.Load() {
		t.Fatal("refill used a non-standard batch size")
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("refill starts = %d, want 1", got)
	}
	claim := <-claimResult
	if !state.pool.ReleaseExtendClaim(claim) {
		t.Fatal("winning refill claim could not be released")
	}
}

func TestOTReadyPublicationSerializesFinalReservationAndRefillCompletion(t *testing.T) {
	teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
	state := teek.otPrecomputeState
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTsPerOPRF)); err != nil {
		t.Fatal(err)
	}
	claim := state.pool.ClaimExtendIfNeeded()
	if claim == nil {
		t.Fatal("claim refill")
	}
	sessionState, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}

	reservationBeforePublish := make(chan struct{})
	allowReservationPublish := make(chan struct{})
	var reservationHook sync.Once
	teek.beforeReserveOTReadyPublish = func() {
		reservationHook.Do(func() { close(reservationBeforePublish) })
		<-allowReservationPublish
	}
	completionBeforeState := make(chan struct{})
	pending := &senderPrecompute{
		count: mpc.OTPoolExtendSize, startIndex: mpc.OTsPerOPRF,
		done: make(chan error, 1), controlConn: sessionConn.controlConn,
		controlGeneration: sessionConn.controlGeneration, extendClaim: claim,
		sendComplete: func(uint32) error { return nil },
		beforeStateValidation: func() {
			close(completionBeforeState)
		},
	}
	state.mu.Lock()
	state.pending = pending
	teek.publishOTReadyLocked(state)
	state.mu.Unlock()

	reservationResult := make(chan error, 1)
	go func() {
		_, _, _, reserveErr := teek.reserveOTEntriesForSessionWithRefill(identity, sessionState, 0, mpc.OTsPerOPRF, func(int, *mpc.SenderExtendClaim, *controlConnectionToken) {
			t.Error("final reservation started a second refill")
		})
		reservationResult <- reserveErr
	}()
	<-reservationBeforePublish

	completionResult := make(chan error, 1)
	go func() {
		completionResult <- teek.completeSenderPrecompute(state, pending, accountingSenderOTs(mpc.OTsPerOPRF, mpc.OTPoolExtendSize))
	}()
	<-completionBeforeState
	close(allowReservationPublish)
	if err := <-reservationResult; err != nil {
		t.Fatalf("final reservation: %v", err)
	}
	if err := <-completionResult; err != nil {
		t.Fatalf("refill completion: %v", err)
	}
	if !teek.OTReady() || !teek.isOTPoolReady() {
		t.Fatal("final readiness did not match the refilled usable pool")
	}
	if got := state.pool.Available(); got != mpc.OTPoolExtendSize {
		t.Fatalf("available after serialized reservation/refill = %d, want %d", got, mpc.OTPoolExtendSize)
	}
}

func TestClaimedRefillRecoveryReleasesEarlyFailure(t *testing.T) {
	state := NewOTPrecomputeState()
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTPoolWatermark-1)); err != nil {
		t.Fatal(err)
	}
	claim := state.pool.ClaimExtendIfNeeded()
	if claim == nil {
		t.Fatal("failed to claim low-water refill")
	}
	teek := &TEEK{otPrecomputeState: state, logger: shared.NewNopLogger()}
	if err := teek.performClaimedOTExtension(mpc.OTPoolExtendSize, claim, &controlConnectionToken{}); err == nil {
		t.Fatal("claimed refill unexpectedly succeeded without a connection manager")
	}
	if !state.pool.OwnsExtendClaim(claim) {
		t.Fatal("early refill failure opened an unowned recovery gap")
	}
	teek.recoverFailedClaimedOTExtension(claim, nil, errors.New("injected early failure"))
	if state.pool.IsExtendPending() {
		t.Fatal("early refill recovery retained its claim")
	}
	if state.pool.ClaimExtendIfNeeded() == nil {
		t.Fatal("released refill claim could not be reacquired")
	}
}

func TestDelayedRefillWorkerCannotReleaseReplacementClaim(t *testing.T) {
	state := NewOTPrecomputeState()
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTPoolWatermark-1)); err != nil {
		t.Fatal(err)
	}
	oldClaim := state.pool.ClaimExtendIfNeeded()
	if oldClaim == nil {
		t.Fatal("claim old refill")
	}
	state.pool.Clear()
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTPoolWatermark-1)); err != nil {
		t.Fatal(err)
	}
	replacementClaim := state.pool.ClaimExtendIfNeeded()
	if replacementClaim == nil {
		t.Fatal("claim replacement refill")
	}

	teek := &TEEK{otPrecomputeState: state, logger: shared.NewNopLogger()}
	if err := teek.performClaimedOTExtension(mpc.OTPoolExtendSize, oldClaim, &controlConnectionToken{}); err == nil {
		t.Fatal("delayed old refill unexpectedly started")
	}
	if !state.pool.OwnsExtendClaim(replacementClaim) {
		t.Fatal("delayed old worker released replacement claim")
	}
}

func TestValidatedOldGenerationCannotReserveAfterReplacementSnapshot(t *testing.T) {
	teek, cm, session, oldSessionConn, _ := newTEEKPeerLossSession(t)
	state := teek.otPrecomputeState
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, 2*mpc.OTsPerOPRF)); err != nil {
		t.Fatal(err)
	}
	sessionState, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity, err := cm.identityForSession(session)
	if err != nil {
		t.Fatal(err)
	}

	validated := make(chan struct{})
	continueReserve := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(validated)
		<-continueReserve
		_, _, _, reserveErr := teek.reserveOTEntriesForSessionWithRefill(oldIdentity, sessionState, 0, mpc.OTsPerOPRF, func(int, *mpc.SenderExtendClaim, *controlConnectionToken) {
			t.Error("stale reservation started a refill")
		})
		result <- reserveErr
	}()
	<-validated

	replacementControl := newAckTestWebSocket(t)
	_, replacementGeneration := installAckTestControl(cm, replacementControl)
	replacementSessionConn := &SessionTEETConnection{
		sessionID: session.ID, session: session, controlConn: replacementControl,
		controlGeneration: replacementGeneration, conn: newAckTestWebSocket(t),
	}
	cm.mu.Lock()
	cm.sessionConns[session.ID] = replacementSessionConn
	cm.mu.Unlock()
	resumeSnapshot := state.pool.NextIndex()
	close(continueReserve)
	if err := <-result; err == nil {
		t.Fatal("old validated generation reserved after replacement")
	}
	if got := state.pool.NextIndex(); got != resumeSnapshot {
		t.Fatalf("stale reservation advanced sender frontier: got %d, resume snapshot %d", got, resumeSnapshot)
	}
	if len(sessionState.OTReservations) != 0 {
		t.Fatal("stale reservation was tracked on the replacement session")
	}
	if oldSessionConn.controlGeneration == replacementGeneration {
		t.Fatal("test did not install a replacement control generation")
	}
}

func TestInsufficientReservationStillClaimsRefill(t *testing.T) {
	teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
	state := teek.otPrecomputeState
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTsPerOPRF-1)); err != nil {
		t.Fatal(err)
	}
	sessionState, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}
	claimed := make(chan *mpc.SenderExtendClaim, 1)
	_, _, reservation, err := teek.reserveOTEntriesForSessionWithRefill(identity, sessionState, 0, mpc.OTsPerOPRF, func(count int, claim *mpc.SenderExtendClaim, origin *controlConnectionToken) {
		if count != mpc.OTPoolExtendSize || origin.conn != sessionConn.controlConn || origin.generation != sessionConn.controlGeneration {
			t.Error("refill lost its exact size/control ownership")
		}
		claimed <- claim
	})
	if err == nil {
		t.Fatal("insufficient reservation unexpectedly succeeded")
	}
	if reservation != nil || state.pool.NextIndex() != 0 {
		t.Fatal("insufficient reservation changed sender accounting")
	}
	claim := <-claimed
	if !state.pool.OwnsExtendClaim(claim) {
		t.Fatal("insufficient reservation did not retain the refill claim")
	}
	state.pool.ReleaseExtendClaim(claim)
}

func TestFailedRefillAfterFinalUsableReservationForcesAutomaticRecovery(t *testing.T) {
	teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
	state := teek.otPrecomputeState
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTsPerOPRF)); err != nil {
		t.Fatal(err)
	}
	teek.otReady.Store(true)
	teek.controlHealthy.Store(true)
	sessionState, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}
	type claimedRefill struct {
		claim  *mpc.SenderExtendClaim
		origin *controlConnectionToken
	}
	refill := make(chan claimedRefill, 1)
	if _, _, _, err := teek.reserveOTEntriesForSessionWithRefill(identity, sessionState, 0, mpc.OTsPerOPRF, func(_ int, claim *mpc.SenderExtendClaim, origin *controlConnectionToken) {
		refill <- claimedRefill{claim: claim, origin: origin}
	}); err != nil {
		t.Fatalf("final usable reservation: %v", err)
	}
	owned := <-refill
	if state.pool.Available() != 0 || teek.OTReady() {
		t.Fatal("final reservation remained advertised without a usable circuit")
	}
	if !teek.recoverFailedClaimedOTExtension(owned.claim, owned.origin, errors.New("injected extension timeout")) {
		t.Fatal("unusable failed refill did not force exact-control recovery")
	}
	if err := sessionConn.controlConn.WriteMessage(websocket.BinaryMessage, []byte("closed")); err == nil {
		t.Fatal("failed refill retained its originating control")
	}

	replacementControl := newAckTestWebSocket(t)
	_, replacementGeneration := installAckTestControl(cm, replacementControl)
	replacementOrigin := &controlConnectionToken{conn: replacementControl, generation: replacementGeneration}
	state.mu.Lock()
	state.inconsistent = false // accepted resume performs this transition
	state.mu.Unlock()
	if err := teek.ensureResumedOTPoolUsableWithRefill(replacementOrigin, func(count int, claim *mpc.SenderExtendClaim, origin *controlConnectionToken) error {
		if origin != replacementOrigin || count != mpc.OTPoolExtendSize {
			t.Fatal("resume refill lost replacement ownership")
		}
		if err := state.pool.Add(accountingSenderOTs(mpc.OTsPerOPRF, count)); err != nil {
			return err
		}
		if !state.pool.ReleaseExtendClaim(claim) {
			t.Fatal("resume refill could not release exact claim")
		}
		return nil
	}, nil); err != nil {
		t.Fatalf("automatic resume refill: %v", err)
	}
	if !teek.isOTPoolReady() || state.pool.Available() != mpc.OTPoolExtendSize {
		t.Fatal("automatic recovery did not restore a usable sender pool")
	}
}

func TestFailedRefillWithUsablePoolRestoresReadinessAndReclaim(t *testing.T) {
	teek, _, _, sessionConn, _ := newTEEKPeerLossSession(t)
	state := teek.otPrecomputeState
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, 2*mpc.OTsPerOPRF)); err != nil {
		t.Fatal(err)
	}
	claim := state.pool.ClaimExtendIfNeeded()
	if claim == nil {
		t.Fatal("claim usable-pool refill")
	}
	teek.otReady.Store(false)
	origin := &controlConnectionToken{conn: sessionConn.controlConn, generation: sessionConn.controlGeneration}
	if teek.recoverFailedClaimedOTExtension(claim, origin, errors.New("injected extension timeout")) {
		t.Fatal("usable failed refill unnecessarily closed the control")
	}
	if !teek.OTReady() {
		t.Fatal("usable failed refill did not restore readiness")
	}
	replacementClaim := state.pool.ClaimExtendIfNeeded()
	if replacementClaim == nil {
		t.Fatal("usable failed refill did not permit a future exact claim")
	}
	if !state.pool.ReleaseExtendClaim(replacementClaim) {
		t.Fatal("future exact claim could not be released")
	}
	if err := sessionConn.controlConn.WriteMessage(websocket.BinaryMessage, []byte("still-open")); err != nil {
		t.Fatalf("usable failed refill closed its control: %v", err)
	}
}

func TestStaleFailedRefillRecoveryCannotHarmReplacementClaim(t *testing.T) {
	teek, _, _, sessionConn, _ := newTEEKPeerLossSession(t)
	state := teek.otPrecomputeState
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, mpc.OTsPerOPRF-1)); err != nil {
		t.Fatal(err)
	}
	c1 := state.pool.ClaimExtendIfNeeded()
	if c1 == nil {
		t.Fatal("claim C1 refill")
	}
	origin := &controlConnectionToken{conn: sessionConn.controlConn, generation: sessionConn.controlGeneration}
	pendingC1 := &senderPrecompute{
		done: make(chan error, 1), controlConn: origin.conn,
		controlGeneration: origin.generation, extendClaim: c1,
	}
	state.pending = pendingC1
	teek.otReady.Store(true)
	teek.controlHealthy.Store(true)

	wakeC1 := make(chan struct{})
	c1Ready := make(chan struct{})
	c1Result := make(chan bool, 1)
	go func() {
		close(c1Ready)
		<-wakeC1
		c1Result <- teek.recoverFailedClaimedOTExtension(c1, origin, errors.New("injected C1 timeout"))
	}()
	<-c1Ready
	if !teek.failPendingPrecompute(state, pendingC1, errors.New("injected C1 failure")) {
		t.Fatal("C1 failure did not claim its pending state")
	}
	if !state.pool.OwnsExtendClaim(c1) {
		t.Fatal("C1 failure released ownership before recovery")
	}
	if state.pool.ClaimExtendIfNeeded() != nil {
		t.Fatal("C2 acquired during the C1 failure/recovery handoff")
	}

	// A lifecycle transition revokes C1 before a replacement refill starts.
	// C1 recovery wakes only after C2 owns the exact replacement token.
	state.mu.Lock()
	state.pool.InvalidateExtendClaim()
	c2 := state.pool.ClaimExtendIfNeeded()
	if c2 == nil {
		state.mu.Unlock()
		t.Fatal("claim C2 refill")
	}
	state.pending = &senderPrecompute{
		done: make(chan error, 1), controlConn: origin.conn,
		controlGeneration: origin.generation, extendClaim: c2,
	}
	state.mu.Unlock()
	close(wakeC1)
	if <-c1Result {
		t.Fatal("stale C1 recovery closed the current control")
	}
	if !state.pool.OwnsExtendClaim(c2) {
		t.Fatal("stale C1 recovery released C2 ownership")
	}
	state.mu.Lock()
	inconsistent := state.inconsistent
	state.mu.Unlock()
	if inconsistent || !teek.OTReady() || !teek.ControlHealthy() {
		t.Fatal("stale C1 recovery changed replacement readiness")
	}
	if err := origin.conn.WriteMessage(websocket.BinaryMessage, []byte("C2-still-open")); err != nil {
		t.Fatalf("stale C1 recovery closed C2 control: %v", err)
	}
}

func TestOPRFPublicationGapHasNoLostWakeup(t *testing.T) {
	state := &TEEKSessionState{}
	teek := &TEEK{logger: shared.NewNopLogger()}
	rangePublisherStarted := make(chan struct{})
	allowRangePublication := make(chan struct{})
	result := make(chan error, 1)
	var initiations atomic.Int32
	initiate := func(_ string, _ *TEEKSessionState, _ int, _ *teeproto.OPRFRangeSpec, _ []byte, _ []byte, _ int) error {
		initiations.Add(1)
		return nil
	}
	go func() {
		close(rangePublisherStarted)
		<-allowRangePublication
		if state.publishOPRFClientInputs([]*teeproto.OPRFRangeSpec{{TlsStart: 0, TlsLength: 1}}, make([]byte, 16)) {
			result <- teek.processQueuedOPRFRangesWithInitiator("publication-gap", state, initiate)
			return
		}
		result <- nil
	}()
	<-rangePublisherStarted

	// Publish keystream while the ranges path is paused in the former gap:
	// crypto sees no client ranges, then the ranges transition must observe the
	// committed keystream and initiate exactly once.
	if state.publishOPRFKeystream(make([]byte, 64)) {
		t.Fatal("keystream publisher observed ranges before the barrier released")
	}
	close(allowRangePublication)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if got := initiations.Load(); got != 1 {
		t.Fatalf("OPRF initiations = %d, want 1", got)
	}
}

func TestConcurrentOPRFInitiationHasSingleWinner(t *testing.T) {
	state := &TEEKSessionState{
		ConsolidatedKeystream: make([]byte, 64),
		OPRFKeyShare:          make([]byte, 16),
		OPRFRanges:            []*teeproto.OPRFRangeSpec{{TlsStart: 0, TlsLength: 1}},
	}
	state.ClientRangesReceived.Store(true)
	state.OPRFState.Store(int32(shared.OPRFStateInProgress))
	teek := &TEEK{logger: shared.NewNopLogger()}
	start := make(chan struct{})
	callbackStarted := make(chan struct{})
	finishCallback := make(chan struct{})
	var callbackOnce sync.Once
	var reserves atomic.Int32
	var sends atomic.Int32
	initiate := func(_ string, _ *TEEKSessionState, _ int, _ *teeproto.OPRFRangeSpec, keystream, keyShare []byte, total int) error {
		reserves.Add(1)
		if len(keystream) != 64 || len(keyShare) != 16 || total != 1 {
			t.Error("winner received an inconsistent OPRF snapshot")
		}
		callbackOnce.Do(func() { close(callbackStarted) })
		<-finishCallback
		sends.Add(1)
		return nil
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := teek.processQueuedOPRFRangesWithInitiator("concurrent-oprf", state, initiate); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)
	<-callbackStarted
	close(finishCallback)
	wg.Wait()
	if reserves.Load() != 1 || sends.Load() != 1 {
		t.Fatalf("concurrent initiation reserved/sent %d/%d times, want 1/1", reserves.Load(), sends.Load())
	}
}

func TestOTReservationRejectsDuplicateAndConfirmsExactRound2(t *testing.T) {
	state := &TEEKSessionState{}
	origin := newAckTestWebSocket(t)
	first := &senderOTReservation{startIndex: 0, controlConn: origin, controlGeneration: 7}
	if err := state.TrackOTReservation(0, first); err != nil {
		t.Fatal(err)
	}
	if err := state.TrackOTReservation(0, &senderOTReservation{startIndex: mpc.OTsPerOPRF, controlConn: origin, controlGeneration: 7}); err == nil {
		t.Fatal("duplicate OT reservation overwrote the first owner")
	}
	if state.ConfirmOTReservation(0, origin, 8) {
		t.Fatal("wrong control generation confirmed the reservation")
	}
	if !state.ConfirmOTReservation(0, origin, 7) {
		t.Fatal("matching authenticated Round2 did not confirm reservation")
	}
	if state.ConfirmOTReservation(0, origin, 7) {
		t.Fatal("reservation confirmation was replayable")
	}
}

func TestInjectedOnlineFailureForcesExactControlReconciliation(t *testing.T) {
	logger := shared.NewNopLogger()
	state := NewOTPrecomputeState()
	state.ready = true
	if err := state.pool.Add(accountingSenderOTs(0, 2*mpc.OTsPerOPRF)); err != nil {
		t.Fatal(err)
	}
	receiver := mpc.NewReceiverPool(2 * mpc.OTsPerOPRF)
	if err := receiver.Add(accountingReceiverOTs(0, 2*mpc.OTsPerOPRF)); err != nil {
		t.Fatal(err)
	}
	start, _, err := state.pool.Reserve(mpc.OTsPerOPRF)
	if err != nil {
		t.Fatal(err)
	}
	teek := &TEEK{otPrecomputeState: state, logger: logger}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	origin, generation := installAckTestControl(cm, newAckTestWebSocket(t))
	reservation := &senderOTReservation{startIndex: start, controlConn: origin, controlGeneration: generation}
	sessionState := &TEEKSessionState{}
	if err := sessionState.TrackOTReservation(0, reservation); err != nil {
		t.Fatal(err)
	}

	injectedErr := errors.New("injected online send rejection")
	if err := teek.sendReservedOPRFOnline(sessionState, 0, reservation, func() error { return injectedErr }); !errors.Is(err, injectedErr) {
		t.Fatalf("online send error = %v, want injected failure", err)
	}
	if !state.inconsistent || teek.isOTPoolReady() {
		t.Fatal("abandoned reservation remained advertised as usable")
	}
	if err := origin.WriteMessage(websocket.BinaryMessage, []byte("closed")); err == nil {
		t.Fatal("reconciliation did not close the originating control")
	}
	if err := receiver.AdvanceTo(state.pool.NextIndex()); err != nil {
		t.Fatalf("receiver resume reconciliation: %v", err)
	}
	if receiver.NextIndex() != mpc.OTsPerOPRF || receiver.Available() != mpc.OTsPerOPRF {
		t.Fatalf("receiver frontier after reconciliation: next=%d available=%d", receiver.NextIndex(), receiver.Available())
	}

	replacement := newAckTestWebSocket(t)
	_, replacementGeneration := installAckTestControl(cm, replacement)
	state.mu.Lock()
	state.inconsistent = false
	state.mu.Unlock()
	stale := &senderOTReservation{controlConn: origin, controlGeneration: generation}
	if teek.reconcileAbandonedOTReservation(stale) {
		t.Fatal("stale reservation reconciled through replacement control")
	}
	if err := replacement.WriteMessage(websocket.BinaryMessage, []byte("replacement-alive")); err != nil {
		t.Fatalf("stale reservation closed replacement generation %d: %v", replacementGeneration, err)
	}
	if _, _, err := state.pool.Reserve(mpc.OTsPerOPRF); err != nil {
		t.Fatalf("sender successful range after reconciliation: %v", err)
	}
	if _, err := receiver.Consume(mpc.OTsPerOPRF, mpc.OTsPerOPRF); err != nil {
		t.Fatalf("receiver successful range after reconciliation: %v", err)
	}
	const extensionStart = 2 * mpc.OTsPerOPRF
	if err := state.pool.Add(accountingSenderOTs(extensionStart, mpc.OTPoolExtendSize)); err != nil {
		t.Fatalf("sender extension after reconciliation: %v", err)
	}
	if err := receiver.Add(accountingReceiverOTs(extensionStart, mpc.OTPoolExtendSize)); err != nil {
		t.Fatalf("receiver extension after reconciliation: %v", err)
	}
	if err := mpc.ValidatePoolAgreement(state.pool, receiver); err != nil {
		t.Fatalf("pools after successful range and extension: %v", err)
	}
}

func accountingSenderOTs(start uint64, count int) []mpc.SenderOT {
	entries := make([]mpc.SenderOT, count)
	for i := range entries {
		entries[i].Index = start + uint64(i)
	}
	return entries
}

func accountingReceiverOTs(start uint64, count int) []mpc.ReceiverOT {
	entries := make([]mpc.ReceiverOT, count)
	for i := range entries {
		entries[i].Index = start + uint64(i)
	}
	return entries
}
