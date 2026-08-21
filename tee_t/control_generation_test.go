package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func TestConnectionManagerConcurrentInitializationReturnsSingleOwner(t *testing.T) {
	teet := &TEET{logger: shared.NewNopLogger()}
	const callers = 64
	start := make(chan struct{})
	results := make(chan *TEEKConnectionManager, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			results <- teet.connectionManager()
		})
	}
	close(start)
	wg.Wait()
	close(results)

	var owner *TEEKConnectionManager
	for manager := range results {
		if owner == nil {
			owner = manager
		}
		if manager != owner {
			t.Fatal("concurrent initialization returned separate connection managers")
		}
	}
	if owner == nil || owner.teet != teet {
		t.Fatal("connection manager owner was not initialized on TEET")
	}
}

func TestControlReplacementDoesNotWaitForLongHandlerAndRejectsStalePublication(t *testing.T) {
	teet := &TEET{logger: shared.NewNopLogger()}
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := shared.NewWSConnection(nil)
	replacementControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1

	// Model a control handler after its short state capture but while its OT
	// crypto or old-origin write is indefinitely blocked outside the lease.
	longWorkStarted := make(chan struct{})
	releaseLongWork := make(chan struct{})
	oldResult := make(chan error, 1)
	var stalePublished atomic.Bool
	go func() {
		if err := cm.withCurrentControlState(oldControl, 1, func() error { return nil }); err != nil {
			oldResult <- err
			return
		}
		close(longWorkStarted)
		<-releaseLongWork
		oldResult <- cm.withCurrentControlState(oldControl, 1, func() error {
			stalePublished.Store(true)
			return nil
		})
	}()
	<-longWorkStarted
	replacementDone := make(chan uint64, 1)
	go func() {
		generation, _, _, _ := cm.activateControlConnection(replacementControl)
		replacementDone <- generation
	}()
	var generation uint64
	select {
	case generation = <-replacementDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("replacement activation was blocked by old long-running handler")
	}
	if err := cm.completeControlAttestation(replacementControl, generation, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	close(releaseLongWork)
	if err := <-oldResult; err == nil {
		t.Fatal("superseded long handler retained publication authority")
	}
	if stalePublished.Load() {
		t.Fatal("superseded long handler published stale state")
	}
}

func TestFailedAttestationResponseNeverPublishesReadiness(t *testing.T) {
	teet := &TEET{logger: shared.NewNopLogger()}
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	control := shared.NewWSConnection(nil)
	generation, _, _, _ := cm.activateControlConnection(control)
	wantErr := fmt.Errorf("blocked response write failed")
	if err := cm.completeControlAttestation(control, generation, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("attestation response error = %v, want %v", err, wantErr)
	}
	if cm.IsAttestationVerified() || teet.isTEEKConnected() || teet.controlHealthy.Load() {
		t.Fatal("failed attestation response published connection readiness")
	}
	if cm.IsControlConnected() {
		t.Fatal("failed attestation response retained control connection")
	}
}

func TestFailedAttestationResponseNeverPublishesPairAssignment(t *testing.T) {
	teet := &TEET{logger: shared.NewNopLogger()}
	initialPair := "pair-a"
	teet.pairID.Store(&initialPair)
	var assigned atomic.Int32
	teet.onPairAssigned = func(string) { assigned.Add(1) }
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	control := shared.NewWSConnection(nil)
	generation, _, _, _ := cm.activateControlConnection(control)
	wantErr := errors.New("attestation response write failed")

	err := cm.completeControlAttestationForPair(control, generation, "attacker-pair", func() error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("attestation response error = %v, want %v", err, wantErr)
	}
	if got := teet.PairID(); got != initialPair {
		t.Fatalf("failed handshake changed pair ID to %q, want %q", got, initialPair)
	}
	if got := assigned.Load(); got != 0 {
		t.Fatalf("failed handshake invoked pair assignment hook %d times", got)
	}
}

func TestSupersededAttestationCannotPublishPairAssignment(t *testing.T) {
	teet := &TEET{logger: shared.NewNopLogger()}
	initialPair := "pair-a"
	teet.pairID.Store(&initialPair)
	assigned := make(chan string, 2)
	teet.onPairAssigned = func(pairID string) {
		if got := teet.PairID(); got != pairID {
			t.Errorf("hook observed pair ID %q, want %q", got, pairID)
		}
		if !teet.isTEEKConnected() || !teet.controlHealthy.Load() {
			t.Error("hook ran before authenticated control readiness was published")
		}
		assigned <- pairID
	}
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := shared.NewWSConnection(nil)
	replacementControl := shared.NewWSConnection(nil)
	oldGeneration, _, _, _ := cm.activateControlConnection(oldControl)
	var replacementGeneration uint64

	err := cm.completeControlAttestationForPair(oldControl, oldGeneration, "stale-pair", func() error {
		replacementGeneration, _, _, _ = cm.activateControlConnection(replacementControl)
		return nil
	})
	if err == nil {
		t.Fatal("superseded handshake published its pair assignment")
	}
	if got := teet.PairID(); got != initialPair {
		t.Fatalf("superseded handshake changed pair ID to %q, want %q", got, initialPair)
	}
	select {
	case got := <-assigned:
		t.Fatalf("superseded handshake invoked pair assignment hook with %q", got)
	default:
	}

	if err := cm.completeControlAttestationForPair(replacementControl, replacementGeneration, "pair-b", func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	if got := teet.PairID(); got != "pair-b" {
		t.Fatalf("replacement pair ID = %q, want pair-b", got)
	}
	select {
	case got := <-assigned:
		if got != "pair-b" {
			t.Fatalf("replacement hook pair ID = %q, want pair-b", got)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement pair assignment hook was not invoked")
	}
}

func TestReplacementDuringAttestationResponseCannotPublishOldReadiness(t *testing.T) {
	teet := &TEET{logger: shared.NewNopLogger()}
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := shared.NewWSConnection(nil)
	replacementControl := shared.NewWSConnection(nil)
	oldGeneration, _, _, _ := cm.activateControlConnection(oldControl)
	var replacementGeneration uint64
	err := cm.completeControlAttestation(oldControl, oldGeneration, func() error {
		replacementGeneration, _, _, _ = cm.activateControlConnection(replacementControl)
		return nil
	})
	if err == nil {
		t.Fatal("superseded attestation response published old readiness")
	}
	if cm.IsAttestationVerified() || teet.isTEEKConnected() || teet.controlHealthy.Load() {
		t.Fatal("replacement became ready before its response completed")
	}
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement response: %v", err)
	}
	if !cm.IsAttestationVerified() || !teet.isTEEKConnected() || !teet.controlHealthy.Load() {
		t.Fatal("successful replacement response did not publish readiness")
	}
}

func TestControlReplacementPurgesOldSessionsAndPreservesNew(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := newReceiverTestWebSocket(t)
	replacementControl := newReceiverTestWebSocket(t)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	oldSharedSession, err := teet.registerSessionForControl("same-id", 1)
	if err != nil {
		t.Fatalf("register old session: %v", err)
	}
	oldSession := &SessionTEEKConnection{
		sessionID: "same-id", controlGeneration: 1, session: oldSharedSession, conn: newReceiverTestWebSocket(t),
	}
	cm.sessionOwners["same-id"] = controlSessionOwner{controlGeneration: 1, session: oldSharedSession}
	cm.sessionConns["same-id"] = oldSession

	generation, superseded, oldSessions, oldSessionIDs := cm.activateControlConnection(replacementControl)
	if generation != 2 || superseded != oldControl || len(oldSessions) != 1 || oldSessions[0] != oldSession || len(oldSessionIDs) != 1 {
		t.Fatal("replacement did not atomically detach old control sessions")
	}
	cm.closeSupersededConnections(superseded, oldSessions, oldSessionIDs)
	if !oldSession.closed {
		t.Fatal("detached old session was not closed")
	}

	replacementSharedSession := &shared.Session{ID: "same-id"}
	replacementSession := &SessionTEEKConnection{
		sessionID: "same-id", controlGeneration: generation, session: replacementSharedSession, closed: true,
	}
	cm.mu.Lock()
	cm.sessionOwners["same-id"] = controlSessionOwner{controlGeneration: generation, session: replacementSharedSession}
	cm.sessionConns["same-id"] = replacementSession
	cm.mu.Unlock()
	cm.removeSessionConnection("same-id", oldSession)
	cm.tearDownControlConnection(oldControl, 1)
	cm.mu.RLock()
	got := cm.sessionConns["same-id"]
	cm.mu.RUnlock()
	if got != replacementSession {
		t.Fatal("stale session/control teardown removed replacement session")
	}
}

func TestAckedSessionOwnerIsRemovedBeforeDelayedDial(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := shared.NewWSConnection(nil)
	replacementControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	if err := cm.registerSessionOwner(oldControl, 1, "acked-before-dial"); err != nil {
		t.Fatalf("register acknowledged session owner: %v", err)
	}

	replacementGeneration, superseded, oldSessions, oldSessionIDs := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, oldSessions, oldSessionIDs)
	if superseded != oldControl || replacementGeneration != 2 {
		t.Fatal("replacement did not supersede acknowledged owner generation")
	}
	if _, err := teet.sessionManager.GetSession("acked-before-dial"); err == nil {
		t.Fatal("replacement retained acknowledged old-generation session")
	}
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	stale := &SessionTEEKConnection{
		sessionID: "acked-before-dial", controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection("acked-before-dial", stale); err == nil {
		t.Fatal("delayed old-generation dial published after replacement")
	}
}

func TestLocalCleanupRemovesUndialedSessionOwner(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	control := shared.NewWSConnection(nil)
	cm.controlConn = control
	cm.controlGeneration = 1
	const sessionID = "local-cleanup-before-dial"
	if err := cm.registerSessionOwner(control, 1, sessionID); err != nil {
		t.Fatalf("register acknowledged owner: %v", err)
	}
	session, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get registered session: %v", err)
	}

	teet.cleanupSessionWithSession(session)

	cm.mu.RLock()
	_, ownerExists := cm.sessionOwners[sessionID]
	_, connExists := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if ownerExists {
		t.Fatal("local cleanup retained acknowledged owner without a session dial")
	}
	if connExists {
		t.Fatal("local cleanup retained per-session connection")
	}
}

func TestSessionClosedRemovesUndialedAcknowledgedOwnerImmediately(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	control := shared.NewWSConnection(nil)
	cm.controlConn = control
	cm.controlGeneration = 1
	const sessionID = "session-closed-before-dial"
	if err := cm.registerSessionOwner(control, 1, sessionID); err != nil {
		t.Fatalf("register acknowledged owner: %v", err)
	}
	session, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get acknowledged session: %v", err)
	}

	// This is the exact handler invoked for an existing SessionClosed control
	// envelope. No per-session dial or expiry callback is required.
	cm.closeOwnedSession(control, 1, sessionID)

	cm.mu.RLock()
	_, ownerExists := cm.sessionOwners[sessionID]
	_, connectionExists := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if ownerExists || connectionExists {
		t.Fatal("SessionClosed retained the undialed acknowledged owner")
	}
	if _, err := teet.sessionManager.GetSession(sessionID); err == nil {
		t.Fatal("SessionClosed retained the undialed shared session")
	}
	if !session.CleanedUp.Load() {
		t.Fatal("SessionClosed did not complete local session cleanup")
	}
}

func TestSessionClosedControlFrameRemovesUndialedOwnerSynchronously(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	control, inbound := newInboundReceiverTestWebSocket(t)
	cm.controlConn = control
	cm.controlGeneration = 1
	const sessionID = "session-closed-control-frame-before-dial"
	if err := cm.registerSessionOwner(control, 1, sessionID); err != nil {
		t.Fatalf("register acknowledged owner: %v", err)
	}
	session, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get acknowledged session: %v", err)
	}
	data, err := proto.Marshal(&teeproto.Envelope{
		SessionId: sessionID,
		Payload: &teeproto.Envelope_SessionClosed{
			SessionClosed: &teeproto.SessionClosed{SessionId: sessionID, Reason: "session_connection_setup_failed"},
		},
	})
	if err != nil {
		t.Fatalf("marshal SessionClosed: %v", err)
	}
	handlerDone := make(chan struct{})
	go func() {
		cm.handleControlMessages(control, 1)
		close(handlerDone)
	}()
	inbound <- data

	waitForDetachedSessionOwner(t, cm, sessionID, false)
	deadline := time.Now().Add(time.Second)
	for {
		_, sessionErr := teet.sessionManager.GetSession(sessionID)
		if sessionErr != nil && session.CleanedUp.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SessionClosed control frame retained the undialed shared session")
		}
		runtime.Gosched()
	}
	_ = control.Close()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("control handler did not stop after test connection closed")
	}
}

func TestConcurrentSessionPublicationNeverExceedsCapacity(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	control := shared.NewWSConnection(nil)
	cm.controlConn = control
	cm.controlGeneration = 1
	cm.attestationVerified = true
	for i := range MaxConcurrentSessions - 1 {
		cm.sessionConns[fmt.Sprintf("occupied-%d", i)] = &SessionTEEKConnection{}
	}
	const firstID = "capacity-race-first"
	const secondID = "capacity-race-second"
	if err := cm.registerSessionOwner(control, 1, firstID); err != nil {
		t.Fatalf("register first owner: %v", err)
	}
	if err := cm.registerSessionOwner(control, 1, secondID); err != nil {
		t.Fatalf("register second owner: %v", err)
	}
	firstOwner := cm.sessionOwners[firstID]
	secondOwner := cm.sessionOwners[secondID]
	firstCandidate := &SessionTEEKConnection{
		sessionID: firstID, controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}
	secondCandidate := &SessionTEEKConnection{
		sessionID: secondID, controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}

	// Both handshakes have observed 99 connections and pause immediately
	// before publication. The publication lock must admit only one.
	cm.mu.RLock()
	if got := len(cm.sessionConns); got != MaxConcurrentSessions-1 {
		cm.mu.RUnlock()
		t.Fatalf("precheck count=%d want=%d", got, MaxConcurrentSessions-1)
	}
	cm.mu.RUnlock()
	start := make(chan struct{})
	ready := sync.WaitGroup{}
	ready.Add(2)
	type publicationResult struct {
		sessionID string
		candidate *SessionTEEKConnection
		err       error
	}
	results := make(chan publicationResult, 2)
	publish := func(sessionID string, candidate *SessionTEEKConnection) {
		ready.Done()
		<-start
		results <- publicationResult{sessionID: sessionID, candidate: candidate, err: cm.publishSessionConnection(sessionID, candidate)}
	}
	go publish(firstID, firstCandidate)
	go publish(secondID, secondCandidate)
	ready.Wait()
	close(start)
	firstResult := <-results
	secondResult := <-results

	successes := 0
	failures := 0
	var failed publicationResult
	for _, result := range []publicationResult{firstResult, secondResult} {
		if result.err == nil {
			successes++
			continue
		}
		failures++
		failed = result
		if !strings.Contains(result.err.Error(), "max concurrent sessions") {
			t.Fatalf("publication error=%v, want capacity rejection", result.err)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("publication results: successes=%d failures=%d, want 1/1", successes, failures)
	}
	cm.mu.RLock()
	count := len(cm.sessionConns)
	failedPublished := cm.sessionConns[failed.sessionID]
	firstOwnerAfter := cm.sessionOwners[firstID]
	secondOwnerAfter := cm.sessionOwners[secondID]
	cm.mu.RUnlock()
	if count != MaxConcurrentSessions {
		t.Fatalf("published connection count=%d want=%d", count, MaxConcurrentSessions)
	}
	if failedPublished != nil {
		t.Fatal("capacity rejection published the losing candidate")
	}
	if firstOwnerAfter.session != firstOwner.session || firstOwnerAfter.controlGeneration != 1 || secondOwnerAfter.session != secondOwner.session || secondOwnerAfter.controlGeneration != 1 {
		t.Fatal("capacity rejection changed acknowledged session owner state")
	}
	if !teet.sessionManager.isCurrentControlSession(firstOwner.session, 1) || !teet.sessionManager.isCurrentControlSession(secondOwner.session, 1) {
		t.Fatal("capacity rejection removed an acknowledged shared session")
	}
}

func TestStaleLocalCleanupPreservesSameIDReplacementOwner(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	oldControl := shared.NewWSConnection(nil)
	replacementControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	const sessionID = "stale-cleanup-same-id"
	if err := cm.registerSessionOwner(oldControl, 1, sessionID); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	oldSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}

	// Model expiry's ordering: the shared session is removed before its callback.
	if err := teet.sessionManager.SessionManager.CloseSession(sessionID); err != nil {
		t.Fatalf("expire old shared session: %v", err)
	}
	replacementGeneration, _, oldSessionConns, oldSessionIDs := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, oldSessionConns, oldSessionIDs)
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	if err := cm.registerSessionOwner(replacementControl, replacementGeneration, sessionID); err != nil {
		t.Fatalf("register replacement owner: %v", err)
	}
	replacementSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get replacement session: %v", err)
	}

	// The delayed expiry callback carries the old session pointer. It must not
	// remove either the replacement owner or the replacement session.
	teet.cleanupSessionWithSession(oldSession)

	cm.mu.RLock()
	owner := cm.sessionOwners[sessionID]
	cm.mu.RUnlock()
	if owner.controlGeneration != replacementGeneration || owner.session != replacementSession {
		t.Fatalf("replacement owner = %+v, want generation %d and exact session", owner, replacementGeneration)
	}
	currentSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("replacement session removed by stale cleanup: %v", err)
	}
	if currentSession != replacementSession {
		t.Fatal("stale cleanup replaced current session identity")
	}
}

func TestControlTeardownCleanupPreservesReplacementRegisteredWhileOrphanCloseBlocks(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	oldControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	const sessionID = "teardown-blocked-same-id"
	if err := cm.registerSessionOwner(oldControl, 1, sessionID); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	oldSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}
	orphan := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: 1, session: oldSession, conn: shared.NewWSConnection(nil), closed: true,
	}
	cm.mu.Lock()
	cm.sessionConns[sessionID] = orphan
	cm.mu.Unlock()

	// Hold the orphan lock so teardown must pause after it has detached the
	// exact owner and connection and released the control-generation lease.
	orphan.mu.Lock()
	orphanReleased := false
	defer func() {
		if !orphanReleased {
			orphan.mu.Unlock()
		}
	}()
	teardownDone := make(chan struct{})
	go func() {
		cm.tearDownControlConnection(oldControl, 1)
		close(teardownDone)
	}()
	waitForDetachedSessionOwner(t, cm, sessionID, true)

	// Model expiry removing the old shared session while its callback is
	// delayed behind orphan closure, then reuse the ID on the replacement.
	if err := teet.sessionManager.SessionManager.CloseSession(sessionID); err != nil {
		t.Fatalf("expire old session: %v", err)
	}
	replacementControl := shared.NewWSConnection(nil)
	replacementGeneration, _, replacementOrphans, replacementOwners := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, replacementOrphans, replacementOwners)
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	if err := cm.registerSessionOwner(replacementControl, replacementGeneration, sessionID); err != nil {
		t.Fatalf("register replacement owner: %v", err)
	}
	replacementSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get replacement session: %v", err)
	}

	orphan.mu.Unlock()
	orphanReleased = true
	select {
	case <-teardownDone:
	case <-time.After(time.Second):
		t.Fatal("old teardown did not resume after orphan close")
	}
	assertExactSessionOwner(t, cm, sessionID, replacementGeneration, replacementSession)
	if !teet.sessionManager.isCurrentControlSession(replacementSession, replacementGeneration) {
		t.Fatal("old teardown removed replacement shared session or TEE_T state")
	}
}

func TestCloseOwnedSessionCleanupPreservesSameGenerationReuse(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	control := shared.NewWSConnection(nil)
	cm.controlConn = control
	cm.controlGeneration = 1
	const sessionID = "same-generation-reuse"
	if err := cm.registerSessionOwner(control, 1, sessionID); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	oldSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}
	orphan := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: 1, session: oldSession, conn: shared.NewWSConnection(nil), closed: true,
	}
	cm.mu.Lock()
	cm.sessionConns[sessionID] = orphan
	cm.mu.Unlock()

	orphan.mu.Lock()
	orphanReleased := false
	defer func() {
		if !orphanReleased {
			orphan.mu.Unlock()
		}
	}()
	cleanupDone := make(chan struct{})
	go func() {
		cm.closeOwnedSession(control, 1, sessionID)
		close(cleanupDone)
	}()
	waitForDetachedSessionOwner(t, cm, sessionID, false)
	if err := teet.sessionManager.SessionManager.CloseSession(sessionID); err != nil {
		t.Fatalf("expire old session: %v", err)
	}
	if err := cm.registerSessionOwner(control, 1, sessionID); err != nil {
		t.Fatalf("register same-generation replacement owner: %v", err)
	}
	replacementSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get same-generation replacement session: %v", err)
	}

	orphan.mu.Unlock()
	orphanReleased = true
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("old session cleanup did not resume after orphan close")
	}
	assertExactSessionOwner(t, cm, sessionID, 1, replacementSession)
	if !teet.sessionManager.isCurrentControlSession(replacementSession, 1) {
		t.Fatal("old cleanup removed same-generation replacement session or TEE_T state")
	}
}

func TestClientFramePausedAfterReadCannotMutateSameIDReplacement(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	oldControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	const sessionID = "client-paused-after-read"
	if err := cm.registerSessionOwner(oldControl, 1, sessionID); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	oldSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}
	oldClient := newReceiverTestWebSocket(t)
	if err := teet.sessionManager.ActivateSessionIfCurrent(oldSession, oldClient); err != nil {
		t.Fatalf("activate old client: %v", err)
	}
	oldIdentity := teet.clientSessionIdentity(oldSession, oldClient)

	// The old handler has read and decoded its frame but has not dispatched it.
	if err := teet.sessionManager.SessionManager.CloseSession(sessionID); err != nil {
		t.Fatalf("expire old shared session: %v", err)
	}
	replacementControl := shared.NewWSConnection(nil)
	replacementGeneration, _, oldConns, oldOwners := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, oldConns, oldOwners)
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	if err := cm.registerSessionOwner(replacementControl, replacementGeneration, sessionID); err != nil {
		t.Fatalf("register replacement owner: %v", err)
	}
	replacementSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get replacement session: %v", err)
	}
	replacementClient := newReceiverTestWebSocket(t)
	if err := teet.sessionManager.ActivateSessionIfCurrent(replacementSession, replacementClient); err != nil {
		t.Fatalf("activate replacement client: %v", err)
	}
	replacementState, err := teet.sessionManager.stateForSession(replacementSession)
	if err != nil {
		t.Fatalf("get replacement TEE_T state: %v", err)
	}

	err = teet.handleRedactionStreams(oldIdentity, &shared.Message{
		SessionID: sessionID,
		Type:      shared.MsgRedactionStreams,
		Data:      shared.RedactionStreamsData{Streams: [][]byte{{1, 2, 3}}},
	})
	if err == nil {
		t.Fatal("paused old client frame was accepted after same-ID replacement")
	}
	if got := len(replacementSession.RedactionState.RedactionStreams); got != 0 {
		t.Fatalf("replacement redaction streams mutated by old frame: %d", got)
	}
	if replacementState.RequestPartsArrived.Load() != 0 {
		t.Fatal("replacement join state mutated by old client frame")
	}
	teet.cleanupSessionWithSession(oldSession)
	assertExactSessionOwner(t, cm, sessionID, replacementGeneration, replacementSession)
	if !teet.sessionManager.isCurrentControlSession(replacementSession, replacementGeneration) {
		t.Fatal("old client final cleanup removed replacement session or state")
	}
}

func TestTEEKFramePausedAfterReadCannotMutateSameIDReplacement(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	oldControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	const sessionID = "teek-paused-after-read"
	if err := cm.registerSessionOwner(oldControl, 1, sessionID); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	oldSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}
	oldSessionConn := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: 1, session: oldSession, conn: shared.NewWSConnection(nil), closed: true,
	}
	cm.mu.Lock()
	cm.sessionConns[sessionID] = oldSessionConn
	cm.mu.Unlock()
	oldIdentity := &teetSessionIdentity{session: oldSession, validate: func() error {
		return cm.validateSessionConnection(oldSessionConn)
	}}

	// The old inter-TEE handler has read its frame and is paused before dispatch.
	if err := teet.sessionManager.SessionManager.CloseSession(sessionID); err != nil {
		t.Fatalf("expire old shared session: %v", err)
	}
	replacementControl := shared.NewWSConnection(nil)
	replacementGeneration, _, oldConns, oldOwners := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, oldConns, oldOwners)
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	if err := cm.registerSessionOwner(replacementControl, replacementGeneration, sessionID); err != nil {
		t.Fatalf("register replacement owner: %v", err)
	}
	replacementSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get replacement session: %v", err)
	}
	replacementConn := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: replacementGeneration, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection(sessionID, replacementConn); err != nil {
		t.Fatalf("publish replacement inter-TEE connection: %v", err)
	}
	replacementState, err := teet.sessionManager.stateForSession(replacementSession)
	if err != nil {
		t.Fatalf("get replacement TEE_T state: %v", err)
	}

	err = teet.handleKeyShareRequestSession(oldIdentity, &shared.Message{
		SessionID: sessionID,
		Type:      shared.MsgKeyShareRequest,
		Data:      shared.KeyShareRequestData{KeyLength: 16, IVLength: 12},
	})
	if err == nil {
		t.Fatal("paused old inter-TEE frame was accepted after same-ID replacement")
	}
	if replacementState.KeyShare != nil {
		t.Fatal("replacement key share mutated by old inter-TEE frame")
	}
	teet.cleanupSessionWithSession(oldSession)
	assertExactSessionOwner(t, cm, sessionID, replacementGeneration, replacementSession)
	cm.mu.RLock()
	currentConn := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if currentConn != replacementConn || !teet.sessionManager.isCurrentControlSession(replacementSession, replacementGeneration) {
		t.Fatal("old inter-TEE cleanup removed replacement connection, session, or state")
	}
}

func TestOTConsumePausedAfterIdentityCheckDoesNotConsumeReplacementPool(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	oldControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	cm.attestationVerified = true
	const sessionID = "ot-consume-paused-before-lease"
	if err := cm.registerSessionOwner(oldControl, 1, sessionID); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	oldSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}
	oldSessionConn := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection(sessionID, oldSessionConn); err != nil {
		t.Fatalf("publish old inter-TEE connection: %v", err)
	}
	teet.otReceiverState = &OTReceiverState{pool: receiverPoolWith(t, 20), ready: true, epoch: "old-epoch"}

	preConsumeChecked := make(chan struct{})
	resumeConsume := make(chan struct{})
	defer func() {
		select {
		case <-resumeConsume:
		default:
			close(resumeConsume)
		}
	}()
	identity := &teetSessionIdentity{
		session:           oldSession,
		controlGeneration: 1,
		sessionConn:       oldSessionConn,
		validate: func() error {
			return cm.validateSessionConnection(oldSessionConn)
		},
		beforeOTReceiverConsume: func() {
			close(preConsumeChecked)
			<-resumeConsume
		},
	}
	result := make(chan receiverConsumeResult, 1)
	go func() {
		entries, consumeErr := teet.consumeOTReceiverEntriesForIdentity(identity, oldSession.Context, 0, 1, waitForReceiverPrecompute)
		result <- receiverConsumeResult{entries: entries, err: consumeErr}
	}()
	select {
	case <-preConsumeChecked:
	case <-time.After(time.Second):
		t.Fatal("OT request did not pause after its pre-consume identity check")
	}

	replacementControl := shared.NewWSConnection(nil)
	replacementGeneration, _, oldConns, oldOwners := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, oldConns, oldOwners)
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	if err := cm.registerSessionOwner(replacementControl, replacementGeneration, sessionID); err != nil {
		t.Fatalf("register replacement owner: %v", err)
	}
	replacementSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get replacement session: %v", err)
	}
	replacementConn := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: replacementGeneration, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection(sessionID, replacementConn); err != nil {
		t.Fatalf("publish replacement inter-TEE connection: %v", err)
	}
	replacementPool := receiverPoolWith(t, 20)
	teet.otReceiverStateMu.Lock()
	teet.otReceiverState = &OTReceiverState{pool: replacementPool, ready: true, epoch: "replacement-epoch"}
	teet.otReceiverStateMu.Unlock()

	close(resumeConsume)
	got := receiveConsumeResult(t, result)
	if got.err == nil {
		t.Fatal("stale OT request consumed after control/session replacement")
	}
	if available, next := replacementPool.Available(), replacementPool.NextIndex(); available != 20 || next != 0 {
		t.Fatalf("replacement pool changed by stale request: available=%d next=%d", available, next)
	}
	assertExactSessionOwner(t, cm, sessionID, replacementGeneration, replacementSession)
	cm.mu.RLock()
	currentConn := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if currentConn != replacementConn {
		t.Fatal("stale OT request changed the replacement session connection")
	}
}

func TestOTConsumeRevalidatesIdentityAfterPendingWait(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	oldControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	cm.attestationVerified = true
	const sessionID = "ot-consume-pending-revalidate"
	if err := cm.registerSessionOwner(oldControl, 1, sessionID); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	oldSession, err := teet.sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}
	oldSessionConn := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection(sessionID, oldSessionConn); err != nil {
		t.Fatalf("publish old inter-TEE connection: %v", err)
	}
	pending := &receiverPrecompute{
		begin:             mpc.PrecomputeBegin{StartIndex: 10, Count: 10},
		entries:           receiverEntries(10, 10),
		controlGeneration: 1,
		done:              make(chan struct{}),
	}
	teet.otReceiverState = &OTReceiverState{
		pool: receiverPoolWith(t, 10), ready: true, epoch: "old-epoch", pending: pending,
	}
	identity := &teetSessionIdentity{
		session: oldSession, controlGeneration: 1, sessionConn: oldSessionConn,
		validate: func() error { return cm.validateSessionConnection(oldSessionConn) },
	}
	waiting := make(chan struct{})
	releaseWait := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)
	go func() {
		entries, consumeErr := teet.consumeOTReceiverEntriesForIdentity(identity, oldSession.Context, 10, 1, func(context.Context, <-chan struct{}) error {
			close(waiting)
			<-releaseWait
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: consumeErr}
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("OT request did not enter pending wait")
	}

	replacementControl := shared.NewWSConnection(nil)
	replacementGeneration, _, oldConns, oldOwners := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, oldConns, oldOwners)
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	replacementPool := receiverPoolWith(t, 20)
	teet.otReceiverStateMu.Lock()
	teet.otReceiverState = &OTReceiverState{pool: replacementPool, ready: true, epoch: "replacement-epoch"}
	teet.otReceiverStateMu.Unlock()
	close(releaseWait)

	got := receiveConsumeResult(t, result)
	if got.err == nil {
		t.Fatal("stale OT request consumed after pending wait and control replacement")
	}
	if available, next := replacementPool.Available(), replacementPool.NextIndex(); available != 20 || next != 0 {
		t.Fatalf("replacement pool changed after stale pending wait: available=%d next=%d", available, next)
	}
}

func TestDuplicateClientConnectionIsRejectedWithoutReplacingAcceptedBinding(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	control := shared.NewWSConnection(nil)
	cm.controlConn = control
	cm.controlGeneration = 1
	if err := cm.registerSessionOwner(control, 1, "duplicate-client"); err != nil {
		t.Fatalf("register session owner: %v", err)
	}
	session, err := teet.sessionManager.GetSession("duplicate-client")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	accepted := newReceiverTestWebSocket(t)
	if err := teet.sessionManager.ActivateSessionIfCurrent(session, accepted); err != nil {
		t.Fatalf("activate accepted client: %v", err)
	}
	acceptedIdentity := teet.clientSessionIdentity(session, accepted)
	duplicate := newReceiverTestWebSocket(t)
	if err := teet.sessionManager.ActivateSessionIfCurrent(session, duplicate); err == nil {
		t.Fatal("duplicate client connection replaced the accepted binding")
	}
	if !teet.sessionManager.IsCurrentSessionWithClient(session, accepted) {
		t.Fatal("duplicate client activation changed the accepted binding")
	}
	if err := acceptedIdentity.ensureCurrent(); err != nil {
		t.Fatalf("accepted client identity became stale after duplicate rejection: %v", err)
	}
}

func TestDuplicateTEEKConnectionIsRejectedWithoutReplacingAcceptedBinding(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	teet.connManager = cm
	control := shared.NewWSConnection(nil)
	cm.controlConn = control
	cm.controlGeneration = 1
	cm.attestationVerified = true
	const sessionID = "duplicate-teek"
	if err := cm.registerSessionOwner(control, 1, sessionID); err != nil {
		t.Fatalf("register session owner: %v", err)
	}
	accepted := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection(sessionID, accepted); err != nil {
		t.Fatalf("publish accepted TEE_K connection: %v", err)
	}
	duplicate := &SessionTEEKConnection{
		sessionID: sessionID, controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection(sessionID, duplicate); err == nil {
		t.Fatal("duplicate TEE_K connection replaced the accepted binding")
	}
	// Model the rejected handler's deferred pointer-safe cleanup.
	cm.removeSessionConnection(sessionID, duplicate)
	cm.mu.RLock()
	current := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if current != accepted {
		t.Fatal("rejected duplicate cleanup removed the accepted TEE_K connection")
	}
	if err := cm.validateSessionConnection(accepted); err != nil {
		t.Fatalf("accepted TEE_K identity became stale after duplicate rejection: %v", err)
	}
	accepted.session.ConnMutex.RLock()
	boundConn := accepted.session.TEEKConn
	accepted.session.ConnMutex.RUnlock()
	if boundConn != accepted.conn {
		t.Fatal("rejected duplicate changed the session's accepted TEE_K binding")
	}
}

func TestSessionTEEKConnectionClosedAccessIsSynchronized(t *testing.T) {
	conn := &SessionTEEKConnection{}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				_ = conn.isClosed()
			}
		})
	}
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	wg.Wait()
	if !conn.isClosed() {
		t.Fatal("closed state was not published")
	}
}

func TestSessionInitBlockedDuringReplacementCannotOverwriteNewConnection(t *testing.T) {
	teet := newGenerationTestTEET()
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := shared.NewWSConnection(nil)
	replacementControl := shared.NewWSConnection(nil)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	if err := cm.registerSessionOwner(oldControl, 1, "blocked-init"); err != nil {
		t.Fatalf("register old owner: %v", err)
	}
	blockedInit := &SessionTEEKConnection{
		sessionID: "blocked-init", controlGeneration: 1, conn: shared.NewWSConnection(nil), closed: true,
	}

	replacementGeneration, _, oldSessions, oldSessionIDs := cm.activateControlConnection(replacementControl)
	cm.closeSupersededConnections(nil, oldSessions, oldSessionIDs)
	if err := cm.completeControlAttestation(replacementControl, replacementGeneration, func() error { return nil }); err != nil {
		t.Fatalf("complete replacement attestation: %v", err)
	}
	if err := cm.registerSessionOwner(replacementControl, replacementGeneration, "blocked-init"); err != nil {
		t.Fatalf("register replacement owner: %v", err)
	}
	replacementSession := &SessionTEEKConnection{
		sessionID: "blocked-init", controlGeneration: replacementGeneration, conn: shared.NewWSConnection(nil), closed: true,
	}
	if err := cm.publishSessionConnection("blocked-init", replacementSession); err != nil {
		t.Fatalf("publish replacement session: %v", err)
	}
	if err := cm.publishSessionConnection("blocked-init", blockedInit); err == nil {
		t.Fatal("blocked old init published after replacement")
	}
	cm.removeSessionConnection("blocked-init", blockedInit)
	cm.mu.RLock()
	got := cm.sessionConns["blocked-init"]
	cm.mu.RUnlock()
	if got != replacementSession {
		t.Fatal("stale init/defer removed replacement session connection")
	}
}

func TestControlReplacementAbortsPendingExtensionThenResumesAndExtends(t *testing.T) {
	teet, oldPending := teetWithPendingReceiverBatch(t, 10, 10)
	oldPending.controlGeneration = 1
	state := teet.otReceiverState
	epoch := mpc.ExtensionEpoch([32]byte{7})
	state.epoch = epoch
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := shared.NewWSConnection(nil)
	replacementControl := newReceiverTestWebSocket(t)
	cm.controlConn = oldControl
	cm.controlGeneration = 1
	if teet.resumeOTPool(epoch, 0) {
		t.Fatal("resume accepted pool with unmatched pending extension")
	}

	generation, _, _, _ := cm.activateControlConnection(replacementControl)
	if generation != 2 {
		t.Fatalf("replacement generation = %d, want 2", generation)
	}
	if state.pending != nil || oldPending.outcome != receiverPrecomputeAborted {
		t.Fatal("replacement did not abort superseded pending extension")
	}
	if !state.ready || state.pool.TotalCount() != 10 {
		t.Fatal("replacement did not retain committed ready pool")
	}
	if !teet.resumeOTPool(epoch, 0) {
		t.Fatal("replacement could not resume retained committed pool")
	}

	begin := mpc.PrecomputeBegin{StartIndex: 10, Count: 1, Epoch: epoch}
	begin.SessionID[0] = 2
	payload, err := mpc.MarshalPrecomputeBegin(begin)
	if err != nil {
		t.Fatalf("marshal extension begin: %v", err)
	}
	if err := teet.handleOTPrecomputeBegin(replacementControl, generation, directControlStateLease, &teeproto.OTPrecomputeRequest{
		Count: 1, OtSenderSetup: payload, Epoch: epoch,
	}); err != nil {
		t.Fatalf("start extension on replacement: %v", err)
	}
	if state.pending == nil || state.pending.controlGeneration != generation {
		t.Fatal("replacement generation did not start its own extension")
	}
	teet.clearOTReceiverPool()
}

func TestSupersededControlTeardownCannotClearReplacement(t *testing.T) {
	pending := &receiverPrecompute{
		begin:             mpc.PrecomputeBegin{StartIndex: 10, Count: 10},
		controlGeneration: 2,
		entries:           receiverEntries(10, 10),
		done:              make(chan struct{}),
	}
	teet := &TEET{
		logger: shared.NewNopLogger(),
		otReceiverState: &OTReceiverState{
			pool:    receiverPoolWith(t, 10),
			ready:   true,
			pending: pending,
		},
		teekConnected: true,
	}
	cm := NewTEEKConnectionManager(teet, shared.NewNopLogger())
	oldControl := shared.NewWSConnection(nil)
	replacementControl := shared.NewWSConnection(nil)
	replacementSession := &SessionTEEKConnection{closed: true}

	cm.mu.Lock()
	cm.controlConn = replacementControl
	cm.controlGeneration = 2
	cm.sessionConns["replacement-session"] = replacementSession
	cm.mu.Unlock()
	cm.attestationVerified = true
	teet.controlHealthy.Store(true)

	// This is the deterministic overlap: generation 2 has replaced generation
	// 1 before generation 1 reaches its deferred teardown.
	cm.tearDownControlConnection(oldControl, 1)

	cm.mu.RLock()
	gotControl := cm.controlConn
	gotGeneration := cm.controlGeneration
	gotSession := cm.sessionConns["replacement-session"]
	cm.mu.RUnlock()
	if gotControl != replacementControl || gotGeneration != 2 {
		t.Fatal("superseded teardown cleared replacement control generation")
	}
	if gotSession != replacementSession {
		t.Fatal("superseded teardown purged replacement session")
	}
	if !cm.attestationVerified || !teet.isTEEKConnected() || !teet.controlHealthy.Load() {
		t.Fatal("superseded teardown cleared replacement connection health")
	}
	if teet.otReceiverState.pending != pending || pending.outcome != receiverPrecomputeInProgress {
		t.Fatal("superseded teardown suspended replacement OT batch")
	}
	select {
	case <-pending.done:
		t.Fatal("superseded teardown woke replacement OT batch")
	default:
	}
}

func newGenerationTestTEET() *TEET {
	logger := shared.NewNopLogger()
	sessionManager := NewTEETSessionManager()
	sessionManager.SetLogger(logger)
	return &TEET{
		logger:            logger,
		sessionManager:    sessionManager,
		sessionTerminator: shared.NewSessionTerminator(logger),
	}
}

func waitForDetachedSessionOwner(t *testing.T, cm *TEEKConnectionManager, sessionID string, requireControlNil bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		cm.mu.RLock()
		_, ownerExists := cm.sessionOwners[sessionID]
		_, connExists := cm.sessionConns[sessionID]
		controlNil := cm.controlConn == nil
		cm.mu.RUnlock()
		if !ownerExists && !connExists && (!requireControlNil || controlNil) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for old session owner and connection detachment")
		}
		runtime.Gosched()
	}
}

func assertExactSessionOwner(t *testing.T, cm *TEEKConnectionManager, sessionID string, generation uint64, session *shared.Session) {
	t.Helper()
	cm.mu.RLock()
	owner, exists := cm.sessionOwners[sessionID]
	cm.mu.RUnlock()
	if !exists || owner.controlGeneration != generation || owner.session != session {
		t.Fatalf("session owner = %+v (exists=%v), want generation %d and exact session", owner, exists, generation)
	}
}
