package main

import (
	"io"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

func TestTEETPeerErrorTerminatesOnlyExactSession(t *testing.T) {
	t.Run("current", func(t *testing.T) {
		teet, cm, session, sessionConn := newTEETPeerLossSession(t, "teet-current-peer-error")
		identity := &teetSessionIdentity{
			session: session, controlGeneration: sessionConn.controlGeneration, sessionConn: sessionConn,
			validate: func() error { return cm.validateSessionConnection(sessionConn) },
		}
		session.ConnMutex.RLock()
		client := session.ClientConn.(*shared.WSConnection)
		session.ConnMutex.RUnlock()

		if err := teet.handlePeerErrorForIdentity(identity, &teeproto.ErrorData{Message: "peer rejected proof"}); err != nil {
			t.Fatalf("handle current peer error: %v", err)
		}
		if _, err := teet.sessionManager.GetSession(session.ID); err == nil {
			t.Fatal("peer error retained current session")
		}
		if !session.CleanedUp.Load() || !sessionConn.isClosed() {
			t.Fatal("peer error did not clean exact session resources")
		}
		if err := client.WriteMessage(websocket.BinaryMessage, []byte("after cleanup")); err == nil {
			t.Fatal("peer error left client connection open")
		}
	})

	t.Run("stale same ID", func(t *testing.T) {
		const sessionID = "teet-stale-peer-error"
		teet, cm, oldSession, oldConn := newTEETPeerLossSession(t, sessionID)
		identity := &teetSessionIdentity{
			session: oldSession, controlGeneration: oldConn.controlGeneration, sessionConn: oldConn,
			validate: func() error { return cm.validateSessionConnection(oldConn) },
		}
		cm.mu.Lock()
		delete(cm.sessionConns, sessionID)
		delete(cm.sessionOwners, sessionID)
		cm.mu.Unlock()
		if err := teet.sessionManager.closeSessionIfCurrent(oldSession); err != nil {
			t.Fatal(err)
		}
		if err := teet.sessionManager.RegisterSession(sessionID); err != nil {
			t.Fatal(err)
		}
		replacement, err := teet.sessionManager.GetSession(sessionID)
		if err != nil {
			t.Fatal(err)
		}
		generation := oldConn.controlGeneration
		teet.sessionManager.SetTEETSessionState(sessionID, &TEETSessionState{session: replacement, controlGeneration: generation})
		replacementConn := &SessionTEEKConnection{
			sessionID: sessionID, session: replacement, controlGeneration: generation,
			conn: newReceiverTestWebSocket(t),
		}
		cm.mu.Lock()
		cm.sessionOwners[sessionID] = controlSessionOwner{controlGeneration: generation, session: replacement}
		cm.sessionConns[sessionID] = replacementConn
		cm.mu.Unlock()

		if err := teet.handlePeerErrorForIdentity(identity, &teeproto.ErrorData{Message: "stale peer error"}); err == nil {
			t.Fatal("stale peer error returned nil")
		}
		current, err := teet.sessionManager.GetSession(sessionID)
		if err != nil || current != replacement || replacement.CleanedUp.Load() || replacementConn.isClosed() {
			t.Fatalf("stale peer error changed replacement: current=%p err=%v cleaned=%v closed=%v", current, err, replacement.CleanedUp.Load(), replacementConn.isClosed())
		}
	})
}

func TestTEETPeerReadFailureCleansExactSession(t *testing.T) {
	teet, cm, session, sessionConn := newTEETPeerLossSession(t, "teet-peer-eof")
	identity := &teetSessionIdentity{
		session: session, controlGeneration: sessionConn.controlGeneration, sessionConn: sessionConn,
		validate: func() error { return cm.validateSessionConnection(sessionConn) },
	}

	cm.handleSessionReadFailure(identity, io.EOF, false)
	if _, err := teet.sessionManager.GetSession(session.ID); err == nil {
		t.Fatal("peer EOF retained the shared session")
	}
	if got := teet.activeSessions.Load(); got != 0 {
		t.Fatalf("active sessions = %d, want 0", got)
	}
	cm.mu.RLock()
	_, ownerExists := cm.sessionOwners[session.ID]
	current := cm.sessionConns[session.ID]
	cm.mu.RUnlock()
	if ownerExists || current != nil {
		t.Fatal("peer EOF retained peer-session ownership")
	}
	if !session.CleanedUp.Load() || !sessionConn.isClosed() {
		t.Fatal("peer EOF did not close exact session resources")
	}
}

func TestTEETPeerReadFailurePreservesLocalCloseAndSameIDReplacement(t *testing.T) {
	t.Run("local close", func(t *testing.T) {
		teet, cm, session, sessionConn := newTEETPeerLossSession(t, "teet-local-close")
		identity := &teetSessionIdentity{
			session: session, controlGeneration: sessionConn.controlGeneration, sessionConn: sessionConn,
			validate: func() error { return cm.validateSessionConnection(sessionConn) },
		}
		cm.handleSessionReadFailure(identity, io.EOF, true)
		current, err := teet.sessionManager.GetSession(session.ID)
		if err != nil || current != session || session.CleanedUp.Load() {
			t.Fatalf("local close path changed session: current=%p err=%v cleaned=%v", current, err, session.CleanedUp.Load())
		}
	})

	t.Run("same ID replacement", func(t *testing.T) {
		const sessionID = "teet-same-id-replacement"
		teet, cm, oldSession, oldConn := newTEETPeerLossSession(t, sessionID)
		identity := &teetSessionIdentity{
			session: oldSession, controlGeneration: oldConn.controlGeneration, sessionConn: oldConn,
			validate: func() error { return cm.validateSessionConnection(oldConn) },
		}
		cm.mu.Lock()
		delete(cm.sessionConns, sessionID)
		delete(cm.sessionOwners, sessionID)
		cm.mu.Unlock()
		if err := teet.sessionManager.closeSessionIfCurrent(oldSession); err != nil {
			t.Fatal(err)
		}
		if err := teet.sessionManager.RegisterSession(sessionID); err != nil {
			t.Fatal(err)
		}
		replacement, err := teet.sessionManager.GetSession(sessionID)
		if err != nil {
			t.Fatal(err)
		}
		generation := oldConn.controlGeneration
		teet.sessionManager.SetTEETSessionState(sessionID, &TEETSessionState{session: replacement, controlGeneration: generation})
		replacementConn := &SessionTEEKConnection{
			sessionID: sessionID, session: replacement, controlGeneration: generation,
			conn: newReceiverTestWebSocket(t),
		}
		cm.mu.Lock()
		cm.sessionOwners[sessionID] = controlSessionOwner{controlGeneration: generation, session: replacement}
		cm.sessionConns[sessionID] = replacementConn
		cm.mu.Unlock()

		cm.handleSessionReadFailure(identity, io.EOF, false)
		current, err := teet.sessionManager.GetSession(sessionID)
		if err != nil || current != replacement || replacement.CleanedUp.Load() {
			t.Fatalf("stale EOF changed replacement: current=%p err=%v cleaned=%v", current, err, replacement.CleanedUp.Load())
		}
	})
}

func newTEETPeerLossSession(t *testing.T, sessionID string) (*TEET, *TEEKConnectionManager, *shared.Session, *SessionTEEKConnection) {
	t.Helper()
	logger := shared.NewNopLogger()
	manager := NewTEETSessionManager()
	manager.SetLogger(logger)
	if err := manager.RegisterSession(sessionID); err != nil {
		t.Fatal(err)
	}
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateSessionIfCurrent(session, newReceiverTestWebSocket(t)); err != nil {
		t.Fatal(err)
	}
	const generation = 1
	manager.SetTEETSessionState(sessionID, &TEETSessionState{session: session, controlGeneration: generation})
	teet := &TEET{
		sessionManager: manager, logger: logger,
		sessionTerminator: shared.NewSessionTerminator(logger),
	}
	teet.activeSessions.Store(1)
	cm := NewTEEKConnectionManager(teet, logger)
	teet.connManager = cm
	cm.mu.Lock()
	cm.controlConn = newReceiverTestWebSocket(t)
	cm.controlGeneration = generation
	cm.sessionOwners[sessionID] = controlSessionOwner{controlGeneration: generation, session: session}
	sessionConn := &SessionTEEKConnection{
		sessionID: sessionID, session: session, controlGeneration: generation,
		conn: newReceiverTestWebSocket(t),
	}
	cm.sessionConns[sessionID] = sessionConn
	cm.mu.Unlock()
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	return teet, cm, session, sessionConn
}
