package main

import (
	"io"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

func TestTEEKPeerErrorTerminatesOnlyExactSession(t *testing.T) {
	t.Run("current", func(t *testing.T) {
		teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
		identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
			return cm.validateSessionConnection(sessionConn)
		}}
		session.ConnMutex.RLock()
		client := session.ClientConn.(*shared.WSConnection)
		session.ConnMutex.RUnlock()

		if err := teek.handlePeerErrorForIdentity(identity, &teeproto.ErrorData{Message: "peer rejected proof"}); err != nil {
			t.Fatalf("handle current peer error: %v", err)
		}
		if _, err := teek.sessionManager.GetSession(session.ID); err == nil {
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
		teek, cm, oldSession, oldConn, _ := newTEEKPeerLossSession(t)
		identity := &teekSessionIdentity{session: oldSession, sessionConn: oldConn, validate: func() error {
			return cm.validateSessionConnection(oldConn)
		}}
		cm.mu.Lock()
		delete(cm.sessionConns, oldSession.ID)
		cm.mu.Unlock()
		if err := teek.sessionManager.CloseSessionIfCurrent(oldSession); err != nil {
			t.Fatal(err)
		}
		if err := teek.sessionManager.RegisterSession(oldSession.ID); err != nil {
			t.Fatal(err)
		}
		replacement, err := teek.sessionManager.GetSession(oldSession.ID)
		if err != nil {
			t.Fatal(err)
		}
		replacementConn := &SessionTEETConnection{
			sessionID: oldSession.ID, session: replacement,
			controlConn: oldConn.controlConn, controlGeneration: oldConn.controlGeneration,
			conn: newAckTestWebSocket(t),
		}
		if err := cm.publishSessionConnection(replacementConn); err != nil {
			t.Fatal(err)
		}

		if err := teek.handlePeerErrorForIdentity(identity, &teeproto.ErrorData{Message: "stale peer error"}); err == nil {
			t.Fatal("stale peer error returned nil")
		}
		current, err := teek.sessionManager.GetSession(oldSession.ID)
		if err != nil || current != replacement || replacement.CleanedUp.Load() || replacementConn.isClosed() {
			t.Fatalf("stale peer error changed replacement: current=%p err=%v cleaned=%v closed=%v", current, err, replacement.CleanedUp.Load(), replacementConn.isClosed())
		}
	})
}

func TestTEEKPeerReadFailureCleansExactSession(t *testing.T) {
	teek, cm, session, sessionConn, controlMessages := newTEEKPeerLossSession(t)
	identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}

	cm.handleSessionReadFailure(identity, io.EOF, false)
	if _, err := teek.sessionManager.GetSession(session.ID); err == nil {
		t.Fatal("peer EOF retained the shared session")
	}
	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("active sessions = %d, want 0", got)
	}
	cm.mu.RLock()
	current := cm.sessionConns[session.ID]
	cm.mu.RUnlock()
	if current != nil {
		t.Fatal("peer EOF retained the session socket owner")
	}
	if !session.CleanedUp.Load() || !sessionConn.isClosed() {
		t.Fatal("peer EOF did not close exact session resources")
	}
	assertSessionClosedMessage(t, controlMessages, session.ID, "session_cleanup")
}

func TestTEEKPeerReadFailurePreservesLocalCloseAndSameIDReplacement(t *testing.T) {
	t.Run("local close", func(t *testing.T) {
		teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
		identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
			return cm.validateSessionConnection(sessionConn)
		}}
		cm.handleSessionReadFailure(identity, io.EOF, true)
		current, err := teek.sessionManager.GetSession(session.ID)
		if err != nil || current != session || session.CleanedUp.Load() {
			t.Fatalf("local close path changed session: current=%p err=%v cleaned=%v", current, err, session.CleanedUp.Load())
		}
	})

	t.Run("same ID replacement", func(t *testing.T) {
		teek, cm, oldSession, oldConn, _ := newTEEKPeerLossSession(t)
		identity := &teekSessionIdentity{session: oldSession, sessionConn: oldConn, validate: func() error {
			return cm.validateSessionConnection(oldConn)
		}}
		cm.mu.Lock()
		delete(cm.sessionConns, oldSession.ID)
		cm.mu.Unlock()
		if err := teek.sessionManager.CloseSessionIfCurrent(oldSession); err != nil {
			t.Fatal(err)
		}
		if err := teek.sessionManager.RegisterSession(oldSession.ID); err != nil {
			t.Fatal(err)
		}
		replacement, err := teek.sessionManager.GetSession(oldSession.ID)
		if err != nil {
			t.Fatal(err)
		}
		replacementConn := &SessionTEETConnection{
			sessionID: oldSession.ID, session: replacement,
			controlConn: oldConn.controlConn, controlGeneration: oldConn.controlGeneration,
			conn: newAckTestWebSocket(t),
		}
		if err := cm.publishSessionConnection(replacementConn); err != nil {
			t.Fatal(err)
		}

		cm.handleSessionReadFailure(identity, io.EOF, false)
		current, err := teek.sessionManager.GetSession(oldSession.ID)
		if err != nil || current != replacement || replacement.CleanedUp.Load() {
			t.Fatalf("stale EOF changed replacement: current=%p err=%v cleaned=%v", current, err, replacement.CleanedUp.Load())
		}
	})
}

func TestTEEKControlTeardownCleansExactSharedSession(t *testing.T) {
	teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
	cm.tearDownControl(sessionConn.controlConn, sessionConn.controlGeneration)
	if _, err := teek.sessionManager.GetSession(session.ID); err == nil {
		t.Fatal("control teardown retained shared session")
	}
	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("active sessions = %d, want 0", got)
	}
	if !session.CleanedUp.Load() || !sessionConn.isClosed() {
		t.Fatal("control teardown did not close exact session resources")
	}
}

func newTEEKPeerLossSession(t *testing.T) (*TEEK, *TEETConnectionManager, *shared.Session, *SessionTEETConnection, <-chan []byte) {
	t.Helper()
	logger := shared.NewNopLogger()
	manager := NewTEEKSessionManager()
	manager.SetLogger(logger)
	clientConn := newAckTestWebSocket(t)
	sessionID, err := manager.CreateSession(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetTEEKSessionState(sessionID, &TEEKSessionState{session: session})
	teek := &TEEK{
		sessionManager: manager, logger: logger,
		sessionTerminator: shared.NewSessionTerminator(logger),
		otPrecomputeState: NewOTPrecomputeState(),
	}
	teek.activeSessions.Store(1)
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	control, messages := newAckTestWebSocketWithMessages(t)
	_, generation := installAckTestControl(cm, control)
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	sessionConn := &SessionTEETConnection{
		sessionID: sessionID, session: session, controlConn: control,
		controlGeneration: generation, conn: newAckTestWebSocket(t),
	}
	if err := cm.publishSessionConnection(sessionConn); err != nil {
		t.Fatal(err)
	}
	return teek, cm, session, sessionConn, messages
}
