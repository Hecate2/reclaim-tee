package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func TestSessionCreatedAckCannotOvertakeWaiterRegistration(t *testing.T) {
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", shared.NewNopLogger())
	const sessionID = "session-ack-before-send-return"
	conn, generation := installAckTestControl(cm, shared.NewWSConnection(nil))

	err := cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Second, func(gotConn *shared.WSConnection, gotGeneration uint64) error {
		if gotConn != conn || gotGeneration != generation {
			t.Fatal("send did not bind to installed control generation")
		}
		cm.pendingAcksMu.Lock()
		_, registered := cm.pendingAcks[sessionID]
		cm.pendingAcksMu.Unlock()
		if !registered {
			t.Fatal("ack waiter was not registered before send")
		}

		ack, err := proto.Marshal(&teeproto.Envelope{
			SessionId: sessionID,
			Payload: &teeproto.Envelope_SessionCreatedAck{
				SessionCreatedAck: &teeproto.SessionCreatedAck{SessionId: sessionID},
			},
		})
		if err != nil {
			t.Fatalf("marshal ack: %v", err)
		}
		// Deliver the acknowledgment before send returns. This deterministically
		// reproduces the cross-connection ordering that used to lose the ack.
		cm.handleControlMessage(conn, generation, ack)
		return nil
	})
	if err != nil {
		t.Fatalf("sendSessionCreatedAndWaitTimeout: %v", err)
	}
	assertNoPendingSessionAck(t, cm, sessionID)
}

func TestSessionCreatedAckWaiterCleanedOnSendFailure(t *testing.T) {
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", shared.NewNopLogger())
	const sessionID = "session-send-failure"
	wantErr := errors.New("write failed")
	installAckTestControl(cm, newAckTestWebSocket(t))

	err := cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Second, func(*shared.WSConnection, uint64) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	assertNoPendingSessionAck(t, cm, sessionID)
}

func TestSessionCreatedAmbiguousSendFailureClosesOnlyOrigin(t *testing.T) {
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", shared.NewNopLogger())
	const sessionID = "session-partial-write-failure"
	origin, _ := installAckTestControl(cm, newAckTestWebSocket(t))
	replacement := newAckTestWebSocket(t)
	wantErr := errors.New("partial control write")

	err := cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Second, func(*shared.WSConnection, uint64) error {
		installAckTestControl(cm, replacement)
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("send error = %v, want %v", err, wantErr)
	}
	if errors.Is(err, errSessionCreatedControlUnavailable) {
		t.Fatalf("ambiguous send error was marked retryable: %v", err)
	}
	if err := origin.WriteMessage(websocket.BinaryMessage, []byte("closed-origin")); err == nil {
		t.Fatal("ambiguous send failure left origin control open")
	}
	if err := replacement.WriteMessage(websocket.BinaryMessage, []byte("usable-replacement")); err != nil {
		t.Fatalf("ambiguous origin failure closed replacement control: %v", err)
	}
}

func TestGenericControlSendDoesNotExposeSessionCreatedRetrySentinel(t *testing.T) {
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", shared.NewNopLogger())
	origin, generation := installAckTestControl(cm, newAckTestWebSocket(t))
	installAckTestControl(cm, newAckTestWebSocket(t))
	err := cm.sendOnControlConnection(origin, generation, &teeproto.Envelope{
		SessionId: "unrelated-control-message",
		Payload: &teeproto.Envelope_SessionClosed{
			SessionClosed: &teeproto.SessionClosed{SessionId: "unrelated-control-message"},
		},
	})
	if !errors.Is(err, errControlUnavailableBeforeWrite) {
		t.Fatalf("generic control error = %v, want pre-write unavailable", err)
	}
	if errors.Is(err, errSessionCreatedControlUnavailable) {
		t.Fatalf("generic control error inherited SessionCreated retry classification: %v", err)
	}
}

func TestSessionCreatedAckWaiterCleanedOnTimeout(t *testing.T) {
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", shared.NewNopLogger())
	const sessionID = "session-ack-timeout"
	conn := newAckTestWebSocket(t)
	installAckTestControl(cm, conn)

	err := cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Millisecond, func(*shared.WSConnection, uint64) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for SessionCreatedAck") {
		t.Fatalf("error = %v, want SessionCreatedAck timeout", err)
	}
	assertNoPendingSessionAck(t, cm, sessionID)
}

func TestSessionCreatedRetryClassification(t *testing.T) {
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", shared.NewNopLogger())
	const sessionID = "session-created-retry-classification"

	_, err := cm.sendSessionCreatedAndWaitToken(sessionID, time.Second, func(*shared.WSConnection, uint64) error {
		t.Fatal("send called without a control connection")
		return nil
	})
	if !errors.Is(err, errSessionCreatedControlUnavailable) {
		t.Fatalf("pre-send error = %v, want errSessionCreatedControlUnavailable", err)
	}

	installAckTestControl(cm, newAckTestWebSocket(t))
	wantSendErr := errors.New("injected control write failure")
	_, err = cm.sendSessionCreatedAndWaitToken(sessionID, time.Second, func(*shared.WSConnection, uint64) error {
		return wantSendErr
	})
	if !errors.Is(err, wantSendErr) {
		t.Fatalf("send error = %v, want %v", err, wantSendErr)
	}
	if errors.Is(err, errSessionCreatedControlUnavailable) {
		t.Fatalf("post-send error was classified as definitely pre-send: %v", err)
	}

	_, err = cm.sendSessionCreatedAndWaitToken(sessionID, time.Millisecond, func(*shared.WSConnection, uint64) error {
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for SessionCreatedAck") {
		t.Fatalf("ACK error = %v, want timeout", err)
	}
	if errors.Is(err, errSessionCreatedControlUnavailable) {
		t.Fatalf("ACK timeout was classified as definitely pre-send: %v", err)
	}
}

func TestSessionCreatedRetryWaitsForReplacementBeforeResend(t *testing.T) {
	logger := shared.NewNopLogger()
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", logger)
	teek := &TEEK{connManager: cm, logger: logger}
	const sessionID = "session-created-control-replacement"
	var attempts int
	var waits []time.Duration

	notify := func(string) error {
		attempts++
		return cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Second, func(conn *shared.WSConnection, generation uint64) error {
			ack, err := proto.Marshal(&teeproto.Envelope{
				SessionId: sessionID,
				Payload: &teeproto.Envelope_SessionCreatedAck{
					SessionCreatedAck: &teeproto.SessionCreatedAck{SessionId: sessionID},
				},
			})
			if err != nil {
				return err
			}
			cm.handleControlMessage(conn, generation, ack)
			return nil
		})
	}
	wait := func(delay time.Duration) {
		waits = append(waits, delay)
		installAckTestControl(cm, newAckTestWebSocket(t))
	}

	if err := teek.notifyTEETNewSessionWithRetryPolicy(sessionID, 3, 10*time.Millisecond, notify, wait); err != nil {
		t.Fatalf("retry after control replacement: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("notify attempts = %d, want 2", attempts)
	}
	if len(waits) != 1 || waits[0] != 10*time.Millisecond {
		t.Fatalf("retry waits = %v, want [10ms]", waits)
	}
}

func TestSessionCreatedRetryBindsResendToReplacementControl(t *testing.T) {
	logger := shared.NewNopLogger()
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", logger)
	teek := &TEEK{connManager: cm, logger: logger}
	const sessionID = "session-created-replaced-before-send"
	origin, originGeneration := installAckTestControl(cm, newAckTestWebSocket(t))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	var replacement *shared.WSConnection
	var replacementGeneration uint64
	attempts := 0

	notify := func(string) error {
		attempts++
		return cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Second, func(conn *shared.WSConnection, generation uint64) error {
			if attempts == 1 {
				if conn != origin || generation != originGeneration {
					t.Fatal("first attempt was not bound to origin control")
				}
				replacement = newAckTestWebSocket(t)
				_, replacementGeneration = installAckTestControl(cm, replacement)
				cm.attestationMutex.Lock()
				cm.attestationVerified = true
				cm.attestationMutex.Unlock()
			}
			env := &teeproto.Envelope{
				SessionId: sessionID,
				Payload: &teeproto.Envelope_SessionCreated{
					SessionCreated: &teeproto.SessionCreated{},
				},
			}
			if err := cm.sendOnControlConnection(conn, generation, env); err != nil {
				return err
			}
			if conn != replacement || generation != replacementGeneration {
				t.Fatal("retry was not bound to replacement control")
			}
			ack, err := proto.Marshal(&teeproto.Envelope{
				SessionId: sessionID,
				Payload: &teeproto.Envelope_SessionCreatedAck{
					SessionCreatedAck: &teeproto.SessionCreatedAck{SessionId: sessionID},
				},
			})
			if err != nil {
				return err
			}
			cm.handleControlMessage(conn, generation, ack)
			return nil
		})
	}

	if err := teek.notifyTEETNewSessionWithRetryPolicy(sessionID, 3, time.Millisecond, notify, func(time.Duration) {}); err != nil {
		t.Fatalf("replacement retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("notify attempts = %d, want 2", attempts)
	}
}

func TestSessionCreatedRetryDoesNotRepeatAmbiguousFailure(t *testing.T) {
	logger := shared.NewNopLogger()
	teek := &TEEK{logger: logger}
	wantErr := errors.New("SessionCreated may have been written")
	attempts := 0
	waits := 0
	err := teek.notifyTEETNewSessionWithRetryPolicy("ambiguous-session", 5, time.Millisecond, func(string) error {
		attempts++
		return wantErr
	}, func(time.Duration) {
		waits++
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("retry error = %v, want %v", err, wantErr)
	}
	if attempts != 1 || waits != 0 {
		t.Fatalf("ambiguous failure attempts=%d waits=%d, want 1 and 0", attempts, waits)
	}
}

func TestSessionCreatedRetryDoesNotRepeatAckTimeout(t *testing.T) {
	logger := shared.NewNopLogger()
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", logger)
	teek := &TEEK{logger: logger}
	installAckTestControl(cm, newAckTestWebSocket(t))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	attempts := 0
	waits := 0

	err := teek.notifyTEETNewSessionWithRetryPolicy("ack-timeout-not-retried", 5, time.Millisecond, func(sessionID string) error {
		attempts++
		return cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Millisecond, func(conn *shared.WSConnection, generation uint64) error {
			return cm.sendOnControlConnection(conn, generation, &teeproto.Envelope{
				SessionId: sessionID,
				Payload: &teeproto.Envelope_SessionCreated{
					SessionCreated: &teeproto.SessionCreated{},
				},
			})
		})
	}, func(time.Duration) {
		waits++
	})
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for SessionCreatedAck") {
		t.Fatalf("retry error = %v, want ACK timeout", err)
	}
	if attempts != 1 || waits != 0 {
		t.Fatalf("ACK timeout attempts=%d waits=%d, want 1 and 0", attempts, waits)
	}
}

func TestSessionCreatedAckDisconnectFailsOriginWaiter(t *testing.T) {
	cm := NewTEETConnectionManager(&TEEK{}, "ws://example.invalid", shared.NewNopLogger())
	const sessionID = "session-disconnect-during-ack"
	origin, generation := installAckTestControl(cm, shared.NewWSConnection(nil))
	sent := make(chan struct{})
	result := make(chan error, 1)

	go func() {
		result <- cm.sendSessionCreatedAndWaitTimeout(sessionID, time.Second, func(*shared.WSConnection, uint64) error {
			close(sent)
			return nil
		})
	}()
	<-sent
	cm.tearDownControl(origin, generation)

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "control connection disconnected") {
			t.Fatalf("error = %v, want control disconnect", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control teardown did not wake SessionCreatedAck waiter")
	}
	assertNoPendingSessionAck(t, cm, sessionID)
}

func TestSessionCreatedAckTimeoutDoesNotCloseReplacementControl(t *testing.T) {
	cm := NewTEETConnectionManager(nil, "ws://example.invalid", shared.NewNopLogger())
	const sessionID = "session-reconnect-before-timeout"
	origin := newAckTestWebSocket(t)
	installAckTestControl(cm, origin)
	replacement := newAckTestWebSocket(t)
	sent := make(chan struct{})
	result := make(chan error, 1)

	go func() {
		result <- cm.sendSessionCreatedAndWaitTimeout(sessionID, 20*time.Millisecond, func(*shared.WSConnection, uint64) error {
			// Install the replacement before the callback returns and the
			// timeout wait begins. This makes the ownership assertion
			// independent of goroutine scheduling.
			installAckTestControl(cm, replacement)
			close(sent)
			return nil
		})
	}()
	<-sent

	if err := <-result; err == nil || !strings.Contains(err.Error(), "timeout waiting for SessionCreatedAck") {
		t.Fatalf("error = %v, want SessionCreatedAck timeout", err)
	}
	if err := replacement.WriteMessage(websocket.BinaryMessage, []byte("still-open")); err != nil {
		t.Fatalf("replacement control was closed by origin timeout: %v", err)
	}
	assertNoPendingSessionAck(t, cm, sessionID)
}

func TestSessionCreatedAckOriginCannotMigrateToReplacementBeforeDial(t *testing.T) {
	logger := shared.NewNopLogger()
	sessionManager := NewTEEKSessionManager()
	sessionManager.SetLogger(logger)
	teek := &TEEK{sessionManager: sessionManager, logger: logger}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	const sessionID = "session-ack-then-control-replacement"
	if err := sessionManager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register session: %v", err)
	}
	origin, generation := installAckTestControl(cm, shared.NewWSConnection(nil))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()

	token, err := cm.sendSessionCreatedAndWaitToken(sessionID, time.Second, func(gotConn *shared.WSConnection, gotGeneration uint64) error {
		if gotConn != origin || gotGeneration != generation {
			t.Fatal("SessionCreated send was not bound to the origin control")
		}
		ack, marshalErr := proto.Marshal(&teeproto.Envelope{
			SessionId: sessionID,
			Payload: &teeproto.Envelope_SessionCreatedAck{
				SessionCreatedAck: &teeproto.SessionCreatedAck{SessionId: sessionID},
			},
		})
		if marshalErr != nil {
			return marshalErr
		}
		cm.handleControlMessage(origin, generation, ack)
		return nil
	})
	if err != nil {
		t.Fatalf("wait for SessionCreatedAck: %v", err)
	}
	if token.conn != origin || token.generation != generation {
		t.Fatal("acknowledgment returned the wrong control identity")
	}

	replacement, replacementGeneration := installAckTestControl(cm, shared.NewWSConnection(nil))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	dialAttempted := false
	cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
		dialAttempted = true
		return shared.NewWSConnection(nil), nil
	}

	err = cm.EstablishSessionConnection(sessionID, token)
	if err == nil || !strings.Contains(err.Error(), "acknowledged control connection changed") {
		t.Fatalf("establishment error = %v, want acknowledged-control replacement failure", err)
	}
	if dialAttempted {
		t.Fatal("stale acknowledged control attempted a session dial on the replacement")
	}
	cm.mu.RLock()
	gotControl := cm.controlConn
	gotGeneration := cm.controlGeneration
	_, published := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if gotControl != replacement || gotGeneration != replacementGeneration {
		t.Fatal("stale acknowledged control changed the replacement control")
	}
	if published {
		t.Fatal("stale acknowledged control published a session connection")
	}
}

func TestControlPeerErrorTerminatesAcknowledgedSessionBeforePublication(t *testing.T) {
	teek, cm, session, origin, generation, controlMessages := newAcknowledgedSessionGap(t)
	session.ConnMutex.RLock()
	client := session.ClientConn.(*shared.WSConnection)
	session.ConnMutex.RUnlock()

	peerError, err := proto.Marshal(&teeproto.Envelope{
		SessionId: session.ID,
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{
			Message: "TEE_T rejected acknowledged session",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cm.handleControlMessage(origin, generation, peerError)

	if _, err := teek.sessionManager.GetSession(session.ID); err == nil {
		t.Fatal("control peer error retained acknowledged session")
	}
	if !session.CleanedUp.Load() {
		t.Fatal("control peer error did not clean acknowledged session")
	}
	cm.mu.RLock()
	owner := cm.acknowledgedSessions[session.ID]
	cm.mu.RUnlock()
	if owner != nil {
		t.Fatal("control peer error retained acknowledged owner token")
	}
	if err := client.WriteMessage(websocket.BinaryMessage, []byte("after peer error")); err == nil {
		t.Fatal("control peer error left exact client open")
	}
	assertSessionClosedMessage(t, controlMessages, session.ID, "session_cleanup")
	assertNoControlMessage(t, controlMessages, "post-peer-error origin")
}

func TestStaleControlPeerErrorInAcknowledgmentGapPreservesReplacement(t *testing.T) {
	teek, cm, oldSession, origin, generation, originMessages := newAcknowledgedSessionGap(t)
	teek.cleanupSessionWithSession(oldSession)
	assertSessionClosedMessage(t, originMessages, oldSession.ID, "session_cleanup")

	if err := teek.sessionManager.RegisterSession(oldSession.ID); err != nil {
		t.Fatal(err)
	}
	replacement, err := teek.sessionManager.GetSession(oldSession.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacementClient := newAckTestWebSocket(t)
	if err := teek.sessionManager.ActivateSessionIfCurrent(replacement, replacementClient); err != nil {
		t.Fatal(err)
	}
	teek.sessionManager.SetTEEKSessionState(oldSession.ID, &TEEKSessionState{session: replacement})
	teek.activeSessions.Store(1)
	replacementControl, replacementMessages := newAckTestWebSocketWithMessages(t)
	installAckTestControl(cm, replacementControl)

	peerError, err := proto.Marshal(&teeproto.Envelope{
		SessionId: oldSession.ID,
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{
			Message: "stale TEE_T error",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cm.handleControlMessage(origin, generation, peerError)

	current, err := teek.sessionManager.GetSession(oldSession.ID)
	if err != nil || current != replacement || replacement.CleanedUp.Load() {
		t.Fatalf("stale control error changed replacement: current=%p err=%v cleaned=%v", current, err, replacement.CleanedUp.Load())
	}
	if err := replacementClient.WriteMessage(websocket.BinaryMessage, []byte("replacement alive")); err != nil {
		t.Fatalf("stale control error closed replacement client: %v", err)
	}
	assertNoControlMessage(t, originMessages, "stale origin")
	assertNoControlMessage(t, replacementMessages, "replacement control")
}

func TestDelayedSessionDialCannotPublishAfterAcknowledgedOwnerCleanup(t *testing.T) {
	tests := []struct {
		name        string
		replacement bool
	}{
		{name: "cleaned session"},
		{name: "same ID replacement", replacement: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			teek, cm, session, _, _, controlMessages := newAcknowledgedSessionGap(t)
			cm.mu.RLock()
			origin := cm.acknowledgedSessions[session.ID]
			cm.mu.RUnlock()
			if origin == nil {
				t.Fatal("missing acknowledged owner before delayed dial")
			}
			candidate := newAckTestWebSocket(t)
			var replacement *shared.Session
			cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
				teek.cleanupSessionWithSession(session)
				if test.replacement {
					if err := teek.sessionManager.RegisterSession(session.ID); err != nil {
						t.Fatal(err)
					}
					var err error
					replacement, err = teek.sessionManager.GetSession(session.ID)
					if err != nil {
						t.Fatal(err)
					}
					if err := teek.sessionManager.ActivateSessionIfCurrent(replacement, newAckTestWebSocket(t)); err != nil {
						t.Fatal(err)
					}
					teek.sessionManager.SetTEEKSessionState(session.ID, &TEEKSessionState{session: replacement})
					teek.activeSessions.Store(1)
				}
				return candidate, nil
			}

			err := cm.EstablishSessionConnection(session.ID, origin)
			if err == nil {
				t.Fatal("delayed dial published after acknowledged owner cleanup")
			}
			if err := candidate.WriteMessage(websocket.BinaryMessage, []byte("closed candidate")); err == nil {
				t.Fatal("rejected delayed-dial candidate was not closed")
			}
			cm.mu.RLock()
			published := cm.sessionConns[session.ID]
			retainedOwner := cm.acknowledgedSessions[session.ID]
			cm.mu.RUnlock()
			if published != nil || retainedOwner != nil {
				t.Fatalf("cleanup left publication state: connection=%p owner=%p", published, retainedOwner)
			}
			assertSessionClosedMessage(t, controlMessages, session.ID, "session_cleanup")

			if test.replacement {
				current, getErr := teek.sessionManager.GetSession(session.ID)
				if getErr != nil || current != replacement || replacement.CleanedUp.Load() {
					t.Fatalf("delayed old dial changed replacement: current=%p err=%v cleaned=%v", current, getErr, replacement.CleanedUp.Load())
				}
			} else if _, getErr := teek.sessionManager.GetSession(session.ID); getErr == nil {
				t.Fatal("cleaned session remained current after delayed dial rejection")
			}
		})
	}
}

func TestDelayedSessionDialRejectsRemovedOwnerWhileSessionIsStillCurrent(t *testing.T) {
	teek, cm, session, _, _, controlMessages := newAcknowledgedSessionGap(t)
	cm.mu.RLock()
	origin := cm.acknowledgedSessions[session.ID]
	cm.mu.RUnlock()
	if origin == nil {
		t.Fatal("missing acknowledged owner before delayed dial")
	}
	candidate := newAckTestWebSocket(t)
	cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
		// Reproduce the cleanup interval after its CAS and exact-owner removal
		// but before CloseSessionIfCurrent removes the shared session entry.
		session.CleanedUp.Store(true)
		if !cm.releaseAcknowledgedSessionOwner(session.ID, origin) {
			t.Fatal("cleanup interval did not remove exact acknowledged owner")
		}
		return candidate, nil
	}

	err := cm.EstablishSessionConnection(session.ID, origin)
	if err == nil {
		t.Fatal("delayed dial published without its acknowledged owner")
	}
	current, getErr := teek.sessionManager.GetSession(session.ID)
	if getErr != nil || current != session {
		t.Fatalf("test did not retain exact shared session: current=%p err=%v", current, getErr)
	}
	if err := candidate.WriteMessage(websocket.BinaryMessage, []byte("closed candidate")); err == nil {
		t.Fatal("rejected delayed-dial candidate was not closed")
	}
	cm.mu.RLock()
	published := cm.sessionConns[session.ID]
	retainedOwner := cm.acknowledgedSessions[session.ID]
	cm.mu.RUnlock()
	if published != nil || retainedOwner != nil {
		t.Fatalf("cleanup interval left publication state: connection=%p owner=%p", published, retainedOwner)
	}
	assertNoControlMessage(t, controlMessages, "cleanup interval origin")
}

func newAcknowledgedSessionGap(t *testing.T) (*TEEK, *TEETConnectionManager, *shared.Session, *shared.WSConnection, uint64, <-chan []byte) {
	t.Helper()
	logger := shared.NewNopLogger()
	manager := NewTEEKSessionManager()
	manager.SetLogger(logger)
	client := newAckTestWebSocket(t)
	sessionID, err := manager.CreateSession(client)
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
	origin, messages := newAckTestWebSocketWithMessages(t)
	_, generation := installAckTestControl(cm, origin)
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	token, err := cm.sendSessionCreatedAndWaitTokenForSession(sessionID, session, time.Second, func(conn *shared.WSConnection, generation uint64) error {
		ack, marshalErr := proto.Marshal(&teeproto.Envelope{
			SessionId: sessionID,
			Payload: &teeproto.Envelope_SessionCreatedAck{
				SessionCreatedAck: &teeproto.SessionCreatedAck{SessionId: sessionID},
			},
		})
		if marshalErr != nil {
			return marshalErr
		}
		cm.handleControlMessage(conn, generation, ack)
		return nil
	})
	if err != nil {
		t.Fatalf("acknowledge session: %v", err)
	}
	if token.session != session || token.conn != origin || token.generation != generation {
		t.Fatal("acknowledged owner token did not retain exact session/control identity")
	}
	cm.mu.RLock()
	retained := cm.acknowledgedSessions[sessionID]
	cm.mu.RUnlock()
	if retained != token {
		t.Fatal("acknowledged owner token was not retained through publication gap")
	}
	return teek, cm, session, origin, generation, messages
}

func TestSessionSetupFailureReleasesUndialedOwnerOnExactControl(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testing.T, *TEETConnectionManager, string)
	}{
		{
			name: "capacity precheck",
			configure: func(t *testing.T, cm *TEETConnectionManager, _ string) {
				cm.mu.Lock()
				for i := range MaxConcurrentSessions {
					cm.sessionConns[fmt.Sprintf("occupied-%d", i)] = &SessionTEETConnection{}
				}
				cm.mu.Unlock()
				cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
					t.Fatal("capacity failure attempted a session dial")
					return nil, nil
				}
			},
		},
		{
			name: "dial failure",
			configure: func(_ *testing.T, cm *TEETConnectionManager, _ string) {
				cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
					return nil, errors.New("dial failed")
				}
			},
		},
		{
			name: "publication failure",
			configure: func(t *testing.T, cm *TEETConnectionManager, _ string) {
				candidate := newAckTestWebSocket(t)
				cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
					cm.mu.Lock()
					for i := range MaxConcurrentSessions {
						cm.sessionConns[fmt.Sprintf("published-race-%d", i)] = &SessionTEETConnection{}
					}
					cm.mu.Unlock()
					return candidate, nil
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const sessionID = "acked-owner-without-session-connection"
			cm, token, originMessages := newAckedSessionSetup(t, sessionID)
			test.configure(t, cm, sessionID)

			if err := cm.EstablishSessionConnection(sessionID, token); err == nil {
				t.Fatal("session setup unexpectedly succeeded")
			}
			assertSessionClosedMessage(t, originMessages, sessionID, "session_connection_setup_failed")
			cm.mu.RLock()
			_, published := cm.sessionConns[sessionID]
			cm.mu.RUnlock()
			if published {
				t.Fatal("failed setup published a per-session connection")
			}
		})
	}
}

func TestSessionSetupCleanupNeverMigratesToReplacementControl(t *testing.T) {
	const sessionID = "acked-owner-superseded-before-dial"
	cm, token, originMessages := newAckedSessionSetup(t, sessionID)
	replacement, replacementMessages := newAckTestWebSocketWithMessages(t)
	installAckTestControl(cm, replacement)
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	dialAttempted := false
	cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
		dialAttempted = true
		return nil, errors.New("must not dial")
	}

	err := cm.EstablishSessionConnection(sessionID, token)
	if err == nil || !strings.Contains(err.Error(), "acknowledged control connection changed") {
		t.Fatalf("establishment error = %v, want exact-control precheck failure", err)
	}
	if dialAttempted {
		t.Fatal("superseded acknowledged control attempted a dial")
	}
	assertNoControlMessage(t, originMessages, "superseded origin")
	assertNoControlMessage(t, replacementMessages, "replacement control")
}

func TestSessionTEETConnectionClosedAccessIsSynchronized(t *testing.T) {
	conn := &SessionTEETConnection{}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = conn.isClosed()
			}
		}()
	}
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	wg.Wait()
	if !conn.isClosed() {
		t.Fatal("closed state was not published")
	}
}

func TestSessionDialAckFromSupersededControlCannotPublish(t *testing.T) {
	logger := shared.NewNopLogger()
	sessionManager := NewTEEKSessionManager()
	sessionManager.SetLogger(logger)
	teek := &TEEK{sessionManager: sessionManager, logger: logger}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	const sessionID = "session-dial-ack-superseded"
	if err := sessionManager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register session: %v", err)
	}
	origin, originGeneration := installAckTestControl(cm, newAckTestWebSocket(t))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()

	candidate := newAckTestWebSocket(t)
	dialAckComplete := make(chan struct{})
	releaseDial := make(chan struct{})
	cm.dialSessionConnectionFn = func(gotSessionID string) (*shared.WSConnection, error) {
		if gotSessionID != sessionID {
			t.Errorf("dial session ID = %q, want %q", gotSessionID, sessionID)
		}
		close(dialAckComplete)
		<-releaseDial
		return candidate, nil
	}
	result := make(chan error, 1)
	go func() {
		result <- cm.EstablishSessionConnection(sessionID, &controlConnectionToken{
			conn: origin, generation: originGeneration,
		})
	}()
	select {
	case <-dialAckComplete:
	case <-time.After(time.Second):
		t.Fatal("session establishment did not reach paused post-ACK point")
	}

	cm.tearDownControl(origin, originGeneration)
	replacement, replacementGeneration := installAckTestControl(cm, newAckTestWebSocket(t))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	close(releaseDial)

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "control connection changed") {
			t.Fatalf("establishment error = %v, want superseded control failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("superseded session establishment did not return")
	}
	cm.mu.RLock()
	gotControl := cm.controlConn
	gotGeneration := cm.controlGeneration
	_, inserted := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if gotControl != replacement || gotGeneration != replacementGeneration {
		t.Fatal("stale session establishment changed replacement control")
	}
	if inserted {
		t.Fatal("stale session socket was inserted")
	}
	if err := candidate.WriteMessage(websocket.BinaryMessage, []byte("must-be-closed")); err == nil {
		t.Fatal("stale session candidate remained open after publication failure")
	}
}

func TestDuplicateSessionDialClosesOnlyCandidate(t *testing.T) {
	logger := shared.NewNopLogger()
	sessionManager := NewTEEKSessionManager()
	sessionManager.SetLogger(logger)
	teek := &TEEK{sessionManager: sessionManager, logger: logger}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	const sessionID = "duplicate-session-dial"
	if err := sessionManager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register session: %v", err)
	}
	session, err := sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	controlSocket, controlMessages := newAckTestWebSocketWithMessages(t)
	control, generation := installAckTestControl(cm, controlSocket)
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	acceptedSocket := newAckTestWebSocket(t)
	accepted := &SessionTEETConnection{
		sessionID: sessionID, session: session, controlConn: control, controlGeneration: generation,
		conn: acceptedSocket, established: time.Now(),
	}
	if err := cm.publishSessionConnection(accepted); err != nil {
		t.Fatalf("publish accepted connection: %v", err)
	}
	candidate := newAckTestWebSocket(t)
	cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) { return candidate, nil }
	if err := cm.EstablishSessionConnection(sessionID, &controlConnectionToken{
		conn: control, generation: generation,
	}); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Fatalf("duplicate establishment error = %v, want duplicate rejection", err)
	}
	cm.mu.RLock()
	current := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if current != accepted {
		t.Fatal("duplicate establishment replaced the accepted connection")
	}
	if err := candidate.WriteMessage(websocket.BinaryMessage, []byte("must-be-closed")); err == nil {
		t.Fatal("duplicate candidate remained open after rejection")
	}
	if err := acceptedSocket.WriteMessage(websocket.BinaryMessage, []byte("still-current")); err != nil {
		t.Fatalf("duplicate rejection closed accepted connection: %v", err)
	}
	assertNoControlMessage(t, controlMessages, "accepted session control")
}

func TestBufferedTEETFrameCannotTerminateSameIDReplacement(t *testing.T) {
	logger := shared.NewNopLogger()
	sessionManager := NewTEEKSessionManager()
	sessionManager.SetLogger(logger)
	teek := &TEEK{sessionManager: sessionManager, logger: logger}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	const sessionID = "buffered-teet-frame-replacement"
	if err := sessionManager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register old session: %v", err)
	}
	oldSession, err := sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get old session: %v", err)
	}
	oldControl, oldGeneration := installAckTestControl(cm, newAckTestWebSocket(t))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	oldSessionConn := &SessionTEETConnection{
		sessionID: sessionID, session: oldSession, controlConn: oldControl, controlGeneration: oldGeneration,
		conn: newAckTestWebSocket(t), established: time.Now(),
	}
	if err := cm.publishSessionConnection(oldSessionConn); err != nil {
		t.Fatalf("publish old session connection: %v", err)
	}
	paused := make(chan struct{})
	resume := make(chan struct{})
	identity := &teekSessionIdentity{
		session: oldSession, sessionConn: oldSessionConn,
		validate: func() error { return cm.validateSessionConnection(oldSessionConn) },
		beforeDispatch: func() {
			close(paused)
			<-resume
		},
	}
	frame, err := proto.Marshal(&teeproto.Envelope{
		SessionId: sessionID,
		Payload: &teeproto.Envelope_BatchedTagVerifications{
			BatchedTagVerifications: &teeproto.BatchedTagVerifications{SessionId: sessionID, AllSuccessful: false},
		},
	})
	if err != nil {
		t.Fatalf("marshal buffered frame: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- teek.handleSharedTEETMessage(identity, frame) }()
	select {
	case <-paused:
	case <-time.After(time.Second):
		t.Fatal("buffered frame did not pause before dispatch")
	}

	cm.tearDownControl(oldControl, oldGeneration)
	if _, err := sessionManager.GetSession(sessionID); err == nil {
		t.Fatal("control teardown retained the old shared session")
	}
	if err := sessionManager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register replacement session: %v", err)
	}
	replacementSession, err := sessionManager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get replacement session: %v", err)
	}
	replacementControl, replacementGeneration := installAckTestControl(cm, newAckTestWebSocket(t))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	replacementConn := &SessionTEETConnection{
		sessionID: sessionID, session: replacementSession, controlConn: replacementControl, controlGeneration: replacementGeneration,
		conn: newAckTestWebSocket(t), established: time.Now(),
	}
	if err := cm.publishSessionConnection(replacementConn); err != nil {
		t.Fatalf("publish replacement session connection: %v", err)
	}
	close(resume)

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("buffered old frame dispatched after same-ID replacement")
		}
	case <-time.After(time.Second):
		t.Fatal("buffered old frame did not return after replacement")
	}
	currentSession, err := sessionManager.GetSession(sessionID)
	if err != nil || currentSession != replacementSession || replacementSession.CleanedUp.Load() {
		t.Fatalf("replacement session was terminated by buffered frame: current=%p err=%v cleaned=%v", currentSession, err, replacementSession.CleanedUp.Load())
	}
	cm.mu.RLock()
	currentConn := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if currentConn != replacementConn {
		t.Fatal("buffered old frame changed the replacement session connection")
	}
}

func installAckTestControl(cm *TEETConnectionManager, conn *shared.WSConnection) (*shared.WSConnection, uint64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.controlGeneration++
	cm.controlConn = conn
	return conn, cm.controlGeneration
}

func newAckTestWebSocket(t *testing.T) *shared.WSConnection {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	handshake := make(chan error, 1)
	go serveAckTestWebSocket(peerNet, handshake)
	conn, _, err := websocket.NewClient(clientNet, &url.URL{Scheme: "ws", Host: "in-memory", Path: "/"}, nil, 1024, 1024)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		t.Fatalf("dial test websocket: %v", err)
	}
	if err := <-handshake; err != nil {
		_ = conn.Close()
		_ = peerNet.Close()
		t.Fatalf("serve test websocket handshake: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peerNet.Close()
	})
	return shared.NewWSConnection(conn)
}

func newAckTestWebSocketWithMessages(t *testing.T) (*shared.WSConnection, <-chan []byte) {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	handshake := make(chan error, 1)
	messages := make(chan []byte, 8)
	go serveAckTestCapturingWebSocket(peerNet, handshake, messages)
	conn, _, err := websocket.NewClient(clientNet, &url.URL{Scheme: "ws", Host: "in-memory", Path: "/"}, nil, 1024, 1024)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		t.Fatalf("dial capturing test websocket: %v", err)
	}
	if err := <-handshake; err != nil {
		_ = conn.Close()
		_ = peerNet.Close()
		t.Fatalf("serve capturing test websocket handshake: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peerNet.Close()
	})
	return shared.NewWSConnection(conn), messages
}

func newAckedSessionSetup(t *testing.T, sessionID string) (*TEETConnectionManager, *controlConnectionToken, <-chan []byte) {
	t.Helper()
	logger := shared.NewNopLogger()
	sessionManager := NewTEEKSessionManager()
	sessionManager.SetLogger(logger)
	teek := &TEEK{sessionManager: sessionManager, logger: logger}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	if err := sessionManager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register session: %v", err)
	}
	origin, messages := newAckTestWebSocketWithMessages(t)
	_, generation := installAckTestControl(cm, origin)
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	token, err := cm.sendSessionCreatedAndWaitToken(sessionID, time.Second, func(gotConn *shared.WSConnection, gotGeneration uint64) error {
		ack, marshalErr := proto.Marshal(&teeproto.Envelope{
			SessionId: sessionID,
			Payload: &teeproto.Envelope_SessionCreatedAck{
				SessionCreatedAck: &teeproto.SessionCreatedAck{SessionId: sessionID},
			},
		})
		if marshalErr != nil {
			return marshalErr
		}
		cm.handleControlMessage(gotConn, gotGeneration, ack)
		return nil
	})
	if err != nil {
		t.Fatalf("get acknowledged control token: %v", err)
	}
	if token.conn != origin || token.generation != generation {
		t.Fatal("acknowledged control token does not match the origin")
	}
	return cm, token, messages
}

func serveAckTestWebSocket(peer net.Conn, handshake chan<- error) {
	reader := bufio.NewReader(peer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		handshake <- err
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, err = fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	handshake <- err
	if err == nil {
		_, _ = io.Copy(io.Discard, reader)
	}
}

func serveAckTestCapturingWebSocket(peer net.Conn, handshake chan<- error, messages chan<- []byte) {
	reader := bufio.NewReader(peer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		handshake <- err
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, err = fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	handshake <- err
	if err != nil {
		return
	}
	for {
		opcode, payload, readErr := readAckTestWebSocketFrame(reader)
		if readErr != nil {
			return
		}
		if opcode == websocket.CloseMessage {
			return
		}
		if opcode == websocket.BinaryMessage {
			messages <- payload
		}
	}
}

func readAckTestWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	payloadLength := uint64(header[1] & 0x7f)
	switch payloadLength {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		payloadLength = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		payloadLength = binary.BigEndian.Uint64(extended[:])
	}
	if payloadLength > MaxWebSocketMessageSize {
		return 0, nil, fmt.Errorf("test websocket frame is too large: %d", payloadLength)
	}
	var mask [4]byte
	masked := header[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(payloadLength))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%len(mask)]
		}
	}
	return header[0] & 0x0f, payload, nil
}

func assertSessionClosedMessage(t *testing.T, messages <-chan []byte, sessionID, reason string) {
	t.Helper()
	select {
	case data := <-messages:
		var env teeproto.Envelope
		if err := proto.Unmarshal(data, &env); err != nil {
			t.Fatalf("unmarshal SessionClosed: %v", err)
		}
		closed, ok := env.Payload.(*teeproto.Envelope_SessionClosed)
		if !ok {
			t.Fatalf("control payload = %T, want SessionClosed", env.Payload)
		}
		if env.GetSessionId() != sessionID || closed.SessionClosed.GetSessionId() != sessionID || closed.SessionClosed.GetReason() != reason {
			t.Fatalf("SessionClosed = %+v envelope_session=%q, want session=%q reason=%q", closed.SessionClosed, env.GetSessionId(), sessionID, reason)
		}
	case <-time.After(time.Second):
		t.Fatal("exact acknowledged control did not receive SessionClosed")
	}
}

func assertNoControlMessage(t *testing.T, messages <-chan []byte, name string) {
	t.Helper()
	select {
	case data := <-messages:
		t.Fatalf("%s received unexpected control message: %x", name, data)
	case <-time.After(25 * time.Millisecond):
	}
}

func assertNoPendingSessionAck(t *testing.T, cm *TEETConnectionManager, sessionID string) {
	t.Helper()
	cm.pendingAcksMu.Lock()
	defer cm.pendingAcksMu.Unlock()
	if _, exists := cm.pendingAcks[sessionID]; exists {
		t.Fatalf("ack waiter for %q was not cleaned up", sessionID)
	}
}
