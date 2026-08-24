package main

import (
	"fmt"
	"sync"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// MaxConcurrentSessions is the maximum number of concurrent session connections
const MaxConcurrentSessions = 100

// SessionReadTimeout bounds idle time on a session connection (client-facing and
// inter-TEE). Below the client's 60s protocol timeout so the TEE times out FIRST
// with a clean error instead of blocking until the client tears down (bad record MAC).
const SessionReadTimeout = 50 * time.Second

// OTReadyWatchdogTimeout bounds how long the control connection may stay up
// without TEE_K sending OtPrecomputeComplete. If the receiver pool isn't ready
// within this window, the watchdog tears the connection down so TEE_K is
// forced through a fresh attestation + IsInitial precompute on reconnect.
//
// Sized above TEE_K's own performOTPrecomputation timeout (60s) so that, on a
// slow but otherwise healthy OT exchange, TEE_K's local timeout fires first
// and self-recovers; the watchdog only kicks in for true wedges where TEE_K
// believes everything is fine.
const OTReadyWatchdogTimeout = 90 * time.Second

// TEEKConnectionManager manages all connections from TEE_K
// - One persistent control connection for attestation, OT precomputation, and session lifecycle
// - One per-session connection for each active session's data flow
type TEEKConnectionManager struct {
	mu             sync.RWMutex
	controlStateMu sync.RWMutex

	// Control connection (persistent)
	controlConn       *shared.WSConnection
	controlGeneration uint64

	// Per-session connections (limited to MaxConcurrentSessions)
	sessionConns  map[string]*SessionTEEKConnection // sessionID -> connection
	sessionOwners map[string]controlSessionOwner    // sessionID -> acknowledged session identity

	// References
	teet   *TEET
	logger *shared.Logger

	// Attestation state (for control connection)
	attestationVerified bool
	attestationMutex    sync.RWMutex
}

// SessionTEEKConnection represents a per-session connection from TEE_K
type SessionTEEKConnection struct {
	sessionID         string
	controlGeneration uint64
	session           *shared.Session
	conn              *shared.WSConnection
	established       time.Time
	mu                sync.Mutex // Protects writes to this connection
	closed            bool
}

type controlSessionOwner struct {
	controlGeneration uint64
	session           *shared.Session
}

func (c *SessionTEEKConnection) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// NewTEEKConnectionManager creates a new connection manager
func NewTEEKConnectionManager(teet *TEET, logger *shared.Logger) *TEEKConnectionManager {
	return &TEEKConnectionManager{
		sessionConns:  make(map[string]*SessionTEEKConnection),
		sessionOwners: make(map[string]controlSessionOwner),
		teet:          teet,
		logger:        logger,
	}
}

// readPairAssignment consumes the first envelope on a router-mode control
// connection and expects it to be TEEKPairAssignment. The decoded pair_id is
// connection-local handshake input until this exact connection completes
// mutual attestation and wins control-generation publication.
func (cm *TEEKConnectionManager) readPairAssignment(conn *websocket.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", fmt.Errorf("read first envelope: %w", err)
	}
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		return "", fmt.Errorf("parse first envelope: %w", err)
	}
	pa, ok := env.Payload.(*teeproto.Envelope_TeekPairAssignment)
	if !ok {
		return "", fmt.Errorf("expected TEEKPairAssignment first, got %T", env.Payload)
	}
	pairID := pa.TeekPairAssignment.GetPairId()
	if pairID == "" {
		return "", fmt.Errorf("TEEKPairAssignment carried empty pair_id")
	}
	return pairID, nil
}

// HandleControlConnection handles a new control connection from TEE_K
// This performs attestation and then handles control messages
func (cm *TEEKConnectionManager) HandleControlConnection(conn *websocket.Conn) error {
	cm.logger.Debug("Handling control connection from TEE_K")

	// Set read limit
	conn.SetReadLimit(MaxWebSocketMessageSize)

	// Router mode: the very first envelope on the wire is TEEKPairAssignment,
	// announcing the pair_id TEE_K generated. Keep it local to this handshake
	// until attestation succeeds, the response is sent, and this exact control
	// generation is still current. Detection uses `router != nil` (not ratls) so
	// local-dev router mode — which has no RA-TLS — still exchanges pair_id.
	// Standalone mode (no router) skips this and reads TEEKAttestation as
	// the first envelope.
	var pairID string
	if cm.teet.router != nil {
		var err error
		pairID, err = cm.readPairAssignment(conn)
		if err != nil {
			return fmt.Errorf("pair assignment: %w", err)
		}
	}

	// Wait for attestation request (first message)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		return fmt.Errorf("failed to receive attestation: %v", err)
	}

	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		return fmt.Errorf("failed to parse attestation message: %v", err)
	}

	attestationRequest, err := teekAttestationRequestFromEnvelope(&env)
	if err != nil {
		return err
	}

	// Pull TEE_K's client cert off the underlying TLS connection so the
	// attestation can be cert-hash-bound. Nil in standalone mode (no TLS),
	// which verifyTEEKAttestation handles separately.
	var peerCert []byte
	if cm.teet.ratls != nil {
		peerCert, err = shared.ExtractTLSCertFromWebSocket(conn)
		if err != nil {
			return fmt.Errorf("extract TEE_K peer cert: %v", err)
		}
	}

	// Verify TEE_K attestation
	if err := cm.teet.verifyTEEKAttestation(attestationRequest, peerCert); err != nil {
		return fmt.Errorf("attestation verification failed: %v", err)
	}

	cm.logger.Info("TEE_K attestation verified on control connection")

	// Generate and send our attestation
	attestation, err := cm.teet.generateAttestationForTEEK()
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	respEnv := &teeproto.Envelope{
		SessionId:   "control",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeetAttestation{
			TeetAttestation: &teeproto.TEETAttestationResponse{
				AttestationReport: attestation,
			},
		},
	}

	data, err := proto.Marshal(respEnv)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation response: %v", err)
	}

	// Install the new generation before publishing the successful attestation.
	// Activation invalidates old-generation state immediately; handlers perform
	// crypto and writes without the state lease and must revalidate before commit.
	wsConn := shared.NewWSConnection(conn)
	controlGeneration, previousControl, previousSessions, previousSessionOwners := cm.activateControlConnection(wsConn)
	cm.closeSupersededConnections(previousControl, previousSessions, previousSessionOwners)

	if err := cm.completeControlAttestationForPair(wsConn, controlGeneration, pairID, func() error {
		return shared.WriteWSBinary(conn, data)
	}); err != nil {
		return fmt.Errorf("failed to send attestation response: %v", err)
	}

	cm.logger.Info("Mutual attestation completed on control connection")

	// Bidirectional ping/pong heartbeat. Sets the read deadline that
	// handleControlMessages relies on, so a dead peer is detected even when no
	// application messages are flowing.
	wsConn.StartControlHeartbeat(cm.logger)

	// OT-ready watchdog: heartbeats prove the connection is alive, but they
	// don't tell us whether TEE_K's OT precomputation flow completed. If
	// OtPrecomputeComplete never arrives, every client connection is rejected
	// with "OT receiver pool not ready" while the control conn looks healthy.
	// The watchdog forces a reconnect (and thus a fresh IsInitial precompute)
	// when the wedge persists, and logs ERROR so paging fires.
	//
	// defer close so the goroutine still stops if handleControlMessages panics.
	watchdogStop := make(chan struct{})
	defer close(watchdogStop)
	go cm.runOTReadyWatchdog(wsConn, watchdogStop)

	// Handle control messages in a loop
	cm.handleControlMessages(wsConn, controlGeneration)

	// Cleanup on disconnect. A superseded handler may return after its
	// replacement is already serving; only this exact generation owns teardown.
	cm.tearDownControlConnection(wsConn, controlGeneration)

	return nil
}

func teekAttestationRequestFromEnvelope(env *teeproto.Envelope) (*teeproto.TEEKAttestationRequest, error) {
	if env == nil {
		return nil, fmt.Errorf("malformed TEE_K attestation request: missing envelope")
	}
	req, ok := env.Payload.(*teeproto.Envelope_TeekAttestation)
	if !ok {
		if peerErr, isError := env.Payload.(*teeproto.Envelope_Error); isError {
			if peerErr == nil || peerErr.Error == nil {
				return nil, fmt.Errorf("malformed TEE_K attestation error: missing error data")
			}
			return nil, fmt.Errorf("TEE_K rejected attestation: %s", peerErr.Error.GetMessage())
		}
		return nil, fmt.Errorf("expected attestation as first message, got %T", env.Payload)
	}
	if req == nil || req.TeekAttestation == nil {
		return nil, fmt.Errorf("malformed TEE_K attestation request: missing request")
	}
	if req.TeekAttestation.AttestationReport == nil {
		return nil, fmt.Errorf("malformed TEE_K attestation request: missing report")
	}
	return req.TeekAttestation, nil
}

func (cm *TEEKConnectionManager) activateControlConnection(conn *shared.WSConnection) (uint64, *shared.WSConnection, []*SessionTEEKConnection, []*shared.Session) {
	cm.controlStateMu.Lock()
	defer cm.controlStateMu.Unlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()
	previousControl := cm.controlConn
	previousGeneration := cm.controlGeneration
	var supersededControl *shared.WSConnection
	var previousSessions []*SessionTEEKConnection
	var previousSessionOwners []*shared.Session
	if previousControl != nil && previousControl != conn {
		supersededControl = previousControl
		for sessionID, owner := range cm.sessionOwners {
			if owner.controlGeneration == previousGeneration {
				if cm.teet.sessionManager.isCurrentControlSession(owner.session, previousGeneration) {
					previousSessionOwners = append(previousSessionOwners, owner.session)
				}
				delete(cm.sessionOwners, sessionID)
			}
		}
		for sessionID, sessionConn := range cm.sessionConns {
			if sessionConn.controlGeneration == previousGeneration {
				previousSessions = append(previousSessions, sessionConn)
				delete(cm.sessionConns, sessionID)
			}
		}

		// A ready committed prefix remains resumable, but no pending extension
		// from the superseded generation may survive into the replacement.
		cm.teet.suspendOTReceiverPoolForReconnect()
	}

	cm.controlGeneration++
	generation := cm.controlGeneration
	cm.controlConn = conn
	cm.attestationMutex.Lock()
	cm.attestationVerified = false
	cm.attestationMutex.Unlock()
	cm.teet.setTEEKConnected(false)
	cm.teet.controlHealthy.Store(false)
	cm.teet.otReady.Store(false)
	return generation, supersededControl, previousSessions, previousSessionOwners
}

func (cm *TEEKConnectionManager) completeControlAttestation(conn *shared.WSConnection, generation uint64, writeResponse func() error) error {
	return cm.completeControlAttestationForPair(conn, generation, "", writeResponse)
}

// completeControlAttestationForPair publishes readiness and the router pair
// identity only after the attestation response is successfully written and
// only while this exact connection still owns the current control generation.
// Holding controlStateMu through the callback prevents a replacement handshake
// from publishing a newer identity before an older callback runs.
func (cm *TEEKConnectionManager) completeControlAttestationForPair(conn *shared.WSConnection, generation uint64, pairID string, writeResponse func() error) error {
	if err := writeResponse(); err != nil {
		cm.tearDownControlConnection(conn, generation)
		return err
	}
	cm.controlStateMu.RLock()
	defer cm.controlStateMu.RUnlock()
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.controlConn != conn || cm.controlGeneration != generation {
		return fmt.Errorf("control connection was superseded during attestation response")
	}
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	cm.teet.setTEEKConnected(true)
	cm.teet.controlHealthy.Store(true)
	if pairID != "" {
		cm.teet.pairID.Store(&pairID)
		cm.logger.Info("Committed pair_id from authenticated TEE_K", zap.String("pair_id", pairID))
		if cm.teet.onPairAssigned != nil {
			cm.teet.onPairAssigned(pairID)
		}
	}
	return nil
}

func (cm *TEEKConnectionManager) closeSupersededConnections(control *shared.WSConnection, sessions []*SessionTEEKConnection, sessionOwners []*shared.Session) {
	if control != nil {
		_ = control.Close()
	}
	if len(sessions) > 0 {
		cm.logger.Info("Purging per-session connections from superseded control generation", zap.Int("count", len(sessions)))
	}
	for _, sessionConn := range sessions {
		sessionConn.mu.Lock()
		if !sessionConn.closed {
			sessionConn.closed = true
			_ = sessionConn.conn.Close()
		}
		sessionConn.mu.Unlock()
	}
	for _, session := range sessionOwners {
		cm.teet.cleanupSessionWithSession(session)
	}
}

func (cm *TEEKConnectionManager) tearDownControlConnection(conn *shared.WSConnection, generation uint64) {
	cm.controlStateMu.Lock()
	cm.mu.Lock()
	if cm.controlConn != conn || cm.controlGeneration != generation {
		cm.mu.Unlock()
		cm.controlStateMu.Unlock()
		return
	}
	cm.controlConn = nil

	cm.attestationMutex.Lock()
	cm.attestationVerified = false
	cm.attestationMutex.Unlock()

	// Snapshot + reset sessionConns under the lock, then close them
	// outside the lock. Orphaned per-session WSes from before the control
	// disconnect would otherwise hold MaxConcurrentSessions slots until
	// their 60s read deadline fires, surfacing as "Max concurrent
	// sessions reached" rejections during recovery.
	orphans := make([]*SessionTEEKConnection, 0, len(cm.sessionConns))
	for sessionID, sessionConn := range cm.sessionConns {
		if sessionConn.controlGeneration == generation {
			orphans = append(orphans, sessionConn)
			delete(cm.sessionConns, sessionID)
		}
	}
	orphanSessionOwners := make([]*shared.Session, 0, len(cm.sessionOwners))
	for sessionID, owner := range cm.sessionOwners {
		if owner.controlGeneration == generation {
			if cm.teet.sessionManager.isCurrentControlSession(owner.session, generation) {
				orphanSessionOwners = append(orphanSessionOwners, owner.session)
			}
			delete(cm.sessionOwners, sessionID)
		}
	}

	cm.teet.setTEEKConnected(false)
	cm.teet.controlHealthy.Store(false)

	// Retain a ready pool so TEE_K can resume it on reconnect; clear it only if
	// it was mid-precompute (nothing to resume). This is an in-memory state
	// transition and completes before a replacement generation can activate.
	cm.teet.suspendOTReceiverPoolForReconnect()
	cm.mu.Unlock()
	cm.controlStateMu.Unlock()

	if len(orphans) > 0 {
		cm.logger.Info("Purging orphaned per-session connections after control disconnect",
			zap.Int("count", len(orphans)))
	}
	for _, c := range orphans {
		c.mu.Lock()
		if !c.closed {
			c.closed = true
			c.conn.Close()
		}
		c.mu.Unlock()
	}
	for _, session := range orphanSessionOwners {
		cm.teet.cleanupSessionWithSession(session)
	}
}

// runOTReadyWatchdog monitors the receiver pool's ready flag while the control
// connection is up. On the first tick where the pool has been not-ready for
// longer than OTReadyWatchdogTimeout, it logs ERROR and closes wsConn — which
// pops handleControlMessages' ReadMessage and runs the disconnect cleanup,
// driving TEE_K through reattest + a fresh IsInitial precompute.
//
// Exits when handleControlMessages returns (stop channel closed) or wsConn
// closes from any other cause.
func (cm *TEEKConnectionManager) runOTReadyWatchdog(wsConn *shared.WSConnection, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var notReadySince time.Time
	fired := false

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if cm.teet.isOTReceiverPoolReady() {
				notReadySince = time.Time{}
				continue
			}
			if notReadySince.IsZero() {
				notReadySince = time.Now()
				continue
			}
			if fired {
				continue
			}
			if time.Since(notReadySince) >= OTReadyWatchdogTimeout {
				cm.logger.Error("OT receiver pool stuck not-ready while control connection is up; closing control conn to force re-precompute",
					zap.Duration("not_ready_for", time.Since(notReadySince)))
				fired = true
				_ = wsConn.Close()
				return
			}
		}
	}
}

// handleControlMessages processes messages on the control connection
func (cm *TEEKConnectionManager) handleControlMessages(conn *shared.WSConnection, generation uint64) {
	cm.logger.Info("Starting control message handler - ready to receive messages")

	messageCount := 0
	for {
		// Read deadline is maintained by StartControlHeartbeat via the
		// Ping/Pong handlers; a missing pong causes ReadMessage to return a
		// timeout error and tear this loop down.
		_, msgBytes, err := conn.ReadMessage()
		messageCount++
		if messageCount == 1 {
			cm.logger.Info("First control message received", zap.Int("bytes", len(msgBytes)))
		}
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.Debug("Control connection closed")
			} else {
				cm.logger.Error("Control connection error", zap.Error(err))
			}
			return
		}
		if !cm.isCurrentControlConnection(conn, generation) {
			return
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			// Parse failure indicates protocol corruption - terminate connection
			cm.logger.Error("Failed to parse control message - closing connection", zap.Error(err))
			return
		}

		sessionID := env.GetSessionId()

		// Route control messages
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_SessionCreated:
			// Session lifecycle notification - create session
			cm.logger.Info("New session from TEE_K (control)", zap.String("sid", shared.TruncateSessionID(sessionID)))
			if err := cm.registerSessionOwner(conn, generation, sessionID); err != nil {
				cm.logger.WithSession(sessionID).Error("Failed to create session", zap.Error(err))
			} else {
				// Send acknowledgment so TEE_K knows it can establish per-session connection
				ackEnv := &teeproto.Envelope{
					SessionId:   sessionID,
					TimestampMs: time.Now().UnixMilli(),
					Payload: &teeproto.Envelope_SessionCreatedAck{
						SessionCreatedAck: &teeproto.SessionCreatedAck{
							SessionId: sessionID,
						},
					},
				}
				if err := cm.sendOnControlConnection(conn, generation, ackEnv); err != nil {
					cm.logger.WithSession(sessionID).Error("Failed to send SessionCreatedAck", zap.Error(err))
				}
			}

		case *teeproto.Envelope_SessionClosed:
			// Session lifecycle notification - cleanup session
			cm.logger.Info("Session closed from TEE_K (control)",
				zap.String("sid", shared.TruncateSessionID(sessionID)),
				zap.String("reason", p.SessionClosed.GetReason()))
			cm.closeOwnedSession(conn, generation, sessionID)

		case *teeproto.Envelope_OtPrecomputeRequest:
			// OT precomputation request
			if err := cm.teet.handleOTPrecomputeRequest(conn, generation, func(mutate func() error) error {
				return cm.withCurrentControlState(conn, generation, mutate)
			}, p.OtPrecomputeRequest); err != nil {
				cm.logger.Error("Failed to handle OT precompute request", zap.Error(err))
				return
			}

		case *teeproto.Envelope_OtPrecomputeComplete:
			// OT precomputation complete acknowledgment
			if err := cm.teet.handleOTPrecomputeComplete(generation, func(mutate func() error) error {
				return cm.withCurrentControlState(conn, generation, mutate)
			}, p.OtPrecomputeComplete); err != nil {
				cm.logger.Error("Failed to handle OT precompute complete", zap.Error(err))
				return
			}

		case *teeproto.Envelope_OtResumeRequest:
			// TEE_K asks to resume the retained pool instead of re-precomputing.
			if err := cm.teet.handleOTResumeRequest(conn, func(mutate func() error) error {
				return cm.withCurrentControlState(conn, generation, mutate)
			}, p.OtResumeRequest); err != nil {
				cm.logger.Error("Failed to handle OT resume request", zap.Error(err))
				return
			}

		case *teeproto.Envelope_Error:
			if sessionID == "" || sessionID == "control" {
				cm.logger.Error("Malformed session error on TEE_K control connection")
				return
			}
			var peerErr *teeproto.ErrorData
			if p != nil {
				peerErr = p.Error
			}
			identity, err := cm.controlSessionIdentity(conn, generation, sessionID)
			if err != nil {
				cm.logger.WithSession(sessionID).Debug("Ignored stale TEE_K control error", zap.Error(err))
				continue
			}
			if err := cm.teet.handlePeerErrorForIdentity(identity, peerErr); err != nil {
				cm.logger.WithSession(sessionID).Debug("Ignored stale TEE_K control error", zap.Error(err))
			} else {
				cm.logger.WithSession(sessionID).Info("Handled TEE_K control error and terminated session")
			}

		default:
			cm.logger.Warn("Unexpected message type on control connection",
				zap.String("type", fmt.Sprintf("%T", p)),
				zap.String("session_id", sessionID))
		}
	}
}

func (cm *TEEKConnectionManager) withCurrentControlState(conn *shared.WSConnection, generation uint64, mutate func() error) error {
	cm.controlStateMu.RLock()
	defer cm.controlStateMu.RUnlock()
	if !cm.isCurrentControlConnection(conn, generation) {
		return fmt.Errorf("control generation %d was superseded", generation)
	}
	return mutate()
}

func (cm *TEEKConnectionManager) registerSessionOwner(conn *shared.WSConnection, generation uint64, sessionID string) error {
	return cm.withCurrentControlState(conn, generation, func() error {
		cm.mu.Lock()
		if _, exists := cm.sessionOwners[sessionID]; exists {
			cm.mu.Unlock()
			return fmt.Errorf("session %s already has a control owner", sessionID)
		}
		cm.mu.Unlock()
		session, err := cm.teet.registerSessionForControl(sessionID, generation)
		if err != nil {
			return err
		}
		cm.mu.Lock()
		cm.sessionOwners[sessionID] = controlSessionOwner{controlGeneration: generation, session: session}
		cm.mu.Unlock()
		return nil
	})
}

func (cm *TEEKConnectionManager) closeOwnedSession(conn *shared.WSConnection, generation uint64, sessionID string) {
	var sessionConn *SessionTEEKConnection
	var ownedSession *shared.Session
	err := cm.withCurrentControlState(conn, generation, func() error {
		cm.mu.Lock()
		defer cm.mu.Unlock()
		owner, exists := cm.sessionOwners[sessionID]
		if !exists || owner.controlGeneration != generation || owner.session == nil {
			return fmt.Errorf("session %s is not owned by control generation %d", sessionID, generation)
		}
		ownedSession = owner.session
		delete(cm.sessionOwners, sessionID)
		if current := cm.sessionConns[sessionID]; current != nil && current.controlGeneration == generation && current.session == ownedSession {
			sessionConn = current
			delete(cm.sessionConns, sessionID)
		}
		return nil
	})
	if err != nil {
		cm.logger.WithSession(sessionID).Warn("Ignored stale session cleanup", zap.Error(err))
		return
	}
	if sessionConn != nil {
		sessionConn.mu.Lock()
		if !sessionConn.closed {
			sessionConn.closed = true
			_ = sessionConn.conn.Close()
		}
		sessionConn.mu.Unlock()
	}
	cm.teet.cleanupSessionWithSession(ownedSession)
}

func (cm *TEEKConnectionManager) controlSessionIdentity(conn *shared.WSConnection, generation uint64, sessionID string) (*teetSessionIdentity, error) {
	cm.controlStateMu.RLock()
	cm.mu.RLock()
	owner, exists := cm.sessionOwners[sessionID]
	controlCurrent := cm.controlConn == conn && cm.controlGeneration == generation
	cm.mu.RUnlock()
	cm.controlStateMu.RUnlock()
	if !controlCurrent || !exists || owner.controlGeneration != generation || owner.session == nil {
		return nil, fmt.Errorf("session error owner was superseded")
	}
	session := owner.session
	validate := func() error {
		cm.controlStateMu.RLock()
		defer cm.controlStateMu.RUnlock()
		cm.mu.RLock()
		owner, exists := cm.sessionOwners[sessionID]
		controlCurrent := cm.controlConn == conn && cm.controlGeneration == generation
		cm.mu.RUnlock()
		if !controlCurrent || !exists || owner.controlGeneration != generation || owner.session != session {
			return fmt.Errorf("session error owner was superseded")
		}
		if !cm.teet.sessionManager.isCurrentControlSession(session, generation) {
			return fmt.Errorf("session error identity was superseded")
		}
		return nil
	}
	identity := &teetSessionIdentity{session: session, controlGeneration: generation, validate: validate}
	if err := identity.ensureCurrent(); err != nil {
		return nil, err
	}
	return identity, nil
}

// HandleSessionConnection handles a new per-session connection from TEE_K
func (cm *TEEKConnectionManager) HandleSessionConnection(conn *websocket.Conn, expectedGeneration uint64) error {
	cm.logger.Debug("Handling session connection from TEE_K")

	// Check session limit to prevent resource exhaustion
	cm.mu.RLock()
	sessionCount := len(cm.sessionConns)
	cm.mu.RUnlock()

	if sessionCount >= MaxConcurrentSessions {
		cm.logger.Warn("Max concurrent sessions reached, rejecting connection",
			zap.Int("current", sessionCount),
			zap.Int("max", MaxConcurrentSessions))
		return fmt.Errorf("max concurrent sessions (%d) reached", MaxConcurrentSessions)
	}

	// Set read limit
	conn.SetReadLimit(MaxWebSocketMessageSize)

	// Wait for SessionConnectionInit (first message)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		return fmt.Errorf("failed to receive SessionConnectionInit: %v", err)
	}

	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		return fmt.Errorf("failed to parse SessionConnectionInit: %v", err)
	}

	init, ok := env.Payload.(*teeproto.Envelope_SessionConnectionInit)
	if !ok {
		cm.sendSessionConnectionAck(conn, "", false, fmt.Sprintf("expected SessionConnectionInit, got %T", env.Payload))
		return fmt.Errorf("expected SessionConnectionInit, got %T", env.Payload)
	}

	sessionID := init.SessionConnectionInit.GetSessionId()
	if sessionID == "" {
		cm.sendSessionConnectionAck(conn, "", false, "missing session ID")
		return fmt.Errorf("missing session ID in SessionConnectionInit")
	}

	// Verify session exists (should have been created via control connection)
	_, err = cm.teet.sessionManager.GetSession(sessionID)
	if err != nil {
		cm.sendSessionConnectionAck(conn, sessionID, false, fmt.Sprintf("session not found: %v", err))
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Create wrapper and store connection
	wsConn := shared.NewWSConnection(conn)
	sessionConn := &SessionTEEKConnection{
		sessionID:         sessionID,
		controlGeneration: expectedGeneration,
		conn:              wsConn,
		established:       time.Now(),
	}

	if err := cm.publishSessionConnection(sessionID, sessionConn); err != nil {
		cm.sendSessionConnectionAck(conn, sessionID, false, err.Error())
		return err
	}
	// Defer the cleanup so it runs even if the handler below panics or
	// any future change adds an early return between here and the
	// existing teardown path. Without this, a goroutine death between
	// map-insert and map-delete would leak the slot forever.
	defer func() {
		cm.removeSessionConnection(sessionID, sessionConn)
		sessionConn.mu.Lock()
		if !sessionConn.closed {
			sessionConn.closed = true
			sessionConn.conn.Close()
		}
		sessionConn.mu.Unlock()
	}()

	// Send acknowledgment
	cm.sendSessionConnectionAck(conn, sessionID, true, "")

	cm.logger.WithSession(sessionID).Debug("Per-session connection established")

	// Handle session messages in a loop. Cleanup runs via the defer
	// above when this returns (or panics).
	cm.handleSessionMessages(sessionID, sessionConn)
	return nil
}

func (cm *TEEKConnectionManager) publishSessionConnection(sessionID string, sessionConn *SessionTEEKConnection) error {
	generation := sessionConn.controlGeneration
	cm.controlStateMu.RLock()
	defer cm.controlStateMu.RUnlock()
	cm.mu.Lock()
	owner, ownerExists := cm.sessionOwners[sessionID]
	if cm.controlConn == nil || cm.controlGeneration != generation || !ownerExists || owner.controlGeneration != generation || owner.session == nil {
		cm.mu.Unlock()
		return fmt.Errorf("session %s is not owned by current control generation", sessionID)
	}
	if current := cm.sessionConns[sessionID]; current != nil && current != sessionConn {
		cm.mu.Unlock()
		return fmt.Errorf("session %s already has a TEE_K connection", sessionID)
	}
	cm.attestationMutex.RLock()
	ready := cm.attestationVerified
	cm.attestationMutex.RUnlock()
	if !ready {
		cm.mu.Unlock()
		return fmt.Errorf("control generation %d is not attested", generation)
	}
	// The early HandleSessionConnection check is only advisory. Recheck under
	// the publication lock so concurrent handshakes cannot both consume the
	// final slot and raise the map above MaxConcurrentSessions.
	if len(cm.sessionConns) >= MaxConcurrentSessions {
		cm.mu.Unlock()
		return fmt.Errorf("max concurrent sessions (%d) reached during publication", MaxConcurrentSessions)
	}
	sessionConn.session = owner.session
	cm.sessionConns[sessionID] = sessionConn
	cm.mu.Unlock()

	if !cm.teet.sessionManager.isCurrentControlSession(owner.session, generation) {
		cm.removeSessionConnection(sessionID, sessionConn)
		return fmt.Errorf("session %s changed before connection publication", sessionID)
	}
	owner.session.ConnMutex.Lock()
	owner.session.TEEKConn = sessionConn.conn
	owner.session.ConnMutex.Unlock()
	return nil
}

func (cm *TEEKConnectionManager) removeSessionConnection(sessionID string, expected *SessionTEEKConnection) {
	cm.mu.Lock()
	if cm.sessionConns[sessionID] == expected {
		delete(cm.sessionConns, sessionID)
	}
	cm.mu.Unlock()
}

// handleSessionMessages processes messages on a per-session connection
// ZERO TOLERANCE: Any error terminates the session immediately
func (cm *TEEKConnectionManager) handleSessionMessages(sessionID string, sessionConn *SessionTEEKConnection) {
	cm.logger.WithSession(sessionID).Debug("Starting session message handler")
	identity := &teetSessionIdentity{
		session:           sessionConn.session,
		controlGeneration: sessionConn.controlGeneration,
		sessionConn:       sessionConn,
		validate: func() error {
			return cm.validateSessionConnection(sessionConn)
		},
	}

	for {
		// Set read deadline to prevent stuck connections
		sessionConn.conn.SetReadDeadline(time.Now().Add(SessionReadTimeout))
		_, msgBytes, err := sessionConn.conn.ReadMessage()
		if err != nil {
			locallyClosed := sessionConn.isClosed()
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.WithSession(sessionID).Debug("Session connection closed normally")
			} else if !locallyClosed {
				cm.logger.WithSession(sessionID).Error("Session connection error", zap.Error(err))
			}
			cm.handleSessionReadFailure(identity, err, locallyClosed)
			return
		}
		if err := identity.ensureCurrent(); err != nil {
			return
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			// ZERO TOLERANCE: Parse failure terminates session
			cm.logger.WithSession(sessionID).Error("Failed to parse session message - terminating", zap.Error(err))
			cm.teet.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to parse message from TEE_K")
			return
		}

		// ZERO TOLERANCE: Session ID mismatch terminates session immediately
		if env.GetSessionId() != sessionID {
			err := fmt.Errorf("expected %s, got %s", sessionID, env.GetSessionId())
			cm.logger.WithSession(sessionID).Error("Session ID mismatch - terminating", zap.Error(err))
			cm.teet.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionIDMismatch, err, "Session ID mismatch from TEE_K")
			return
		}

		// Route session-specific messages
		var handlerErr error
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_KeyShareRequest:
			msg := &shared.Message{
				SessionID: sessionID,
				Type:      shared.MsgKeyShareRequest,
				Data: shared.KeyShareRequestData{
					KeyLength: int(p.KeyShareRequest.GetKeyLength()),
					IVLength:  int(p.KeyShareRequest.GetIvLength()),
				},
			}
			handlerErr = cm.teet.handleKeyShareRequestSession(identity, msg)

		case *teeproto.Envelope_BatchedEncryptedRequest:
			var fragments []shared.EncryptedRequestData
			for _, fragment := range p.BatchedEncryptedRequest.GetFragments() {
				var ranges []shared.RequestRedactionRange
				for _, r := range fragment.GetRedactionRanges() {
					ranges = append(ranges, shared.RequestRedactionRange{
						Start:  int(r.GetStart()),
						Length: int(r.GetLength()),
						Type:   r.GetType(),
					})
				}
				fragments = append(fragments, shared.EncryptedRequestData{
					EncryptedData:   fragment.GetEncryptedData(),
					TagSecrets:      fragment.GetTagSecrets(),
					RedactionRanges: ranges,
					SeqNum:          fragment.GetSeqNum(),
				})
			}
			msg := &shared.Message{
				SessionID: sessionID,
				Type:      shared.MsgBatchedEncryptedRequest,
				Data: shared.BatchedEncryptedRequestData{
					Fragments:   fragments,
					BaseSeqNum:  p.BatchedEncryptedRequest.GetBaseSeqNum(),
					CipherSuite: uint16(p.BatchedEncryptedRequest.GetCipherSuite()),
				},
			}
			handlerErr = cm.teet.handleBatchedEncryptedRequest(identity, msg)

		case *teeproto.Envelope_Tls12CbcReadState:
			handlerErr = cm.teet.handleTLS12CBCReadState(identity, p.Tls12CbcReadState)

		case *teeproto.Envelope_ResponseRedactionSpec:
			handlerErr = cm.teet.handleTLS12CBCResponseRedactionSpec(identity, p.ResponseRedactionSpec)

		case *teeproto.Envelope_Finished:
			msg := &shared.Message{
				SessionID: sessionID,
				Type:      shared.MsgFinished,
				Data:      shared.FinishedMessage{},
			}
			handlerErr = cm.teet.handleFinishedFromTEEK(identity, msg)

		case *teeproto.Envelope_BatchedTagSecrets:
			var ts []struct {
				TagSecrets []byte `json:"tag_secrets"`
				SeqNum     uint64 `json:"seq_num"`
			}
			for _, tsec := range p.BatchedTagSecrets.GetTagSecrets() {
				ts = append(ts, struct {
					TagSecrets []byte `json:"tag_secrets"`
					SeqNum     uint64 `json:"seq_num"`
				}{
					TagSecrets: tsec.GetTagSecrets(),
					SeqNum:     tsec.GetSeqNum(),
				})
			}
			msg := &shared.Message{
				SessionID: sessionID,
				Type:      shared.MsgBatchedTagSecrets,
				Data: shared.BatchedTagSecretsData{
					TagSecrets: ts,
					SessionID:  sessionID,
					TotalCount: int(p.BatchedTagSecrets.GetTotalCount()),
				},
			}
			handlerErr = cm.teet.handleBatchedTagSecrets(identity, msg)

		case *teeproto.Envelope_OprfOnlineFull:
			cm.logger.WithSession(sessionID).Info("OPRF timing: round 1 received from TEE_K (session conn)",
				zap.Int("range_index", int(p.OprfOnlineFull.RangeIndex)),
				zap.Int("garbled_tables_bytes", len(p.OprfOnlineFull.GarbledTables)))
			if err := cm.teet.handleOPRFOnlineFull(identity, p.OprfOnlineFull); err != nil {
				cm.teet.terminateSessionWithErrorForIdentity(identity, shared.ReasonOPRFEvaluationFailed, err, "Failed to handle OPRF online")
				return // ZERO TOLERANCE: terminate on OPRF failure
			}

		case *teeproto.Envelope_OprfMpcRound3:
			if err := cm.teet.handleOPRFMasks(identity, p.OprfMpcRound3); err != nil {
				cm.teet.terminateSessionWithErrorForIdentity(identity, shared.ReasonOPRFEvaluationFailed, err, "Failed to handle OPRF masks")
				return
			}

		case *teeproto.Envelope_Error:
			var peerErr *teeproto.ErrorData
			if p != nil {
				peerErr = p.Error
			}
			_ = cm.teet.handlePeerErrorForIdentity(identity, peerErr)
			return

		default:
			// ZERO TOLERANCE: Unknown message type terminates session
			err := fmt.Errorf("unknown message type: %T", p)
			cm.logger.WithSession(sessionID).Error("Unknown message type - terminating session", zap.Error(err))
			cm.teet.terminateSessionWithErrorForIdentity(identity, shared.ReasonUnknownMessageType, err, "Unknown message type from TEE_K")
			return
		}

		// ZERO TOLERANCE: Any handler error terminates session
		if handlerErr != nil {
			cm.teet.terminateSessionWithErrorForIdentity(identity, shared.ReasonHandlerFailed, handlerErr, "Handler failed")
			return
		}
	}
}

func (cm *TEEKConnectionManager) handleSessionReadFailure(identity *teetSessionIdentity, err error, locallyClosed bool) {
	if locallyClosed || identity == nil || identity.ensureCurrent() != nil {
		return
	}
	cm.teet.terminateSessionWithErrorForIdentity(identity, shared.ReasonConnectionLost, err, "TEE_K session connection lost")
}

// sendSessionConnectionAck sends acknowledgment for session connection
func (cm *TEEKConnectionManager) sendSessionConnectionAck(conn *websocket.Conn, sessionID string, success bool, errMsg string) {
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionConnectionAck{
			SessionConnectionAck: &teeproto.SessionConnectionAck{
				SessionId:    sessionID,
				Success:      success,
				ErrorMessage: errMsg,
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		cm.logger.Error("Failed to marshal SessionConnectionAck", zap.Error(err))
		return
	}

	if err := shared.WriteWSBinary(conn, data); err != nil {
		cm.logger.Error("Failed to send SessionConnectionAck", zap.Error(err))
	}
}

// SendOnSession sends a message on a per-session connection
func (cm *TEEKConnectionManager) SendOnSession(sessionID string, env *teeproto.Envelope) error {
	cm.mu.RLock()
	sessionConn := cm.sessionConns[sessionID]
	cm.mu.RUnlock()

	if sessionConn == nil {
		return fmt.Errorf("no session connection for %s", sessionID)
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}

	cm.logger.WithSession(sessionID).Debug("Sending on session connection",
		zap.Int("bytes", len(data)))

	sessionConn.mu.Lock()
	defer sessionConn.mu.Unlock()

	return sessionConn.conn.WriteMessage(websocket.BinaryMessage, data)
}

// GetSessionConnection returns a session connection
func (cm *TEEKConnectionManager) GetSessionConnection(sessionID string) (*SessionTEEKConnection, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	conn, ok := cm.sessionConns[sessionID]
	return conn, ok
}

// IsAttestationVerified returns whether the control connection attestation is verified
func (cm *TEEKConnectionManager) IsAttestationVerified() bool {
	cm.attestationMutex.RLock()
	defer cm.attestationMutex.RUnlock()
	return cm.attestationVerified
}

func (cm *TEEKConnectionManager) readyControlGeneration() (uint64, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.controlConn == nil {
		return 0, false
	}
	cm.attestationMutex.RLock()
	defer cm.attestationMutex.RUnlock()
	return cm.controlGeneration, cm.attestationVerified
}

// IsControlConnected returns whether the control connection is established
func (cm *TEEKConnectionManager) IsControlConnected() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.controlConn != nil
}

// GetSessionConnectionCount returns the current number of session connections
func (cm *TEEKConnectionManager) GetSessionConnectionCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.sessionConns)
}

// LogConnectionStatus logs current connection status (call periodically)
func (cm *TEEKConnectionManager) LogConnectionStatus() {
	cm.mu.RLock()
	sessionCount := len(cm.sessionConns)
	cm.mu.RUnlock()

	cm.attestationMutex.RLock()
	attested := cm.attestationVerified
	cm.attestationMutex.RUnlock()

	controlConnected := cm.IsControlConnected()

	cm.logger.Info("Connection status",
		zap.Bool("control_connected", controlConnected),
		zap.Bool("attested", attested),
		zap.Int("session_connections", sessionCount),
		zap.Int("max_sessions", MaxConcurrentSessions))
}

// SendOnControl sends a message on the control connection
// Used for error notifications when session connection may be dead
func (cm *TEEKConnectionManager) SendOnControl(env *teeproto.Envelope) error {
	cm.mu.RLock()
	conn := cm.controlConn
	generation := cm.controlGeneration
	cm.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("control connection not available")
	}
	return cm.sendOnControlConnection(conn, generation, env)
}

func (cm *TEEKConnectionManager) sendOnControlConnection(conn *shared.WSConnection, generation uint64, env *teeproto.Envelope) error {
	if !cm.isCurrentControlConnection(conn, generation) {
		return fmt.Errorf("control connection changed before send")
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}

	cm.logger.Debug("Sending on control connection",
		zap.String("session_id", env.GetSessionId()),
		zap.Int("bytes", len(data)))

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

func (cm *TEEKConnectionManager) SendOnControlForSession(session *shared.Session, env *teeproto.Envelope) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	cm.mu.RLock()
	owner, exists := cm.sessionOwners[session.ID]
	conn := cm.controlConn
	generation := cm.controlGeneration
	cm.mu.RUnlock()
	if !exists || owner.controlGeneration != generation || owner.session != session || conn == nil {
		return fmt.Errorf("session is not owned by current control connection")
	}
	return cm.sendOnControlConnection(conn, generation, env)
}

func (cm *TEEKConnectionManager) validateSessionConnection(sessionConn *SessionTEEKConnection) error {
	if sessionConn == nil || sessionConn.session == nil {
		return fmt.Errorf("session connection identity is incomplete")
	}
	cm.controlStateMu.RLock()
	defer cm.controlStateMu.RUnlock()
	return cm.validateSessionConnectionUnderControlStateLock(sessionConn)
}

// validateSessionConnectionUnderControlStateLock validates the exact session
// binding while the caller holds controlStateMu for reading.
func (cm *TEEKConnectionManager) validateSessionConnectionUnderControlStateLock(sessionConn *SessionTEEKConnection) error {
	cm.mu.RLock()
	owner, ownerExists := cm.sessionOwners[sessionConn.sessionID]
	currentConn := cm.sessionConns[sessionConn.sessionID]
	controlCurrent := cm.controlConn != nil && cm.controlGeneration == sessionConn.controlGeneration
	cm.mu.RUnlock()
	if !controlCurrent || !ownerExists || owner.controlGeneration != sessionConn.controlGeneration || owner.session != sessionConn.session || currentConn != sessionConn {
		return fmt.Errorf("session connection was superseded")
	}
	if !cm.teet.sessionManager.isCurrentControlSession(sessionConn.session, sessionConn.controlGeneration) {
		return fmt.Errorf("session identity was superseded")
	}
	return nil
}

// withCurrentSessionControlState keeps exact session/generation validation and
// one short state mutation atomic with respect to control replacement. Callers
// must not perform network I/O or expensive cryptography in mutate.
func (cm *TEEKConnectionManager) withCurrentSessionControlState(identity *teetSessionIdentity, mutate func() error) error {
	if identity == nil || identity.session == nil || identity.sessionConn == nil {
		return fmt.Errorf("session control identity is incomplete")
	}
	if identity.sessionConn.session != identity.session || identity.sessionConn.controlGeneration != identity.controlGeneration {
		return fmt.Errorf("session control identity does not match its connection")
	}
	cm.controlStateMu.RLock()
	defer cm.controlStateMu.RUnlock()
	if err := cm.validateSessionConnectionUnderControlStateLock(identity.sessionConn); err != nil {
		return err
	}
	return mutate()
}

func (cm *TEEKConnectionManager) validateSessionOwner(session *shared.Session) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	generation, ok := cm.teet.sessionManager.controlGenerationForSession(session)
	if !ok {
		return fmt.Errorf("session state was superseded")
	}
	cm.mu.RLock()
	owner, ownerExists := cm.sessionOwners[session.ID]
	controlCurrent := cm.controlConn != nil && cm.controlGeneration == generation
	cm.mu.RUnlock()
	if !controlCurrent || !ownerExists || owner.controlGeneration != generation || owner.session != session {
		return fmt.Errorf("session owner was superseded")
	}
	return nil
}

func (cm *TEEKConnectionManager) isCurrentControlConnection(conn *shared.WSConnection, generation uint64) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.controlConn == conn && cm.controlGeneration == generation
}

// CloseSessionConnection closes a per-session connection from TEE_T side
// Called when client disconnects from TEE_T, to prevent TEE_K from timing out
func (cm *TEEKConnectionManager) CloseSessionConnection(sessionID string, expectedGeneration uint64, expectedSession *shared.Session) {
	cm.mu.Lock()
	owner, ownerExists := cm.sessionOwners[sessionID]
	if ownerExists && owner.controlGeneration == expectedGeneration && owner.session == expectedSession {
		delete(cm.sessionOwners, sessionID)
	}
	sessionConn := cm.sessionConns[sessionID]
	if sessionConn != nil && sessionConn.controlGeneration == expectedGeneration && sessionConn.session == expectedSession {
		delete(cm.sessionConns, sessionID)
	} else {
		sessionConn = nil
	}
	cm.mu.Unlock()

	if sessionConn == nil {
		return
	}

	cm.logger.WithSession(sessionID).Debug("Closing per-session connection (client disconnected)")

	// Mark as closed and close connection (thread-safe)
	sessionConn.mu.Lock()
	if !sessionConn.closed {
		sessionConn.closed = true
		sessionConn.conn.Close()
	}
	sessionConn.mu.Unlock()
}
