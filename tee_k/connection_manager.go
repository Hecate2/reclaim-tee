package main

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
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

// SessionCreatedAckTimeout is how long to wait for SessionCreatedAck from TEE_T
const SessionCreatedAckTimeout = 5 * time.Second

// TEETConnectionManager manages all connections to TEE_T
// - One persistent control connection for attestation, OT precomputation, and session lifecycle
// - One per-session connection for each active session's data flow
type TEETConnectionManager struct {
	mu sync.RWMutex

	// Control connection (persistent)
	controlConn *shared.WSConnection
	controlURL  string // e.g., ws://localhost:8081/ws/control

	// Per-session connections (limited to MaxConcurrentSessions)
	sessionConns map[string]*SessionTEETConnection // sessionID -> connection
	sessionURL   string                            // e.g., ws://localhost:8081/ws/session

	// Pending SessionCreatedAck channels (signaled when ack received)
	pendingAcks   map[string]chan struct{}
	pendingAcksMu sync.Mutex

	// References
	teek   *TEEK
	logger *shared.Logger

	// Attestation state (for control connection)
	attestationVerified bool
	attestationMutex    sync.RWMutex
}

// SessionTEETConnection represents a per-session connection to TEE_T
type SessionTEETConnection struct {
	sessionID   string
	conn        *shared.WSConnection
	established time.Time
	mu          sync.Mutex // Protects writes to this connection
	closed      bool
}

// NewTEETConnectionManager creates a new connection manager
func NewTEETConnectionManager(teek *TEEK, baseURL string, logger *shared.Logger) *TEETConnectionManager {
	// Derive control and session URLs from base URL
	// Base URL: ws://localhost:8081/teek or wss://teet.example.com/ws
	// Control URL: ws://localhost:8081/ws/control
	// Session URL: ws://localhost:8081/ws/session
	controlURL := deriveEndpointURL(baseURL, "/ws/control")
	sessionURL := deriveEndpointURL(baseURL, "/ws/session")

	return &TEETConnectionManager{
		controlURL:   controlURL,
		sessionURL:   sessionURL,
		sessionConns: make(map[string]*SessionTEETConnection),
		pendingAcks:  make(map[string]chan struct{}),
		teek:         teek,
		logger:       logger,
	}
}

// deriveEndpointURL derives a specific endpoint URL from a base WebSocket URL
func deriveEndpointURL(baseURL, endpoint string) string {
	// Handle different URL patterns
	// ws://host:port/path -> ws://host:port/ws/control
	// wss://host/path -> wss://host/ws/control

	// Find the host:port part
	scheme := "ws://"
	if strings.HasPrefix(baseURL, "wss://") {
		scheme = "wss://"
	}

	// Remove scheme
	rest := strings.TrimPrefix(strings.TrimPrefix(baseURL, "ws://"), "wss://")

	// Find first slash (end of host:port)
	before, _, ok := strings.Cut(rest, "/")
	var hostPort string
	if ok {
		hostPort = before
	} else {
		hostPort = rest
	}

	return scheme + hostPort + endpoint
}

// EstablishControlConnection brings up the persistent control connection
// to TEE_T and keeps it up. Blocks until the FIRST connect succeeds
// (attestation verified, OT precomputation done), then returns nil while
// a supervisor goroutine reconnects forever on disconnect.
//
// Splitting first-connect from reconnect lets callers (router_boot,
// standalone main) wait for "ready to serve clients" without owning the
// reconnect loop themselves.
func (cm *TEETConnectionManager) EstablishControlConnection() error {
	cm.logger.Debug("Establishing control connection to TEE_T", zap.String("url", cm.controlURL))

	ready := make(chan struct{})
	var readyOnce sync.Once
	signalReady := func() { readyOnce.Do(func() { close(ready) }) }

	// Until we've successfully connected at least once, dial failures are
	// almost always the boot race (TEE_T's listener not up yet). Log
	// those at WARN so they don't trigger alert metrics keyed on ERROR.
	// After the first successful session, any future failure is a real
	// disconnect and gets ERROR.
	var everConnected atomic.Bool
	onReady := func() {
		signalReady()
		everConnected.Store(true)
	}

	go func() {
		defer shared.RecoverAndCrash(cm.logger, "tee_k.control_supervisor")
		for {
			if err := cm.connectAndServe(onReady); err != nil {
				if everConnected.Load() {
					cm.logger.Error("control session ended with error, retrying", zap.Error(err))
				} else {
					cm.logger.Warn("control session attempt failed during bootstrap, retrying", zap.Error(err))
				}
			} else {
				cm.logger.Info("control session ended, reconnecting")
			}
			time.Sleep(1 * time.Second)
		}
	}()

	<-ready
	return nil
}

// connectAndServe runs one full control-connection lifecycle: dial,
// mutual attestation, OT precomputation, then read-loop until disconnect.
// On clean disconnect returns nil; on any pre-serve failure returns the
// error so the supervisor can log + retry. onReady is invoked exactly
// once after OT precomp succeeds (use sync.Once at the call site for
// the cross-iteration idempotence).
func (cm *TEETConnectionManager) connectAndServe(onReady func()) error {
	conn, err := cm.attemptControlConnection()
	if err != nil {
		return fmt.Errorf("attempt: %w", err)
	}

	wsConn := shared.NewWSConnection(conn)
	cm.mu.Lock()
	cm.controlConn = wsConn
	cm.mu.Unlock()
	cm.logger.Info("Control connection to TEE_T established")

	// Bidirectional ping/pong heartbeat. Sets the read deadline that the
	// control read loop relies on, so a dead peer is detected even when
	// no application messages are flowing.
	wsConn.StartControlHeartbeat(cm.logger)

	// Start control message handler before OT precomp — it needs to
	// receive the OT response messages. handleControlMessages now returns
	// on disconnect rather than chaining a reconnect.
	handlerDone := make(chan struct{})
	go func() {
		defer shared.RecoverAndCrash(cm.logger, "tee_k.handleControlMessages")
		cm.handleControlMessages()
		close(handlerDone)
	}()

	// If we retained a ready pool across a transient disconnect, try to resume
	// it (epoch handshake) instead of paying a full re-precompute. TEE_T denies
	// if it restarted / lost its half, in which case we fall through to a fresh
	// initial precompute. First connect has no pool, so hasResumablePool is false.
	resumed := false
	if cm.teek.hasResumablePool() {
		accepted, err := cm.teek.tryResumeOTPool()
		if err != nil {
			cm.logger.Warn("OT resume attempt failed; will re-precompute", zap.Error(err))
		} else if accepted {
			resumed = true
			cm.logger.Info("Resumed retained OT pool across reconnect (no precompute)")
		} else {
			cm.logger.Info("TEE_T declined OT resume; re-precomputing")
		}
	}
	if !resumed {
		if err := cm.teek.performOTPrecomputation(oprfmpc.OTPoolInitialSize, true); err != nil {
			wsConn.Close()
			<-handlerDone
			cm.tearDownControl()
			return fmt.Errorf("OT precompute: %w", err)
		}
	}

	// Flip both flags together — Audit #7. The router selector treats
	// (control_healthy ∧ ot_ready) as the readiness signal; flipping them
	// in lockstep avoids the brief window where one is true and the other
	// isn't.
	cm.teek.controlHealthy.Store(true)
	cm.teek.otReady.Store(true)
	cm.logger.Info("OT precomputation complete on control connection")
	onReady()

	// Block until the read loop returns (disconnect or read error).
	<-handlerDone
	cm.tearDownControl()
	return nil
}

// tearDownControl resets the connection-scoped state shared with TEEK:
// controlHealthy, OT pool, and cm.controlConn. Called from connectAndServe
// on any exit path (OT failure, normal disconnect).
//
// Also purges all per-session WS connections — they're orphaned without
// a live control link and would otherwise occupy MaxConcurrentSessions
// slots until their 60s read deadline fires. New sessions queue up
// during reconnect and get rejected with "max concurrent sessions
// reached" even though no real work is happening.
func (cm *TEETConnectionManager) tearDownControl() {
	cm.attestationMutex.Lock()
	cm.attestationVerified = false
	cm.attestationMutex.Unlock()

	cm.teek.teetAttestationMutex.Lock()
	cm.teek.teetAttestationVerified = false
	cm.teek.teetAttestationMutex.Unlock()

	cm.teek.controlHealthy.Store(false)
	// Retain a ready pool so the next connection can resume it; clears only if
	// it was mid-precompute (nothing to resume).
	cm.teek.suspendOTPoolForReconnect()

	cm.mu.Lock()
	cm.controlConn = nil
	// Snapshot + reset sessionConns under the lock, then close them
	// outside the lock (close can block briefly on socket teardown).
	orphans := make([]*SessionTEETConnection, 0, len(cm.sessionConns))
	for _, c := range cm.sessionConns {
		orphans = append(orphans, c)
	}
	cm.sessionConns = make(map[string]*SessionTEETConnection)
	cm.mu.Unlock()

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
}

// dialer returns the WebSocket dialer to use for the given URL.
// In router mode (cm.teek.ratls != nil) wss:// dials go through an
// RA-TLS-verified mTLS handshake: server is verified by attestation
// extension, client presents its own RA-TLS cert. In standalone mode
// wss:// uses the existing shared TLS config; ws:// uses the default dialer.
func (cm *TEETConnectionManager) dialer(wsURL string) *websocket.Dialer {
	if cm.teek.ratls != nil && strings.HasPrefix(wsURL, "wss://") {
		return &websocket.Dialer{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: cm.teek.ratls.GetClientCertificate,
				// RA-TLS uses self-signed certs; standard chain verification
				// is replaced by the attestation check in VerifyPeerCertificate.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
					PeerRole:            "tee_t",
					ExpectedImageDigest: cm.teek.expectedPeerImageDigest,
					ExpectedBaseDigest:  cm.teek.expectedPeerBaseDigest,
					Logger:              cm.logger,
				}),
				// TLS 1.3 only on the TEE↔TEE peer link. Independent of
				// minitls's separate target-server handshake which keeps 1.2.
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
			},
		}
	}
	if strings.HasPrefix(wsURL, "wss://") {
		return createTLSWebSocketDialer()
	}
	return websocket.DefaultDialer
}

// sendPairAssignment writes the router-mode pair_id handshake envelope onto a
// freshly-dialed control connection. It is the very first message TEE_T sees
// on the wire — its existing TEEKAttestation handshake comes next.
func (cm *TEETConnectionManager) sendPairAssignment(conn *websocket.Conn) error {
	env := &teeproto.Envelope{
		SessionId:   "control",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeekPairAssignment{
			TeekPairAssignment: &teeproto.TEEKPairAssignment{PairId: cm.teek.pairID},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return shared.WriteWSBinary(conn, data)
}

// attemptControlConnection performs a single connection attempt with attestation
func (cm *TEETConnectionManager) attemptControlConnection() (*websocket.Conn, error) {
	cm.logger.Debug("Starting control connection attempt")

	conn, _, err := cm.dialer(cm.controlURL).Dial(cm.controlURL, nil)
	if err != nil {
		return nil, err
	}

	cm.logger.Info("Control WebSocket connected, starting attestation exchange")

	// Router mode: announce the pair_id as the very first envelope so TEE_T
	// can register with the router under the same ID. Standalone mode skips
	// this entirely.
	if cm.teek.pairID != "" {
		if err := cm.sendPairAssignment(conn); err != nil {
			conn.Close()
			return nil, fmt.Errorf("send pair assignment: %w", err)
		}
	}

	// Generate and send TEE_K attestation
	attestation, err := cm.teek.generateAttestationForTEET()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	env := &teeproto.Envelope{
		SessionId:   "control",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeekAttestation{
			TeekAttestation: &teeproto.TEEKAttestationRequest{
				AttestationReport: attestation,
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to marshal attestation: %v", err)
	}

	cm.logger.Info("Sending attestation on control connection",
		zap.String("type", "TeekAttestation"),
		zap.Int("bytes", len(data)))

	if err := shared.WriteWSBinary(conn, data); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send attestation: %v", err)
	}

	// Wait for TEE_T attestation response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to receive TEE_T attestation: %v", err)
	}

	// Extract TLS certificate for verification
	var tlsCert []byte
	if strings.HasPrefix(cm.controlURL, "wss://") {
		tlsCert, err = shared.ExtractTLSCertFromWebSocket(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to extract TLS cert: %v", err)
		}
	}

	// Verify TEE_T attestation
	if err := cm.teek.verifyTEETAttestation(msgBytes, tlsCert); err != nil {
		conn.Close()
		return nil, fmt.Errorf("attestation verification failed: %v", err)
	}

	// Mark attestation as verified. controlHealthy / otReady are flipped
	// later in connectAndServe — only AFTER OT precomp completes — so
	// router heartbeat never reports a half-ready state.
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()

	cm.teek.teetAttestationMutex.Lock()
	cm.teek.teetAttestationVerified = true
	cm.teek.teetAttestationMutex.Unlock()

	cm.logger.Info("TEE_T attestation verified on control connection")

	return conn, nil
}

// handleControlMessages reads from the control connection until disconnect,
// then returns. Connection teardown and reconnect are owned by the
// supervisor goroutine in EstablishControlConnection — this function
// just translates wire bytes into handler calls.
func (cm *TEETConnectionManager) handleControlMessages() {
	cm.mu.RLock()
	conn := cm.controlConn
	cm.mu.RUnlock()
	if conn == nil {
		return
	}

	cm.logger.Info("Starting control connection message handler")

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.Debug("Control connection closed")
			} else {
				cm.logger.Error("Control connection lost", zap.Error(err))
			}
			return
		}
		cm.handleControlMessage(msgBytes)
	}
}

// handleControlMessage processes a single message from the control connection
func (cm *TEETConnectionManager) handleControlMessage(msgBytes []byte) {
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		cm.logger.Error("Failed to parse control message", zap.Error(err))
		return
	}

	switch p := env.Payload.(type) {
	case *teeproto.Envelope_OtPrecomputeResponse:
		if err := cm.teek.handleOTPrecomputeResponse(p.OtPrecomputeResponse); err != nil {
			cm.logger.Error("OT precompute response failed", zap.Error(err))
		}

	case *teeproto.Envelope_OtResumeResponse:
		if err := cm.teek.handleOTResumeResponse(p.OtResumeResponse); err != nil {
			cm.logger.Error("OT resume response failed", zap.Error(err))
		}

	case *teeproto.Envelope_SessionCreatedAck:
		// TEE_T acknowledges session creation - signal waiting goroutine
		sessionID := p.SessionCreatedAck.GetSessionId()
		cm.pendingAcksMu.Lock()
		if ch, ok := cm.pendingAcks[sessionID]; ok {
			close(ch)
			delete(cm.pendingAcks, sessionID)
		}
		cm.pendingAcksMu.Unlock()
		cm.logger.WithSession(sessionID).Debug("Received SessionCreatedAck")

	case *teeproto.Envelope_Error:
		// Error from TEE_T - cleanup the affected session
		sessionID := env.GetSessionId()
		cm.logger.WithSession(sessionID).Error("Received error from TEE_T (control)",
			zap.String("error", p.Error.GetMessage()))
		if sessionID != "" && sessionID != "control" {
			cm.teek.cleanupSession(sessionID)
		}

	default:
		cm.logger.Warn("Unexpected message type on control connection", zap.String("type", fmt.Sprintf("%T", p)))
	}
}

// WaitForSessionCreatedAck waits for TEE_T to acknowledge session creation
// Returns nil if ack received, error on timeout
func (cm *TEETConnectionManager) WaitForSessionCreatedAck(sessionID string) error {
	// Create channel for this session
	ch := make(chan struct{})
	cm.pendingAcksMu.Lock()
	cm.pendingAcks[sessionID] = ch
	cm.pendingAcksMu.Unlock()

	// Cleanup on exit
	defer func() {
		cm.pendingAcksMu.Lock()
		delete(cm.pendingAcks, sessionID)
		cm.pendingAcksMu.Unlock()
	}()

	// Wait for ack or timeout
	select {
	case <-ch:
		return nil
	case <-time.After(SessionCreatedAckTimeout):
		// Treat ack timeout as evidence the control connection is dead from
		// TEE_T's side (e.g., TEE_T tore it down but our writes still buffer).
		// Closing it pops handleControlMessages' ReadMessage and triggers the
		// existing reconnect path, instead of failing per-session forever.
		cm.mu.RLock()
		conn := cm.controlConn
		cm.mu.RUnlock()
		if conn != nil {
			cm.logger.WithSession(sessionID).Warn("SessionCreatedAck timeout — closing control connection to force reconnect")
			_ = conn.Close()
		}
		return fmt.Errorf("timeout waiting for SessionCreatedAck")
	}
}

// EstablishSessionConnection establishes a per-session connection to TEE_T
func (cm *TEETConnectionManager) EstablishSessionConnection(sessionID string) error {
	cm.logger.WithSession(sessionID).Debug("Establishing per-session connection to TEE_T")

	// Pre-check session limit (will recheck under lock before insert)
	cm.mu.RLock()
	sessionCount := len(cm.sessionConns)
	cm.mu.RUnlock()

	if sessionCount >= MaxConcurrentSessions {
		return fmt.Errorf("max concurrent sessions (%d) reached", MaxConcurrentSessions)
	}

	// Check attestation is verified
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()

	if !verified {
		return fmt.Errorf("cannot establish session connection: control attestation not verified")
	}

	// Dial session WebSocket — same dialer policy as the control link.
	// Per-session dials skip the pair-assignment handshake; that runs only
	// once on control.
	conn, _, err := cm.dialer(cm.sessionURL).Dial(cm.sessionURL, nil)
	if err != nil {
		return fmt.Errorf("failed to dial session connection: %v", err)
	}

	// Set max message size
	conn.SetReadLimit(MaxWebSocketMessageSize)

	// Send SessionConnectionInit
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionConnectionInit{
			SessionConnectionInit: &teeproto.SessionConnectionInit{
				SessionId: sessionID,
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to marshal SessionConnectionInit: %v", err)
	}

	if err := shared.WriteWSBinary(conn, data); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send SessionConnectionInit: %v", err)
	}

	// Wait for SessionConnectionAck
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive SessionConnectionAck: %v", err)
	}

	var ackEnv teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &ackEnv); err != nil {
		conn.Close()
		return fmt.Errorf("failed to parse SessionConnectionAck: %v", err)
	}

	ack, ok := ackEnv.Payload.(*teeproto.Envelope_SessionConnectionAck)
	if !ok {
		conn.Close()
		return fmt.Errorf("expected SessionConnectionAck, got %T", ackEnv.Payload)
	}

	if !ack.SessionConnectionAck.GetSuccess() {
		conn.Close()
		return fmt.Errorf("session connection rejected: %s", ack.SessionConnectionAck.GetErrorMessage())
	}

	// Create and store session connection
	wsConn := shared.NewWSConnection(conn)
	sessionConn := &SessionTEETConnection{
		sessionID:   sessionID,
		conn:        wsConn,
		established: time.Now(),
	}

	// Recheck session limit under lock to prevent TOCTOU race
	cm.mu.Lock()
	if len(cm.sessionConns) >= MaxConcurrentSessions {
		cm.mu.Unlock()
		wsConn.Close()
		return fmt.Errorf("max concurrent sessions (%d) reached (race)", MaxConcurrentSessions)
	}
	cm.sessionConns[sessionID] = sessionConn
	cm.mu.Unlock()

	cm.logger.WithSession(sessionID).Debug("Per-session connection established")

	// Start session message handler in background
	go func() {
		defer shared.RecoverAndCrash(cm.logger, "tee_k.handleSessionMessages")
		cm.handleSessionMessages(sessionID)
	}()

	return nil
}

// handleSessionMessages handles incoming messages on a per-session connection
// ZERO TOLERANCE: Any error terminates the session and closes the connection
func (cm *TEETConnectionManager) handleSessionMessages(sessionID string) {
	cm.mu.RLock()
	sessionConn := cm.sessionConns[sessionID]
	cm.mu.RUnlock()

	if sessionConn == nil {
		return
	}

	cm.logger.WithSession(sessionID).Debug("Starting session message handler")

	// Ensure cleanup on exit - ZERO TOLERANCE for resource leaks
	defer func() {
		cm.mu.Lock()
		if sc, exists := cm.sessionConns[sessionID]; exists && sc == sessionConn {
			delete(cm.sessionConns, sessionID)
		}
		cm.mu.Unlock()

		// Always close the connection
		sessionConn.mu.Lock()
		if !sessionConn.closed {
			sessionConn.closed = true
			sessionConn.conn.Close()
		}
		sessionConn.mu.Unlock()
	}()

	for {
		// Set read deadline to prevent stuck connections
		sessionConn.conn.SetReadDeadline(time.Now().Add(SessionReadTimeout))
		_, msgBytes, err := sessionConn.conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.WithSession(sessionID).Debug("Session connection closed normally")
			} else if !sessionConn.closed {
				cm.logger.WithSession(sessionID).Error("Session connection lost", zap.Error(err))
			}
			return // Cleanup handled by defer
		}

		// Route message to TEEK's handler
		cm.teek.handleSharedTEETMessage(msgBytes)
	}
}

// SendOnControl sends a message on the control connection
func (cm *TEETConnectionManager) SendOnControl(env *teeproto.Envelope) error {
	cm.mu.RLock()
	conn := cm.controlConn
	cm.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("control connection not available")
	}

	// Check attestation
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()

	if !verified {
		return fmt.Errorf("cannot send on control: attestation not verified")
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}

	cm.logger.Debug("Sending on control connection",
		zap.String("type", getEnvelopePayloadType(env)),
		zap.Int("bytes", len(data)))

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// SendOnSession sends a message on a per-session connection
func (cm *TEETConnectionManager) SendOnSession(sessionID string, env *teeproto.Envelope) error {
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
		zap.String("type", getEnvelopePayloadType(env)),
		zap.Int("bytes", len(data)))

	// Use session connection's mutex for thread-safe writes
	sessionConn.mu.Lock()
	defer sessionConn.mu.Unlock()

	return sessionConn.conn.WriteMessage(websocket.BinaryMessage, data)
}

// CloseSessionConnection closes a per-session connection and notifies TEE_T
// ZERO TOLERANCE: Always closes connection, always notifies TEE_T (best effort)
func (cm *TEETConnectionManager) CloseSessionConnection(sessionID string, reason string) {
	cm.mu.Lock()
	sessionConn := cm.sessionConns[sessionID]
	if sessionConn != nil {
		delete(cm.sessionConns, sessionID)
	}
	cm.mu.Unlock()

	if sessionConn == nil {
		return
	}

	cm.logger.WithSession(sessionID).Debug("Closing per-session connection", zap.String("reason", reason))

	// Mark as closed and close connection (thread-safe)
	sessionConn.mu.Lock()
	alreadyClosed := sessionConn.closed
	sessionConn.closed = true
	sessionConn.mu.Unlock()

	if !alreadyClosed {
		// Close the connection first to stop any pending reads
		sessionConn.conn.Close()
	}

	// Send SessionClosed notification on control connection (best effort)
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionClosed{
			SessionClosed: &teeproto.SessionClosed{
				SessionId: sessionID,
				Reason:    reason,
			},
		},
	}

	if err := cm.SendOnControl(env); err != nil {
		cm.logger.WithSession(sessionID).Warn("Failed to send SessionClosed notification", zap.Error(err))
	}
}

// GetControlConnection returns the control connection for direct access (e.g., OT precomputation)
func (cm *TEETConnectionManager) GetControlConnection() *shared.WSConnection {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.controlConn
}

// GetSessionConnection returns a session connection
func (cm *TEETConnectionManager) GetSessionConnection(sessionID string) (*SessionTEETConnection, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	conn, ok := cm.sessionConns[sessionID]
	return conn, ok
}

// IsAttestationVerified returns whether the control connection attestation is verified
func (cm *TEETConnectionManager) IsAttestationVerified() bool {
	cm.attestationMutex.RLock()
	defer cm.attestationMutex.RUnlock()
	return cm.attestationVerified
}

// IsControlConnected returns whether the control connection is established
func (cm *TEETConnectionManager) IsControlConnected() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.controlConn != nil
}

// GetSessionConnectionCount returns the current number of session connections
func (cm *TEETConnectionManager) GetSessionConnectionCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.sessionConns)
}

// LogConnectionStatus logs current connection status (call periodically)
func (cm *TEETConnectionManager) LogConnectionStatus() {
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

// isControlMessage determines if a message should go on the control connection
// Control messages: attestation, OT precomputation, session lifecycle, and errors
// Error messages go on control because session connection may be dead when error occurs
func isControlMessage(env *teeproto.Envelope) bool {
	switch env.Payload.(type) {
	case *teeproto.Envelope_TeekAttestation,
		*teeproto.Envelope_TeetAttestation,
		*teeproto.Envelope_OtPrecomputeRequest,
		*teeproto.Envelope_OtPrecomputeResponse,
		*teeproto.Envelope_OtPrecomputeComplete,
		*teeproto.Envelope_OtResumeRequest,
		*teeproto.Envelope_OtResumeResponse,
		*teeproto.Envelope_SessionCreated,
		*teeproto.Envelope_SessionClosed,
		*teeproto.Envelope_Error: // Errors go on control - session may be dead
		return true
	}
	return false
}
