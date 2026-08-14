package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
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

// errSessionCreatedControlUnavailable is returned only when SessionCreated was
// definitely not written because there was no current attested control at the
// pre-write checks. Write failures and ACK timeouts are ambiguous and must
// never be retried under the same client session.
var errSessionCreatedControlUnavailable = errors.New("SessionCreated control connection unavailable before send")

// errControlUnavailableBeforeWrite is internal to the generic control-send
// primitive. SessionCreated translates it to its retry sentinel; unrelated
// control messages must not inherit SessionCreated retry classification.
var errControlUnavailableBeforeWrite = errors.New("control connection unavailable before write")

// TEETConnectionManager manages all connections to TEE_T
// - One persistent control connection for attestation, OT precomputation, and session lifecycle
// - One per-session connection for each active session's data flow
type TEETConnectionManager struct {
	mu sync.RWMutex

	// Control connection (persistent)
	controlConn       *shared.WSConnection
	controlGeneration uint64
	controlURL        string // e.g., ws://localhost:8081/ws/control

	// Per-session connections (limited to MaxConcurrentSessions)
	sessionConns map[string]*SessionTEETConnection // sessionID -> connection
	sessionURL   string                            // e.g., ws://localhost:8081/ws/session

	// dialSessionConnectionFn overrides the dial/ACK exchange in deterministic
	// lifecycle tests. Production leaves it nil.
	dialSessionConnectionFn func(string) (*shared.WSConnection, error)

	// Pending SessionCreatedAck waiters, bound to the control generation that
	// carried SessionCreated. acknowledgedSessions is protected by cm.mu and
	// retains the exact session/control owner from ACK until publication or
	// cleanup, closing the ACK-to-session-socket ownership gap.
	pendingAcks          map[string]*sessionCreatedAckWaiter
	pendingAcksMu        sync.Mutex
	acknowledgedSessions map[string]*controlConnectionToken

	// References
	teek   *TEEK
	logger *shared.Logger

	// Attestation state (for control connection)
	attestationVerified bool
	attestationMutex    sync.RWMutex
}

type sessionCreatedAckWaiter struct {
	controlConn       *shared.WSConnection
	controlGeneration uint64
	owner             *controlConnectionToken
	done              chan struct{}
	err               error
}

type controlConnectionToken struct {
	conn       *shared.WSConnection
	generation uint64
	session    *shared.Session
}

// SessionTEETConnection represents a per-session connection to TEE_T
type SessionTEETConnection struct {
	sessionID         string
	session           *shared.Session
	controlConn       *shared.WSConnection
	controlGeneration uint64
	admissionOwner    *controlConnectionToken
	conn              *shared.WSConnection
	established       time.Time
	mu                sync.Mutex // Protects writes to this connection
	closed            bool
}

func (c *SessionTEETConnection) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
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
		controlURL:           controlURL,
		sessionURL:           sessionURL,
		sessionConns:         make(map[string]*SessionTEETConnection),
		pendingAcks:          make(map[string]*sessionCreatedAckWaiter),
		acknowledgedSessions: make(map[string]*controlConnectionToken),
		teek:                 teek,
		logger:               logger,
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
	cm.controlGeneration++
	controlGeneration := cm.controlGeneration
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
		cm.handleControlMessages(wsConn, controlGeneration)
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
			if err := cm.teek.ensureResumedOTPoolUsable(); err != nil {
				cm.logger.Warn("Resumed OT pool could not be made usable; re-precomputing", zap.Error(err))
			} else {
				resumed = true
				cm.logger.Info("Resumed retained OT pool across reconnect")
			}
		} else {
			cm.logger.Info("TEE_T declined OT resume; re-precomputing")
		}
	}
	if !resumed {
		if err := cm.teek.performOTPrecomputation(mpc.OTPoolInitialSize, true); err != nil {
			wsConn.Close()
			<-handlerDone
			cm.tearDownControl(wsConn, controlGeneration)
			return fmt.Errorf("OT precompute: %w", err)
		}
	}

	// OT readiness was published under the matching OT-state mutation. Publish
	// control health only after precompute/resume has made that state usable;
	// the router selector requires both flags.
	cm.teek.controlHealthy.Store(true)
	cm.logger.Info("OT precomputation complete on control connection")
	onReady()

	// Block until the read loop returns (disconnect or read error).
	<-handlerDone
	cm.tearDownControl(wsConn, controlGeneration)
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
func (cm *TEETConnectionManager) tearDownControl(conn *shared.WSConnection, generation uint64) {
	cm.mu.Lock()
	cm.failSessionCreatedAckWaitersLocked(conn, generation, fmt.Errorf("control connection disconnected before SessionCreatedAck"))
	if cm.controlConn != conn || cm.controlGeneration != generation {
		cm.mu.Unlock()
		return
	}
	cm.controlConn = nil

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

	// Snapshot + reset sessionConns under the lock, then close them
	// outside the lock (close can block briefly on socket teardown).
	orphans := make([]*SessionTEETConnection, 0, len(cm.sessionConns))
	orphanSessions := make([]*shared.Session, 0, len(cm.sessionConns))
	for sessionID, c := range cm.sessionConns {
		if c.controlConn != conn || c.controlGeneration != generation {
			continue
		}
		orphans = append(orphans, c)
		orphanSessions = append(orphanSessions, c.session)
		delete(cm.sessionConns, sessionID)
	}
	for sessionID, owner := range cm.acknowledgedSessions {
		if owner == nil || owner.conn != conn || owner.generation != generation {
			continue
		}
		if owner.session != nil {
			orphanSessions = append(orphanSessions, owner.session)
		}
		delete(cm.acknowledgedSessions, sessionID)
	}
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
	for _, session := range orphanSessions {
		cm.teek.cleanupSessionWithSession(session)
	}
}

// failSessionCreatedAckWaitersLocked fails only waiters owned by one exact
// control generation. cm.mu must be held so registration cannot race teardown.
func (cm *TEETConnectionManager) failSessionCreatedAckWaitersLocked(conn *shared.WSConnection, generation uint64, err error) {
	cm.pendingAcksMu.Lock()
	defer cm.pendingAcksMu.Unlock()
	for sessionID, waiter := range cm.pendingAcks {
		if waiter.controlConn != conn || waiter.controlGeneration != generation {
			continue
		}
		waiter.err = err
		close(waiter.done)
		delete(cm.pendingAcks, sessionID)
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

	conn, err := cm.dialControlConnection()
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

// dialControlConnection returns a control socket only after installing the
// same policy limit used by every other TEE WebSocket read path. Installing it
// here keeps the attestation read inside attemptControlConnection bounded too.
func (cm *TEETConnectionManager) dialControlConnection() (*websocket.Conn, error) {
	return dialWebSocketWithReadLimit(cm.dialer(cm.controlURL), cm.controlURL, MaxWebSocketMessageSize)
}

func dialWebSocketWithReadLimit(dialer *websocket.Dialer, wsURL string, readLimit int64) (*websocket.Conn, error) {
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(readLimit)
	return conn, nil
}

// handleControlMessages reads from the control connection until disconnect,
// then returns. Connection teardown and reconnect are owned by the
// supervisor goroutine in EstablishControlConnection — this function
// just translates wire bytes into handler calls.
func (cm *TEETConnectionManager) handleControlMessages(conn *shared.WSConnection, generation uint64) {
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
		if !cm.isCurrentControlConnection(conn, generation) {
			return
		}
		cm.handleControlMessage(conn, generation, msgBytes)
	}
}

// handleControlMessage processes a single message from the control connection
func (cm *TEETConnectionManager) handleControlMessage(conn *shared.WSConnection, generation uint64, msgBytes []byte) {
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		cm.logger.Error("Failed to parse control message - closing connection", zap.Error(err))
		cm.closeControlAfterProtocolError(conn)
		return
	}

	switch p := env.Payload.(type) {
	case *teeproto.Envelope_OtPrecomputeResponse:
		if err := cm.teek.handleOTPrecomputeResponse(conn, generation, p.OtPrecomputeResponse); err != nil {
			cm.logger.Error("OT precompute response failed", zap.Error(err))
			cm.closeControlAfterProtocolError(conn)
		}

	case *teeproto.Envelope_OtResumeResponse:
		if err := cm.teek.handleOTResumeResponse(conn, generation, p.OtResumeResponse); err != nil {
			cm.logger.Error("OT resume response failed", zap.Error(err))
			cm.closeControlAfterProtocolError(conn)
		}

	case *teeproto.Envelope_SessionCreatedAck:
		// TEE_T acknowledges session creation - signal waiting goroutine
		sessionID := p.SessionCreatedAck.GetSessionId()
		cm.mu.Lock()
		cm.pendingAcksMu.Lock()
		if waiter, ok := cm.pendingAcks[sessionID]; ok && waiter.controlConn == conn && waiter.controlGeneration == generation {
			cm.acknowledgedSessions[sessionID] = waiter.owner
			close(waiter.done)
			delete(cm.pendingAcks, sessionID)
		}
		cm.pendingAcksMu.Unlock()
		cm.mu.Unlock()
		cm.logger.WithSession(sessionID).Debug("Received SessionCreatedAck")

	case *teeproto.Envelope_Error:
		sessionID := env.GetSessionId()
		if sessionID == "" || sessionID == "control" {
			cm.logger.Error("Malformed session error on TEE_T control connection")
			cm.closeControlAfterProtocolError(conn)
			return
		}
		var peerErr *teeproto.ErrorData
		if p != nil {
			peerErr = p.Error
		}
		if err := cm.handleControlPeerError(conn, generation, sessionID, peerErr); err != nil {
			cm.logger.WithSession(sessionID).Debug("Ignored stale or completed TEE_T control error", zap.Error(err))
		} else {
			cm.logger.WithSession(sessionID).Info("Handled TEE_T control error and terminated session")
		}

	default:
		cm.logger.Warn("Unexpected message type on control connection", zap.String("type", fmt.Sprintf("%T", p)))
	}
}

func (cm *TEETConnectionManager) cleanupSessionOwnedByControl(conn *shared.WSConnection, generation uint64, sessionID string) {
	cm.mu.RLock()
	sessionConn := cm.sessionConns[sessionID]
	cm.mu.RUnlock()
	if sessionConn == nil || sessionConn.controlConn != conn || sessionConn.controlGeneration != generation || sessionConn.session == nil {
		cm.logger.WithSession(sessionID).Debug("Ignoring stale control-session cleanup")
		return
	}
	cm.teek.cleanupSessionWithSession(sessionConn.session)
}

func (cm *TEETConnectionManager) handleControlPeerError(conn *shared.WSConnection, generation uint64, sessionID string, peerErr *teeproto.ErrorData) error {
	cm.mu.RLock()
	sessionConn := cm.sessionConns[sessionID]
	acknowledged := cm.acknowledgedSessions[sessionID]
	controlCurrent := cm.controlConn == conn && cm.controlGeneration == generation
	cm.mu.RUnlock()
	if !controlCurrent {
		return fmt.Errorf("session error owner was superseded")
	}
	if sessionConn != nil && sessionConn.session != nil && sessionConn.controlConn == conn && sessionConn.controlGeneration == generation {
		identity := &teekSessionIdentity{session: sessionConn.session, sessionConn: sessionConn, validate: func() error {
			return cm.validateSessionConnection(sessionConn)
		}}
		return cm.teek.handlePeerErrorForIdentity(identity, peerErr)
	}
	if acknowledged == nil || acknowledged.session == nil || acknowledged.conn != conn || acknowledged.generation != generation {
		return fmt.Errorf("session error owner was superseded")
	}
	identity := &teekSessionIdentity{session: acknowledged.session, validate: func() error {
		return cm.validateAcknowledgedOrPublishedSession(sessionID, acknowledged)
	}}
	return cm.teek.handlePeerErrorForIdentity(identity, peerErr)
}

func (cm *TEETConnectionManager) validateAcknowledgedOrPublishedSession(sessionID string, owner *controlConnectionToken) error {
	if owner == nil || owner.session == nil || owner.conn == nil {
		return fmt.Errorf("acknowledged session identity is incomplete")
	}
	cm.mu.RLock()
	controlCurrent := cm.controlConn == owner.conn && cm.controlGeneration == owner.generation
	acknowledgedCurrent := cm.acknowledgedSessions[sessionID] == owner
	published := cm.sessionConns[sessionID]
	publishedCurrent := published != nil && published.session == owner.session && published.controlConn == owner.conn && published.controlGeneration == owner.generation
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()
	cm.mu.RUnlock()
	if !controlCurrent || !verified || (!acknowledgedCurrent && !publishedCurrent) {
		return fmt.Errorf("acknowledged session owner was superseded")
	}
	current, err := cm.teek.sessionManager.GetSession(sessionID)
	if err != nil || current != owner.session {
		return fmt.Errorf("acknowledged session identity was superseded")
	}
	return nil
}

func (cm *TEETConnectionManager) closeControlAfterProtocolError(conn *shared.WSConnection) {
	if conn != nil {
		_ = conn.Close()
	}
}

func (cm *TEETConnectionManager) isCurrentControlConnection(conn *shared.WSConnection, generation uint64) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.controlConn == conn && cm.controlGeneration == generation
}

func (cm *TEETConnectionManager) currentAttestedControlToken() (*controlConnectionToken, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.controlConn == nil {
		return nil, fmt.Errorf("no TEE_T control connection available")
	}
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()
	if !verified {
		return nil, fmt.Errorf("TEE_T control attestation not verified")
	}
	return &controlConnectionToken{conn: cm.controlConn, generation: cm.controlGeneration}, nil
}

// sendSessionCreatedAndWait registers the acknowledgment waiter before send so
// an acknowledgment received on the control read loop cannot overtake waiter
// registration. The waiter is removed on every exit path.
func (cm *TEETConnectionManager) sendSessionCreatedAndWait(sessionID string, send func(*shared.WSConnection, uint64) error) (*controlConnectionToken, error) {
	return cm.sendSessionCreatedAndWaitToken(sessionID, SessionCreatedAckTimeout, send)
}

func (cm *TEETConnectionManager) sendSessionCreatedAndWaitForSession(session *shared.Session, send func(*shared.WSConnection, uint64) error) (*controlConnectionToken, error) {
	if session == nil {
		return nil, fmt.Errorf("failed to send SessionCreated: session is nil")
	}
	return cm.sendSessionCreatedAndWaitTokenForSession(session.ID, session, SessionCreatedAckTimeout, send)
}

func (cm *TEETConnectionManager) sendSessionCreatedAndWaitTimeout(sessionID string, timeout time.Duration, send func(*shared.WSConnection, uint64) error) error {
	_, err := cm.sendSessionCreatedAndWaitToken(sessionID, timeout, send)
	return err
}

func (cm *TEETConnectionManager) sendSessionCreatedAndWaitToken(sessionID string, timeout time.Duration, send func(*shared.WSConnection, uint64) error) (*controlConnectionToken, error) {
	return cm.sendSessionCreatedAndWaitTokenForSession(sessionID, nil, timeout, send)
}

func (cm *TEETConnectionManager) sendSessionCreatedAndWaitTokenForSession(sessionID string, session *shared.Session, timeout time.Duration, send func(*shared.WSConnection, uint64) error) (*controlConnectionToken, error) {
	if session != nil && session.ID != sessionID {
		return nil, fmt.Errorf("failed to send SessionCreated: session ID mismatch")
	}
	cm.mu.Lock()
	conn := cm.controlConn
	generation := cm.controlGeneration
	if conn == nil {
		cm.mu.Unlock()
		return nil, fmt.Errorf("%w: failed to send SessionCreated", errSessionCreatedControlUnavailable)
	}
	owner := &controlConnectionToken{conn: conn, generation: generation, session: session}
	waiter := &sessionCreatedAckWaiter{
		controlConn:       conn,
		controlGeneration: generation,
		owner:             owner,
		done:              make(chan struct{}),
	}
	cm.pendingAcksMu.Lock()
	if _, exists := cm.pendingAcks[sessionID]; exists {
		cm.pendingAcksMu.Unlock()
		cm.mu.Unlock()
		return nil, fmt.Errorf("failed to send SessionCreated: SessionCreatedAck waiter already registered")
	}
	if _, exists := cm.acknowledgedSessions[sessionID]; exists {
		cm.pendingAcksMu.Unlock()
		cm.mu.Unlock()
		return nil, fmt.Errorf("failed to send SessionCreated: acknowledged session owner already registered")
	}
	cm.pendingAcks[sessionID] = waiter
	cm.pendingAcksMu.Unlock()
	cm.mu.Unlock()

	defer func() {
		cm.pendingAcksMu.Lock()
		// Do not remove a newer waiter if the session ID was reused after the
		// acknowledgment handler removed this one.
		if cm.pendingAcks[sessionID] == waiter {
			delete(cm.pendingAcks, sessionID)
		}
		cm.pendingAcksMu.Unlock()
	}()

	if err := send(conn, generation); err != nil {
		if errors.Is(err, errControlUnavailableBeforeWrite) {
			return nil, fmt.Errorf("%w: %v", errSessionCreatedControlUnavailable, err)
		}
		// A write error may mean that any prefix or the complete envelope was
		// delivered. Close only the captured origin so its eventual teardown
		// resolves that ambiguity; never close a concurrently installed control.
		_ = conn.Close()
		return nil, fmt.Errorf("failed to send SessionCreated: %w", err)
	}

	select {
	case <-waiter.done:
		if waiter.err != nil {
			return nil, waiter.err
		}
		return owner, nil
	case <-time.After(timeout):
		// Treat ack timeout as evidence the control connection is dead from
		// TEE_T's side (e.g., TEE_T tore it down but our writes still buffer).
		// Closing it pops handleControlMessages' ReadMessage and triggers the
		// existing reconnect path, instead of failing per-session forever.
		cm.logger.WithSession(sessionID).Warn("SessionCreatedAck timeout — closing originating control connection to force reconnect")
		_ = conn.Close()
		return nil, fmt.Errorf("failed to get session ack: timeout waiting for SessionCreatedAck")
	}
}

// EstablishSessionConnection establishes a per-session connection to TEE_T
func (cm *TEETConnectionManager) EstablishSessionConnection(sessionID string, origin *controlConnectionToken) error {
	cm.logger.WithSession(sessionID).Debug("Establishing per-session connection to TEE_T")
	if origin == nil || origin.conn == nil {
		return fmt.Errorf("cannot establish session connection: acknowledged control identity is missing")
	}
	published := false
	defer func() {
		if published || cm.hasSessionConnection(sessionID) {
			return
		}
		claimed := cm.releaseAcknowledgedSessionOwner(sessionID, origin)
		if origin.session != nil && !claimed {
			return
		}
		// SessionCreated was already acknowledged, so TEE_T owns an undialed
		// session. Release it on the exact acknowledging control. A replaced or
		// unusable origin is intentionally ignored; never migrate cleanup.
		if err := cm.sendSessionClosedOnControl(sessionID, "session_connection_setup_failed", origin); err != nil {
			cm.logger.WithSession(sessionID).Debug("Could not release undialed TEE_T session owner", zap.Error(err))
		}
	}()

	session := origin.session
	if session == nil {
		var err error
		session, err = cm.teek.sessionManager.GetSession(sessionID)
		if err != nil {
			return fmt.Errorf("cannot establish session connection: %w", err)
		}
	} else {
		current, err := cm.teek.sessionManager.GetSession(sessionID)
		if err != nil || current != session {
			return fmt.Errorf("cannot establish session connection: acknowledged session identity changed")
		}
	}

	// Require the exact control generation that acknowledged SessionCreated;
	// never migrate the per-session dial onto a replacement control.
	cm.mu.Lock()
	sessionCount := len(cm.sessionConns)
	controlCurrent := cm.controlConn == origin.conn && cm.controlGeneration == origin.generation
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()
	cm.mu.Unlock()
	if sessionCount >= MaxConcurrentSessions {
		return fmt.Errorf("max concurrent sessions (%d) reached", MaxConcurrentSessions)
	}
	if !controlCurrent {
		return fmt.Errorf("cannot establish session connection: acknowledged control connection changed before session dial")
	}
	if !verified {
		return fmt.Errorf("cannot establish session connection: control attestation not verified")
	}

	dial := cm.dialSessionConnectionFn
	if dial == nil {
		dial = cm.dialSessionConnection
	}
	wsConn, err := dial(sessionID)
	if err != nil {
		return err
	}
	candidate := &SessionTEETConnection{
		sessionID:         sessionID,
		session:           session,
		controlConn:       origin.conn,
		controlGeneration: origin.generation,
		admissionOwner:    origin,
		conn:              wsConn,
		established:       time.Now(),
	}

	if err := cm.publishSessionConnection(candidate); err != nil {
		_ = wsConn.Close()
		return err
	}
	published = true

	cm.logger.WithSession(sessionID).Debug("Per-session connection established")

	// Start session message handler in background with the exact published
	// connection identity. It must never re-resolve a reused session ID.
	go func() {
		defer shared.RecoverAndCrash(cm.logger, "tee_k.handleSessionMessages")
		cm.handleSessionMessages(candidate)
	}()

	return nil
}

func (cm *TEETConnectionManager) dialSessionConnection(sessionID string) (*shared.WSConnection, error) {
	// Dial session WebSocket — same dialer policy as the control link.
	// Per-session dials skip the pair-assignment handshake; that runs only
	// once on control.
	conn, _, err := cm.dialer(cm.sessionURL).Dial(cm.sessionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial session connection: %v", err)
	}

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
		return nil, fmt.Errorf("failed to marshal SessionConnectionInit: %v", err)
	}

	if err := shared.WriteWSBinary(conn, data); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send SessionConnectionInit: %v", err)
	}

	// Wait for SessionConnectionAck
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to receive SessionConnectionAck: %v", err)
	}

	var ackEnv teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &ackEnv); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to parse SessionConnectionAck: %v", err)
	}

	ack, ok := ackEnv.Payload.(*teeproto.Envelope_SessionConnectionAck)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("expected SessionConnectionAck, got %T", ackEnv.Payload)
	}

	if !ack.SessionConnectionAck.GetSuccess() {
		conn.Close()
		return nil, fmt.Errorf("session connection rejected: %s", ack.SessionConnectionAck.GetErrorMessage())
	}
	return shared.NewWSConnection(conn), nil
}

func (cm *TEETConnectionManager) publishSessionConnection(candidate *SessionTEETConnection) error {
	if candidate == nil || candidate.session == nil || candidate.controlConn == nil || candidate.conn == nil {
		return fmt.Errorf("session connection identity is incomplete")
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if candidate.session.CleanedUp.Load() {
		return fmt.Errorf("session was cleaned up during session dial")
	}
	if cm.controlConn != candidate.controlConn || cm.controlGeneration != candidate.controlGeneration {
		return fmt.Errorf("control connection changed during session dial")
	}
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()
	if !verified {
		return fmt.Errorf("control attestation changed during session dial")
	}
	if current, exists := cm.sessionConns[candidate.sessionID]; exists && current != candidate {
		return fmt.Errorf("session %s already has a TEE_T connection", candidate.sessionID)
	}
	if len(cm.sessionConns) >= MaxConcurrentSessions {
		return fmt.Errorf("max concurrent sessions (%d) reached (race)", MaxConcurrentSessions)
	}
	currentSession, err := cm.teek.sessionManager.GetSession(candidate.sessionID)
	if err != nil || currentSession != candidate.session {
		return fmt.Errorf("session identity changed during session dial")
	}
	acknowledged, acknowledgedExists := cm.acknowledgedSessions[candidate.sessionID]
	if candidate.admissionOwner != nil {
		if !acknowledgedExists || acknowledged != candidate.admissionOwner {
			return fmt.Errorf("acknowledged session owner changed during session dial")
		}
	} else if acknowledgedExists {
		return fmt.Errorf("session connection is missing its acknowledged owner")
	}
	if acknowledgedExists {
		delete(cm.acknowledgedSessions, candidate.sessionID)
	}
	cm.sessionConns[candidate.sessionID] = candidate
	return nil
}

func (cm *TEETConnectionManager) releaseAcknowledgedSessionOwner(sessionID string, owner *controlConnectionToken) bool {
	if owner == nil {
		return false
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.acknowledgedSessions[sessionID] != owner {
		return false
	}
	delete(cm.acknowledgedSessions, sessionID)
	return true
}

// handleSessionMessages handles incoming messages on a per-session connection
// ZERO TOLERANCE: Any error terminates the session and closes the connection
func (cm *TEETConnectionManager) handleSessionMessages(sessionConn *SessionTEETConnection) {
	if sessionConn == nil || sessionConn.session == nil {
		return
	}
	sessionID := sessionConn.sessionID
	identity := &teekSessionIdentity{session: sessionConn.session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}

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
			locallyClosed := sessionConn.isClosed()
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.WithSession(sessionID).Debug("Session connection closed normally")
			} else if !locallyClosed {
				cm.logger.WithSession(sessionID).Error("Session connection lost", zap.Error(err))
			}
			cm.handleSessionReadFailure(identity, err, locallyClosed)
			return // Cleanup handled by defer
		}
		if err := identity.ensureCurrent(); err != nil {
			return
		}

		// Route message to TEEK's handler
		if err := cm.teek.handleSharedTEETMessage(identity, msgBytes); err != nil {
			return
		}
	}
}

func (cm *TEETConnectionManager) handleSessionReadFailure(identity *teekSessionIdentity, err error, locallyClosed bool) {
	if locallyClosed || identity == nil || identity.ensureCurrent() != nil {
		return
	}
	cm.teek.terminateSessionWithErrorForIdentity(identity, shared.ReasonConnectionLost, err, "TEE_T session connection lost")
}

func (cm *TEETConnectionManager) validateSessionConnection(sessionConn *SessionTEETConnection) error {
	if sessionConn == nil || sessionConn.session == nil || sessionConn.controlConn == nil {
		return fmt.Errorf("session connection identity is incomplete")
	}
	cm.mu.RLock()
	err := cm.validateSessionConnectionLocked(sessionConn)
	cm.mu.RUnlock()
	return err
}

// validateSessionConnectionLocked validates one per-session identity while its
// caller holds cm.mu for the complete control-generation lease.
func (cm *TEETConnectionManager) validateSessionConnectionLocked(sessionConn *SessionTEETConnection) error {
	if sessionConn == nil || sessionConn.session == nil || sessionConn.controlConn == nil {
		return fmt.Errorf("session connection identity is incomplete")
	}
	current := cm.sessionConns[sessionConn.sessionID]
	controlCurrent := cm.controlConn == sessionConn.controlConn && cm.controlGeneration == sessionConn.controlGeneration
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()
	if current != sessionConn || !controlCurrent || !verified {
		return fmt.Errorf("session connection was superseded")
	}
	currentSession, err := cm.teek.sessionManager.GetSession(sessionConn.sessionID)
	if err != nil || currentSession != sessionConn.session {
		return fmt.Errorf("session identity was superseded")
	}
	return nil
}

func (cm *TEETConnectionManager) identityForSession(session *shared.Session) (*teekSessionIdentity, error) {
	if session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	cm.mu.RLock()
	sessionConn := cm.sessionConns[session.ID]
	cm.mu.RUnlock()
	if sessionConn == nil || sessionConn.session != session {
		return nil, fmt.Errorf("session has no current TEE_T connection")
	}
	identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}
	if err := identity.ensureCurrent(); err != nil {
		return nil, err
	}
	return identity, nil
}

// SendOnControl sends a message on the control connection
func (cm *TEETConnectionManager) SendOnControl(env *teeproto.Envelope) error {
	cm.mu.RLock()
	conn := cm.controlConn
	generation := cm.controlGeneration
	cm.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("control connection not available")
	}
	return cm.sendOnControlConnection(conn, generation, env)
}

// sendOnControlConnection writes only to the exact connection generation the
// caller selected. It prevents a delayed SessionCreated send from migrating to
// a replacement control connection.
func (cm *TEETConnectionManager) sendOnControlConnection(conn *shared.WSConnection, generation uint64, env *teeproto.Envelope) error {
	if !cm.isCurrentControlConnection(conn, generation) {
		return fmt.Errorf("%w: control connection changed before send", errControlUnavailableBeforeWrite)
	}

	// Check attestation
	cm.attestationMutex.RLock()
	verified := cm.attestationVerified
	cm.attestationMutex.RUnlock()

	if !verified {
		return fmt.Errorf("%w: control attestation not verified", errControlUnavailableBeforeWrite)
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

func (cm *TEETConnectionManager) hasSessionConnection(sessionID string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.sessionConns[sessionID] != nil
}

func (cm *TEETConnectionManager) sendSessionClosedOnControl(sessionID, reason string, origin *controlConnectionToken) error {
	if origin == nil || origin.conn == nil {
		return fmt.Errorf("acknowledged control identity is missing")
	}
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
	return cm.sendOnControlConnection(origin.conn, origin.generation, env)
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

// CloseSessionConnection closes the exact session's per-session connection and notifies TEE_T
// ZERO TOLERANCE: Always closes connection, always notifies TEE_T (best effort)
func (cm *TEETConnectionManager) CloseSessionConnection(session *shared.Session, reason string) {
	if session == nil {
		return
	}
	sessionID := session.ID
	cm.mu.Lock()
	sessionConn := cm.sessionConns[sessionID]
	if sessionConn != nil && sessionConn.session == session {
		delete(cm.sessionConns, sessionID)
	} else {
		sessionConn = nil
	}
	acknowledged := cm.acknowledgedSessions[sessionID]
	if acknowledged != nil && acknowledged.session == session {
		delete(cm.acknowledgedSessions, sessionID)
	} else {
		acknowledged = nil
	}
	cm.mu.Unlock()

	if sessionConn == nil && acknowledged == nil {
		return
	}

	if sessionConn != nil {
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
		acknowledged = &controlConnectionToken{
			conn: sessionConn.controlConn, generation: sessionConn.controlGeneration, session: session,
		}
	}

	// Send SessionClosed notification on the owning control (best effort).
	if err := cm.sendSessionClosedOnControl(sessionID, reason, acknowledged); err != nil {
		cm.logger.WithSession(sessionID).Warn("Failed to send SessionClosed notification", zap.Error(err))
	}
}

func (cm *TEETConnectionManager) SendOnExactSession(identity *teekSessionIdentity, env *teeproto.Envelope) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}
	sessionConn := identity.sessionConn
	sessionConn.mu.Lock()
	defer sessionConn.mu.Unlock()
	if sessionConn.closed {
		return fmt.Errorf("session connection is closed")
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return sessionConn.conn.WriteMessage(websocket.BinaryMessage, data)
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
