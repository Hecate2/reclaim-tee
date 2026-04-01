package main

import (
	"fmt"
	"strings"
	"sync"
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

// SessionReadTimeout is the maximum time to wait for a message on a session connection
const SessionReadTimeout = 1 * time.Minute

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
	slashIdx := strings.Index(rest, "/")
	var hostPort string
	if slashIdx >= 0 {
		hostPort = rest[:slashIdx]
	} else {
		hostPort = rest
	}

	return scheme + hostPort + endpoint
}

// EstablishControlConnection establishes the persistent control connection to TEE_T
// This blocks until the connection is established, attestation is verified, and OT precomputation is complete
func (cm *TEETConnectionManager) EstablishControlConnection() error {
	cm.logger.Debug("Establishing control connection to TEE_T", zap.String("url", cm.controlURL))

	for {
		conn, err := cm.attemptControlConnection()
		if err != nil {
			cm.logger.Error("Failed to establish control connection, retrying", zap.Error(err))
			time.Sleep(1 * time.Second)
			continue
		}

		wsConn := shared.NewWSConnection(conn)

		cm.mu.Lock()
		cm.controlConn = wsConn
		cm.mu.Unlock()

		cm.logger.Debug("Control connection to TEE_T established")

		// Perform OT precomputation BEFORE starting handler goroutine
		// This prevents goroutine leak if OT fails
		if err := cm.teek.performOTPrecomputation(oprfmpc.OTPoolInitialSize, true); err != nil {
			cm.logger.Error("Failed to perform OT precomputation", zap.Error(err))
			wsConn.Close()
			cm.mu.Lock()
			cm.controlConn = nil
			cm.mu.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}

		cm.logger.Info("OT precomputation complete on control connection")

		// Start control message handler AFTER OT succeeds - no goroutine leak
		go cm.handleControlMessages()

		return nil
	}
}

// attemptControlConnection performs a single connection attempt with attestation
func (cm *TEETConnectionManager) attemptControlConnection() (*websocket.Conn, error) {
	cm.logger.Debug("Starting control connection attempt")

	// Dial WebSocket
	var conn *websocket.Conn
	var err error

	if strings.HasPrefix(cm.controlURL, "wss://") {
		dialer := createTLSWebSocketDialer()
		conn, _, err = dialer.Dial(cm.controlURL, nil)
	} else {
		conn, _, err = websocket.DefaultDialer.Dial(cm.controlURL, nil)
	}

	if err != nil {
		return nil, err
	}

	cm.logger.Debug("Control WebSocket connected, starting attestation exchange")

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

	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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

	// Mark attestation as verified
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()

	// Also update TEEK's attestation flag for backward compatibility
	cm.teek.teetAttestationMutex.Lock()
	cm.teek.teetAttestationVerified = true
	cm.teek.teetAttestationMutex.Unlock()

	cm.logger.Debug("TEE_T attestation verified on control connection")

	return conn, nil
}

// handleControlMessages handles incoming messages on the control connection
func (cm *TEETConnectionManager) handleControlMessages() {
	cm.mu.RLock()
	conn := cm.controlConn
	cm.mu.RUnlock()

	if conn == nil {
		return
	}

	cm.logger.Debug("Starting control connection message handler")

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.Debug("Control connection closed")
			} else {
				cm.logger.Error("Control connection lost", zap.Error(err))
			}

			// Clear attestation flag
			cm.attestationMutex.Lock()
			cm.attestationVerified = false
			cm.attestationMutex.Unlock()

			cm.teek.teetAttestationMutex.Lock()
			cm.teek.teetAttestationVerified = false
			cm.teek.teetAttestationMutex.Unlock()

			// Clear OT pool
			cm.teek.clearOTPool()

			// Clear the broken connection
			cm.mu.Lock()
			cm.controlConn = nil
			cm.mu.Unlock()

			// Reconnect
			cm.EstablishControlConnection()
			return
		}

		// Parse and handle control message
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

// EstablishSessionConnection establishes a per-session connection to TEE_T
func (cm *TEETConnectionManager) EstablishSessionConnection(sessionID string) error {
	cm.logger.WithSession(sessionID).Debug("Establishing per-session connection to TEE_T")

	// Check session limit to prevent resource exhaustion
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

	// Dial session WebSocket
	var conn *websocket.Conn
	var err error

	if strings.HasPrefix(cm.sessionURL, "wss://") {
		dialer := createTLSWebSocketDialer()
		conn, _, err = dialer.Dial(cm.sessionURL, nil)
	} else {
		conn, _, err = websocket.DefaultDialer.Dial(cm.sessionURL, nil)
	}

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

	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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

	cm.mu.Lock()
	cm.sessionConns[sessionID] = sessionConn
	cm.mu.Unlock()

	cm.logger.WithSession(sessionID).Debug("Per-session connection established")

	// Start session message handler in background
	go cm.handleSessionMessages(sessionID)

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
		*teeproto.Envelope_SessionCreated,
		*teeproto.Envelope_SessionClosed,
		*teeproto.Envelope_Error: // Errors go on control - session may be dead
		return true
	}
	return false
}
