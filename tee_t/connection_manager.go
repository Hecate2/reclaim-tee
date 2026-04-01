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

// SessionReadTimeout is the maximum time to wait for a message on a session connection
const SessionReadTimeout = 1 * time.Minute

// ControlReadTimeout is the maximum time to wait for a message on the control connection
// Longer than session timeout since control handles OT which can take time
const ControlReadTimeout = 5 * time.Minute

// TEEKConnectionManager manages all connections from TEE_K
// - One persistent control connection for attestation, OT precomputation, and session lifecycle
// - One per-session connection for each active session's data flow
type TEEKConnectionManager struct {
	mu sync.RWMutex

	// Control connection (persistent)
	controlConn *shared.WSConnection

	// Per-session connections (limited to MaxConcurrentSessions)
	sessionConns map[string]*SessionTEEKConnection // sessionID -> connection

	// References
	teet   *TEET
	logger *shared.Logger

	// Attestation state (for control connection)
	attestationVerified bool
	attestationMutex    sync.RWMutex
}

// SessionTEEKConnection represents a per-session connection from TEE_K
type SessionTEEKConnection struct {
	sessionID   string
	conn        *shared.WSConnection
	established time.Time
	mu          sync.Mutex // Protects writes to this connection
	closed      bool
}

// NewTEEKConnectionManager creates a new connection manager
func NewTEEKConnectionManager(teet *TEET, logger *shared.Logger) *TEEKConnectionManager {
	return &TEEKConnectionManager{
		sessionConns: make(map[string]*SessionTEEKConnection),
		teet:         teet,
		logger:       logger,
	}
}

// HandleControlConnection handles a new control connection from TEE_K
// This performs attestation and then handles control messages
func (cm *TEEKConnectionManager) HandleControlConnection(conn *websocket.Conn) error {
	cm.logger.Debug("Handling control connection from TEE_K")

	// Set read limit
	conn.SetReadLimit(MaxWebSocketMessageSize)

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

	req, ok := env.Payload.(*teeproto.Envelope_TeekAttestation)
	if !ok {
		return fmt.Errorf("expected attestation as first message, got %T", env.Payload)
	}

	// Verify TEE_K attestation
	if err := cm.teet.verifyTEEKAttestation(req.TeekAttestation); err != nil {
		return fmt.Errorf("attestation verification failed: %v", err)
	}

	cm.logger.Debug("TEE_K attestation verified on control connection")

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

	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("failed to send attestation response: %v", err)
	}

	cm.logger.Debug("Mutual attestation completed on control connection")

	// Create wrapper and store connection
	wsConn := shared.NewWSConnection(conn)

	cm.mu.Lock()
	cm.controlConn = wsConn
	cm.mu.Unlock()

	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()

	// Update TEET's connection state
	cm.teet.setTEEKConnected(true)

	// Handle control messages in a loop
	cm.handleControlMessages(wsConn)

	// Cleanup on disconnect
	cm.attestationMutex.Lock()
	cm.attestationVerified = false
	cm.attestationMutex.Unlock()

	cm.mu.Lock()
	cm.controlConn = nil
	cm.mu.Unlock()

	cm.teet.setTEEKConnected(false)

	// Clear OT pool on disconnect
	cm.teet.clearOTReceiverPool()

	return nil
}

// handleControlMessages processes messages on the control connection
func (cm *TEEKConnectionManager) handleControlMessages(conn *shared.WSConnection) {
	cm.logger.Debug("Starting control message handler")

	for {
		// Set read deadline to detect dead connections
		conn.SetReadDeadline(time.Now().Add(ControlReadTimeout))
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.Debug("Control connection closed")
			} else {
				cm.logger.Error("Control connection error", zap.Error(err))
			}
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
			msg := &shared.Message{
				SessionID: sessionID,
				Type:      shared.MsgSessionCreated,
				Data:      map[string]any{"session_id": sessionID},
			}
			if err := cm.teet.handleSessionCreation(msg); err != nil {
				cm.logger.WithSession(sessionID).Error("Failed to create session", zap.Error(err))
			} else {
				cm.logger.Info("Session registered", zap.String("sid", shared.TruncateSessionID(sessionID)))
			}

		case *teeproto.Envelope_SessionClosed:
			// Session lifecycle notification - cleanup session
			cm.logger.Info("Session closed from TEE_K (control)",
				zap.String("sid", shared.TruncateSessionID(sessionID)),
				zap.String("reason", p.SessionClosed.GetReason()))
			cm.teet.cleanupSession(sessionID)

			// Also cleanup per-session connection if exists
			cm.mu.Lock()
			if sessionConn, ok := cm.sessionConns[sessionID]; ok {
				delete(cm.sessionConns, sessionID)
				cm.mu.Unlock()
				// Lock sessionConn.mu to safely set closed flag
				sessionConn.mu.Lock()
				if !sessionConn.closed {
					sessionConn.closed = true
					sessionConn.conn.Close()
				}
				sessionConn.mu.Unlock()
			} else {
				cm.mu.Unlock()
			}

		case *teeproto.Envelope_OtPrecomputeRequest:
			// OT precomputation request
			if err := cm.teet.handleOTPrecomputeRequest(conn, p.OtPrecomputeRequest); err != nil {
				cm.logger.Error("Failed to handle OT precompute request", zap.Error(err))
			}

		case *teeproto.Envelope_OtPrecomputeComplete:
			// OT precomputation complete acknowledgment
			if err := cm.teet.handleOTPrecomputeComplete(p.OtPrecomputeComplete); err != nil {
				cm.logger.Error("Failed to handle OT precompute complete", zap.Error(err))
			}

		case *teeproto.Envelope_Error:
			// Error from TEE_K - cleanup the affected session
			cm.logger.WithSession(sessionID).Error("Received error from TEE_K (control)",
				zap.String("error", p.Error.GetMessage()))
			if sessionID != "" && sessionID != "control" {
				cm.teet.cleanupSession(sessionID)
				// Also cleanup per-session connection if exists
				cm.mu.Lock()
				if sessionConn, ok := cm.sessionConns[sessionID]; ok {
					delete(cm.sessionConns, sessionID)
					cm.mu.Unlock()
					// Lock sessionConn.mu to safely set closed flag
					sessionConn.mu.Lock()
					if !sessionConn.closed {
						sessionConn.closed = true
						sessionConn.conn.Close()
					}
					sessionConn.mu.Unlock()
				} else {
					cm.mu.Unlock()
				}
			}

		default:
			cm.logger.Warn("Unexpected message type on control connection",
				zap.String("type", fmt.Sprintf("%T", p)),
				zap.String("session_id", sessionID))
		}
	}
}

// HandleSessionConnection handles a new per-session connection from TEE_K
func (cm *TEEKConnectionManager) HandleSessionConnection(conn *websocket.Conn) error {
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
		sessionID:   sessionID,
		conn:        wsConn,
		established: time.Now(),
	}

	cm.mu.Lock()
	cm.sessionConns[sessionID] = sessionConn
	cm.mu.Unlock()

	// Associate connection with session for routing (use mutex to prevent race)
	session, _ := cm.teet.sessionManager.GetSession(sessionID)
	if session != nil {
		session.ConnMutex.Lock()
		session.TEEKConn = wsConn
		session.ConnMutex.Unlock()
	}

	// Send acknowledgment
	cm.sendSessionConnectionAck(conn, sessionID, true, "")

	cm.logger.WithSession(sessionID).Debug("Per-session connection established")

	// Handle session messages in a loop
	cm.handleSessionMessages(sessionID, sessionConn)

	// Cleanup on disconnect - ZERO TOLERANCE for resource leaks
	cm.mu.Lock()
	delete(cm.sessionConns, sessionID)
	cm.mu.Unlock()

	// Explicitly close connection to ensure no leak
	sessionConn.mu.Lock()
	if !sessionConn.closed {
		sessionConn.closed = true
		sessionConn.conn.Close()
	}
	sessionConn.mu.Unlock()

	return nil
}

// handleSessionMessages processes messages on a per-session connection
// ZERO TOLERANCE: Any error terminates the session immediately
func (cm *TEEKConnectionManager) handleSessionMessages(sessionID string, sessionConn *SessionTEEKConnection) {
	cm.logger.WithSession(sessionID).Debug("Starting session message handler")

	for {
		// Set read deadline to prevent stuck connections
		sessionConn.conn.SetReadDeadline(time.Now().Add(SessionReadTimeout))
		_, msgBytes, err := sessionConn.conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				cm.logger.WithSession(sessionID).Debug("Session connection closed normally")
			} else if !sessionConn.closed {
				cm.logger.WithSession(sessionID).Error("Session connection error", zap.Error(err))
			}
			return
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			// ZERO TOLERANCE: Parse failure terminates session
			cm.logger.WithSession(sessionID).Error("Failed to parse session message - terminating", zap.Error(err))
			cm.teet.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse message from TEE_K")
			return
		}

		// ZERO TOLERANCE: Session ID mismatch terminates session immediately
		if env.GetSessionId() != sessionID {
			err := fmt.Errorf("expected %s, got %s", sessionID, env.GetSessionId())
			cm.logger.WithSession(sessionID).Error("Session ID mismatch - terminating", zap.Error(err))
			cm.teet.terminateSessionWithError(sessionID, shared.ReasonSessionIDMismatch, err, "Session ID mismatch from TEE_K")
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
			handlerErr = cm.teet.handleKeyShareRequestSession(msg)

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
					Commitments: p.BatchedEncryptedRequest.GetCommitments(),
				},
			}
			handlerErr = cm.teet.handleBatchedEncryptedRequest(msg)

		case *teeproto.Envelope_Finished:
			msg := &shared.Message{
				SessionID: sessionID,
				Type:      shared.MsgFinished,
				Data:      shared.FinishedMessage{},
			}
			handlerErr = cm.teet.handleFinishedFromTEEK(msg)

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
			handlerErr = cm.teet.handleBatchedTagSecrets(msg)

		case *teeproto.Envelope_OprfOnlineFull:
			// Handle 2-round MPC OPRF online message
			cm.logger.WithSession(sessionID).Info("OPRF timing: message received from TEE_K (session conn)",
				zap.Int("range_index", int(p.OprfOnlineFull.RangeIndex)),
				zap.Int("garbled_tables_bytes", len(p.OprfOnlineFull.GarbledTables)),
				zap.Int("dual_masks_bytes", len(p.OprfOnlineFull.DualMasks)))
			if err := cm.teet.handleOPRFOnlineFull(sessionID, p.OprfOnlineFull); err != nil {
				cm.teet.terminateSessionWithError(sessionID, shared.ReasonOPRFEvaluationFailed, err, "Failed to handle OPRF online")
				return // ZERO TOLERANCE: terminate on OPRF failure
			}

		case *teeproto.Envelope_Error:
			// TEE_K encountered an error - terminate immediately
			cm.logger.WithSession(sessionID).Error("Received error from TEE_K - terminating session")
			cm.teet.cleanupSession(sessionID)
			return

		default:
			// ZERO TOLERANCE: Unknown message type terminates session
			err := fmt.Errorf("unknown message type: %T", p)
			cm.logger.WithSession(sessionID).Error("Unknown message type - terminating session", zap.Error(err))
			cm.teet.terminateSessionWithError(sessionID, shared.ReasonUnknownMessageType, err, "Unknown message type from TEE_K")
			return
		}

		// ZERO TOLERANCE: Any handler error terminates session
		if handlerErr != nil {
			cm.teet.terminateSessionWithError(sessionID, shared.ReasonHandlerFailed, handlerErr, "Handler failed")
			return
		}
	}
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

	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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
	cm.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("control connection not available")
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

// CloseSessionConnection closes a per-session connection from TEE_T side
// Called when client disconnects from TEE_T, to prevent TEE_K from timing out
func (cm *TEEKConnectionManager) CloseSessionConnection(sessionID string) {
	cm.mu.Lock()
	sessionConn := cm.sessionConns[sessionID]
	if sessionConn != nil {
		delete(cm.sessionConns, sessionID)
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
