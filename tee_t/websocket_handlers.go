package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// handleClientWebSocket handles WebSocket connections from clients
func (t *TEET) handleClientWebSocket(w http.ResponseWriter, r *http.Request) {
	// Reject connections if system not ready (prevents wasted client work)
	if !t.isTEEKConnected() {
		t.logger.Warn("Rejecting client connection - TEE_K not connected")
		http.Error(w, "Service temporarily unavailable - TEE connection not established", http.StatusServiceUnavailable)
		return
	}
	if !t.isOTReceiverPoolReady() {
		t.logger.Warn("Rejecting client connection - OT receiver pool not ready")
		http.Error(w, "Service temporarily unavailable - OT pool not ready", http.StatusServiceUnavailable)
		return
	}

	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Debug("Failed to upgrade client websocket", zap.Error(err))
		return
	}
	defer conn.Close() // Ensure connection is always closed on exit

	// Set read limit to prevent DoS via large messages
	conn.SetReadLimit(MaxWebSocketMessageSize)

	t.logger.Debug("Client WebSocket connection established")

	var sessionID string

	for {

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.Debug("Client connection closed")
			} else if !isNetworkShutdownError(err) {
				t.logger.Error("Client connection error", zap.Error(err))
				if sessionID != "" {
					t.terminateSessionWithError(sessionID, shared.ReasonConnectionLost, err, "Client connection lost")
				}
			}
			break
		}

		// t.logger.Debug("Received raw message from client",
		// 	zap.Int("bytes", len(msgBytes)),
		// 	zap.String("preview", string(msgBytes[:min(100, len(msgBytes))])))

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			t.logger.Error("Failed to parse message from client", zap.Error(err))
			if sessionID != "" {
				t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse message from client")
			}
			break
		}
		var msg *shared.Message
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_RedactionStreams:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgRedactionStreams, Data: shared.RedactionStreamsData{Streams: p.RedactionStreams.GetStreams(), CommitmentKeys: p.RedactionStreams.GetCommitmentKeys()}}
		case *teeproto.Envelope_Finished:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgFinished, Data: shared.FinishedMessage{}}
		case *teeproto.Envelope_BatchedEncryptedResponses:
			var arr []shared.EncryptedResponseData
			for _, r := range p.BatchedEncryptedResponses.GetResponses() {
				arr = append(arr, shared.EncryptedResponseData{EncryptedData: r.GetEncryptedData(), Tag: r.GetTag(), RecordHeader: r.GetRecordHeader(), SeqNum: r.GetSeqNum(), ExplicitIV: r.GetExplicitIv()})
			}
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgBatchedEncryptedResponses, Data: shared.BatchedEncryptedResponseData{Responses: arr, SessionID: p.BatchedEncryptedResponses.GetSessionId(), TotalCount: int(p.BatchedEncryptedResponses.GetTotalCount())}}
		case *teeproto.Envelope_OprfRangesSubmission:
			// Create a message to go through session validation first
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgOPRFRanges, Data: p.OprfRangesSubmission}
		default:
			t.sendErrorToClient(sessionID, "Unknown message type")
		}

		t.logger.Debug("Received client message", zap.String("type", string(msg.Type)))

		if msg.SessionID != "" {
			if sessionID == "" {
				sessionID = msg.SessionID
				wsConn := shared.NewWSConnection(conn)
				if err := t.sessionManager.ActivateSession(sessionID, wsConn); err != nil {
					t.logger.WithSession(sessionID).Error("Failed to activate session", zap.Error(err))
					// Send error directly to client since session doesn't exist
					errEnv := &teeproto.Envelope{
						SessionId:   sessionID,
						TimestampMs: time.Now().UnixMilli(),
						Payload: &teeproto.Envelope_Error{
							Error: &teeproto.ErrorData{Message: fmt.Sprintf("Session activation failed: %v", err)},
						},
					}
					if data, marshalErr := proto.Marshal(errEnv); marshalErr == nil {
						conn.WriteMessage(websocket.BinaryMessage, data)
					}
					break
				}

				teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
				if err != nil {
					teetState = &TEETSessionState{TEETClientConn: conn}
					t.sessionManager.SetTEETSessionState(sessionID, teetState)
				} else {
					teetState.TEETClientConn = conn
				}
				t.logger.Info("Session activated", zap.String("sid", shared.TruncateSessionID(sessionID)))
			} else if msg.SessionID != sessionID {
				err := fmt.Errorf("expected %s, got %s", sessionID, msg.SessionID)
				t.terminateSessionWithError(sessionID, shared.ReasonSessionIDMismatch, err, "Session ID mismatch")
				break
			}
		}

		var handlerErr error
		switch msg.Type {
		case shared.MsgRedactionStreams:
			t.logger.Debug("Handling MsgRedactionStreams", zap.String("session_id", sessionID))
			handlerErr = t.handleRedactionStreams(sessionID, msg)
		case shared.MsgFinished:
			t.logger.Debug("Handling MsgFinished from TEE_K", zap.String("session_id", sessionID))
			handlerErr = t.handleFinishedFromTEEK(msg)
		case shared.MsgBatchedEncryptedResponses:
			t.logger.WithSession(sessionID).Debug("Handling batched encrypted responses")
			handlerErr = t.handleBatchedEncryptedResponses(sessionID, msg)
		case shared.MsgOPRFRanges:
			// Handle OPRF ranges from client (after session validation)
			// ZERO ERROR POLICY: Any error terminates the session immediately
			t.logger.WithSession(sessionID).Debug("Handling OPRF ranges")
			oprfRanges, ok := msg.Data.(*teeproto.OPRFRangesSubmission)
			if !ok {
				handlerErr = fmt.Errorf("invalid OPRF ranges data type")
			} else {
				handlerErr = t.handleOPRFRangesFromClient(sessionID, oprfRanges)
			}
		default:
			err := fmt.Errorf("unknown message type: %s", string(msg.Type))
			t.terminateSessionWithError(sessionID, shared.ReasonUnknownMessageType, err, "Unknown message type")
			return
		}

		// If handler returned error, session already terminated - exit loop
		if handlerErr != nil {
			return
		}
	}

	if sessionID != "" {
		t.logger.Info("Session finished", zap.String("sid", shared.TruncateSessionID(sessionID)))
		t.sessionManager.CloseSession(sessionID)
		t.sessionTerminator.CleanupSession(sessionID)
	}
}

// handleTEEKWebSocket handles WebSocket connections from TEE_K
func (t *TEET) handleTEEKWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade TEE_K websocket", zap.Error(err))
		return
	}

	// Set read limit to prevent DoS via large messages
	conn.SetReadLimit(MaxWebSocketMessageSize)

	t.logger.Debug("TEE_K connected")

	// Wait for attestation request (first message)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		t.logger.Error("Failed to receive attestation", zap.Error(err))
		conn.Close()
		return
	}

	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		t.logger.Error("Failed to parse message", zap.Error(err))
		t.sendErrorAndClose(conn, "", "Failed to parse attestation")
		return
	}

	req, ok := env.Payload.(*teeproto.Envelope_TeekAttestation)
	if !ok {
		t.logger.Error("Expected attestation as first message")
		t.sendErrorAndClose(conn, "", "Expected attestation request")
		return
	}

	// Verify TEE_K attestation
	if err := t.verifyTEEKAttestation(req.TeekAttestation); err != nil {
		t.logger.Error("Attestation verification failed", zap.Error(err))
		t.sendErrorAndClose(conn, "", fmt.Sprintf("Attestation failed: %v", err))
		return
	}

	t.logger.Debug("TEE_K attestation verified")

	// Generate and send our attestation
	attestation, err := t.generateAttestationForTEEK()
	if err != nil {
		t.logger.Error("Failed to generate attestation", zap.Error(err))
		t.sendErrorAndClose(conn, "", "Failed to generate attestation")
		return
	}

	respEnv := &teeproto.Envelope{
		SessionId:   "mutual_auth",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeetAttestation{
			TeetAttestation: &teeproto.TEETAttestationResponse{
				AttestationReport: attestation,
			},
		},
	}

	data, err := proto.Marshal(respEnv)
	if err != nil {
		t.logger.Error("Failed to marshal response", zap.Error(err))
		conn.Close()
		return
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.logger.Error("Failed to send attestation", zap.Error(err))
		conn.Close()
		return
	}

	t.logger.Debug("Mutual attestation completed")

	// Create single shared wrapper for TEE_K connection (internal mutex handles synchronization)
	wsConn := shared.NewWSConnection(conn)
	t.sharedTEEKConnMu.Lock()
	t.sharedTEEKConn = wsConn
	t.sharedTEEKConnMu.Unlock()

	// Mark TEE_K as connected (enables client connections)
	t.setTEEKConnected(true)

	// Ensure we mark disconnected when this function exits
	defer func() {
		t.setTEEKConnected(false)
		t.sharedTEEKConnMu.Lock()
		t.sharedTEEKConn = nil
		t.sharedTEEKConnMu.Unlock()
		t.clearOTReceiverPool() // Clear OT pool on disconnect (prevents replay)
	}()

	// Continue with existing message loop
	activeSessions := make(map[string]bool)
	var activeSessionsMutex sync.RWMutex

	for {
		_, msgBytes, err := wsConn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.Debug("TEE_K disconnected")
			} else if !isNetworkShutdownError(err) {
				t.logger.Error("TEE_K connection error", zap.Error(err))
			}
			break
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			// Log hex dump of first 64 bytes for debugging proto mismatch
			hexDump := fmt.Sprintf("%x", msgBytes)
			if len(hexDump) > 128 {
				hexDump = hexDump[:128] + "..."
			}
			t.logger.Error("Failed to parse message from TEE_K",
				zap.Error(err),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int("message_size", len(msgBytes)),
				zap.String("hex_preview", hexDump))
			// Can't send error back - we don't have a valid session ID from unparsed message
			continue
		}

		sessionID := env.GetSessionId()
		if sessionID == "" {
			t.logger.Error("Missing session ID in message from TEE_K")
			// Can't send error back - no session ID to route to
			continue
		}

		var msg *shared.Message
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_SessionCreated:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgSessionCreated, Data: map[string]any{"session_id": sessionID}}
			activeSessionsMutex.Lock()
			activeSessions[sessionID] = true
			activeSessionsMutex.Unlock()
			t.logger.Info("New session from TEE_K", zap.String("sid", shared.TruncateSessionID(sessionID)))
		case *teeproto.Envelope_KeyShareRequest:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgKeyShareRequest, Data: shared.KeyShareRequestData{KeyLength: int(p.KeyShareRequest.GetKeyLength()), IVLength: int(p.KeyShareRequest.GetIvLength())}}
		case *teeproto.Envelope_BatchedEncryptedRequest:
			// Convert protobuf fragments to shared format
			var fragments []shared.EncryptedRequestData
			for _, fragment := range p.BatchedEncryptedRequest.GetFragments() {
				var ranges []shared.RequestRedactionRange
				for _, r := range fragment.GetRedactionRanges() {
					ranges = append(ranges, shared.RequestRedactionRange{Start: int(r.GetStart()), Length: int(r.GetLength()), Type: r.GetType()})
				}
				fragments = append(fragments, shared.EncryptedRequestData{
					EncryptedData:   fragment.GetEncryptedData(),
					TagSecrets:      fragment.GetTagSecrets(),
					RedactionRanges: ranges,
					SeqNum:          fragment.GetSeqNum(),
				})
			}
			msg = &shared.Message{
				SessionID: sessionID,
				Type:      shared.MsgBatchedEncryptedRequest,
				Data: shared.BatchedEncryptedRequestData{
					Fragments:   fragments,
					BaseSeqNum:  p.BatchedEncryptedRequest.GetBaseSeqNum(),
					CipherSuite: uint16(p.BatchedEncryptedRequest.GetCipherSuite()),
					Commitments: p.BatchedEncryptedRequest.GetCommitments(),
				},
			}
		case *teeproto.Envelope_Finished:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgFinished, Data: shared.FinishedMessage{}}
		case *teeproto.Envelope_BatchedTagSecrets:
			var ts []struct {
				TagSecrets []byte `json:"tag_secrets"`
				SeqNum     uint64 `json:"seq_num"`
			}
			for _, tsec := range p.BatchedTagSecrets.GetTagSecrets() {
				ts = append(ts, struct {
					TagSecrets []byte `json:"tag_secrets"`
					SeqNum     uint64 `json:"seq_num"`
				}{TagSecrets: tsec.GetTagSecrets(), SeqNum: tsec.GetSeqNum()})
			}
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgBatchedTagSecrets, Data: shared.BatchedTagSecretsData{TagSecrets: ts, SessionID: sessionID, TotalCount: int(p.BatchedTagSecrets.GetTotalCount())}}
		case *teeproto.Envelope_Error:
			// TEE_K encountered an error (e.g., TLS handshake failure)
			// Terminate session locally without sending error back (avoid infinite loop)
			t.logger.WithSession(sessionID).Warn("Received error from TEE_K, cleaning up")
			t.cleanupSession(sessionID)
			continue
		case *teeproto.Envelope_OtPrecomputeRequest:
			// Handle OT precomputation request from TEE_K (unified init/extend)
			if err := t.handleOTPrecomputeRequest(wsConn, p.OtPrecomputeRequest); err != nil {
				t.logger.Error("Failed to handle OT precompute request", zap.Error(err))
				// Don't terminate session - this is a system-wide operation
			}
			continue
		case *teeproto.Envelope_OtPrecomputeComplete:
			// Handle OT precomputation complete acknowledgment from TEE_K
			if err := t.handleOTPrecomputeComplete(p.OtPrecomputeComplete); err != nil {
				t.logger.Error("Failed to handle OT precompute complete", zap.Error(err))
			}
			continue
		case *teeproto.Envelope_OprfOnlineFull:
			// Handle 2-round MPC OPRF online message from TEE_K
			if err := t.handleOPRFOnlineFull(sessionID, p.OprfOnlineFull); err != nil {
				t.terminateSessionWithError(sessionID, shared.ReasonOPRFEvaluationFailed, err, "Failed to handle OPRF online")
			}
			continue
		default:
			t.logger.Error("Unknown message type from TEE_K",
				zap.String("session_id", sessionID),
				zap.String("remote_addr", r.RemoteAddr))
			t.sendErrorToTEEK(sessionID, "Unknown message type from TEE_K")
			continue
		}

		t.logger.Debug("Received TEE_K message", zap.String("type", string(msg.Type)))

		var handlerErr error
		switch msg.Type {
		case shared.MsgSessionCreated:
			handlerErr = t.handleSessionCreation(msg)
			if handlerErr == nil && sessionID != "" {
				session, err := t.sessionManager.GetSession(sessionID)
				if err != nil {
					t.terminateSessionWithError(sessionID, shared.ReasonSessionManagerFailure, err, "Failed to get session after creation")
					continue
				}
				// Use the shared wrapper - all sessions share one wrapper with one mutex
				session.TEEKConn = wsConn
				t.logger.Debug("Associated TEE_K connection with session")
			}
		case shared.MsgKeyShareRequest:
			handlerErr = t.handleKeyShareRequestSession(msg)
		case shared.MsgBatchedEncryptedRequest:
			handlerErr = t.handleBatchedEncryptedRequest(msg)
		case shared.MsgFinished:
			handlerErr = t.handleFinishedFromTEEK(msg)
		case shared.MsgBatchedTagSecrets:
			handlerErr = t.handleBatchedTagSecrets(msg)
		default:
			err := fmt.Errorf("unknown message type: %s", string(msg.Type))
			t.terminateSessionWithError(sessionID, shared.ReasonUnknownMessageType, err, "Unknown message type from TEE_K")
			continue
		}

		// If handler returned error, session already terminated - continue to next message
		if handlerErr != nil {
			continue
		}
	}

	// Clear OT receiver pool on TEE_K disconnect
	// This prevents replay attacks and ensures fresh precomputation on reconnect
	t.clearOTReceiverPool()

	activeSessionsMutex.RLock()
	sessionCount := len(activeSessions)
	activeSessionsMutex.RUnlock()

	if sessionCount > 0 {
		t.logger.Warn("Cleaning up sessions due to TEE_K disconnect", zap.Int("count", sessionCount))
		activeSessionsMutex.RLock()
		for sessionID := range activeSessions {
			t.sessionTerminator.CleanupSession(sessionID)
		}
		activeSessionsMutex.RUnlock()
	}
}

// Helper function to detect network errors that occur during normal shutdown
func isNetworkShutdownError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}

// sendErrorToTEEK sends an error message to TEE_K
func (t *TEET) sendErrorToTEEK(sessionID string, errMsg string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if err := t.sessionManager.RouteToTEEK(sessionID, env); err != nil {
		t.logger.Error("Failed to send error message to TEE_K via session manager",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

// sendErrorToClient sends an error message to a client
func (t *TEET) sendErrorToClient(sessionID, errMsg string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
		t.logger.Error("Failed to send error message to client session",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

// sendErrorAndClose sends error message then closes connection
func (t *TEET) sendErrorAndClose(conn *websocket.Conn, sessionID string, errMsg string) {
	t.logger.Error("Sending error and closing", zap.String("error", errMsg))

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{
			Error: &teeproto.ErrorData{Message: errMsg},
		},
	}

	if data, err := proto.Marshal(env); err == nil {
		conn.WriteMessage(websocket.BinaryMessage, data)
	}

	time.Sleep(100 * time.Millisecond)
	conn.Close()
}
