package main

import (
	"fmt"
	"net/http"
	"strings"
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
					t.logger.WithSession(sessionID).Error("TEETSessionState not found - session not registered via control connection", zap.Error(err))
					t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Session state not initialized")
					break
				}
				teetState.TEETClientConn = conn
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

		// Close per-session connection to TEE_K
		// This prevents TEE_K from timing out waiting for messages
		if t.connManager != nil {
			t.connManager.CloseSessionConnection(sessionID)
		}
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

// sendErrorToTEEK sends an error message to TEE_K on control connection
// Uses control connection because session connection may be dead when error occurs
func (t *TEET) sendErrorToTEEK(sessionID string, errMsg string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if t.connManager == nil {
		t.logger.Error("Cannot send error to TEE_K: connection manager not initialized",
			zap.String("session_id", sessionID))
		return
	}
	if err := t.connManager.SendOnControl(env); err != nil {
		t.logger.Error("Failed to send error message to TEE_K on control",
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

// handleControlWebSocket handles control connections from TEE_K
// Control connection is used for: attestation, OT precomputation, session lifecycle
func (t *TEET) handleControlWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade control websocket", zap.Error(err))
		return
	}

	t.logger.Debug("Control WebSocket connection from TEE_K")

	// Initialize connection manager if not already done
	if t.connManager == nil {
		t.connManager = NewTEEKConnectionManager(t, t.logger)
	}

	// Handle the control connection (blocks until disconnect)
	if err := t.connManager.HandleControlConnection(conn); err != nil {
		t.logger.Error("Control connection failed", zap.Error(err))
	}

	conn.Close()
}

// handleSessionWebSocket handles per-session connections from TEE_K
// Session connections carry all session-specific data: encrypted requests, keystream, OPRF
func (t *TEET) handleSessionWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade session websocket", zap.Error(err))
		return
	}

	t.logger.Debug("Session WebSocket connection from TEE_K")

	// Check that control connection is established and attested
	if t.connManager == nil || !t.connManager.IsAttestationVerified() {
		t.logger.Warn("Rejecting session connection - control not attested")
		t.sendErrorAndClose(conn, "", "Control connection not established or attested")
		return
	}

	// Handle the session connection (blocks until disconnect)
	if err := t.connManager.HandleSessionConnection(conn); err != nil {
		t.logger.Error("Session connection failed", zap.Error(err))
	}

	conn.Close()
}
