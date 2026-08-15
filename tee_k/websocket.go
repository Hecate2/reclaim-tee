package main

import (
	"errors"
	"fmt"
	"io"
	"net"
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

// MaxWebSocketMessageSize is the maximum allowed WebSocket message size (30 MB)
// The 100,000-OT KOS2 commitment response is 1,607,840 bytes before protobuf
// framing, and the fixed online garbled-circuit payload is 1,034,536 bytes.
// Preserve the existing larger policy limit for attestation and batched TLS
// messages whose encoded sizes are not governed by those MPC constants.
const MaxWebSocketMessageSize = 30 * 1024 * 1024

// HandshakeReadTimeout bounds a single minitls read of the client-relayed target
// stream. Matches the client's own handshake-stall guard (client/tcp.go) so TEE_K
// is never the first to abandon a handshake the client still considers live.
const HandshakeReadTimeout = 15 * time.Second

var teekUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
	ReadBufferSize:  64 * 1024, // 64 KB read buffer
	WriteBufferSize: 64 * 1024, // 64 KB write buffer
}

// WebSocketConn adapts websocket to net.Conn interface for miniTLS
type WebSocketConn struct {
	wsConn      *shared.WSConnection // Use wrapper for thread-safe writes
	readBuffer  []byte
	readOffset  int
	pendingData chan []byte
	// done is closed exactly once on session cleanup. Senders to pendingData
	// must select on both channels so a wedged minitls (or one that returned
	// early without draining) doesn't pin the sender goroutine forever when
	// the buffer fills up.
	done     chan struct{}
	doneOnce sync.Once

	teek      *TEEK  // Reference to TEEK for transcript collection
	sessionID string // Session ID for per-session transcript collection
}

// Shutdown signals senders to abandon pendingData. Idempotent.
func (w *WebSocketConn) Shutdown() {
	w.doneOnce.Do(func() { close(w.done) })
}

// createTLSWebSocketDialer creates a WebSocket dialer with TLS config for secure connections
func createTLSWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		TLSClientConfig: shared.GetTLSConfig(),
	}
}

// establishSharedTEETConnection establishes the control connection and completes OT precomputation
func (t *TEEK) establishSharedTEETConnection() {
	t.logger.Debug("Establishing control connection to TEE_T")

	// Initialize connection manager if not already done
	if t.connManager == nil {
		t.connManager = NewTEETConnectionManager(t, t.teetURL, t.logger)
	}

	// Establish control connection (blocks until complete, handles retries internally)
	if err := t.connManager.EstablishControlConnection(); err != nil {
		t.logger.Critical("Failed to establish control connection to TEE_T", zap.Error(err))
		return
	}

	t.logger.Info("Control connection and OT precomputation complete, TEE_K ready to accept clients")
}

// handleSharedTEETMessage processes messages from TEE_T and routes them to sessions
func (t *TEEK) handleSharedTEETMessage(identity *teekSessionIdentity, msgBytes []byte) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		t.logger.Error("Failed to parse TEE_T message", zap.Error(err))
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to parse TEE_T message")
		return err
	}

	sessionID := env.GetSessionId()
	if sessionID != identity.session.ID {
		err := fmt.Errorf("session ID mismatch: expected %s, got %s", identity.session.ID, sessionID)
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionIDMismatch, err, "Session ID mismatch from TEE_T")
		return err
	}
	if identity.beforeDispatch != nil {
		identity.beforeDispatch()
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}

	// Route session-aware messages
	var handlerErr error
	switch p := env.Payload.(type) {
	case *teeproto.Envelope_Finished:
		// Protocol specification: TEE_T no longer sends finished responses to TEE_K
		t.logger.WithSession(sessionID).Debug("Ignoring finished message from TEE_T")

	case *teeproto.Envelope_BatchedResponseLengths:
		// Build minimal shared message wrapper for existing handler
		msg := &shared.Message{SessionID: sessionID, Type: shared.MsgBatchedResponseLengths,
			Data: func() shared.BatchedResponseLengthData {
				var out shared.BatchedResponseLengthData
				out.SessionID = p.BatchedResponseLengths.GetSessionId()
				out.TotalCount = int(p.BatchedResponseLengths.GetTotalCount())
				for _, l := range p.BatchedResponseLengths.GetLengths() {
					out.Lengths = append(out.Lengths, struct {
						Length       int    `json:"length"`
						RecordHeader []byte `json:"record_header"`
						SeqNum       uint64 `json:"seq_num"`
						ExplicitIV   []byte `json:"explicit_iv,omitempty"`
					}{Length: int(l.GetLength()), RecordHeader: l.GetRecordHeader(), SeqNum: l.GetSeqNum(), ExplicitIV: l.GetExplicitIv()})
				}
				return out
			}(),
		}
		handlerErr = t.handleBatchedResponseLengths(identity, msg)

	case *teeproto.Envelope_BatchedTagVerifications:
		msg := &shared.Message{SessionID: sessionID, Type: shared.MsgBatchedTagVerifications,
			Data: func() shared.BatchedTagVerificationData {
				var out shared.BatchedTagVerificationData
				out.SessionID = p.BatchedTagVerifications.GetSessionId()
				out.TotalCount = int(p.BatchedTagVerifications.GetTotalCount())
				out.AllSuccessful = p.BatchedTagVerifications.GetAllSuccessful()
				for _, v := range p.BatchedTagVerifications.GetVerifications() {
					out.Verifications = append(out.Verifications, shared.ResponseTagVerificationData{Success: v.GetSuccess(), SeqNum: v.GetSeqNum(), Message: v.GetMessage()})
				}
				return out
			}(),
		}
		if handlerErr = t.handleBatchedTagVerifications(identity, msg); handlerErr != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagVerificationFailed, handlerErr, "Tag verification processing failed")
		}
		return handlerErr

	case *teeproto.Envelope_Error:
		return t.handlePeerErrorForIdentity(identity, p.Error)

	// OT precomputation messages.
	case *teeproto.Envelope_OtPrecomputeResponse:
		handlerErr = fmt.Errorf("OT precompute response received on per-session connection")
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonProtocolViolation, handlerErr, "Control message received on session connection")
		return handlerErr

	case *teeproto.Envelope_OprfMpcRound2:
		if handlerErr = t.handleOPRFChoiceCorrections(identity, p.OprfMpcRound2); handlerErr != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonOPRFProtocolFailed, handlerErr, "MPC OPRF correction handling failed")
		}
		return handlerErr

	case *teeproto.Envelope_OprfMpcResult:
		if handlerErr = t.handleOPRFResult(identity, p.OprfMpcResult); handlerErr != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonOPRFProtocolFailed, handlerErr, "MPC OPRF result handling failed")
		}
		return handlerErr

	case *teeproto.Envelope_CiphertextReady:
		if handlerErr = t.handleCiphertextReady(identity, p.CiphertextReady); handlerErr != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonResponseValidationFailed, handlerErr, "Ciphertext verification failed")
		}
		return handlerErr

	default:
		err := fmt.Errorf("unknown TEE_T message type: %T", p)
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonUnknownMessageType, err, "Unknown TEE_T message type")
		return err
	}

	// ZERO ERROR POLICY: Any handler error terminates the session immediately
	// This catches handleBatchedResponseLengths errors
	if handlerErr != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonResponseValidationFailed, handlerErr, "Response processing failed")
		return handlerErr
	}
	return nil
}

// handleWebSocket handles incoming WebSocket connections from clients
func (t *TEEK) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Reject connections if system not ready (prevents wasted client work)
	if !t.isOTPoolReady() {
		t.logger.Warn("Rejecting client connection - OT pool not ready")
		http.Error(w, "Service temporarily unavailable - OT pool not ready", http.StatusServiceUnavailable)
		return
	}
	if t.connManager == nil || !t.connManager.IsControlConnected() {
		t.logger.Warn("Rejecting client connection - TEE_T connection not established")
		http.Error(w, "Service temporarily unavailable - TEE connection not established", http.StatusServiceUnavailable)
		return
	}

	conn, err := teekUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Debug("Failed to upgrade websocket", zap.Error(err))
		return
	}

	// Set maximum message size to prevent memory exhaustion
	conn.SetReadLimit(MaxWebSocketMessageSize)

	// Router mode: require a valid allocation JWT as the very first envelope.
	// jwtPubKey is nil in standalone (local-dev) mode, where the JWT step
	// is skipped and the first wire message is whatever the legacy protocol
	// expects.
	var clientVersion string
	if t.jwtPubKey != nil {
		_, cv, err := shared.ReadAndVerifyClientAuth(conn, t.jwtPubKey, t.expectedJWTIssuer, t.pairID, t.jtiTracker)
		if err != nil {
			t.logger.Warn("Rejecting client: ClientAuth invalid", zap.Error(err))
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(4001, "unauthorized"),
				time.Now().Add(time.Second))
			conn.Close()
			return
		}
		clientVersion = cv
	}

	// Create session for this client connection
	wsConn := shared.NewWSConnection(conn)
	sessionID, err := t.sessionManager.CreateSession(wsConn)
	if err != nil {
		t.logger.Error("Failed to create session", zap.Error(err))
		conn.Close()
		return
	}
	t.activeSessions.Add(1)

	// client_version is empty for pre-versioning builds; a non-empty value on a
	// later tag-failure means a build that should already carry the fix.
	t.logger.Info("Session created", zap.String("sid", shared.TruncateSessionID(sessionID)),
		zap.String("client_version", clientVersion))

	// Notify TEE_T about the new session (with retry for shared connection)
	if err := t.notifyTEETNewSessionWithRetry(sessionID); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to notify TEE_T about session after retries", zap.Error(err))
		t.cleanupSession(sessionID) // Use cleanupSession to send SessionClosed to TEE_T
		return
	}

	// Send session ready message to client
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionReady{SessionReady: &teeproto.SessionReady{Ready: true}},
	}
	if data, err := proto.Marshal(env); err != nil || wsConn.WriteMessage(websocket.BinaryMessage, data) != nil {
		t.logger.WithSession(sessionID).Error("Failed to send session ready to client", zap.Error(err))
		t.cleanupSession(sessionID) // Use cleanupSession to send SessionClosed to TEE_T
		return
	}

	// shared.Message handling loop
	for {
		conn.SetReadDeadline(time.Now().Add(SessionReadTimeout))
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
				t.logger.WithSession(sessionID).Warn("Client session read timeout", zap.Duration("timeout", SessionReadTimeout))
				t.terminateSessionWithError(sessionID, shared.ReasonTimeoutExceeded, err, "client session idle timeout")
			} else if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.WithSession(sessionID).Debug("Client disconnected")
			} else if !isNetworkShutdownError(err) {
				t.logger.WithSession(sessionID).Error("Failed to read websocket message", zap.Error(err))
			}
			break
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse client message")
			return
		}
		// Verify session ID matches
		if env.GetSessionId() != sessionID {
			sessionErr := fmt.Errorf("session ID mismatch: expected %s, got %s", sessionID, env.GetSessionId())
			t.terminateSessionWithError(sessionID, shared.ReasonSessionIDMismatch, sessionErr, "Session ID mismatch")
			return
		}

		// Handle message based on type
		var handlerErr error
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_RequestConnection:
			// Inline conversion
			data := shared.RequestConnectionData{Hostname: p.RequestConnection.GetHostname(), Port: int(p.RequestConnection.GetPort()), SNI: p.RequestConnection.GetSni(), ALPN: p.RequestConnection.GetAlpn(), ForceTLSVersion: p.RequestConnection.GetForceTlsVersion(), ForceCipherSuite: p.RequestConnection.GetForceCipherSuite()}
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgRequestConnection, Data: data}
			handlerErr = t.handleRequestConnection(sessionID, msg)
		case *teeproto.Envelope_TcpReady:
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgTCPReady, Data: shared.TCPReadyData{Success: p.TcpReady.GetSuccess()}}
			handlerErr = t.handleTCPReady(sessionID, msg)
		case *teeproto.Envelope_TcpData:
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgTCPData, Data: shared.TCPData{Data: p.TcpData.GetData()}}
			handlerErr = t.handleTCPData(sessionID, msg)
		case *teeproto.Envelope_RedactedRequest:
			// Convert protobuf ranges to shared ranges
			var ranges []shared.RequestRedactionRange
			for _, r := range p.RedactedRequest.GetRedactionRanges() {
				ranges = append(ranges, shared.RequestRedactionRange{Start: int(r.GetStart()), Length: int(r.GetLength()), Type: r.GetType()})
			}
			rr := shared.RedactedRequestData{RedactedRequest: p.RedactedRequest.GetRedactedRequest(), RedactionRanges: ranges}
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgRedactedRequest, Data: rr}
			handlerErr = t.handleRedactedRequest(sessionID, msg)
		case *teeproto.Envelope_ResponseRedactionSpec:
			// Convert to shared type for existing handler logic
			var ranges []shared.ResponseRedactionRange
			for _, rr := range p.ResponseRedactionSpec.GetRanges() {
				ranges = append(ranges, shared.ResponseRedactionRange{Start: int(rr.GetStart()), Length: int(rr.GetLength())})
			}
			spec := shared.ResponseRedactionSpec{Ranges: ranges}
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgRedactionSpec, Data: spec}
			handlerErr = t.handleRedactionSpec(sessionID, msg)
		case *teeproto.Envelope_Finished:
			// Protocol specification: No client finished messages in single session mode
			// TEE_K only sends finished to TEE_T, doesn't receive from client
			t.logger.WithSession(sessionID).Debug("Ignoring finished message from client")
		case *teeproto.Envelope_OprfRangesSubmission:
			handlerErr = t.handleOPRFRangesFromClient(sessionID, p.OprfRangesSubmission)
		default:
			unknownMsgErr := fmt.Errorf("unknown message type: %T", p)
			t.terminateSessionWithError(sessionID, shared.ReasonUnknownMessageType, unknownMsgErr, "Unknown message type")
			return
		}

		// If handler returned error, session already terminated - exit loop
		if handlerErr != nil {
			return
		}
	}

	// Clean up session when connection closes
	t.logger.WithSession(sessionID).Info("Session finished")
	t.cleanupSession(sessionID) // Use cleanupSession to send SessionClosed to TEE_T
}

// notifyTEETNewSessionWithRetry retries session notification if shared connection isn't ready
func (t *TEEK) notifyTEETNewSessionWithRetry(sessionID string) error {
	return t.notifyTEETNewSessionWithRetryPolicy(sessionID, 5, 100*time.Millisecond, t.notifyTEETNewSession, time.Sleep)
}

func (t *TEEK) notifyTEETNewSessionWithRetryPolicy(sessionID string, maxRetries int, retryDelay time.Duration, notify func(string) error, wait func(time.Duration)) error {
	if maxRetries <= 0 || notify == nil || wait == nil {
		return fmt.Errorf("invalid SessionCreated retry policy")
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := notify(sessionID)
		if err == nil {
			return nil
		}

		// Retry only when SessionCreated was definitely not written. A send error
		// or ACK timeout is ambiguous: TEE_T may already own the session.
		if errors.Is(err, errSessionCreatedControlUnavailable) && attempt < maxRetries {
			t.logger.WithSession(sessionID).Warn("Shared TEE_T connection not ready, retrying...",
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries),
				zap.Duration("retry_delay", retryDelay))
			wait(retryDelay)
			retryDelay *= 2 // Exponential backoff
			continue
		}

		// For other errors or final attempt, return the error
		return err
	}

	return fmt.Errorf("failed to notify TEE_T after %d attempts", maxRetries)
}

// notifyTEETNewSession sends SessionCreated on control connection and establishes per-session connection
func (t *TEEK) notifyTEETNewSession(sessionID string) error {
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("bind SessionCreated to client session: %w", err)
	}

	// Step 1: Send SessionCreated notification on control connection
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload:     &teeproto.Envelope_SessionCreated{SessionCreated: &teeproto.SessionCreated{}},
	}

	t.logger.WithSession(sessionID).Info("Sending to TEE_T",
		zap.String("type", "SessionCreated"))

	origin, err := t.connManager.sendSessionCreatedAndWaitForSession(session, func(conn *shared.WSConnection, generation uint64) error {
		return t.connManager.sendOnControlConnection(conn, generation, env)
	})
	if err != nil {
		return err
	}

	t.logger.WithSession(sessionID).Debug("TEE_T acknowledged session creation")

	// Step 3: Establish per-session connection
	if err := t.connManager.EstablishSessionConnection(sessionID, origin); err != nil {
		return fmt.Errorf("failed to establish per-session connection: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Per-session connection established")
	return nil
}

// WebSocketConn implementation of net.Conn interface with thread-safe writes

func (w *WebSocketConn) Read(p []byte) (int, error) {
	// If we have data in the buffer, read from it first
	if w.readOffset < len(w.readBuffer) {
		n := copy(p, w.readBuffer[w.readOffset:])
		w.readOffset += n

		// If we've consumed all buffer data, reset
		if w.readOffset >= len(w.readBuffer) {
			w.readBuffer = nil
			w.readOffset = 0
		}

		return n, nil
	}

	// Wait for new data from websocket
	select {
	case data := <-w.pendingData:
		// Single Session Mode: Collect all incoming handshake packets for transcript
		// TEE_K only sees handshake packets - application data goes directly to TEE_T
		if w.teek != nil && w.sessionID != "" {
			if err := w.teek.addToTranscript(w.sessionID, data, shared.TranscriptDataTypeTLSRecord); err != nil {
				// Transcript addition is best-effort, log but don't fail the read
				// Session already terminated by addToTranscript if error is critical
				return 0, err
			}
		}

		w.readBuffer = data
		w.readOffset = 0

		n := copy(p, w.readBuffer)
		w.readOffset = n

		// If we've consumed all buffer data, reset
		if w.readOffset >= len(w.readBuffer) {
			w.readBuffer = nil
			w.readOffset = 0
		}

		return n, nil
	case <-w.done:
		return 0, io.EOF
	case <-time.After(HandshakeReadTimeout):
		return 0, fmt.Errorf("timeout reading from websocket")
	}
}

func (w *WebSocketConn) Write(p []byte) (int, error) {
	// Single Session Mode: Collect outgoing packets for transcript
	if w.teek != nil && w.sessionID != "" {
		if err := w.teek.addToTranscript(w.sessionID, p, shared.TranscriptDataTypeTLSRecord); err != nil {
			// Session already terminated by addToTranscript if error is critical
			return 0, err
		}
	}

	// Build protobuf envelope to forward TCP data to client
	env := &teeproto.Envelope{SessionId: w.sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TcpData{TcpData: &teeproto.TCPData{Data: p}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal tcp data envelope: %v", err)
	}

	// Use wrapper's WriteMessage which has internal mutex for thread safety
	if err := w.wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, fmt.Errorf("failed to send TCP data: %v", err)
	}
	return len(p), nil
}

func (w *WebSocketConn) Close() error {
	return nil // WebSocket connection is managed by TEEK
}

func (w *WebSocketConn) LocalAddr() net.Addr {
	return &dummyAddr{network: "websocket", address: "local"}
}

func (w *WebSocketConn) RemoteAddr() net.Addr {
	return &dummyAddr{network: "websocket", address: "remote"}
}

func (w *WebSocketConn) SetDeadline(t time.Time) error {
	return nil // Not implemented for WebSocket adapter
}

func (w *WebSocketConn) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for WebSocket adapter
}

func (w *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for WebSocket adapter
}

// Dummy network address implementation
type dummyAddr struct {
	network string
	address string
}

func (d *dummyAddr) Network() string {
	return d.network
}

func (d *dummyAddr) String() string {
	return d.address
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
