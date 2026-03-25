package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// MaxWebSocketMessageSize is the maximum allowed WebSocket message size (30 MB)
// Sized for OT precomputation: 100,000 COSenderSetups at ~200 bytes each = ~20 MB
const MaxWebSocketMessageSize = 30 * 1024 * 1024

var teekUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
	ReadBufferSize:  64 * 1024, // 64 KB read buffer
	WriteBufferSize: 64 * 1024, // 64 KB write buffer
}

// WebSocketConn adapts websocket to net.Conn interface for miniTLS
type WebSocketConn struct {
	wsConn      *websocket.Conn
	readBuffer  []byte
	readOffset  int
	pendingData chan []byte
	teek        *TEEK  // Reference to TEEK for transcript collection
	sessionID   string // Session ID for per-session transcript collection
}

// createTLSWebSocketDialer creates a WebSocket dialer with TLS config for secure connections
func createTLSWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		TLSClientConfig: shared.GetTLSConfig(),
	}
}

// establishSharedTEETConnection establishes the single persistent connection to TEE_T
func (t *TEEK) establishSharedTEETConnection() {
	t.logger.Debug("Establishing shared persistent connection to TEE_T")

	for {
		conn, err := t.attemptTEETConnection("shared", 1)
		if err != nil {
			t.logger.Error("Failed to establish shared TEE_T connection, retrying immediately", zap.Error(err))
			time.Sleep(1 * time.Second)
			continue
		}

		t.teetConnMutex.Lock()
		t.sharedTEETConn = conn
		t.teetConnMutex.Unlock()

		t.logger.Debug("Shared persistent connection to TEE_T established")

		// Start monitoring the connection in background (handles incoming messages)
		go t.monitorSharedTEETConnection()

		// Perform OT precomputation - this BLOCKS until complete
		if err := t.performOTPrecomputation(oprfmpc.OTPoolInitialSize, true); err != nil {
			t.logger.Error("Failed to perform OT precomputation", zap.Error(err))
			// Close connection and retry
			conn.Close()
			t.teetConnMutex.Lock()
			t.sharedTEETConn = nil
			t.teetConnMutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}

		t.logger.Info("OT precomputation complete, TEE_K ready to accept clients")
		break
	}
}

// monitorSharedTEETConnection monitors the shared connection and handles all incoming messages
func (t *TEEK) monitorSharedTEETConnection() {
	t.teetConnMutex.RLock()
	conn := t.sharedTEETConn
	t.teetConnMutex.RUnlock()

	t.logger.Debug("Starting shared TEE_T connection message handler")

	// Handle all incoming messages from TEE_T
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.Debug("Shared TEE_T connection closed")
			} else {
				t.logger.Error("Shared TEE_T connection lost, reconnecting", zap.Error(err))
			}

			// Clear attestation flag on disconnect
			t.teetAttestationMutex.Lock()
			t.teetAttestationVerified = false
			t.teetAttestationMutex.Unlock()

			// Clear OT pool on disconnect (prevents replay attacks)
			t.clearOTPool()

			// Clear the broken connection
			t.teetConnMutex.Lock()
			t.sharedTEETConn = nil
			t.teetConnMutex.Unlock()

			// Reconnect (will re-do attestation and OT precomputation)
			t.establishSharedTEETConnection()
			break
		}

		// Parse and route the message to the appropriate session
		t.handleSharedTEETMessage(msgBytes)
	}
}

// handleSharedTEETMessage processes messages from TEE_T and routes them to sessions
func (t *TEEK) handleSharedTEETMessage(msgBytes []byte) {
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		t.logger.Error("Failed to parse TEE_T message", zap.Error(err))
		return
	}

	sessionID := env.GetSessionId()
	if sessionID == "" {
		t.logger.Error("Received TEE_T message without session ID")
		return
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
		handlerErr = t.handleBatchedResponseLengths(sessionID, msg)

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
		if handlerErr = t.handleBatchedTagVerifications(sessionID, msg); handlerErr != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonCryptoTagVerificationFailed, handlerErr, "Tag verification processing failed")
		}
		return

	case *teeproto.Envelope_Error:
		// TEE_T encountered an error (likely a response to our earlier error)
		// Log it but don't terminate again (session is likely already terminating)
		t.logger.WithSession(sessionID).Info("Received error from TEE_T", zap.String("error", p.Error.GetMessage()))
		return

	// OT Precomputation messages (2-round OPRF protocol)
	case *teeproto.Envelope_OtPrecomputeResponse:
		if handlerErr = t.handleOTPrecomputeResponse(p.OtPrecomputeResponse); handlerErr != nil {
			t.logger.Error("OT precompute response failed", zap.Error(handlerErr))
		}
		return

	case *teeproto.Envelope_OprfMpcResult:
		if handlerErr = t.handleOPRFResult(sessionID, p.OprfMpcResult); handlerErr != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonOPRFProtocolFailed, handlerErr, "MPC OPRF result handling failed")
		}
		return

	case *teeproto.Envelope_CiphertextReady:
		if handlerErr = t.handleCiphertextReady(sessionID, p.CiphertextReady); handlerErr != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonResponseValidationFailed, handlerErr, "Ciphertext verification failed")
		}
		return

	default:
		err := fmt.Errorf("unknown TEE_T message type: %T", p)
		t.terminateSessionWithError(sessionID, shared.ReasonUnknownMessageType, err, "Unknown TEE_T message type")
		return
	}

	// ZERO ERROR POLICY: Any handler error terminates the session immediately
	// This catches handleBatchedResponseLengths errors
	if handlerErr != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonResponseValidationFailed, handlerErr, "Response processing failed")
	}
}

// getSharedTEETConnection returns the shared connection, establishing it if needed
func (t *TEEK) getSharedTEETConnection() *websocket.Conn {
	t.teetConnMutex.RLock()
	conn := t.sharedTEETConn
	t.teetConnMutex.RUnlock()

	if conn == nil {
		t.logger.Warn("Shared TEE_T connection not available, this should not happen in normal operation")
		return nil
	}

	return conn
}

// attemptTEETConnection performs a single connection attempt to TEE_T with attestation
func (t *TEEK) attemptTEETConnection(sessionID string, attempt int) (*websocket.Conn, error) {
	logger := t.logger.WithSession(sessionID)

	logger.Debug("Starting TEE_T connection attempt", zap.Int("attempt", attempt))

	// Dial WebSocket
	var conn *websocket.Conn
	var err error

	if strings.HasPrefix(t.teetURL, "wss://") {
		// Secure connection - use TLS dialer
		logger.Debug("Using TLS WebSocket dialer")
		dialer := createTLSWebSocketDialer()
		conn, _, err = dialer.Dial(t.teetURL, nil)
	} else {
		// Standalone mode (ws://) - use default dialer
		logger.Debug("Standalone mode - using default dialer")
		conn, _, err = websocket.DefaultDialer.Dial(t.teetURL, nil)
	}

	if err != nil {
		return nil, err
	}

	logger.Debug("WebSocket connected, starting attestation exchange")

	// Generate and send TEE_K attestation
	attestation, err := t.generateAttestationForTEET()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	env := &teeproto.Envelope{
		SessionId:   "mutual_auth",
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

	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send attestation: %v", err)
	}

	logger.Debug("Sent TEE_K attestation")

	// Wait for TEE_T attestation response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to receive TEE_T attestation: %v", err)
	}

	// Extract TLS certificate
	var tlsCert []byte
	if strings.HasPrefix(t.teetURL, "wss://") {
		tlsCert, err = shared.ExtractTLSCertFromWebSocket(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to extract TLS cert: %v", err)
		}
	}

	// Verify TEE_T attestation
	if err := t.verifyTEETAttestation(msgBytes, tlsCert); err != nil {
		conn.Close()
		return nil, fmt.Errorf("attestation verification failed: %v", err)
	}

	// Mark attestation as verified
	t.teetAttestationMutex.Lock()
	t.teetAttestationVerified = true
	t.teetAttestationMutex.Unlock()

	logger.Debug("TEE_T attestation verified")

	return conn, nil
}

// connectToTEET now uses the shared connection instead of creating new ones
func (t *TEEK) connectToTEET(sessionID string) (*websocket.Conn, error) {
	t.logger.WithSession(sessionID).Debug("Using shared persistent connection to TEE_T")

	conn := t.getSharedTEETConnection()
	if conn == nil {
		return nil, fmt.Errorf("shared TEE_T connection not available")
	}

	t.logger.WithSession(sessionID).Debug("Shared connection to TEE_T available for session")
	return conn, nil
}

// handleWebSocket handles incoming WebSocket connections from clients
func (t *TEEK) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Reject connections if system not ready (prevents wasted client work)
	if !t.isOTPoolReady() {
		t.logger.Warn("Rejecting client connection - OT pool not ready")
		http.Error(w, "Service temporarily unavailable - OT pool not ready", http.StatusServiceUnavailable)
		return
	}
	if t.getSharedTEETConnection() == nil {
		t.logger.Warn("Rejecting client connection - TEE_T connection not established")
		http.Error(w, "Service temporarily unavailable - TEE connection not established", http.StatusServiceUnavailable)
		return
	}

	conn, err := teekUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade websocket", zap.Error(err))
		return
	}

	// Set maximum message size to prevent memory exhaustion
	conn.SetReadLimit(MaxWebSocketMessageSize)

	// Create session for this client connection
	wsConn := shared.NewWSConnection(conn)
	sessionID, err := t.sessionManager.CreateSession(wsConn)
	if err != nil {
		t.logger.Error("Failed to create session", zap.Error(err))
		conn.Close()
		return
	}

	t.logger.Info("Session created", zap.String("sid", shared.TruncateSessionID(sessionID)))

	// Notify TEE_T about the new session (with retry for shared connection)
	if err := t.notifyTEETNewSessionWithRetry(sessionID); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to notify TEE_T about session after retries", zap.Error(err))
		t.sessionManager.CloseSession(sessionID)
		return
	}

	// Send session ready message to client
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionReady{SessionReady: &teeproto.SessionReady{Ready: true}},
	}
	if data, err := proto.Marshal(env); err != nil || wsConn.WriteMessage(websocket.BinaryMessage, data) != nil {
		t.logger.WithSession(sessionID).Error("Failed to send session ready to client", zap.Error(err))
		t.sessionManager.CloseSession(sessionID)
		return
	}

	// shared.Message handling loop
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
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
			rr := shared.RedactedRequestData{RedactedRequest: p.RedactedRequest.GetRedactedRequest(), Commitments: p.RedactedRequest.GetCommitments(), RedactionRanges: ranges}
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
	t.sessionManager.CloseSession(sessionID)
}

// notifyTEETNewSessionWithRetry retries session notification if shared connection isn't ready
func (t *TEEK) notifyTEETNewSessionWithRetry(sessionID string) error {
	maxRetries := 5
	retryDelay := 100 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := t.notifyTEETNewSession(sessionID)
		if err == nil {
			return nil
		}

		// If it's a "connection not available" error and we have retries left, wait and retry
		if strings.Contains(err.Error(), "shared TEE_T connection not available") && attempt < maxRetries {
			t.logger.WithSession(sessionID).Warn("Shared TEE_T connection not ready, retrying...",
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries),
				zap.Duration("retry_delay", retryDelay))
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
			continue
		}

		// For other errors or final attempt, return the error
		return err
	}

	return fmt.Errorf("failed to notify TEE_T after %d attempts", maxRetries)
}

// notifyTEETNewSession creates per-session connection and sends session registration to TEE_T
func (t *TEEK) notifyTEETNewSession(sessionID string) error {
	// Get shared connection to TEE_T
	teetConn, err := t.connectToTEET(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get shared TEE_T connection for session %s: %v", sessionID, err)
	}

	// Store the shared connection in the session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		// Don't close shared connection on session error
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	wsConn := shared.NewWSConnection(teetConn)
	session.TEETConn = wsConn

	// No per-session message handler needed - shared connection is monitored centrally

	// Send session registration to TEE_T via protobuf
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionCreated{SessionCreated: &teeproto.SessionCreated{}},
	}
	if data, err := proto.Marshal(env); err != nil {
		return fmt.Errorf("failed to marshal session registration: %v", err)
	} else if err := wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("failed to send session registration: %v", err)
	}

	t.logger.WithSession(sessionID).Debug("TEE_T session registered")
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
	case <-time.After(2 * time.Second):
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

	// Use thread-safe WriteMessage - this WebSocketConn wraps a raw websocket.Conn
	// so we need to add our own mutex protection
	// For now, use the raw WriteMessage but this could be a race condition source
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
