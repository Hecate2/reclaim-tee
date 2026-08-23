package client

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// ConnectToTEEK establishes WebSocket connection to TEE_K
func (c *Client) ConnectToTEEK() error {
	c.teekConnectMutex.Lock()
	defer c.teekConnectMutex.Unlock()

	c.connectionMutex.Lock()
	if c.isClosing.Load() {
		c.connectionMutex.Unlock()
		return fmt.Errorf("client is closed")
	}
	if c.connectionsClosing {
		c.connectionMutex.Unlock()
		return fmt.Errorf("client connection cleanup is in progress")
	}
	if c.wsConn != nil {
		c.connectionMutex.Unlock()
		return nil
	}
	connectionEpoch := c.connectionEpoch
	c.connectionMutex.Unlock()

	u, err := url.Parse(c.teekURL)
	if err != nil {
		return fmt.Errorf("failed to parse TEE_K URL: %v", err)
	}

	c.logger.Info("Attempting WebSocket connection to TEE_K",
		zap.String("url", c.teekURL))

	var conn *websocket.Conn
	if c.teeDial != nil {
		conn, err = c.teeDial("tee_k", u.String())
	} else {

		// Check if native networking is enabled (for iOS VPN compatibility)
		if IsNativeNetworkingEnabled() {
			c.logger.Info("Using native networking for VPN compatibility (TEE_K)")
			dialer := createNativeNetworkDialer(c.teekURL, int(DefaultWSHandshakeTimeout.Milliseconds()))
			conn, _, err = dialer.Dial(u.String(), nil)
			if err != nil {
				c.logger.Error("Native WebSocket dial failed for TEE_K", zap.String("url", c.teekURL), zap.Error(err))
				return fmt.Errorf("native WebSocket connect failed: %w", err)
			}
		} else if strings.HasPrefix(c.teekURL, "wss://") {
			// Router-allocated wss:// — TEE serves an RA-TLS cert; the dialer
			// verifies the embedded attestation but doesn't inspect what's
			// inside it (the TEE's signed bundles carry the full attestation
			// downstream).
			c.logger.Info("Using RA-TLS dialer for TEE_K")
			dialer := newRATLSWebSocketDialer("tee_k", c.logger)
			conn, _, err = dialer.Dial(u.String(), nil)
		} else {
			// Local-dev router-standalone over plain ws://.
			c.logger.Info("Using default dialer for TEE_K (local dev)")
			conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
		}
	}

	if err != nil {
		c.logger.Error("WebSocket dial failed for TEE_K", zap.String("url", c.teekURL), zap.Error(err))
		return fmt.Errorf("failed to connect to TEE_K: %v", err)
	}
	installWebSocketReadLimit(conn)

	// Router mode: TEE_K's handleWebSocket requires ClientAuth as the very
	// first envelope. Send it now, before the message-handling goroutine
	// starts, so the response read (SessionReady) lands cleanly on its
	// dedicated loop. In direct-URL standalone mode this is a no-op.
	if c.routerJWT != "" {
		if err := sendClientAuth(conn, c.routerJWT); err != nil {
			c.logger.Error("Failed to send ClientAuth to TEE_K", zap.Error(err))
			conn.Close()
			return fmt.Errorf("send ClientAuth to TEE_K: %w", err)
		}
	}

	c.connectionMutex.Lock()
	if c.connectionEpoch != connectionEpoch {
		c.connectionMutex.Unlock()
		_ = conn.Close()
		return fmt.Errorf("TEE_K connection attempt was superseded by cleanup")
	}
	if c.isClosing.Load() || c.connectionsClosing {
		c.connectionMutex.Unlock()
		_ = conn.Close()
		return fmt.Errorf("client closed while connecting to TEE_K")
	}
	if c.wsConn != nil {
		c.connectionMutex.Unlock()
		_ = conn.Close()
		return nil
	}
	c.teekGeneration++
	generation := c.teekGeneration
	readerDone := make(chan struct{})
	c.wsConn = conn
	c.teekReaderDone = readerDone
	c.connectionMutex.Unlock()
	c.logger.Info("WebSocket connection to TEE_K established successfully")

	// Start message handling goroutine
	go c.handleMessages(conn, generation, readerDone)

	return nil
}

// ClientBuildVersion is reported to the TEE in ClientAuth so a tag failure can
// be attributed to a specific client build (empty on pre-versioning builds).
// Bump on material client changes; override at build time with
// -ldflags "-X github.com/reclaimprotocol/reclaim-tee/client.ClientBuildVersion=<ver>".
var ClientBuildVersion = "secure-boot"

// sendClientAuth writes the ClientAuth(jwt) envelope as the very first
// frame on a TEE-bound WebSocket. Used in router mode so the TEE can
// validate the JWT before allocating any session resources.
func sendClientAuth(conn *websocket.Conn, jwt string) error {
	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_ClientAuth{
			ClientAuth: &teeproto.ClientAuth{Jwt: jwt, ClientVersion: ClientBuildVersion},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal ClientAuth: %w", err)
	}
	return shared.WriteWSBinary(conn, data)
}

// ConnectToTEET establishes WebSocket connection to TEE_T
func (c *Client) ConnectToTEET() error {
	c.teetConnectMutex.Lock()
	defer c.teetConnectMutex.Unlock()

	c.connectionMutex.Lock()
	if c.isClosing.Load() {
		c.connectionMutex.Unlock()
		return fmt.Errorf("client is closed")
	}
	if c.connectionsClosing {
		c.connectionMutex.Unlock()
		return fmt.Errorf("client connection cleanup is in progress")
	}
	if c.teetConn != nil {
		c.connectionMutex.Unlock()
		return nil
	}
	connectionEpoch := c.connectionEpoch
	c.connectionMutex.Unlock()

	u, err := url.Parse(c.teetURL)
	if err != nil {
		return fmt.Errorf("failed to parse TEE_T URL: %v", err)
	}

	c.logger.Info("Attempting WebSocket connection to TEE_T",
		zap.String("url", c.teetURL))

	var conn *websocket.Conn
	if c.teeDial != nil {
		conn, err = c.teeDial("tee_t", u.String())
	} else {

		// Check if native networking is enabled (for iOS VPN compatibility)
		if IsNativeNetworkingEnabled() {
			c.logger.Info("Using native networking for VPN compatibility (TEE_T)")
			dialer := createNativeNetworkDialer(c.teetURL, int(DefaultWSHandshakeTimeout.Milliseconds()))
			conn, _, err = dialer.Dial(u.String(), nil)
			if err != nil {
				c.logger.Error("Native WebSocket dial failed for TEE_T", zap.String("url", c.teetURL), zap.Error(err))
				return fmt.Errorf("native WebSocket connect failed: %w", err)
			}
		} else if strings.HasPrefix(c.teetURL, "wss://") {
			// Router-allocated wss:// — RA-TLS verification only; the TEE's
			// signed bundles carry the attestation contents for downstream
			// verification.
			c.logger.Info("Using RA-TLS dialer for TEE_T")
			dialer := newRATLSWebSocketDialer("tee_t", c.logger)
			conn, _, err = dialer.Dial(u.String(), nil)
		} else {
			// Local-dev router-standalone over plain ws://.
			c.logger.Info("Using default dialer for TEE_T (local dev)")
			conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
		}
	}

	if err != nil {
		c.logger.Error("WebSocket dial failed for TEE_T", zap.String("url", c.teetURL), zap.Error(err))
		return fmt.Errorf("failed to connect to TEE_T: %v", err)
	}
	installWebSocketReadLimit(conn)

	// Router mode: TEE_T's client handler requires ClientAuth as the first
	// envelope, same as TEE_K. Send it before starting the read loop.
	if c.routerJWT != "" {
		if err := sendClientAuth(conn, c.routerJWT); err != nil {
			c.logger.Error("Failed to send ClientAuth to TEE_T", zap.Error(err))
			conn.Close()
			return fmt.Errorf("send ClientAuth to TEE_T: %w", err)
		}
	}

	c.connectionMutex.Lock()
	if c.connectionEpoch != connectionEpoch {
		c.connectionMutex.Unlock()
		_ = conn.Close()
		return fmt.Errorf("TEE_T connection attempt was superseded by cleanup")
	}
	if c.isClosing.Load() || c.connectionsClosing {
		c.connectionMutex.Unlock()
		_ = conn.Close()
		return fmt.Errorf("client closed while connecting to TEE_T")
	}
	if c.teetConn != nil {
		c.connectionMutex.Unlock()
		_ = conn.Close()
		return nil
	}
	c.teetGeneration++
	generation := c.teetGeneration
	readerDone := make(chan struct{})
	c.teetConn = conn
	c.teetReaderDone = readerDone
	c.connectionMutex.Unlock()
	c.logger.Info("WebSocket connection to TEE_T established successfully")

	// Start message handling goroutine for TEE_T
	go c.handleTEETMessages(conn, generation, readerDone)

	return nil
}

func (c *Client) connectTEEPair() (string, error) {
	c.pairConnectMutex.Lock()
	defer c.pairConnectMutex.Unlock()
	c.resolveClientMode()

	if err := c.ConnectToTEEK(); err != nil {
		c.resetTEEConnectionsForRetry()
		return "TEE_K", err
	}
	if err := c.ConnectToTEET(); err != nil {
		c.resetTEEConnectionsForRetry()
		return "TEE_T", err
	}
	return "", nil
}

func (c *Client) connectToTEEs() error {
	role, err := c.connectTEEPair()
	if err != nil {
		return fmt.Errorf("%s: %w", role, err)
	}
	return nil
}

// handleMessages handles incoming messages from TEE_K
func (c *Client) handleMessages(conn *websocket.Conn, generation uint64, done chan struct{}) {
	defer close(done)
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			c.handleTEEReadFailure("TEE_K", conn, generation, err)
			return
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			if !c.isClosing.Load() {
				c.terminateConnectionWithError("Failed to parse message from TEE_K", err)
				return
			}
			break
		}

		switch p := env.Payload.(type) {
		case *teeproto.Envelope_ConnectionReady:
			msg := &shared.Message{Type: shared.MsgConnectionReady, SessionID: env.GetSessionId(), Data: shared.ConnectionReadyData{Success: p.ConnectionReady.GetSuccess()}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleConnectionReady(msg)
		case *teeproto.Envelope_TcpData:
			msg := &shared.Message{Type: shared.MsgSendTCPData, SessionID: env.GetSessionId(), Data: shared.TCPData{Data: p.TcpData.GetData()}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleSendTCPData(msg)
		case *teeproto.Envelope_HandshakeComplete:
			msg := &shared.Message{Type: shared.MsgHandshakeComplete, SessionID: env.GetSessionId(), Data: shared.HandshakeCompleteData{Success: p.HandshakeComplete.GetSuccess(), CertificateChain: p.HandshakeComplete.GetCertificateChain(), CipherSuite: uint16(p.HandshakeComplete.GetCipherSuite())}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleHandshakeComplete(msg)
		case *teeproto.Envelope_SessionReady:
			msg := &shared.Message{Type: shared.MsgSessionReady, SessionID: env.GetSessionId(), Data: shared.SessionReadyData{SessionID: env.GetSessionId(), Ready: p.SessionReady.GetReady()}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleSessionReady(msg)
		case *teeproto.Envelope_Error:
			msg := &shared.Message{Type: shared.MsgError, SessionID: env.GetSessionId(), Data: shared.ErrorData{Message: p.Error.GetMessage()}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleError(msg)
		case *teeproto.Envelope_SignedMessage:
			sm := p.SignedMessage
			if err := c.acceptTEEKSignedMessage(env.GetSessionId(), sm); err != nil {
				c.terminateConnectionWithError("Invalid TEE_K signed message", err)
				return
			}
			c.logger.Info("TEE_K SignedMessage verified")
			c.checkForProtocolCompletion()

		case *teeproto.Envelope_BatchedDecryptionStreams:
			var ds []shared.ResponseDecryptionStreamData
			for _, s := range p.BatchedDecryptionStreams.GetDecryptionStreams() {
				ds = append(ds, shared.ResponseDecryptionStreamData{DecryptionStream: s.GetDecryptionStream(), SeqNum: s.GetSeqNum(), Length: int(s.GetLength())})
			}
			msg := &shared.Message{Type: shared.MsgBatchedDecryptionStreams, SessionID: env.GetSessionId(), Data: shared.BatchedDecryptionStreamData{DecryptionStreams: ds, SessionID: p.BatchedDecryptionStreams.GetSessionId(), TotalCount: int(p.BatchedDecryptionStreams.GetTotalCount())}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleBatchedDecryptionStreams(msg)
		default:
			if !c.isClosing.Load() {
				c.logger.Error("Unknown message payload from TEE_K")
			}
		}
	}
}

// handleTEETMessages handles incoming messages from TEE_T
func (c *Client) handleTEETMessages(conn *websocket.Conn, generation uint64, done chan struct{}) {
	defer close(done)
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			c.handleTEEReadFailure("TEE_T", conn, generation, err)
			return
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			if !c.isClosing.Load() {
				c.terminateConnectionWithError("Failed to parse message from TEE_T", err)
				return
			}
			break
		}

		switch p := env.Payload.(type) {
		case *teeproto.Envelope_BatchedEncryptedData:
			c.handleBatchedEncryptedRequest(env.GetSessionId(), p.BatchedEncryptedData)
		case *teeproto.Envelope_SignedMessage:
			sm := p.SignedMessage
			if err := c.acceptTEETSignedMessage(env.GetSessionId(), sm); err != nil {
				c.terminateConnectionWithError("Invalid TEE_T signed message", err)
				return
			}
			c.logger.Info("TEE_T SignedMessage verified")
			c.checkForProtocolCompletion()
		case *teeproto.Envelope_Error:
			msg := &shared.Message{Type: shared.MsgError, SessionID: env.GetSessionId(), Data: shared.ErrorData{Message: p.Error.GetMessage()}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleTEETError(msg)
		default:
			if !c.isClosing.Load() {
				c.logger.Error("Unknown TEE_T message payload")
			}
		}
	}
}

// sendEnvelope sends a protobuf envelope directly to TEE_K
func (c *Client) sendEnvelope(env *teeproto.Envelope) error {
	c.wsWriteMutex.Lock()
	defer c.wsWriteMutex.Unlock()

	c.connectionMutex.Lock()
	conn := c.wsConn
	c.connectionMutex.Unlock()
	if conn == nil {
		return fmt.Errorf("no websocket connection")
	}

	// Add session ID if available and not already set
	c.sessionMutex.RLock()
	sessionID := c.sessionID
	c.sessionMutex.RUnlock()

	if sessionID != "" && env.GetSessionId() == "" {
		env.SessionId = sessionID
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	return shared.WriteWSBinary(conn, data)
}

// sendEnvelopeToTEET sends a protobuf envelope directly to TEE_T
func (c *Client) sendEnvelopeToTEET(env *teeproto.Envelope) error {
	c.teetWriteMutex.Lock()
	defer c.teetWriteMutex.Unlock()

	c.connectionMutex.Lock()
	conn := c.teetConn
	c.connectionMutex.Unlock()
	if conn == nil {
		return fmt.Errorf("no TEE_T websocket connection")
	}

	// Add session ID if available and not already set
	c.sessionMutex.RLock()
	sessionID := c.sessionID
	c.sessionMutex.RUnlock()

	if sessionID != "" && env.GetSessionId() == "" {
		env.SessionId = sessionID
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	if err := shared.WriteWSBinary(conn, data); err != nil {
		return err
	}
	return nil
}

// sendPendingConnectionRequest sends the stored connection request with the session ID
func (c *Client) sendPendingConnectionRequest() error {
	// Check and copy the pending request while holding the lock
	c.sessionMutex.Lock()
	if !c.connectionRequestPending || c.pendingConnectionRequest == nil {
		c.sessionMutex.Unlock()
		return nil
	}

	// Copy the request data while holding lock
	reqData := *c.pendingConnectionRequest
	c.connectionRequestPending = false
	c.pendingConnectionRequest = nil
	c.sessionMutex.Unlock()

	// Now build and send envelope without holding the session lock
	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_RequestConnection{
			RequestConnection: &teeproto.RequestConnection{
				Hostname:         reqData.Hostname,
				Port:             int32(reqData.Port),
				Sni:              reqData.SNI,
				Alpn:             reqData.ALPN,
				ForceTlsVersion:  reqData.ForceTLSVersion,
				ForceCipherSuite: reqData.ForceCipherSuite,
			},
		},
	}

	if err := c.sendEnvelope(env); err != nil {
		return fmt.Errorf("failed to send connection request: %v", err)
	}

	return nil
}

func (c *Client) handleBatchedEncryptedRequest(sessionID string, batchData *teeproto.BatchedEncryptedDataResponse) {
	if !batchData.GetSuccess() {
		c.logger.Error("TEE_T reported failure in batched encrypted data")
		c.terminateConnectionWithError("TEE_T reported failure in batched encrypted data", fmt.Errorf("batchData.Success=false"))
		return
	}

	fragments := batchData.GetFragments()
	if len(fragments) == 0 {
		c.logger.Error("TEE_T returned empty fragments in batched encrypted data")
		c.terminateConnectionWithError("TEE_T returned empty fragments", fmt.Errorf("no fragments in batch response"))
		return
	}

	baseSeqNum := batchData.GetBaseSeqNum()

	c.logger.Info("Received batched encrypted request from TEE_T",
		zap.Int("fragment_count", len(fragments)),
		zap.Uint64("base_seq_num", baseSeqNum))

	// Process each fragment and send as separate TLS records
	for i, fragment := range fragments {
		seqNum := baseSeqNum + uint64(i)

		payload := minitls.CreateAEADPayload(c.cipherSuite, seqNum, fragment.GetEncryptedData(), fragment.GetAuthTag())
		tlsRecord := minitls.CreateApplicationDataRecord(payload)

		c.logger.Info("Sending TLS record fragment",
			zap.Int("fragment", i+1),
			zap.Int("of", len(fragments)),
			zap.Uint64("seq_num", seqNum),
			zap.Int("bytes", len(tlsRecord)))

		c.capturedTrafficMu.Lock()
		c.capturedTraffic = append(c.capturedTraffic, tlsRecord)
		c.capturedTrafficMu.Unlock()

		if c.tcpConn != nil {
			n, err := c.tcpConn.Write(tlsRecord)
			if err != nil {
				c.logger.Error("Failed to write TLS fragment to TCP connection", zap.Error(err))
				c.terminateConnectionWithError("Failed to write TLS fragment to TCP connection", err)
				return
			}
			c.logger.Info("Sent fragment bytes to website", zap.Int("bytes", n))
		} else {
			c.logger.Error("No TCP connection available")
			c.terminateConnectionWithError("No TCP connection available", fmt.Errorf("TCP connection to target website not established"))
			return
		}
	}

	// Mark request as sent after all fragments are sent
	c.httpRequestSent.Store(true)
	c.httpResponseExpected = true
	c.logger.Info("HTTP request sent (all fragments)", zap.Int("total_fragments", len(fragments)))
}

// validateTranscriptsAgainstCapturedTraffic performs comprehensive validation of signed transcripts

// Close closes all WebSocket connections
func (c *Client) Close() {
	c.isClosing.Store(true)
	claimed := c.claimProtocolCompletionWithState()
	c.stopCoreProtocolWatchdog()

	// Close the underlying TCP conn; let the closed-conn error propagate
	// to the TCP-reader. Don't nil the pointer — readers may be mid-deref.
	if c.tcpConn != nil {
		c.tcpConn.Close()
	}

	c.closeTEEConnectionsInternal(true)
	c.closeAttestorClient()
	if claimed {
		if c.closeBeforePublishHook != nil {
			c.closeBeforePublishHook()
		}
		c.publishProtocolCompletion(fmt.Errorf("client closed"))
	}
}

// closeTEEConnections detaches the published pair before closing either
// socket. Reader failures caused by this cleanup are therefore stale and
// cannot terminate a later connection generation.
func (c *Client) closeTEEConnections() {
	c.closeTEEConnectionsInternal(false)
}

func (c *Client) resetTEEConnectionsForRetry() {
	c.closeTEEConnectionsInternal(true)
	c.closeAttestorClient()
	c.sessionMutex.Lock()
	c.sessionID = ""
	c.pendingConnectionRequest = nil
	c.connectionRequestPending = false
	c.sessionMutex.Unlock()
}

func (c *Client) closeTEEConnectionsInternal(waitForReaders bool) {
	c.connectionCleanupMutex.Lock()
	c.connectionMutex.Lock()
	if c.connectionsClosing {
		cleanupDone := c.connectionCleanupDone
		c.connectionMutex.Unlock()
		c.connectionCleanupMutex.Unlock()
		if waitForReaders && cleanupDone != nil {
			<-cleanupDone
		}
		return
	}
	c.connectionsClosing = true
	cleanupDone := make(chan struct{})
	c.connectionCleanupDone = cleanupDone
	teekConn := c.wsConn
	teetConn := c.teetConn
	teekReaderDone := c.teekReaderDone
	teetReaderDone := c.teetReaderDone
	c.connectionEpoch++
	c.wsConn = nil
	c.teetConn = nil
	c.teekReaderDone = nil
	c.teetReaderDone = nil
	c.connectionMutex.Unlock()
	c.connectionCleanupMutex.Unlock()

	c.closeTEEKConnection(teekConn)
	c.closeTEETConnection(teetConn)
	if waitForReaders {
		if teekReaderDone != nil {
			<-teekReaderDone
		}
		if teetReaderDone != nil {
			<-teetReaderDone
		}
	}

	c.connectionMutex.Lock()
	c.connectionsClosing = false
	c.connectionCleanupDone = nil
	close(cleanupDone)
	c.connectionMutex.Unlock()
}

func (c *Client) closeTEEKConnection(conn *websocket.Conn) {
	if conn == nil {
		return
	}
	c.closeWebSocketConnection(conn)
}

func (c *Client) closeTEETConnection(conn *websocket.Conn) {
	if conn == nil {
		return
	}
	c.closeWebSocketConnection(conn)
}

const webSocketCloseControlTimeout = 25 * time.Millisecond

func (c *Client) closeWebSocketConnection(conn *websocket.Conn) {
	deadline := time.Now().Add(webSocketCloseControlTimeout)
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline)
	_ = conn.Close()
}

func (c *Client) handleTEEReadFailure(role string, conn *websocket.Conn, generation uint64, err error) {
	c.connectionMutex.Lock()
	if c.isClosing.Load() {
		c.connectionMutex.Unlock()
		return
	}
	current := (role == "TEE_K" && c.wsConn == conn && c.teekGeneration == generation) ||
		(role == "TEE_T" && c.teetConn == conn && c.teetGeneration == generation)
	if !current {
		c.connectionMutex.Unlock()
		return
	}
	// Prevent publication of a replacement between the exact-generation check
	// and pair cleanup.
	c.isClosing.Store(true)
	c.connectionMutex.Unlock()

	if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) && !isClientNetworkShutdownError(err) {
		c.logger.Error("Unexpected TEE websocket read failure", zap.String("tee", role), zap.Error(err))
	}
	c.terminateConnectionWithError(role+" connection closed unexpectedly", err)
}

func (c *Client) hasTEEConnection(role string) bool {
	c.connectionMutex.Lock()
	defer c.connectionMutex.Unlock()
	if role == "TEE_K" {
		return c.wsConn != nil
	}
	return c.teetConn != nil
}

// terminateConnectionWithError performs immediate connection termination due to critical error
// This implements strict fail-fast behavior - no error continuation is allowed
func (c *Client) terminateConnectionWithError(reason string, err error) {
	c.terminateConnection(reason, err, false)
}

func (c *Client) terminateConnectionWithErrorAndWait(reason string, err error) {
	c.terminateConnection(reason, err, true)
}

func (c *Client) terminateConnection(reason string, err error, waitForReaders bool) {
	claimed := c.claimProtocolCompletionWithState()
	c.terminateConnectionCleanup(reason, err, waitForReaders)
	if claimed {
		c.publishProtocolCompletion(fmt.Errorf("%s: %v", reason, err))
	}
}

func (c *Client) terminateConnectionCleanup(reason string, err error, waitForReaders bool) {
	// Log the critical error
	c.logger.Error("CRITICAL ERROR - terminating connection", zap.String("reason", reason), zap.Error(err))

	c.logBatchDiagnostics(reason)

	// Perform immediate cleanup and termination. Reader-originated failures do
	// not wait on their own goroutine; caller-originated start/timeout failures
	// wait until both exact reader generations have exited.
	c.isClosing.Store(true)
	if c.tcpConn != nil {
		_ = c.tcpConn.Close()
	}
	c.closeTEEConnectionsInternal(waitForReaders)
	c.closeAttestorClient()

}

func (c *Client) closeAttestorClient() {
	c.attestorMutex.Lock()
	attestorClient := c.attestorClient
	c.attestorClient = nil
	c.attestorMutex.Unlock()
	if attestorClient != nil {
		_ = attestorClient.Close()
	}
}

// logBatchDiagnostics dumps the fingerprints of the last batch sent to TEE_T
// so a failure can be correlated with TEE_T's per-record fingerprints. Tail
// records are logged individually (failures cluster there); volume is bounded.
func (c *Client) logBatchDiagnostics(reason string) {
	diag := c.lastBatchDiag
	if len(diag) == 0 {
		return
	}
	const tail = 48
	start := 0
	if len(diag) > tail {
		start = len(diag) - tail
	}
	c.logger.Warn("Response batch diagnostics",
		zap.String("reason", reason),
		zap.Int("records", len(diag)),
		zap.Uint64("first_seq", diag[0].seq),
		zap.Uint64("last_seq", diag[len(diag)-1].seq),
		zap.Int("logged_tail", len(diag)-start),
		zap.Int64("concurrent_captures", activeResponseCaptures.Load()))
	for _, d := range diag[start:] {
		c.logger.Info("resp-record-fp", zap.Uint64("seq", d.seq), zap.Int("len", d.length), zap.String("fp", d.fp))
	}
}

// sendOPRFRangesToTEEK sends MPC OPRF ranges to TEE_K only. TEE_K relays them
// to TEE_T (with TotalRanges) over the mutually-attested inter-TEE connection,
// so TEE_T learns ranges from a single ordered source rather than racing a
// separate client message.
func (c *Client) sendOPRFRangesToTEEK(ranges []*teeproto.OPRFRangeSpec) error {
	env := &teeproto.Envelope{
		SessionId:   c.sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfRangesSubmission{
			OprfRangesSubmission: &teeproto.OPRFRangesSubmission{
				SessionId: c.sessionID,
				Ranges:    ranges,
			},
		},
	}

	if err := c.sendEnvelope(env); err != nil {
		return fmt.Errorf("send to TEE_K: %w", err)
	}

	c.oprfMpcRangesSent = true
	c.oprfMpcRangesSpec = ranges
	return nil
}
