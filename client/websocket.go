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
	u, err := url.Parse(c.teekURL)
	if err != nil {
		return fmt.Errorf("failed to parse TEE_K URL: %v", err)
	}

	c.logger.Info("Attempting WebSocket connection to TEE_K",
		zap.String("url", c.teekURL))

	var conn *websocket.Conn

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

	if err != nil {
		c.logger.Error("WebSocket dial failed for TEE_K", zap.String("url", c.teekURL), zap.Error(err))
		return fmt.Errorf("failed to connect to TEE_K: %v", err)
	}

	c.wsConn = conn
	c.logger.Info("WebSocket connection to TEE_K established successfully")

	// Router mode: TEE_K's handleWebSocket requires ClientAuth as the very
	// first envelope. Send it now, before the message-handling goroutine
	// starts, so the response read (SessionReady) lands cleanly on its
	// dedicated loop. In direct-URL standalone mode this is a no-op.
	if c.routerJWT != "" {
		if err := sendClientAuth(conn, c.routerJWT); err != nil {
			c.logger.Error("Failed to send ClientAuth to TEE_K", zap.Error(err))
			conn.Close()
			c.wsConn = nil
			return fmt.Errorf("send ClientAuth to TEE_K: %w", err)
		}
	}

	// Start message handling goroutine
	go c.handleMessages()

	return nil
}

// ClientBuildVersion is reported to the TEE in ClientAuth so a tag failure can
// be attributed to a specific client build (empty on pre-versioning builds).
// Bump on material client changes; override at build time with
// -ldflags "-X github.com/reclaimprotocol/reclaim-tee/client.ClientBuildVersion=<ver>".
var ClientBuildVersion = "recordbuf-fix"

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
	u, err := url.Parse(c.teetURL)
	if err != nil {
		return fmt.Errorf("failed to parse TEE_T URL: %v", err)
	}

	c.logger.Info("Attempting WebSocket connection to TEE_T",
		zap.String("url", c.teetURL))

	var conn *websocket.Conn

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

	if err != nil {
		c.logger.Error("WebSocket dial failed for TEE_T", zap.String("url", c.teetURL), zap.Error(err))
		return fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	c.teetConn = conn
	c.logger.Info("WebSocket connection to TEE_T established successfully")

	// Router mode: TEE_T's client handler requires ClientAuth as the first
	// envelope, same as TEE_K. Send it before starting the read loop.
	if c.routerJWT != "" {
		if err := sendClientAuth(conn, c.routerJWT); err != nil {
			c.logger.Error("Failed to send ClientAuth to TEE_T", zap.Error(err))
			conn.Close()
			c.teetConn = nil
			return fmt.Errorf("send ClientAuth to TEE_T: %w", err)
		}
	}

	// Start message handling goroutine for TEE_T
	go c.handleTEETMessages()

	return nil
}

// handleMessages handles incoming messages from TEE_K
func (c *Client) handleMessages() {
	for {
		conn := c.wsConn
		closing := c.isClosing.Load()

		if conn == nil {
			break
		}

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			// Only log errors if we're not intentionally closing and it's not a normal shutdown condition
			if !closing {
				// Check for normal close conditions or network errors during shutdown
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				} else if !isClientNetworkShutdownError(err) {
					c.logger.Error("Failed to read websocket message", zap.Error(err))
				}
			}
			break
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			if !closing {
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
			// Handle SignedMessage from TEE_K (K_OUTPUT)
			sm := p.SignedMessage
			if sm == nil {
				break
			}
			if sm.GetBodyType() == teeproto.BodyType_BODY_TYPE_K_OUTPUT {
				// Store the original SignedMessage for verification bundle
				// Attestor handles all cryptographic verification server-side
				c.teekSignedMessage = sm
				c.logger.Info("TEE_K SignedMessage received")

				var body teeproto.KOutputPayload
				if err := proto.Unmarshal(sm.GetBody(), &body); err != nil {
					c.logger.Error("Failed to unmarshal KOutputPayload", zap.Error(err))
					break
				}
				// Use consolidated keystream from SignedMessage for final verification
				c.responseKeystream = body.GetConsolidatedResponseKeystream()
				c.markTEEKTranscriptReceived()
			}

		case *teeproto.Envelope_BatchedDecryptionStreams:
			var ds []shared.ResponseDecryptionStreamData
			for _, s := range p.BatchedDecryptionStreams.GetDecryptionStreams() {
				ds = append(ds, shared.ResponseDecryptionStreamData{DecryptionStream: s.GetDecryptionStream(), SeqNum: s.GetSeqNum(), Length: int(s.GetLength())})
			}
			msg := &shared.Message{Type: shared.MsgBatchedDecryptionStreams, SessionID: env.GetSessionId(), Data: shared.BatchedDecryptionStreamData{DecryptionStreams: ds, SessionID: p.BatchedDecryptionStreams.GetSessionId(), TotalCount: int(p.BatchedDecryptionStreams.GetTotalCount())}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleBatchedDecryptionStreams(msg)
		default:
			if !closing {
				c.logger.Error("Unknown message payload from TEE_K")
			}
		}
	}
}

// handleTEETMessages handles incoming messages from TEE_T
func (c *Client) handleTEETMessages() {
	for {
		conn := c.teetConn
		closing := c.isClosing.Load()

		if conn == nil {
			break
		}

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if !closing {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				} else if !isClientNetworkShutdownError(err) {
					c.logger.Error("Failed to read TEE_T websocket message", zap.Error(err))
				}
			}
			break
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			if !closing {
				c.terminateConnectionWithError("Failed to parse message from TEE_T", err)
				return
			}
			break
		}

		switch p := env.Payload.(type) {
		case *teeproto.Envelope_BatchedEncryptedData:
			c.handleBatchedEncryptedRequest(env.GetSessionId(), p.BatchedEncryptedData)
		case *teeproto.Envelope_SignedMessage:
			// Handle SignedMessage from TEE_T (T_OUTPUT)
			sm := p.SignedMessage
			if sm == nil {
				break
			}
			if sm.GetBodyType() == teeproto.BodyType_BODY_TYPE_T_OUTPUT {
				// Store the original SignedMessage for verification bundle
				// Attestor handles all cryptographic verification server-side
				c.teetSignedMessage = sm
				c.logger.Info("TEE_T SignedMessage received")

				var body teeproto.TOutputPayload
				if err := proto.Unmarshal(sm.GetBody(), &body); err != nil {
					c.logger.Error("Failed to unmarshal TOutputPayload", zap.Error(err))
					break
				}

				c.consolidatedResponseCiphertext = body.GetConsolidatedResponseCiphertext()

				c.markTEETTranscriptReceived()
			}
		case *teeproto.Envelope_Error:
			msg := &shared.Message{Type: shared.MsgError, SessionID: env.GetSessionId(), Data: shared.ErrorData{Message: p.Error.GetMessage()}, Timestamp: time.UnixMilli(env.GetTimestampMs())}
			c.handleTEETError(msg)
		default:
			if !closing {
				c.logger.Error("Unknown TEE_T message payload")
			}
		}
	}
}

// sendMessage sends a message to TEE_K
func (c *Client) sendMessage(msg *shared.Message) error {
	c.wsWriteMutex.Lock()
	defer c.wsWriteMutex.Unlock()

	conn := c.wsConn

	if conn == nil {
		return fmt.Errorf("no websocket connection")
	}

	// Add session ID if available and not already set
	c.sessionMutex.RLock()
	sessionID := c.sessionID
	c.sessionMutex.RUnlock()

	if sessionID != "" && msg.SessionID == "" {
		msg.SessionID = sessionID
	}

	// Build protobuf envelope directly
	env := &teeproto.Envelope{SessionId: msg.SessionID, TimestampMs: time.Now().UnixMilli()}
	switch msg.Type {
	case shared.MsgRequestConnection:
		if d, ok := msg.Data.(shared.RequestConnectionData); ok {
			env.Payload = &teeproto.Envelope_RequestConnection{RequestConnection: &teeproto.RequestConnection{
				Hostname:         d.Hostname,
				Port:             int32(d.Port),
				Sni:              d.SNI,
				Alpn:             d.ALPN,
				ForceTlsVersion:  d.ForceTLSVersion,
				ForceCipherSuite: d.ForceCipherSuite,
			}}
		}
	case shared.MsgTCPReady:
		if d, ok := msg.Data.(shared.TCPReadyData); ok {
			env.Payload = &teeproto.Envelope_TcpReady{TcpReady: &teeproto.TCPReady{Success: d.Success}}
		}
	case shared.MsgTCPData, shared.MsgSendTCPData:
		if d, ok := msg.Data.(shared.TCPData); ok {
			env.Payload = &teeproto.Envelope_TcpData{TcpData: &teeproto.TCPData{Data: d.Data}}
		}
	case shared.MsgRedactedRequest:
		if d, ok := msg.Data.(shared.RedactedRequestData); ok {
			// Convert ranges
			ranges := make([]*teeproto.RequestRedactionRange, 0, len(d.RedactionRanges))
			for _, r := range d.RedactionRanges {
				ranges = append(ranges, &teeproto.RequestRedactionRange{Start: int32(r.Start), Length: int32(r.Length), Type: r.Type})
			}
			env.Payload = &teeproto.Envelope_RedactedRequest{RedactedRequest: &teeproto.RedactedRequest{
				RedactedRequest: d.RedactedRequest,
				Commitments:     d.Commitments,
				RedactionRanges: ranges,
			}}
		}
	case shared.MsgError:
		if d, ok := msg.Data.(shared.ErrorData); ok {
			env.Payload = &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: d.Message}}
		}
	default:
		// Unknown/unsupported send type
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	return shared.WriteWSBinary(conn, data)
}

// sendEnvelope sends a protobuf envelope directly to TEE_K
func (c *Client) sendEnvelope(env *teeproto.Envelope) error {
	c.wsWriteMutex.Lock()
	defer c.wsWriteMutex.Unlock()

	conn := c.wsConn
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

// isEnclaveMode checks if the client is running in enclave mode
func (c *Client) isEnclaveMode() bool {
	return c.clientMode == ModeEnclave
}

// sendEnvelopeToTEET sends a protobuf envelope directly to TEE_T
func (c *Client) sendEnvelopeToTEET(env *teeproto.Envelope) error {
	c.teetWriteMutex.Lock()
	defer c.teetWriteMutex.Unlock()

	conn := c.teetConn
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

// sendError sends an error message to TEE_K (fail-fast implementation)
func (c *Client) sendError(errMsg string) {
	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{
			Error: &teeproto.ErrorData{Message: errMsg},
		},
	}

	// sendEnvelope already has mutex protection, so no need to lock here
	if err := c.sendEnvelope(env); err != nil {
		c.terminateConnectionWithError("Failed to send error message", err)
		return
	}
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

	// Close the underlying TCP conn; let the closed-conn error propagate
	// to the TCP-reader. Don't nil the pointer — readers may be mid-deref.
	if c.tcpConn != nil {
		c.tcpConn.Close()
	}

	// Close TEE_K connection (with mutex protection)
	c.wsWriteMutex.Lock()
	if c.wsConn != nil {
		c.wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.wsConn.Close()
		c.wsConn = nil
	}
	c.wsWriteMutex.Unlock()

	// Close TEE_T connection (with mutex protection)
	c.teetWriteMutex.Lock()
	if c.teetConn != nil {
		c.teetConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.teetConn.Close()
		c.teetConn = nil
	}
	c.teetWriteMutex.Unlock()
}

// terminateConnectionWithError performs immediate connection termination due to critical error
// This implements strict fail-fast behavior - no error continuation is allowed
func (c *Client) terminateConnectionWithError(reason string, err error) {
	// Log the critical error
	c.logger.Error("CRITICAL ERROR - terminating connection", zap.String("reason", reason), zap.Error(err))

	// Perform immediate cleanup and termination
	c.Close()

	// Signal completion with error to prevent hanging
	c.completionOnce.Do(func() {
		protocolErr := fmt.Errorf("%s: %v", reason, err)
		select {
		case c.completionChan <- protocolErr:
		default:
			// Channel might be full, but that's ok
		}
	})
}

// sendOPRFRangesToTEEK sends MPC OPRF ranges to TEE_K only. TEE_K relays them
// to TEE_T (with TotalRanges) over the mutually-attested inter-TEE connection,
// so TEE_T learns ranges from a single ordered source rather than racing a
// separate client message.
func (c *Client) sendOPRFRangesToTEEK(ranges []*teeproto.OPRFRangeSpec) error {
	if c.wsConn == nil {
		return fmt.Errorf("TEE_K connection not available")
	}

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

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal OPRF ranges envelope: %w", err)
	}

	c.wsWriteMutex.Lock()
	err = shared.WriteWSBinary(c.wsConn, data)
	c.wsWriteMutex.Unlock()
	if err != nil {
		return fmt.Errorf("send to TEE_K: %w", err)
	}

	c.oprfMpcRangesSent = true
	c.oprfMpcRangesSpec = ranges
	return nil
}
