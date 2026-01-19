package client

import (
	"fmt"
	"net/url"
	"strings"
	"tee-mpc/minitls"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"
	"time"

	"go.uber.org/zap"

	"github.com/gorilla/websocket"
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

	// Determine connection mode and use appropriate dialer
	var conn *websocket.Conn
	if strings.HasPrefix(c.teekURL, "wss://") && strings.Contains(c.teekURL, "reclaimprotocol.org") {
		// Enclave mode: use custom dialer with TLS config
		c.logger.Info("Enclave mode detected for TEE_K - using custom dialer")
		dialer := createEnclaveWebSocketDialer()
		conn, _, err = dialer.Dial(u.String(), nil)
	} else {
		// Standalone mode: use default dialer
		c.logger.Info("Standalone mode detected for TEE_K - using default dialer")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	}

	if err != nil {
		c.logger.Error("WebSocket dial failed for TEE_K", zap.String("url", c.teekURL), zap.Error(err))
		return fmt.Errorf("failed to connect to TEE_K: %v", err)
	}

	c.wsConn = conn
	c.logger.Info("WebSocket connection to TEE_K established successfully")

	// Start message handling goroutine
	go c.handleMessages()

	return nil
}

// ConnectToTEET establishes WebSocket connection to TEE_T
func (c *Client) ConnectToTEET() error {
	u, err := url.Parse(c.teetURL)
	if err != nil {
		return fmt.Errorf("failed to parse TEE_T URL: %v", err)
	}

	c.logger.Info("Attempting WebSocket connection to TEE_T",
		zap.String("url", c.teetURL))

	// Determine connection mode and use appropriate dialer
	var conn *websocket.Conn
	if strings.HasPrefix(c.teetURL, "wss://") && strings.Contains(c.teetURL, "reclaimprotocol.org") {
		// Enclave mode: use custom dialer with TLS config
		c.logger.Info("Enclave mode detected for TEE_T - using custom dialer")
		dialer := createEnclaveWebSocketDialer()
		conn, _, err = dialer.Dial(u.String(), nil)
	} else {
		// Standalone mode: use default dialer
		c.logger.Info("Standalone mode detected for TEE_T - using default dialer")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	}

	if err != nil {
		c.logger.Error("WebSocket dial failed for TEE_T", zap.String("url", c.teetURL), zap.Error(err))
		return fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	c.teetConn = conn
	c.logger.Info("WebSocket connection to TEE_T established successfully")

	// Start message handling goroutine for TEE_T
	go c.handleTEETMessages()

	return nil
}

// handleMessages handles incoming messages from TEE_K
func (c *Client) handleMessages() {
	for {
		conn := c.wsConn
		closing := c.isClosing

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
		closing := c.isClosing

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
	return conn.WriteMessage(websocket.BinaryMessage, data)
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
	return conn.WriteMessage(websocket.BinaryMessage, data)
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
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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

		c.capturedTraffic = append(c.capturedTraffic, tlsRecord)

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
	c.httpRequestSent = true
	c.httpResponseExpected = true
	c.logger.Info("HTTP request sent (all fragments)", zap.Int("total_fragments", len(fragments)))
}

// validateTranscriptsAgainstCapturedTraffic performs comprehensive validation of signed transcripts

// Close closes all WebSocket connections
func (c *Client) Close() {
	c.isClosing = true

	// This mimics standard HTTP client behavior - close the underlying connection first
	if c.tcpConn != nil {
		c.tcpConn.Close()
		c.tcpConn = nil
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
