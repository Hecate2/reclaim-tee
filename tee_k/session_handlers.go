package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

const defaultHTTPSPort = 443

var supportedHTTPSTargetPorts = [...]int{
	81, 85, 150, 155, 443, 1006, 2095, 2096, 4430,
	8079, 8080, 8081, 8084, 8443, 8483, 50001, 50300,
}

func validateSupportedHTTPSPort(port int) error {
	for _, supportedPort := range supportedHTTPSTargetPorts {
		if port == supportedPort {
			return nil
		}
	}
	return fmt.Errorf("only HTTPS ports %v are allowed, got port %d", supportedHTTPSTargetPorts, port)
}

func expectedHTTPRequestAuthority(connData *shared.RequestConnectionData) (string, error) {
	if err := validateSupportedHTTPSPort(connData.Port); err != nil {
		return "", err
	}
	if connData.Port == defaultHTTPSPort {
		return connData.Hostname, nil
	}
	return net.JoinHostPort(connData.Hostname, strconv.Itoa(connData.Port)), nil
}

// handleRequestConnection handles connection request from client
func (t *TEEK) handleRequestConnection(sessionID string, msg *shared.Message) error {
	t.logger.WithSession(sessionID).Debug("Handling connection request")

	var reqData shared.RequestConnectionData
	if err := msg.UnmarshalData(&reqData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse connection request")
		return err
	}
	if err := validateSupportedHTTPSPort(reqData.Port); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonProtocolViolation, err, "Unsupported target port")
		return err
	}

	// Store connection data in session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Session not found")
		return err
	}
	session.ConnectionData = &reqData

	// Send connection ready message to client
	envReady := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_ConnectionReady{ConnectionReady: &teeproto.ConnectionReady{Success: true}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, envReady); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send connection ready message")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Connection ready, waiting for TCP")
	return nil
}

// handleTCPReady handles TCP ready message from client
func (t *TEEK) handleTCPReady(sessionID string, msg *shared.Message) error {
	var tcpData shared.TCPReadyData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal TCP ready data")
		return err
	}

	if !tcpData.Success {
		tcpErr := fmt.Errorf("TCP connection failed")
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, tcpErr, "TCP connection failed")
		return tcpErr
	}

	t.logger.WithSession(sessionID).Debug("TCP ready, starting TLS handshake")

	// Start TLS handshake for this session
	go func() {
		if err := t.performTLSHandshakeAndHTTP(sessionID); err != nil {
			// Error already handled inside performTLSHandshakeAndHTTP
		}
	}()

	return nil
}

// handleTCPData handles TCP data from client
func (t *TEEK) handleTCPData(sessionID string, msg *shared.Message) error {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to unmarshal TCP data")
		return err
	}

	// Handle incoming data from Client (TLS handshake data or encrypted application data)
	// Use session state for TCP data handling
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to get TLS state")
		return err
	}

	if tlsState.WSConn2TLS != nil {
		// Count App records so TLS-1.3 response tag-gen can derive the right offset.
		if len(tcpData.Data) >= 1 && tcpData.Data[0] == 0x17 {
			tlsState.AppRecordsViaTCPData.Add(1)
		}
		// Bail out via done channel if the session was torn down between
		// the websocket recv and here — otherwise we'd pin this goroutine
		// when pendingData is full and minitls is no longer draining.
		select {
		case tlsState.WSConn2TLS.pendingData <- tcpData.Data:
		case <-tlsState.WSConn2TLS.done:
			return nil
		}
	} else {
		err := fmt.Errorf("no WebSocket-to-TLS adapter available")
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "No WebSocket-to-TLS adapter available")
		return err
	}

	return nil
}

// handleRedactedRequest handles redacted request from client
func (t *TEEK) handleRedactedRequest(sessionID string, msg *shared.Message) error {
	var redactedRequest shared.RedactedRequestData
	if err := msg.UnmarshalData(&redactedRequest); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to unmarshal redacted request")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Validating redacted request",
		zap.Int("bytes", len(redactedRequest.RedactedRequest)),
		zap.Int("ranges", len(redactedRequest.RedactionRanges)))

	if len(redactedRequest.RedactedRequest) > shared.MaxHTTPRequestSize {
		err := fmt.Errorf("HTTP request too large: %d bytes (max %d)", len(redactedRequest.RedactedRequest), shared.MaxHTTPRequestSize)
		t.terminateSessionWithError(sessionID, shared.ReasonProtocolViolation, err, "Request exceeds maximum size")
		return err
	}

	if len(redactedRequest.RedactionRanges) > shared.MaxRedactionRanges {
		err := fmt.Errorf("too many redaction ranges: %d (max %d)", len(redactedRequest.RedactionRanges), shared.MaxRedactionRanges)
		t.terminateSessionWithError(sessionID, shared.ReasonProtocolViolation, err, "Too many redaction ranges")
		return err
	}

	// Get session to access connection data for Host header validation
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Session not found")
		return err
	}

	// Type assert ConnectionData

	if session.ConnectionData == nil {
		err = fmt.Errorf("invalid connection data type")
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Invalid connection data")
		return err
	}

	// Validate redacted request format and positions
	if err := t.validateHTTPRequestFormat(redactedRequest.RedactedRequest, redactedRequest.RedactionRanges, session.ConnectionData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to validate redacted request format")
		return err
	}

	if err := t.validateRedactionPositions(redactedRequest.RedactionRanges, len(redactedRequest.RedactedRequest)); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to validate redaction positions")
		return err
	}

	// --- Add redacted request and redaction ranges to transcript before encryption ---
	if err := t.addToTranscript(sessionID, redactedRequest.RedactedRequest, shared.TranscriptDataTypeHTTPRequestRedacted); err != nil {
		return err
	}

	// Store redaction ranges in transcript for signing using protobuf
	redactionRangesBytes, err := shared.MarshalRequestRedactionRangesProtobuf(redactedRequest.RedactionRanges)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to marshal redaction ranges")
		return err
	}
	if err := t.addToTranscript(sessionID, redactionRangesBytes, "redaction_ranges"); err != nil {
		return err
	}
	t.logger.WithSession(sessionID).Debug("Stored redaction ranges in transcript")

	// Encrypt the request and send to TEE_T
	if err := t.encryptAndSendRequest(sessionID, redactedRequest); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to encrypt and send request")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Encrypted request sent to TEE_T")
	return nil
}

// validateHTTPRequestFormat validates that the redacted request maintains proper HTTP format
func (t *TEEK) validateHTTPRequestFormat(redactedRequest []byte, ranges []shared.RequestRedactionRange, connData *shared.RequestConnectionData) error {
	// Create a pretty version with asterisks for redacted ranges
	prettyRequest := make([]byte, len(redactedRequest))
	copy(prettyRequest, redactedRequest)

	// Replace redacted ranges with asterisks for display
	for _, r := range ranges {
		end := r.Start + r.Length
		if r.Start >= 0 && end <= len(prettyRequest) {
			for i := r.Start; i < end; i++ {
				prettyRequest[i] = '*'
			}
		}
	}

	// Log the pretty version that TEE_K sees
	// t.logger.Info("TEE_K sees redacted request with asterisks",
	// 	zap.String("redacted_request", string(prettyRequest)),
	// 	zap.Int("redaction_ranges", len(ranges)))

	// Log details of each redaction range
	// for i, r := range ranges {
	// 	t.logger.Info("Redaction range for TEE_K",
	// 		zap.Int("index", i),
	// 		zap.Int("start", r.Start),
	// 		zap.Int("length", r.Length),
	// 		zap.String("type", r.Type))
	// }

	// Convert to string for easier parsing
	reqStr := string(prettyRequest)

	// Check basic HTTP request format
	if !strings.HasPrefix(reqStr, "GET ") && !strings.HasPrefix(reqStr, "POST ") {
		return fmt.Errorf("request does not start with valid HTTP method")
	}

	// Check for HTTP version
	if !strings.Contains(reqStr, " HTTP/1.1") {
		return fmt.Errorf("request does not contain HTTP/1.1 version")
	}

	// Check for proper line endings
	if !strings.Contains(reqStr, "\r\n") {
		return fmt.Errorf("request does not contain proper CRLF line endings")
	}

	// Check that request has double CRLF
	if !strings.Contains(reqStr, "\r\n\r\n") {
		return fmt.Errorf("request does not end with proper double CRLF")
	}

	// Validate that critical parts aren't fully redacted
	lines := strings.Split(reqStr, "\r\n")
	if len(lines) < 2 {
		return fmt.Errorf("request has insufficient lines")
	}

	// First line should contain method, path, and version
	firstLine := lines[0]
	parts := strings.Split(firstLine, " ")
	if len(parts) < 3 {
		return fmt.Errorf("invalid HTTP request line format")
	}

	// CRITICAL VALIDATION: Check Host header matches the connection authority.
	if connData != nil {
		expectedAuthority, err := expectedHTTPRequestAuthority(connData)
		if err != nil {
			return err
		}

		hostHeader := extractHeader(lines, "Host")
		if hostHeader == "" {
			return fmt.Errorf("host header is missing")
		}

		// Check if Host header is redacted (contains asterisks)
		if strings.Contains(hostHeader, "*") {
			return fmt.Errorf("host header must not be redacted")
		}

		// Bind the HTTP authority to the TCP destination. The default HTTPS port
		// is omitted; alternate ports must be explicit in the Host header.
		if hostHeader != expectedAuthority {
			return fmt.Errorf("host header '%s' does not match connection authority '%s'", hostHeader, expectedAuthority)
		}

		t.logger.Debug("Host header validation passed")
	}

	// CRITICAL VALIDATION: Check Connection: close is present
	connectionHeader := extractHeader(lines, "Connection")
	if connectionHeader == "" {
		return fmt.Errorf("connection header is missing")
	}

	if strings.Contains(connectionHeader, "*") {
		return fmt.Errorf("connection header must not be redacted")
	}

	if !strings.EqualFold(strings.TrimSpace(connectionHeader), "close") {
		return fmt.Errorf("connection header must be 'close', got '%s'", connectionHeader)
	}

	t.logger.Debug("Request format validation passed")
	return nil
}

// extractHeader extracts a header value from HTTP request lines (case-insensitive)
func extractHeader(lines []string, headerName string) string {
	headerPrefix := strings.ToLower(headerName) + ":"
	for i := 1; i < len(lines); i++ { // Skip first line (request line)
		line := lines[i]
		if strings.HasPrefix(strings.ToLower(line), headerPrefix) {
			// Extract value after colon and trim whitespace
			if _, after, ok := strings.Cut(line, ":"); ok {
				return strings.TrimSpace(after)
			}
		}
	}
	return ""
}

// validateRedactionPositions validates that redaction ranges are within bounds and non-overlapping
func (t *TEEK) validateRedactionPositions(ranges []shared.RequestRedactionRange, requestLen int) error {
	for i, r := range ranges {
		// Check bounds
		if r.Start < 0 || r.Length <= 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("range %d out of bounds: [%d:%d] for request length %d", i, r.Start, r.Start+r.Length, requestLen)
		}

		// Check for valid type
		if r.Type != shared.RedactionTypeSensitive && r.Type != shared.RedactionTypeSensitiveProof {
			return fmt.Errorf("range %d has invalid type: %s", i, r.Type)
		}

		// Check for overlaps with other ranges
		for j := i + 1; j < len(ranges); j++ {
			other := ranges[j]
			if !(r.Start+r.Length <= other.Start || other.Start+other.Length <= r.Start) {
				return fmt.Errorf("ranges %d and %d overlap: [%d:%d] and [%d:%d]", i, j, r.Start, r.Start+r.Length, other.Start, other.Start+other.Length)
			}
		}
	}

	t.logger.Debug("Redaction position validation passed")
	return nil
}

// handleRedactionSpec handles redaction specification from client
func (t *TEEK) handleRedactionSpec(sessionID string, msg *shared.Message) error {
	t.logger.WithSession(sessionID).Debug("Handling redaction specification")

	var redactionSpec shared.ResponseRedactionSpec
	if err := msg.UnmarshalData(&redactionSpec); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to parse redaction specification")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Received redaction spec", zap.Int("ranges", len(redactionSpec.Ranges)))

	// Validate redaction ranges
	if err := t.validateResponseRedactionSpec(redactionSpec); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Invalid redaction specification")
		return err
	}

	// Store response redaction ranges in session state for transcript signature
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to store redaction ranges")
		return err
	}

	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{}
	}
	session.ResponseState.ResponseRedactionRanges = redactionSpec.Ranges
	t.logger.WithSession(sessionID).Debug("Stored response redaction ranges")

	// Generate and send redacted decryption streams
	if err := t.generateAndSendRedactedDecryptionStreamResponse(sessionID, redactionSpec); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to generate redacted streams")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Processed redaction specification")

	// Send "finished" to TEE_T as per protocol specification
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Finished{
			Finished: &teeproto.FinishedMessage{},
		},
	}
	if err := t.sendEnvelopeToTEET(sessionID, env); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to send finished message to TEE_T")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Sent finished to TEE_T")
	return nil
}

// validateResponseRedactionSpec validates the response redaction specification from client
func (t *TEEK) validateResponseRedactionSpec(spec shared.ResponseRedactionSpec) error {
	if len(spec.Ranges) > shared.MaxResponseRedactionRanges {
		return fmt.Errorf("too many response redaction ranges: %d (max %d)", len(spec.Ranges), shared.MaxResponseRedactionRanges)
	}

	// Validate ranges don't overlap and are within bounds
	for i, range1 := range spec.Ranges {
		// Check for overlaps with other ranges
		for j := i + 1; j < len(spec.Ranges); j++ {
			range2 := spec.Ranges[j]
			if rangesOverlapResponse(range1, range2) {
				return fmt.Errorf("ranges %d and %d overlap", i, j)
			}
		}

		// Basic bounds check (we'll validate against actual packet boundaries later)
		if range1.Start < 0 || range1.Length <= 0 {
			return fmt.Errorf("range %d: invalid bounds (start=%d, length=%d)", i, range1.Start, range1.Length)
		}
	}

	return nil
}

// rangesOverlapResponse checks if two response redaction ranges overlap
func rangesOverlapResponse(r1, r2 shared.ResponseRedactionRange) bool {
	return r1.Start < r2.Start+r2.Length && r2.Start < r1.Start+r1.Length
}
