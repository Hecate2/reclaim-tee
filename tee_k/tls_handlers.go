package main

import (
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// performTLSHandshakeAndHTTP performs TLS handshake for a specific session
func (t *TEEK) performTLSHandshakeAndHTTP(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to get session for TLS handshake")
		return err
	}

	// Get connection data
	if session.ConnectionData == nil {
		err := fmt.Errorf("missing connection data")
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Missing connection data")
		return err
	}

	// Initialize TEE_K session state first
	initialState := &TEEKSessionState{
		HandshakeComplete: false,
		TCPReady:          make(chan bool, 1),
	}
	t.sessionManager.SetTEEKSessionState(sessionID, initialState)

	// Create session-specific TLS client
	wsConn := session.ClientConn.(*shared.WSConnection)
	tlsConn := &WebSocketConn{
		wsConn:      wsConn.GetWebSocketConn(),
		pendingData: make(chan []byte, 10),
		teek:        t,         // Add TEEK reference for transcript collection
		sessionID:   sessionID, // Add session ID for per-session transcript collection
	}

	// Configure TLS with shared cached certificate fetcher
	config := &minitls.Config{
		// Use shared cached certificate fetcher (1-week TTL, max 1000 entries)
		CertFetcher: t.certFetcher,
	}

	// Prefer client-requested TLS version over server default
	effectiveTLSVersion := session.ConnectionData.ForceTLSVersion
	if effectiveTLSVersion == "" {
		effectiveTLSVersion = t.forceTLSVersion
	}

	// Prefer client-requested cipher suite over server default
	effectiveCipherSuite := session.ConnectionData.ForceCipherSuite
	if effectiveCipherSuite == "" {
		effectiveCipherSuite = t.forceCipherSuite
	}

	switch effectiveTLSVersion {
	case "1.2":
		config.MinVersion = minitls.VersionTLS12
		config.MaxVersion = minitls.VersionTLS12
		t.logger.WithSession(sessionID).Info("Forcing TLS 1.2")
	case "1.3":
		config.MinVersion = minitls.VersionTLS13
		config.MaxVersion = minitls.VersionTLS13
		t.logger.WithSession(sessionID).Info("Forcing TLS 1.3")
	default:
		// Auto-negotiate (default behavior)
		config.MinVersion = minitls.VersionTLS12
		config.MaxVersion = minitls.VersionTLS13
		t.logger.WithSession(sessionID).Info("TLS version auto-negotiation enabled")
	}

	// Configure cipher suite restrictions if specified
	if err := configureCipherSuites(config, effectiveCipherSuite, effectiveTLSVersion); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Invalid cipher suite configuration")
		return err
	}

	if effectiveCipherSuite != "" {
		t.logger.WithSession(sessionID).Info("Forcing cipher suite", zap.String("cipher_suite", effectiveCipherSuite))
	} else {
		t.logger.WithSession(sessionID).Info("Cipher suite auto-negotiation enabled")
	}

	// Initialize TLS client with config
	tlsClient := minitls.NewClientWithConfig(tlsConn, config)
	// tlsClient.SetLogger(t.logger)

	// Store in session state instead of global fields
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "Failed to get TLS state")
		return err
	}
	tlsState.TLSClient = tlsClient
	tlsState.WSConn2TLS = tlsConn
	tlsState.CurrentConn = wsConn.GetWebSocketConn()
	tlsState.CurrentRequest = session.ConnectionData

	if err = tlsClient.Handshake(session.ConnectionData.Hostname); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, "TLS handshake failed")
		return err
	}

	// Update TEE_K session state to mark handshake complete
	tlsState.HandshakeComplete = true

	// Extract certificate info from TLS client for structured storage
	session, sessionErr := t.sessionManager.GetSession(sessionID)
	if sessionErr == nil && tlsClient.GetCertificateInfo() != nil {
		session.CertificateInfo = tlsClient.GetCertificateInfo()
		t.logger.WithSession(sessionID).Info("Captured certificate info for structured verification",
			zap.String("common_name", session.CertificateInfo.CommonName),
			zap.String("issuer", session.CertificateInfo.IssuerCommonName))
	}

	// Store cipher suite for session
	cipherSuite := tlsClient.GetCipherSuite()
	tlsState.CipherSuite = cipherSuite

	// Certificate info is stored as structured data instead of raw handshake packets

	t.logger.WithSession(sessionID).Info("Handshake finished - ready for split AEAD")

	// Send handshake complete message
	envHandshake := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_HandshakeComplete{HandshakeComplete: &teeproto.HandshakeComplete{
			Success:     true,
			CipherSuite: uint32(cipherSuite), // Include cipher suite for consolidated verification
		}},
	}

	if err := t.sessionManager.RouteToClient(sessionID, envHandshake); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send handshake complete")
		return err
	}

	t.logger.WithSession(sessionID).Info("TLS handshake complete",
		zap.Uint16("cipher_suite", cipherSuite))
	t.logger.WithSession(sessionID).Info("Ready for Phase 4 split AEAD response handling")
	return nil
}
