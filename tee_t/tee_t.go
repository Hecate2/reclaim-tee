package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var teetUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// TEET represents the TEE_T (Execution Environment for Transcript generation)
type TEET struct {
	port int

	// Session management
	sessionManager *TEETSessionManager

	// Logging and error handling
	logger            *shared.Logger
	sessionTerminator *shared.SessionTerminator

	ready bool

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Enclave manager for attestation generation
	enclaveManager *shared.EnclaveManager

	// Attestation caching for performance optimization
	cachedAttestation *teeproto.AttestationReport
	attestationMutex  sync.RWMutex
	attestationExpiry time.Time

	// Mutual attestation
	expectedTEEKPCR0 string
}

// NewTEETWithLogger creates a TEET with a specific logger
func NewTEETWithLogger(port int, logger *shared.Logger) *TEET {
	return NewTEETWithEnclaveManagerAndLogger(port, nil, logger)
}

// NewTEETWithEnclaveManagerAndLogger creates a TEET with enclave manager and logger
func NewTEETWithEnclaveManagerAndLogger(port int, enclaveManager *shared.EnclaveManager, logger *shared.Logger) *TEET {
	sessionTerminator := shared.NewSessionTerminator(logger)

	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		if logger != nil {
			logger.Fatal("CRITICAL: Failed to generate signing key pair", zap.Error(err))
		}
		// Fallback if logger is nil
		log.Fatalf("[TEE_T] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	if logger != nil {
		logger.Info("Generated ECDSA signing key pair", zap.String("curve", "P-256"))
	}

	teet := &TEET{
		port:              port,
		sessionManager:    NewTEETSessionManager(),
		logger:            logger,
		sessionTerminator: sessionTerminator,
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
		expectedTEEKPCR0:  os.Getenv("EXPECTED_TEEK_PCR0"),
	}

	return teet
}

// Helper functions to access session state
func (t *TEET) getSessionRedactionState(sessionID string) (*shared.RedactionSessionState, error) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}
	return session.RedactionState, nil
}

func (t *TEET) getTEETSessionState(sessionID string) (*TEETSessionState, error) {
	return t.sessionManager.GetTEETSessionState(sessionID)
}

// cleanupSession performs complete cleanup of session resources
func (t *TEET) cleanupSession(sessionID string) {
	// Close the session in session manager (handles connections and state cleanup)
	if err := t.sessionManager.CloseSession(sessionID); err != nil {
		// Log cleanup failure but don't continue with broken session
		t.logger.WithSession(sessionID).Error("Failed to cleanup session", zap.Error(err))
	}

	// Cleanup session terminator tracking
	t.sessionTerminator.CleanupSession(sessionID)

	t.logger.WithSession(sessionID).Info("Session terminated and cleaned up")
}

// terminateSessionWithError terminates a session due to a critical error
// Sends error notification to both client and TEE_K, then cleans up session
// This function implements ZERO TOLERANCE - always terminates the session
func (t *TEET) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
	t.logger.WithSession(sessionID).Error(message, zap.Error(err), zap.String("reason", string(reason)))

	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{
			Error: &teeproto.ErrorData{
				Message: errorMsg,
			},
		},
	}

	// Send error to client
	if routeErr := t.sessionManager.RouteToClient(sessionID, env); routeErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to client", zap.Error(routeErr))
	}

	// Send error to TEE_K
	if sendErr := t.sessionManager.RouteToTEEK(sessionID, env); sendErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to TEE_K", zap.Error(sendErr))
	}

	// Small delay to ensure error messages are sent before connection closes
	time.Sleep(50 * time.Millisecond)

	// Cleanup session resources
	t.cleanupSession(sessionID)
}
