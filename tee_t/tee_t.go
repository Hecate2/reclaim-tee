package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// MaxWebSocketMessageSize is the maximum allowed WebSocket message size (30 MB)
// Sized for OT precomputation: 100,000 COSenderSetups at ~200 bytes each = ~20 MB
const MaxWebSocketMessageSize = 30 * 1024 * 1024

var teetUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
	ReadBufferSize:  64 * 1024, // 64 KB read buffer
	WriteBufferSize: 64 * 1024, // 64 KB write buffer
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

	// Persistent OPRF key share (loaded from cloud storage)
	oprfKeyShare []byte

	// OT receiver state for 2-round OPRF protocol
	otReceiverState   *OTReceiverState
	otReceiverStateMu sync.Mutex

	// TEE_K connection tracking
	teekConnected   bool
	teekConnectedMu sync.RWMutex
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

	// Initialize OPRF key share (persistent across restarts)
	oprfKeyShare := initializeOPRFKeyShare(enclaveManager, logger, "tee_t")

	teet := &TEET{
		port:              port,
		sessionManager:    NewTEETSessionManager(),
		logger:            logger,
		sessionTerminator: sessionTerminator,
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
		expectedTEEKPCR0:  os.Getenv("EXPECTED_TEEK_PCR0"),
		oprfKeyShare:      oprfKeyShare,
	}

	return teet
}

// initializeOPRFKeyShare loads OPRF key share from cloud storage or generates and saves a new one
func initializeOPRFKeyShare(enclaveManager *shared.EnclaveManager, logger *shared.Logger, serviceName string) []byte {
	const oprfKeyShareSize = 16

	// Build domain-specific key name (e.g., "eu-tt-oprf-key-share" for eu.tt.reclaimprotocol.org)
	oprfKeyShareKey := "oprf-key-share" // default for standalone
	if enclaveManager != nil {
		if cfg := enclaveManager.GetConfig(); cfg != nil && cfg.Domain != "" {
			// Use domain prefix for region-specific keys
			oprfKeyShareKey = cfg.Domain + "-oprf-key-share"
		}
	}

	// In standalone mode (no enclave manager), use static key for testing
	if enclaveManager == nil {
		keyShare := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
		if logger != nil {
			logger.Info("Using static OPRF key share (standalone mode)")
		}
		return keyShare
	}

	// Try to load from cloud storage
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := enclaveManager.GetCache()
	if cache == nil {
		if logger != nil {
			logger.Error("EnclaveManager has no cache - OPRF keys will not persist!")
		}
	} else {
		existingKey, err := cache.Get(ctx, oprfKeyShareKey)
		if err == nil && len(existingKey) == oprfKeyShareSize {
			if logger != nil {
				logger.Info("Loaded OPRF key share from cloud storage")
			}
			return existingKey
		}
		if err != nil {
			if logger != nil {
				logger.Info("OPRF key share not found in cloud storage, will generate new one", zap.Error(err))
			}
		} else if len(existingKey) == 0 {
			if logger != nil {
				logger.Error("Cache returned empty data without error - GCP adapter may be nil")
			}
		}
	}

	// Generate new key share
	keyShare := make([]byte, oprfKeyShareSize)
	if _, err := rand.Read(keyShare); err != nil {
		log.Fatalf("[%s] CRITICAL: Failed to generate OPRF key share: %v", serviceName, err)
	}

	// Save to cloud storage
	if cache != nil {
		if err := cache.Put(ctx, oprfKeyShareKey, keyShare); err != nil {
			if logger != nil {
				logger.Error("Failed to save OPRF key share to cloud storage", zap.Error(err))
			}
			// Continue anyway - we have a valid key share in memory
		} else if logger != nil {
			logger.Info("Generated and saved OPRF key share to cloud storage")
		}
	} else if logger != nil {
		logger.Info("Generated OPRF key share (no cache available)")
	}

	return keyShare
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

// setTEEKConnected updates the TEE_K connection status
func (t *TEET) setTEEKConnected(connected bool) {
	t.teekConnectedMu.Lock()
	defer t.teekConnectedMu.Unlock()
	t.teekConnected = connected
	if connected {
		t.logger.Info("TEE_K connection established")
	} else {
		t.logger.Info("TEE_K connection lost")
	}
}

// isTEEKConnected returns whether TEE_K is connected
func (t *TEET) isTEEKConnected() bool {
	t.teekConnectedMu.RLock()
	defer t.teekConnectedMu.RUnlock()
	return t.teekConnected
}

// cleanupSession performs complete cleanup of session resources
// This function is idempotent - safe to call multiple times for the same session
func (t *TEET) cleanupSession(sessionID string) {
	// Close the session in session manager (handles connections and state cleanup)
	if err := t.sessionManager.CloseSession(sessionID); err != nil {
		// Session already cleaned up - this is expected in race conditions
		// Log at debug level to avoid log spam
		t.logger.WithSession(sessionID).Debug("Session already cleaned up", zap.Error(err))
		return
	}

	// Cleanup session terminator tracking
	t.sessionTerminator.CleanupSession(sessionID)

	t.logger.WithSession(sessionID).Info("Session terminated and cleaned up")
}

// terminateSessionWithError terminates a session due to a critical error
// Sends error notification to both client and TEE_K, then cleans up session
// This function implements ZERO TOLERANCE - always terminates the session
func (t *TEET) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
	// Check if session exists - if not, it's already been terminated
	if _, sessionErr := t.sessionManager.GetSession(sessionID); sessionErr != nil {
		t.logger.WithSession(sessionID).Debug("Session already terminated, skipping duplicate termination",
			zap.String("reason", string(reason)))
		return
	}

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
