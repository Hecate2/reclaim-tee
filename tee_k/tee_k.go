package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// RedactionOperation represents a redaction to be applied to a specific sequence
type RedactionOperation struct {
	SeqNum uint64
	Start  int    // Start offset within the sequence
	End    int    // End offset within the sequence
	Bytes  []byte // Redaction bytes to apply
}

// TEEK is the main TEE_K service structure
type TEEK struct {
	port int

	// Session management
	sessionManager    *TEEKSessionManager
	sessionTerminator *shared.SessionTerminator

	// Logging
	logger *shared.Logger

	// TEE_T connection settings
	teetURL string

	// Shared persistent connection to TEE_T
	sharedTEETConn *websocket.Conn
	teetConnMutex  sync.RWMutex

	// TLS configuration
	forceTLSVersion  string                     // Force specific TLS version: "1.2", "1.3", or "" for auto
	forceCipherSuite string                     // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
	certFetcher      minitls.CertificateFetcher // Shared cached certificate fetcher

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Enclave manager for attestation generation
	enclaveManager *shared.EnclaveManager

	// Attestation caching for performance optimization
	cachedAttestation *teeproto.AttestationReport
	attestationMutex  sync.RWMutex
	attestationExpiry time.Time

	// Mutual attestation
	teetAttestationVerified bool
	teetAttestationMutex    sync.RWMutex
	teetWriteMutex          sync.Mutex

	// Persistent OPRF key share (loaded from cloud storage)
	oprfKeyShare []byte
}

// NewTEEKWithConfig creates a new TEEK instance with the provided configuration
func NewTEEKWithConfig(config *TEEKConfig) *TEEK {
	teek := NewTEEKWithEnclaveManager(config.Port, nil)
	teek.SetTEETURL(config.TEETURL)
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)
	return teek
}

// NewTEEKWithEnclaveManager creates a new TEEK instance with optional enclave manager
func NewTEEKWithEnclaveManager(port int, enclaveManager *shared.EnclaveManager) *TEEK {
	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		log.Fatalf("[TEE_K] CRITICAL: Failed to generate signing key pair: %v", err)
	}

	// Get logger
	logger := shared.GetTEEKLogger()
	logger.Info("Generated ECDSA signing key pair")

	// Initialize cached certificate fetcher (shared across all TLS connections)
	certFetcher, err := NewCertificateFetcher(enclaveManager, logger)
	if err != nil {
		log.Fatalf("[TEE_K] CRITICAL: Failed to initialize certificate fetcher: %v", err)
	}
	logger.Info("Initialized cached certificate fetcher", zap.String("mode", func() string {
		if enclaveManager != nil {
			return "vsock"
		}
		return "http"
	}()))

	// Initialize OPRF key share (persistent across restarts)
	oprfKeyShare := initializeOPRFKeyShare(enclaveManager, logger, "tee_k")

	return &TEEK{
		port:              port,
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
		teetURL:           "ws://localhost:8081/teek", // Default TEE_T URL
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
		certFetcher:       certFetcher,
		oprfKeyShare:      oprfKeyShare,
	}
}

// initializeOPRFKeyShare loads OPRF key share from cloud storage or generates and saves a new one
func initializeOPRFKeyShare(enclaveManager *shared.EnclaveManager, logger *shared.Logger, serviceName string) []byte {
	const oprfKeyShareKey = "tee_k_oprf_key_share"
	const oprfKeyShareSize = 16

	// In standalone mode (no enclave manager), generate ephemeral key
	if enclaveManager == nil {
		keyShare := make([]byte, oprfKeyShareSize)
		if _, err := rand.Read(keyShare); err != nil {
			log.Fatalf("[%s] CRITICAL: Failed to generate OPRF key share: %v", serviceName, err)
		}
		logger.Info("Generated ephemeral OPRF key share (standalone mode)")
		return keyShare
	}

	// Try to load from cloud storage
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := enclaveManager.GetCache()
	if cache != nil {
		existingKey, err := cache.Get(ctx, oprfKeyShareKey)
		if err == nil && len(existingKey) == oprfKeyShareSize {
			logger.Info("Loaded OPRF key share from cloud storage")
			return existingKey
		}
		if err != nil {
			logger.Debug("OPRF key share not found in cloud storage, will generate new one", zap.Error(err))
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
			logger.Error("Failed to save OPRF key share to cloud storage", zap.Error(err))
			// Continue anyway - we have a valid key share in memory
		} else {
			logger.Info("Generated and saved OPRF key share to cloud storage")
		}
	} else {
		logger.Info("Generated OPRF key share (no cache available)")
	}

	return keyShare
}

// SetTEETURL sets the TEE_T connection URL
func (t *TEEK) SetTEETURL(url string) {
	t.teetURL = url
}

// SetForceTLSVersion sets the forced TLS version
func (t *TEEK) SetForceTLSVersion(version string) {
	t.forceTLSVersion = version
}

// SetForceCipherSuite sets the forced cipher suite
func (t *TEEK) SetForceCipherSuite(cipherSuite string) {
	t.forceCipherSuite = cipherSuite
}

// Helper functions to access session state
func (t *TEEK) getSessionTLSState(sessionID string) (*TEEKSessionState, error) {
	return t.sessionManager.GetTEEKSessionState(sessionID)
}

func (t *TEEK) getSessionResponseState(sessionID string) (*shared.ResponseSessionState, error) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingResponses:          make(map[string][]byte),
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}
	return session.ResponseState, nil
}

// cleanupSession performs complete cleanup of session resources
// This function is idempotent - safe to call multiple times for the same session
func (t *TEEK) cleanupSession(sessionID string) {
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
// Sends error notification to both client and TEE_T, then cleans up session
// This function implements ZERO TOLERANCE - always terminates the session
func (t *TEEK) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
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

	// Send error to TEE_T
	if sendErr := t.sendEnvelopeToTEET(sessionID, env); sendErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to TEE_T", zap.Error(sendErr))
	}

	// Small delay to ensure error messages are sent before connection closes
	time.Sleep(50 * time.Millisecond)

	// Cleanup session resources
	t.cleanupSession(sessionID)
}

// sendToTEET sends a message to TEE_T with attestation check
func (t *TEEK) sendToTEET(sessionID string, env *teeproto.Envelope) error {
	// Check attestation flag BEFORE sending
	t.teetAttestationMutex.RLock()
	verified := t.teetAttestationVerified
	t.teetAttestationMutex.RUnlock()

	if !verified {
		err := fmt.Errorf("cannot send to TEE_T: attestation not verified")
		t.logger.WithSession(sessionID).Error("Attestation check failed", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonAttestationVerificationFailed, err,
			"TEE_T attestation not verified")
		return err
	}

	// Get connection
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no TEE_T connection")
	}

	// Marshal and send
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}

	t.teetWriteMutex.Lock()
	defer t.teetWriteMutex.Unlock()

	return conn.WriteMessage(websocket.BinaryMessage, data)
}
