package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
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

	// Per-session connection manager (control + per-session connections)
	connManager *TEETConnectionManager

	// TLS configuration
	forceTLSVersion  string                     // Force specific TLS version: "1.2", "1.3", or "" for auto
	forceCipherSuite string                     // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
	certFetcher      minitls.CertificateFetcher // Shared cached certificate fetcher

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// genAttestationDocFn, when non-nil, overrides the platform attestation
	// call in generateAttestationDoc. Production leaves it nil; tests set it
	// to stub the launcher/SEV-guest dependency.
	genAttestationDocFn func(ctx context.Context, nonces ...string) ([]byte, error)

	// Attestation caching for performance optimization
	cachedAttestation *teeproto.AttestationReport
	attestationMutex  sync.RWMutex
	attestationExpiry time.Time
	// attestationSF coalesces concurrent cache-miss refreshes into a single
	// launcher-socket call. Without it, N concurrent sessions all hitting
	// an empty cache spawn N simultaneous GenerateGCPAttestation calls,
	// which saturate the launcher socket and time out.
	attestationSF singleflight.Group

	// Mutual attestation (managed by connection manager)
	teetAttestationVerified bool
	teetAttestationMutex    sync.RWMutex

	// Persistent OPRF key share (loaded from cloud storage)
	oprfKeyShare []byte

	// OT precomputation state for the MPC OPRF protocol.
	otPrecomputeState *OTPrecomputeState

	// V2 router-mode wiring. Nil/zero in standalone mode; filled in by
	// NewTEEKForRouter when ROUTER_URL is set. The connection manager,
	// attestation code, and heartbeat goroutine all read these.
	ratls                   *shared.RATLSManager
	router                  *shared.RouterClient
	pairID                  string
	expectedPeerImageDigest string             // sha256:... of TEE_T container image, for RA-TLS peer verification
	expectedPeerBaseDigest  string             // snp-base:<PCR11> of TEE_T's per-cloud base UKI (SEV-SNP only)
	jwtPubKey               *ecdsa.PublicKey   // verifies client allocation JWTs (nil = no JWT check, local dev)
	expectedJWTIssuer       string             // expected iss claim on client allocation JWTs
	jtiTracker              *shared.JTITracker // replay guard for allocation-JWT jti (nil in standalone)

	// Heartbeat observation state — written by the connection manager
	// (controlHealthy on peer connect/disconnect), OT precompute code
	// (otReady on pool ready/cleared), and the session manager
	// (activeSessions). Read by the router-heartbeat goroutine each tick.
	// Atomic so reads stay lock-free.
	controlHealthy atomic.Bool
	otReady        atomic.Bool
	activeSessions atomic.Int32

	// beforeReserveOTReadyPublish is a deterministic test-only hook invoked
	// while OT state ownership is still held. Production leaves it nil.
	beforeReserveOTReadyPublish func()

	// attestHealth gates the pair off the router (via ControlHealthy) and
	// self-resets when the SEV attestation path wedges. Nil-safe.
	attestHealth *shared.AttestationHealth
}

// NewTEEKWithConfig creates a new TEEK instance with the provided configuration
func NewTEEKWithConfig(config *TEEKConfig) *TEEK {
	teek := NewTEEK(config.Port)
	teek.SetTEETURL(config.TEETURL)
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)
	return teek
}

// NewTEEKForRouter constructs a TEEK wired for the V2 router-mode path:
// RA-TLS instead of ACME-issued certs, router client for register +
// heartbeat, deterministic pair_id generated at boot. Used only when
// ROUTER_URL is set; standalone-mode boot continues to use NewTEEKWithConfig.
//
// Returns a fully-initialized TEEK with router-mode fields populated but
// no peer connection or HTTP server started yet — the caller wires those up.
func NewTEEKForRouter(
	config *TEEKConfig,
	ratls *shared.RATLSManager,
	router *shared.RouterClient,
	pairID string,
) *TEEK {
	teek := NewTEEK(config.Port)
	teek.ratls = ratls
	teek.router = router
	teek.pairID = pairID
	teek.expectedPeerImageDigest = config.ExpectedPeerImageDigest
	teek.expectedPeerBaseDigest = config.ExpectedPeerBaseDigest
	if config.JWTPublicKey != "" {
		pubKey, err := shared.ParseECDSAPublicKeyPEM([]byte(config.JWTPublicKey))
		if err != nil {
			log.Fatalf("[TEE_K] CRITICAL: parse JWT_PUBLIC_KEY: %v", err)
		}
		teek.jwtPubKey = pubKey
		teek.expectedJWTIssuer = config.ExpectedJWTIssuer
		teek.jtiTracker = shared.NewJTITracker(0)
	}
	// In router mode the peer URL is derived from PEER_ADDR rather than
	// the legacy TEET_URL env var. /ws is the base path; the connection
	// manager extends it to /ws/control and /ws/session. Scheme tracks
	// whether we have an RA-TLS identity (prod) or not (local dev).
	scheme := "wss"
	if ratls == nil {
		scheme = "ws"
	}
	teek.SetTEETURL(scheme + "://" + config.PeerAddr + "/ws")
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)
	return teek
}

// NewTEEK constructs a baseline TEEK on the given port. Higher-level
// constructors (NewTEEKWithConfig, NewTEEKForRouter) layer mode-specific
// wiring on top.
func NewTEEK(port int) *TEEK {
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		log.Fatalf("[TEE_K] CRITICAL: Failed to generate signing key pair: %v", err)
	}

	logger := shared.GetTEEKLogger()
	logger.Info("Generated ECDSA signing key pair")

	certFetcher, err := NewCertificateFetcher(logger)
	if err != nil {
		log.Fatalf("[TEE_K] CRITICAL: Failed to initialize certificate fetcher: %v", err)
	}
	logger.Info("Initialized cached certificate fetcher")

	oprfKeyShare := initializeOPRFKeyShare(logger)

	sessionManager := NewTEEKSessionManager()
	sessionManager.SetLogger(logger)

	teek := &TEEK{
		port:              port,
		sessionManager:    sessionManager,
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
		teetURL:           "ws://localhost:8081/teek", // Default TEE_T URL
		signingKeyPair:    signingKeyPair,
		certFetcher:       certFetcher,
		oprfKeyShare:      oprfKeyShare,
	}

	sessionManager.SetOnSessionExpired(teek.cleanupSessionWithSession)

	return teek
}

// initializeOPRFKeyShare returns TEE_K's MPC OPRF key share. When
// KMS_ENCLAVE_DOMAIN_KEY is set the share is loaded from (or created in)
// GCP Secret Manager — same secret name + envelope format as the legacy
// EnclaveCache, so existing V1 shares are picked up unchanged. When the
// env var is empty (local dev / standalone), a hardcoded share is used.
func initializeOPRFKeyShare(logger *shared.Logger) []byte {
	deploymentKey := shared.GetEnvOrDefault("KMS_ENCLAVE_DOMAIN_KEY", "")
	if deploymentKey == "" {
		// The static share is a world-known dev constant. An attested TEE
		// (SEV-SNP / enclave) must NEVER use it — that would make nullifiers
		// forgeable, and the env isn't measured so attestation can't detect it.
		// Defense in depth behind validateRouterConfig's KMS requirement.
		if shared.IsProductionTEE() {
			log.Fatalf("[TEE_K] CRITICAL: attested TEE requires KMS_ENCLAVE_DOMAIN_KEY (real OPRF); refusing the static dev share")
		}
		keyShare := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
		logger.Info("Using static OPRF key share (KMS_ENCLAVE_DOMAIN_KEY unset; local dev only)")
		return keyShare
	}
	share, err := shared.LoadOPRFShare("tee_k", deploymentKey, logger)
	if err != nil {
		log.Fatalf("[TEE_K] CRITICAL: load OPRF share: %v", err)
	}
	return share
}

// PairID / Router / ControlHealthy / OTReady / ActiveSessions satisfy
// shared.HeartbeatTarget so router heartbeat logic lives in shared/.
func (t *TEEK) PairID() string               { return t.pairID }
func (t *TEEK) Router() *shared.RouterClient { return t.router }
func (t *TEEK) ControlHealthy() bool         { return t.controlHealthy.Load() && t.attestHealth.Healthy() }
func (t *TEEK) OTReady() bool                { return t.otReady.Load() }
func (t *TEEK) ActiveSessions() int          { return int(t.activeSessions.Load()) }

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

// CAS-guarded; exactly one caller per session runs the cleanup side-effects.
func (t *TEEK) cleanupSession(sessionID string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Debug("Session missing, cleanup already ran")
		return
	}
	t.cleanupSessionWithSession(session)
}

// Variant used by the expiry callback, which already holds *Session.
func (t *TEEK) cleanupSessionWithSession(session *shared.Session) {
	if !session.CleanedUp.CompareAndSwap(false, true) {
		t.logger.WithSession(session.ID).Debug("Session cleanup already claimed by another caller")
		return
	}
	if teekState, err := t.sessionManager.stateForSession(session); err == nil {
		for _, reservation := range teekState.AbandonAllOTReservations() {
			t.reconcileAbandonedOTReservation(reservation)
		}
	}
	// Unblock any TCPData sender that's waiting on a full pendingData
	// buffer because minitls has stopped draining.
	if tlsState, err := t.sessionManager.stateForSession(session); err == nil && tlsState.WSConn2TLS != nil {
		tlsState.WSConn2TLS.Shutdown()
	}
	if t.connManager != nil {
		t.connManager.CloseSessionConnection(session, "session_cleanup")
	}
	_ = t.sessionManager.CloseSessionIfCurrent(session)
	t.activeSessions.Add(-1)
	if t.sessionTerminator != nil {
		t.sessionTerminator.CleanupSession(session.ID)
	}
	t.logger.WithSession(session.ID).Info("Session terminated and cleaned up")
}

func (t *TEEK) terminateSessionWithErrorForIdentity(identity *teekSessionIdentity, reason shared.TerminationReason, err error, message string) {
	if identity == nil || identity.ensureCurrent() != nil {
		return
	}
	session := identity.session
	sessionID := session.ID
	t.logger.WithSession(sessionID).Error(message, zap.Error(err), zap.String("reason", string(reason)))
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}
	env := &teeproto.Envelope{
		SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errorMsg}},
	}
	if routeErr := t.routeToClientForSession(session, env); routeErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to client", zap.Error(routeErr))
	}
	if sendErr := t.connManager.SendOnExactSession(identity, env); sendErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to TEE_T", zap.Error(sendErr))
	}
	time.Sleep(50 * time.Millisecond)
	t.cleanupSessionWithSession(session)
}

func (t *TEEK) routeToClientForSession(session *shared.Session, env *teeproto.Envelope) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	session.ConnMutex.RLock()
	conn := session.ClientConn
	session.ConnMutex.RUnlock()
	ws, ok := conn.(*shared.WSConnection)
	if !ok || ws == nil {
		return fmt.Errorf("no client connection in session %s", session.ID)
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	return ws.WriteMessage(websocket.BinaryMessage, data)
}

// terminateSessionWithError terminates a session due to a critical error
// Sends error notification to both client and TEE_T, then cleans up session
// This function implements ZERO TOLERANCE - always terminates the session
func (t *TEEK) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
	// Check if session exists - if not, it's already been terminated
	if _, sessionErr := t.sessionManager.GetSession(sessionID); sessionErr != nil {
		t.logger.WithSession(sessionID).Warn("Session already terminated, skipping duplicate termination",
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

// getEnvelopePayloadType returns a string describing the payload type for logging
func getEnvelopePayloadType(env *teeproto.Envelope) string {
	if env == nil {
		return "nil"
	}
	switch env.Payload.(type) {
	case *teeproto.Envelope_SessionCreated:
		return "SessionCreated"
	case *teeproto.Envelope_KeyShareRequest:
		return "KeyShareRequest"
	case *teeproto.Envelope_BatchedEncryptedRequest:
		return "BatchedEncryptedRequest"
	case *teeproto.Envelope_Finished:
		return "Finished"
	case *teeproto.Envelope_BatchedTagSecrets:
		return "BatchedTagSecrets"
	case *teeproto.Envelope_Error:
		return "Error"
	case *teeproto.Envelope_OtPrecomputeRequest:
		return "OtPrecomputeRequest"
	case *teeproto.Envelope_OtPrecomputeComplete:
		return "OtPrecomputeComplete"
	case *teeproto.Envelope_OprfOnlineFull:
		return "OprfOnlineFull"
	case *teeproto.Envelope_OprfMpcRound3:
		return "OprfMpcRound3"
	case *teeproto.Envelope_TeekAttestation:
		return "TeekAttestation"
	default:
		return fmt.Sprintf("Unknown(%T)", env.Payload)
	}
}

// sendToTEET sends a message to TEE_T, routing to control or session connection as appropriate
func (t *TEEK) sendToTEET(sessionID string, env *teeproto.Envelope) error {
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	// Check attestation via connection manager
	if !t.connManager.IsAttestationVerified() {
		err := fmt.Errorf("cannot send to TEE_T: attestation not verified")
		t.logger.WithSession(sessionID).Error("Attestation check failed", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonAttestationVerificationFailed, err,
			"TEE_T attestation not verified")
		return err
	}

	t.logger.WithSession(sessionID).Info("Sending to TEE_T",
		zap.String("type", getEnvelopePayloadType(env)))

	// Route control messages to control connection, session messages to session connection
	if isControlMessage(env) {
		return t.connManager.SendOnControl(env)
	}
	return t.connManager.SendOnSession(sessionID, env)
}
