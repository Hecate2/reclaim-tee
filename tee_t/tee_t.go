package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/proto"
)

// MaxWebSocketMessageSize is the maximum allowed WebSocket message size (30 MB)
// KOS precomputation for 100,000 OTs is about 1.7 MB; the larger limit also
// covers online garbled-circuit messages and protocol overhead.
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
	// attestationSF coalesces concurrent cache-miss refreshes — see
	// tee_k/tee_k.go for the full rationale.
	attestationSF singleflight.Group

	// Persistent OPRF key share (loaded from cloud storage)
	oprfKeyShare []byte

	// OT receiver state for the MPC OPRF protocol.
	otReceiverState   *OTReceiverState
	otReceiverStateMu sync.Mutex

	// TEE_K connection tracking
	teekConnected   bool
	teekConnectedMu sync.RWMutex

	// Per-session connection manager (control + per-session connections)
	connManager     *TEEKConnectionManager
	connManagerOnce sync.Once

	// V2 router-mode wiring. Nil/zero in standalone mode; filled by
	// NewTEETForRouter when ROUTER_URL is set.
	//
	// pairID is unknown until TEE_K's first envelope arrives on the
	// control connection — atomic.Pointer so the heartbeat goroutine,
	// connection manager, and OT code can all read/write without locks.
	ratls                   *shared.RATLSManager
	router                  *shared.RouterClient
	pairID                  atomic.Pointer[string]
	jwtPubKey               *ecdsa.PublicKey   // verifies client allocation JWTs (nil = no JWT check, local dev)
	expectedJWTIssuer       string             // expected iss claim on client allocation JWTs
	jtiTracker              *shared.JTITracker // replay guard for allocation-JWT jti (nil in standalone)
	expectedPeerImageDigest string             // sha256:... of TEE_K container image, for RA-TLS peer verification
	expectedPeerBaseDigest  string             // snp-base:<PCR11> of TEE_K's per-cloud base UKI (SEV-SNP only)

	// Heartbeat observation state — same shape as TEEK's. Written by the
	// connection manager / OT code; read by the heartbeat goroutine.
	controlHealthy atomic.Bool
	otReady        atomic.Bool
	activeSessions atomic.Int32

	// attestHealth gates the pair off the router (via ControlHealthy) and
	// self-resets when the SEV attestation path wedges. Nil-safe.
	attestHealth *shared.AttestationHealth

	// onPairAssigned is fired by the connection manager when it reads
	// TEE_K's TEEKPairAssignment envelope. Nil in standalone mode; set by
	// router_boot to register with the router and spin up the heartbeat
	// goroutine using the pair_id TEE_K just told us about.
	onPairAssigned func(pairID string)
}

// NewTEETWithLogger creates a baseline TEET with a specific logger.
// Higher-level constructors (NewTEETForRouter) layer mode-specific wiring
// on top.
func NewTEETWithLogger(port int, logger *shared.Logger) *TEET {
	sessionTerminator := shared.NewSessionTerminator(logger)

	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		if logger != nil {
			logger.Fatal("CRITICAL: Failed to generate signing key pair", zap.Error(err))
		}
		log.Fatalf("[TEE_T] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	if logger != nil {
		logger.Info("Generated ECDSA signing key pair", zap.String("curve", "P-256"))
	}

	oprfKeyShare := initializeOPRFKeyShare(logger)

	sessionManager := NewTEETSessionManager()
	sessionManager.SetLogger(logger)

	teet := &TEET{
		port:              port,
		sessionManager:    sessionManager,
		logger:            logger,
		sessionTerminator: sessionTerminator,
		signingKeyPair:    signingKeyPair,
		oprfKeyShare:      oprfKeyShare,
	}
	teet.connectionManager()

	sessionManager.SetOnSessionExpired(teet.cleanupSessionWithSession)

	return teet
}

func (t *TEET) connectionManager() *TEEKConnectionManager {
	t.connManagerOnce.Do(func() {
		t.connManager = NewTEEKConnectionManager(t, t.logger)
	})
	return t.connManager
}

// NewTEETForRouter constructs a TEET wired for the V2 router-mode path.
// pair_id is NOT set here — it arrives over the peer connection in
// TEE_K's TEEKPairAssignment envelope. The connection manager fills it
// in via teet.pairID.Store(&pid).
func NewTEETForRouter(
	config *TEETConfig,
	ratls *shared.RATLSManager,
	router *shared.RouterClient,
	logger *shared.Logger,
) *TEET {
	teet := NewTEETWithLogger(config.Port, logger)
	teet.ratls = ratls
	teet.router = router
	teet.expectedPeerImageDigest = config.ExpectedPeerImageDigest
	teet.expectedPeerBaseDigest = config.ExpectedPeerBaseDigest
	return teet
}

// initializeOPRFKeyShare returns TEE_T's MPC OPRF key share. When
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
			log.Fatalf("[TEE_T] CRITICAL: attested TEE requires KMS_ENCLAVE_DOMAIN_KEY (real OPRF); refusing the static dev share")
		}
		keyShare := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
		if logger != nil {
			logger.Info("Using static OPRF key share (KMS_ENCLAVE_DOMAIN_KEY unset; local dev only)")
		}
		return keyShare
	}
	share, err := shared.LoadOPRFShare("tee_t", deploymentKey, logger)
	if err != nil {
		log.Fatalf("[TEE_T] CRITICAL: load OPRF share: %v", err)
	}
	return share
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

// PairID / Router / ControlHealthy / OTReady / ActiveSessions satisfy
// shared.HeartbeatTarget so router heartbeat logic lives in shared/.
// PairID returns "" until TEE_K's TEEKPairAssignment envelope arrives;
// callers must tolerate the empty case.
func (t *TEET) PairID() string {
	p := t.pairID.Load()
	if p == nil {
		return ""
	}
	return *p
}
func (t *TEET) Router() *shared.RouterClient { return t.router }
func (t *TEET) ControlHealthy() bool         { return t.controlHealthy.Load() && t.attestHealth.Healthy() }
func (t *TEET) OTReady() bool                { return t.otReady.Load() }
func (t *TEET) ActiveSessions() int          { return int(t.activeSessions.Load()) }

// CAS-guarded; mirrors TEE_K's cleanupSession.
func (t *TEET) cleanupSession(sessionID string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Debug("Session missing, cleanup already ran")
		return
	}
	t.cleanupSessionWithSession(session)
}

func (t *TEET) cleanupSessionWithSession(session *shared.Session) {
	if !session.CleanedUp.CompareAndSwap(false, true) {
		t.logger.WithSession(session.ID).Debug("Session cleanup already claimed by another caller")
		return
	}
	ownerGeneration, ownsSessionState := t.sessionManager.controlGenerationForSession(session)
	if t.connManager != nil && ownsSessionState {
		t.connManager.CloseSessionConnection(session.ID, ownerGeneration, session)
	}
	_ = t.sessionManager.closeSessionIfCurrent(session)
	t.activeSessions.Add(-1)
	if ownsSessionState && t.sessionTerminator != nil {
		t.sessionTerminator.CleanupSession(session.ID)
	}
	t.logger.WithSession(session.ID).Info("Session terminated and cleaned up")
}

// terminateSessionWithError terminates a session due to a critical error
// Sends error notification to both client and TEE_K, then cleans up session
// This function implements ZERO TOLERANCE - always terminates the session
func (t *TEET) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
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

	// Send error to TEE_K on control connection (session connection may be dead)
	if t.connManager != nil {
		if sendErr := t.connManager.SendOnControl(env); sendErr != nil {
			t.logger.WithSession(sessionID).Warn("Failed to send error to TEE_K on control", zap.Error(sendErr))
		}
	}

	// Small delay to ensure error messages are sent before connection closes
	time.Sleep(50 * time.Millisecond)

	// Cleanup session resources
	t.cleanupSession(sessionID)
}

func (t *TEET) terminateSessionWithErrorForIdentity(identity *teetSessionIdentity, reason shared.TerminationReason, err error, message string) {
	if identity == nil || identity.session == nil {
		return
	}
	session := identity.session
	if currentErr := identity.ensureCurrent(); currentErr != nil {
		t.logger.WithSession(session.ID).Debug("Ignoring stale session termination", zap.Error(currentErr))
		return
	}

	t.logger.WithSession(session.ID).Error(message, zap.Error(err), zap.String("reason", string(reason)))
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}
	env := &teeproto.Envelope{
		SessionId: session.ID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errorMsg}},
	}
	if routeErr := t.routeToClientForSession(session, env); routeErr != nil {
		t.logger.WithSession(session.ID).Warn("Failed to send error to client", zap.Error(routeErr))
	}
	if t.connManager != nil {
		if sendErr := t.connManager.SendOnControlForSession(session, env); sendErr != nil {
			t.logger.WithSession(session.ID).Warn("Failed to send error to TEE_K on control", zap.Error(sendErr))
		}
	}
	time.Sleep(50 * time.Millisecond)
	t.cleanupSessionWithSession(session)
}

// handlePeerErrorForIdentity forwards an independently generated TEE_K error
// to this session's client and cleans the exact owner without echoing it back.
func (t *TEET) handlePeerErrorForIdentity(identity *teetSessionIdentity, peerErr *teeproto.ErrorData) error {
	if identity == nil || identity.ensureCurrent() != nil {
		return fmt.Errorf("peer error belongs to a superseded session")
	}
	session := identity.session
	if peerErr == nil {
		t.logger.WithSession(session.ID).Error("Malformed terminal error from TEE_K: missing error data")
		peerErr = &teeproto.ErrorData{Message: "Malformed error from TEE_K: missing error data"}
	} else {
		t.logger.WithSession(session.ID).Info("TEE_K reported a terminal session error", zap.String("error", peerErr.GetMessage()))
	}
	env := &teeproto.Envelope{
		SessionId: session.ID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: peerErr},
	}
	if routeErr := t.routeToClientForSession(session, env); routeErr != nil {
		t.logger.WithSession(session.ID).Warn("Failed to forward TEE_K error to client", zap.Error(routeErr))
	}
	t.cleanupSessionWithSession(session)
	return nil
}

func (t *TEET) routeToClientForSession(session *shared.Session, env *teeproto.Envelope) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	session.ConnMutex.RLock()
	conn := session.ClientConn
	session.ConnMutex.RUnlock()
	return writeEnvelopeToExactSessionConnection(session.ID, conn, env, "client")
}

func (t *TEET) routeToTEEKForSession(session *shared.Session, env *teeproto.Envelope) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	session.ConnMutex.RLock()
	conn := session.TEEKConn
	session.ConnMutex.RUnlock()
	return writeEnvelopeToExactSessionConnection(session.ID, conn, env, "TEE_K")
}

func writeEnvelopeToExactSessionConnection(sessionID string, conn shared.Connection, env *teeproto.Envelope, peer string) error {
	if conn == nil {
		return fmt.Errorf("no %s connection in session %s", peer, sessionID)
	}
	ws, ok := conn.(*shared.WSConnection)
	if !ok {
		return fmt.Errorf("unsupported %s connection type", peer)
	}
	if env.GetSessionId() == "" {
		env.SessionId = sessionID
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	return ws.WriteMessage(websocket.BinaryMessage, data)
}
