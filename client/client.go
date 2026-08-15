package client

import (
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type ProtocolPhase int

const (
	// Core TEE protocol phases (0-60%)
	PhaseHandshaking         ProtocolPhase = iota // 0-10%: TLS handshake
	PhaseCollectingResponses                      // 10-30%: HTTP request/response
	PhaseReceivingDecryption                      // 30-40%: Receiving decryption streams
	PhaseSendingRedaction                         // 40-45%: Sending redaction specs
	PhaseReceivingRedacted                        // 45-55%: Receiving redacted streams
	PhaseValidating                               // 55-60%: Validation checks

	// OPRF processing phases (60-80%) - optional
	PhaseProcessingOPRF     // 60-70%: OPRF service calls
	PhaseGeneratingZKProofs // 70-80%: ZK proof generation

	// Final phases (85-100%)
	PhaseBuildingBundle   // 85%: Building verification bundle
	PhaseSubmittingAttest // 90%: Submitting to attestor
	PhaseReceivingClaim   // 95-100%: Receiving claim
	PhaseComplete         // 100%: Everything done
)

func (p ProtocolPhase) String() string {
	switch p {
	case PhaseHandshaking:
		return "Handshaking"
	case PhaseCollectingResponses:
		return "CollectingResponses"
	case PhaseReceivingDecryption:
		return "ReceivingDecryption"
	case PhaseSendingRedaction:
		return "SendingRedaction"
	case PhaseReceivingRedacted:
		return "ReceivingRedacted"
	case PhaseValidating:
		return "Validating"
	case PhaseProcessingOPRF:
		return "ProcessingOPRF"
	case PhaseGeneratingZKProofs:
		return "GeneratingZKProofs"
	case PhaseBuildingBundle:
		return "BuildingBundle"
	case PhaseSubmittingAttest:
		return "SubmittingAttest"
	case PhaseReceivingClaim:
		return "ReceivingClaim"
	case PhaseComplete:
		return "Complete"
	default:
		return "Unknown"
	}
}

// TLSResponseData stores parsed TLS response data to avoid repeated parsing
type TLSResponseData struct {
	ActualContent []byte // Content after removing padding
	ContentType   byte   // TLS content type (inner for TLS 1.3, record type for TLS 1.2)
	OriginalLen   int    // Length before stripping (matches TEE_T's view: decrypted_len including content type)
}

// GetPhasePercentage returns the progress percentage for a given phase
func (p ProtocolPhase) GetPhasePercentage() int {
	switch p {
	case PhaseHandshaking:
		return 5
	case PhaseCollectingResponses:
		return 20
	case PhaseReceivingDecryption:
		return 35
	case PhaseSendingRedaction:
		return 42
	case PhaseReceivingRedacted:
		return 50
	case PhaseValidating:
		return 60
	case PhaseProcessingOPRF:
		return 65
	case PhaseGeneratingZKProofs:
		return 75
	case PhaseBuildingBundle:
		return 85
	case PhaseSubmittingAttest:
		return 90
	case PhaseReceivingClaim:
		return 97
	case PhaseComplete:
		return 100
	default:
		return 0
	}
}

type Client struct {
	// WebSocket connections
	wsConn   *websocket.Conn // Protected by connectionMutex
	teetConn *websocket.Conn // Protected by connectionMutex
	tcpConn  net.Conn

	// connectionMutex owns publication of both TEE connections and their
	// generations. Readers receive the exact connection and generation they
	// belong to and never reload these mutable fields.
	connectionMutex        sync.Mutex
	connectionCleanupMutex sync.Mutex
	pairConnectMutex       sync.Mutex
	teekConnectMutex       sync.Mutex
	teetConnectMutex       sync.Mutex
	connectionEpoch        uint64
	connectionsClosing     bool
	connectionCleanupDone  chan struct{}
	teekGeneration         uint64
	teetGeneration         uint64
	teekReaderDone         chan struct{}
	teetReaderDone         chan struct{}
	teeDial                func(role, rawURL string) (*websocket.Conn, error) // test hook

	// WebSocket write synchronization (gorilla/websocket requires serialized writes)
	wsWriteMutex   sync.Mutex // Protects all writes to wsConn
	teetWriteMutex sync.Mutex // Protects all writes to teetConn

	// Logging
	logger    *shared.Logger
	requestId string // Request ID for tracking across system

	// Session management (protected by sessionMutex)
	sessionID                string                        // Session ID received from TEE_K
	pendingConnectionRequest *shared.RequestConnectionData // Connection request waiting for session ID
	connectionRequestPending bool                          // Whether a connection request is pending
	sessionMutex             sync.RWMutex                  // Protects sessionID and pending connection fields

	teekURL           string
	teetURL           string
	routerJWT         string // allocation JWT; sent as ClientAuth first envelope when non-empty
	attestorURL       string
	forceTLSVersion   string // Force specific TLS version: "1.2", "1.3", or "" for auto
	forceCipherSuite  string // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
	proxyURL          string // HTTPS proxy URL template from env var
	targetHost        string
	targetPort        int
	isClosing         atomic.Bool
	capturedTraffic   [][]byte // Append guarded by capturedTrafficMu (three writer goroutines).
	capturedTrafficMu sync.Mutex
	handshakeComplete atomic.Bool // Routing boundary for captured records; Store after responseSeqNum write.

	// Attestor client (created lazily when needed)
	attestorClient      *AttestorClient
	attestorMutex       sync.Mutex
	attestorAuthRequest *teeproto.AuthenticationRequest // Optional auth request forwarded to the attestor

	// Phase 4: Response handling
	responseSeqNum uint64 // TLS sequence number for response AEAD
	requestSeqNum  uint64 // TLS sequence number for request AEAD (starts at 1 after handshake)

	// Protocol completion signaling
	completionChan      chan error // Signals when protocol is complete (nil = success, non-nil = error)
	coreProtocolTimeout time.Duration
	coreProtocolDone    chan struct{}

	completionOnce    sync.Once // Ensures completion channel is only closed once
	completionClaimed atomic.Bool
	watchdogOnce      sync.Once
	watchdogStop      chan struct{}
	watchdogStopOnce  sync.Once

	protocolPhase          ProtocolPhase // Current protocol phase
	teeKTranscriptReceived bool          // TEE_K transcript received
	teeTTranscriptReceived bool          // TEE_T transcript received
	teeKSignatureValid     bool          // TEE_K body, identity, and signature validated
	teeTSignatureValid     bool          // TEE_T body, identity, and signature validated
	protocolStateMutex     sync.RWMutex  // Protect simple state
	phaseCompletionHook    func()        // test hook after success claim while state remains locked
	closeBeforePublishHook func()        // test hook after cleanup and before Close completion publication
	protocolRunMutex       sync.Mutex
	protocolStarted        bool
	httpRequestStarted     bool

	// Track HTTP request/response lifecycle
	httpRequestSent       atomic.Bool                 // Set after final fragment written to TCP; read by TCP reader goroutine.
	httpResponseExpected  bool                        // Track if we should expect HTTP response
	parsedResponseBySeq   map[uint64]*TLSResponseData // Store parsed TLS response data by sequence
	responseContentMutex  sync.Mutex                  // For all response maps
	ciphertextBySeq       map[uint64][]byte           // Store encrypted response data by sequence
	decryptionStreamBySeq map[uint64][]byte           // Store decryption streams by sequence

	// Batched response tracking (collection until EOF)
	batchedResponses []shared.EncryptedResponseData // Collect response packets until EOF

	// recordState is this session's TLS record-reassembly buffer. Per-Client
	// (never a package global) so an overlapping session/retry can't splice or
	// drop records across streams. One reader goroutine, so no lock needed.
	recordState tlsRecordState

	// lastBatchDiag retains per-record fingerprints of the batch last sent to
	// TEE_T, kept after the batch is cleared so a failure can be correlated
	// with TEE_T's per-record fingerprints. Diagnostic only, no plaintext.
	lastBatchDiag []recordDiag

	// Response processing success tracking
	responseProcessingSuccessful bool // Track if response was successfully processed
	reconstructedResponseSize    int  // Size of reconstructed response data

	// Track redaction ranges so we can prettify later and include in bundle
	requestRedactionRanges []shared.RequestRedactionRange

	// Library interface fields
	modeMutex            sync.Mutex
	clientMode           ClientMode // Client operational mode (enclave vs standalone)
	verifyGCPAttestation func([]byte) error
	findGCPNonce         func([]byte, string) (string, error)
	verifySEVAttestation func([]byte) ([]string, error)

	// Provider parameters for automatic response redactions
	providerParams       *providers.HTTPProviderParams
	providerSecretParams *providers.HTTPProviderSecretParams

	// Result tracking fields
	protocolStartTime           time.Time                       // When protocol started
	lastResponseData            *HTTPResponse                   // Last received HTTP response
	lastRedactionRanges         []shared.ResponseRedactionRange // Last redaction ranges from callback
	responseReconstructed       bool                            // Flag to prevent multiple response reconstruction
	transcriptValidationResults *TranscriptValidationResults    // Cached validation results

	// Verification bundle tracking fields
	cipherSuite       uint16                  // negotiated cipher suite (replaces handshakeDisclosure)
	teekSignedMessage *teeproto.SignedMessage // original protobuf SignedMessage from TEE_K
	teetSignedMessage *teeproto.SignedMessage // original protobuf SignedMessage from TEE_T

	responseKeystream              []byte // redacted keystream
	consolidatedResponseCiphertext []byte // ciphertext

	redactedRequestPlain    []byte // R_red plaintext sent to TEE_K
	expectedRedactedStreams int    // expected number of redacted streams from response sequences

	// Request data from libreclaim library
	requestData []byte

	// Redaction ranges that need OPRF processing (client-side TOPRF)
	// Map from range start position to length
	oprfRedactionRanges map[int]int

	// MPC OPRF redaction ranges (TEE-to-TEE MPC OPRF)
	// Map from HTTP range start position to length
	oprfMpcRedactionRanges map[int]int

	// HTTP to TLS position mapping from response analysis
	httpToTlsMapping []TLSToHTTPMapping

	// OPRF processed data for each hashed range
	oprfRanges map[int]*OPRFRangeData
	oprfMutex  sync.RWMutex
	// Legacy completion cannot be inferred from len(oprfRanges): MPC ranges may
	// already be present, and a failed legacy attempt must remain retryable.
	oprfLegacyComplete bool
	processOPRFRange   func(start, length int) (*OPRFRangeData, error) // test hook

	// MPC OPRF state
	oprfMpcRangesSent    bool                      // Track if ranges were sent
	oprfMpcRangesSpec    []*teeproto.OPRFRangeSpec // Ranges sent to TEEs
	oprfMpcRangeMappings []OPRFMPCRangeMapping     // HTTP <-> TLS position mappings for OPRF
}

func NewClient(teekURL string) *Client {
	// Use the shared Flutter-enabled logger
	logger := GetLogger("client", false)

	return &Client{
		logger:              logger,
		teekURL:             teekURL,
		teetURL:             "wss://tee-t-gcp.reclaimprotocol.org/ws", // Default TEE_T URL (enclave mode)
		completionChan:      make(chan error, 1),                      // buffered to avoid blocking
		coreProtocolTimeout: time.Minute,
		coreProtocolDone:    make(chan struct{}),
		watchdogStop:        make(chan struct{}),

		protocolPhase:          PhaseHandshaking,
		teeKTranscriptReceived: false,
		teeTTranscriptReceived: false,
		protocolStateMutex:     sync.RWMutex{},
		httpResponseExpected:   false,
		responseContentMutex:   sync.Mutex{},
		parsedResponseBySeq:    make(map[uint64]*TLSResponseData),
		ciphertextBySeq:        make(map[uint64][]byte),
		decryptionStreamBySeq:  make(map[uint64][]byte),
		requestRedactionRanges: nil,

		// Initialize batching fields
		batchedResponses: make([]shared.EncryptedResponseData, 0),

		// Response processing success tracking
		responseProcessingSuccessful: false,
		reconstructedResponseSize:    0,
		requestSeqNum:                1, // Start at 1 for first application data after handshake

		clientMode:                  ModeAuto, // Default to auto-detect
		providerParams:              nil,
		providerSecretParams:        nil,
		protocolStartTime:           time.Now(),
		lastResponseData:            nil,
		transcriptValidationResults: nil,
		expectedRedactedStreams:     0,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (c *Client) SetTEETURL(url string) {
	c.modeMutex.Lock()
	defer c.modeMutex.Unlock()
	c.teetURL = url
}

// SetRouterJWT installs the allocation JWT the client received from the
// router. When set, ConnectToTEEK / ConnectToTEET send a ClientAuth
// envelope as the first message before any other protocol traffic.
func (c *Client) SetRouterJWT(jwt string) {
	c.modeMutex.Lock()
	defer c.modeMutex.Unlock()
	c.routerJWT = jwt
}

// SetMode sets the client operational mode
func (c *Client) SetMode(mode ClientMode) {
	c.modeMutex.Lock()
	defer c.modeMutex.Unlock()
	c.clientMode = mode
}

// resolveClientMode preserves the direct NewClient compatibility path while
// keeping unresolved router clients fail-closed. NewReclaimClient resolves
// ModeAuto explicitly; a router JWT on a still-Auto direct client is therefore
// production evidence, not standalone evidence.
func (c *Client) resolveClientMode() ClientMode {
	c.modeMutex.Lock()
	defer c.modeMutex.Unlock()
	if c.clientMode != ModeAuto {
		return c.clientMode
	}
	if c.routerJWT != "" {
		return ModeEnclave
	}
	return detectMode(c.teekURL, c.teetURL)
}

// setAttestorAuthRequest decodes a base64 protobuf AuthenticationRequest and
// stores it for the attestor InitRequest. Empty input clears any auth request.
func (c *Client) setAttestorAuthRequest(authRequestB64 string) error {
	if authRequestB64 == "" {
		c.attestorAuthRequest = nil
		return nil
	}

	raw, err := base64.StdEncoding.DecodeString(authRequestB64)
	if err != nil {
		return fmt.Errorf("failed to base64-decode auth request: %v", err)
	}

	authRequest := &teeproto.AuthenticationRequest{}
	if err := proto.Unmarshal(raw, authRequest); err != nil {
		return fmt.Errorf("failed to unmarshal auth request: %v", err)
	}

	c.attestorAuthRequest = authRequest
	c.logger.Info("Attestor auth request configured",
		zap.String("user_id", authRequest.GetData().GetId()),
		zap.Uint32("expires_at", authRequest.GetData().GetExpiresAt()))
	return nil
}

// getAttestorClient returns the attestor client, creating it lazily if needed
func (c *Client) getAttestorClient() (*AttestorClient, error) {
	c.attestorMutex.Lock()
	defer c.attestorMutex.Unlock()
	if c.isClosing.Load() {
		return nil, fmt.Errorf("client is closed")
	}

	if c.attestorClient != nil {
		return c.attestorClient, nil
	}
	if c.attestorURL == "" {
		return nil, fmt.Errorf("attestor URL not configured")
	}

	// Do not publish partial state. A generation failure leaves the next call
	// free to retry, while a successful client is reused exactly.
	privateKey, err := shared.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	c.attestorClient = NewAttestorClient(c.attestorURL, privateKey, c.attestorAuthRequest, c.logger)
	return c.attestorClient, nil
}

func (c *Client) RequestHTTP() error {
	if err := c.beginHTTPRequest(); err != nil {
		return err
	}
	abortBeforePublication := func(err error) error {
		c.resetTEEConnectionsForRetry()
		c.resetProtocolStart()
		return err
	}

	// Extract hostname and port from provider params
	hostname, port, err := c.getHostPortFromProviderParams()
	if err != nil {
		return abortBeforePublication(fmt.Errorf("failed to extract host and port from provider params: %v", err))
	}

	c.targetHost = hostname
	c.targetPort = port

	c.logger.Info("Requesting connection",
		zap.String("hostname", hostname),
		zap.Int("port", port))

	// Generate request data and redaction ranges automatically from provider params
	if err := c.generateAutomaticRequestData(); err != nil {
		return abortBeforePublication(fmt.Errorf("failed to generate automatic request data: %v", err))
	}

	// Store connection request data to be sent once session ID is received
	c.sessionMutex.Lock()
	c.pendingConnectionRequest = &shared.RequestConnectionData{
		Hostname:         hostname,
		Port:             port,
		SNI:              hostname,
		ALPN:             []string{"http/1.1"},
		ForceTLSVersion:  c.forceTLSVersion,
		ForceCipherSuite: c.forceCipherSuite,
	}
	c.connectionRequestPending = true
	sessionID := c.sessionID
	c.sessionMutex.Unlock()

	// Check if we already have a session ID and send immediately
	if sessionID != "" {
		if err := c.sendPendingConnectionRequest(); err != nil {
			c.terminateConnectionWithErrorAndWait("Failed to send connection request", err)
			return err
		}
	}
	c.startCoreProtocolWatchdog()

	// Otherwise, request will be sent when session ID is received in handleSessionReady
	return nil
}

func (c *Client) beginHTTPRequest() error {
	c.protocolRunMutex.Lock()
	defer c.protocolRunMutex.Unlock()
	if c.isClosing.Load() {
		return fmt.Errorf("client is closed")
	}
	if c.httpRequestStarted {
		return fmt.Errorf("protocol request already started")
	}
	if !c.protocolStarted {
		c.protocolStarted = true
	}
	c.httpRequestStarted = true
	return nil
}

func (c *Client) beginProtocol() error {
	c.protocolRunMutex.Lock()
	defer c.protocolRunMutex.Unlock()
	if c.protocolStarted {
		return fmt.Errorf("protocol already started")
	}
	if c.isClosing.Load() {
		return fmt.Errorf("client is closed")
	}
	c.protocolStarted = true
	return nil
}

// resetProtocolStart is only used after all acquired TEE sockets have been
// detached and closed, before any protocol request was published.
func (c *Client) resetProtocolStart() {
	c.protocolRunMutex.Lock()
	c.protocolStarted = false
	c.httpRequestStarted = false
	c.protocolRunMutex.Unlock()
}

// advanceToPhase transitions to a new protocol phase (thread-safe)
func (c *Client) advanceToPhase(newPhase ProtocolPhase) {
	c.protocolStateMutex.Lock()
	oldPhase := c.protocolPhase
	if newPhase <= oldPhase {
		c.protocolStateMutex.Unlock()
		return
	}
	c.protocolPhase = newPhase
	reachedCoreCompletion := oldPhase < PhaseValidating && newPhase >= PhaseValidating
	claimedCompletion := false
	if reachedCoreCompletion {
		claimedCompletion = c.claimProtocolCompletion()
		if c.phaseCompletionHook != nil {
			c.phaseCompletionHook()
		}
	}
	c.protocolStateMutex.Unlock()

	// Get phase description for progress reporting
	description := c.getPhaseDescription(newPhase)

	logFields := []zap.Field{
		zap.String("from", oldPhase.String()),
		zap.String("to", newPhase.String()),
		zap.Int("progress_percentage", newPhase.GetPhasePercentage()),
		zap.String("progress_description", description),
	}
	if c.requestId != "" {
		logFields = append(logFields, zap.String("requestId", c.requestId))
	}
	c.logger.Info("Protocol progress", logFields...)

	// Signal completion when core protocol validation is complete (ready for post-protocol work)
	if reachedCoreCompletion {
		c.logger.Info("Core protocol validation complete - signaling success")
		if claimedCompletion {
			c.publishProtocolCompletion(nil)
		}
	}
}

// checkForProtocolCompletion checks if protocol can be completed
func (c *Client) checkForProtocolCompletion() {
	c.protocolStateMutex.RLock()
	complete := c.teeKTranscriptReceived && c.teeTTranscriptReceived && c.teeKSignatureValid && c.teeTSignatureValid
	c.protocolStateMutex.RUnlock()
	if complete {
		c.logger.Info("Both transcripts received AND redacted streams processed - core protocol validation complete")
		c.advanceToPhase(PhaseValidating)
	} else {
		c.logger.Info("Waiting for both transcripts...")
	}
}

func (c *Client) claimProtocolCompletion() bool {
	return c.completionClaimed.CompareAndSwap(false, true)
}

func (c *Client) claimProtocolCompletionWithState() bool {
	c.protocolStateMutex.Lock()
	claimed := c.claimProtocolCompletion()
	c.protocolStateMutex.Unlock()
	return claimed
}

func (c *Client) publishProtocolCompletion(err error) {
	c.completionOnce.Do(func() {
		select {
		case c.completionChan <- err:
		default:
		}
		close(c.coreProtocolDone)
	})
}

func (c *Client) startCoreProtocolWatchdog() {
	c.watchdogOnce.Do(func() {
		timeout := c.coreProtocolTimeout
		if timeout <= 0 {
			timeout = time.Minute
		}
		go func() {
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			select {
			case <-c.coreProtocolDone:
				return
			case <-c.watchdogStop:
				return
			case <-timer.C:
			}

			err := fmt.Errorf("core TEE protocol timed out after %s", timeout)
			// Claim completion before cleanup so a success racing the timer cannot
			// be followed by timeout-driven teardown.
			if !c.claimProtocolCompletionWithState() {
				return
			}
			c.terminateConnectionCleanup("Core TEE protocol timeout", err, true)
			c.publishProtocolCompletion(err)
		}()
	})
}

func (c *Client) stopCoreProtocolWatchdog() {
	c.watchdogStopOnce.Do(func() { close(c.watchdogStop) })
}

// getResponseRedactions generates automatic response redactions using provider params
func (c *Client) getResponseRedactions(response *HTTPResponse) ([]shared.ResponseRedactionRange, error) {
	if c.providerParams == nil {
		c.logger.Debug("No provider params available for automatic redactions")
		return []shared.ResponseRedactionRange{}, nil
	}

	if len(c.providerParams.ResponseRedactions) == 0 {
		c.logger.Debug("No response redaction rules specified in provider params")
		return []shared.ResponseRedactionRange{}, nil
	}

	ctx := &providers.ProviderCtx{Version: providers.ATTESTOR_VERSION_3_2_0}

	ranges, err := providers.GetResponseRedactions(response.FullResponse, c.providerParams, ctx, c.requestId)
	if err != nil {
		return nil, fmt.Errorf("failed to get automatic response redactions: %v", err)
	}

	// Initialize OPRF redaction maps if needed
	if c.oprfRedactionRanges == nil {
		c.oprfRedactionRanges = make(map[int]int)
	}
	if c.oprfMpcRedactionRanges == nil {
		c.oprfMpcRedactionRanges = make(map[int]int)
	}

	// Process OPRF redactions - store ranges that need OPRF processing
	for _, r := range ranges {
		// Check if this range requires OPRF processing (Hash field indicates OPRF type)
		if r.Start >= 0 && r.Start+r.Length <= len(response.FullResponse) {
			if r.Hash == *providers.HASH_TYPE_OPRF {
				// Client-side TOPRF processing
				c.oprfRedactionRanges[r.Start] = r.Length
				c.logger.Info("Marked range for TOPRF processing",
					zap.Int("start", r.Start),
					zap.Int("length", r.Length),
					zap.String("hash_type", r.Hash))
			} else if r.Hash == *providers.HASH_TYPE_OPRF_MPC {
				// TEE-to-TEE MPC OPRF processing
				c.oprfMpcRedactionRanges[r.Start] = r.Length
				c.logger.Info("Marked range for MPC OPRF processing",
					zap.Int("start", r.Start),
					zap.Int("length", r.Length),
					zap.String("hash_type", r.Hash))
			}
		}
	}

	// Consolidate ranges to reduce transmission overhead
	consolidatedRanges := shared.ConsolidateResponseRedactionRanges(ranges)

	c.logger.Info("Generated automatic response redactions",
		zap.Int("original_ranges", len(ranges)),
		zap.Int("consolidated_ranges", len(consolidatedRanges)))

	return consolidatedRanges, nil
}

// generateAutomaticRequestData generates request data and redaction ranges automatically from provider params
func (c *Client) generateAutomaticRequestData() error {
	if c.providerParams == nil {
		c.logger.Debug("No provider params available for automatic request generation")
		return fmt.Errorf("provider params required for automatic request generation")
	}

	// Generate request using provider params
	req, err := providers.CreateRequest(c.providerSecretParams, c.providerParams)
	if err != nil {
		return fmt.Errorf("failed to create request from provider params: %v", err)
	}

	// Set the generated request data and redaction ranges
	c.requestData = req.Data
	c.requestRedactionRanges = req.Redactions

	c.logger.Info("Generated automatic request from provider params",
		zap.Int("request_data_bytes", len(req.Data)),
		zap.Int("redaction_ranges", len(req.Redactions)))

	return nil
}

// getHostPortFromProviderParams extracts hostname and port from provider params
func (c *Client) getHostPortFromProviderParams() (string, int, error) {
	if c.providerParams == nil {
		return "", 0, fmt.Errorf("provider params required to determine host and port")
	}

	return providers.GetHostPort(c.providerParams, c.providerSecretParams)
}

// NOTE: Session coordination removed - handled naturally by RequestHTTP()
// The client receives sessionID asynchronously via handleSessionReady() and
// RequestHTTP() automatically waits for it before sending connection requests.

// buildTranscriptResults constructs the transcript results from SignedMessage data
// moved to results_build.go

// extractEthAddressFromSignedMessage extracts the ETH address from a SignedMessage (attestation or direct address)
func extractEthAddressFromSignedMessage(signedMsg *teeproto.SignedMessage) []byte {
	if signedMsg.GetAttestationReport() != nil {
		// In enclave mode, ETH address should be extracted from attestation (but that's complex)
		// For now, return empty - the ETH address extraction happens during verification
		return nil
	}
	// In standalone mode, return the direct ETH address
	return append([]byte(nil), signedMsg.GetEthAddress()...)
}

// SubmitToAttestorCore submits the completed verification bundle to attestor-core for claim validation
func (c *Client) SubmitToAttestorCore(params ClaimTeeBundleParams) (*ClaimWithSignatures, error) {
	// Submit to attestor-core
	c.logger.Info("Submitting verification bundle to attestor-core...")

	// Ensure we have a verification bundle ready
	if c.teekSignedMessage == nil || c.teetSignedMessage == nil {
		return nil, fmt.Errorf("TEE protocol not completed - no signed messages available")
	}

	// Get attestor client (created lazily if needed)
	attestorClient, err := c.getAttestorClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get attestor client: %v", err)
	}

	// Process OPRF for all hashed ranges before building bundle
	if len(c.oprfRedactionRanges) > 0 {
		c.logger.Info("Processing OPRF for redaction ranges",
			zap.Int("num_ranges", len(c.oprfRedactionRanges)))

		if err := c.ProcessOPRFForHashedRanges(attestorClient); err != nil {
			return nil, fmt.Errorf("failed to process OPRF for hashed ranges: %v", err)
		}

		// Replace ParamValues with OPRF outputs for attestor validation
		if params.Parameters != nil && params.Parameters.ParamValues != nil {
			c.replaceParamValuesWithOPRF(params.Parameters)

			c.logger.Info("Updated parameters with OPRF replacements",
				zap.Int("parameter_count", len(params.Parameters.ParamValues)))
		}
	}

	// Build verification bundle using the same method as standalone
	// This ensures OPRF data is properly included
	bundleData, err := c.buildVerificationBundle()
	if err != nil {
		return nil, fmt.Errorf("failed to build verification bundle: %v", err)
	}

	// Unmarshal the bundle data to get the protobuf structure
	var bundle teeproto.VerificationBundle
	if err := proto.Unmarshal(bundleData, &bundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verification bundle: %v", err)
	}

	c.logger.Info("Submitting verification bundle to attestor-core",
		zap.String("attestor_url", attestorClient.url),
		zap.Int("oprf_verifications", len(bundle.OprfVerifications)))

	result, err := attestorClient.SubmitTeeBundle(&bundle, params)
	if err != nil {
		return nil, fmt.Errorf("failed to submit TEE bundle: %v", err)
	}

	c.logger.Info("Successfully submitted TEE bundle to attestor-core",
		zap.String("claim_id", result.Claim.Identifier),
		zap.String("provider", result.Claim.Provider),
		zap.Bool("has_signatures", result.Signature != nil))

	return result, nil
}

// ExecuteCompleteProtocol runs the complete protocol flow from initialization through claim receipt
// This method replaces the split model where external code handled OPRF processing and attestor submission
func (c *Client) ExecuteCompleteProtocol(
	providerData *ProviderRequestData,
) (result *ClaimWithSignatures, retErr error) {
	if providerData == nil {
		return nil, fmt.Errorf("provider data is required")
	}
	if err := c.beginProtocol(); err != nil {
		return nil, err
	}

	c.logger.Info("Starting complete protocol execution")

	// Helper function to report progress
	reportProgress := func(phase ProtocolPhase, description string) {
		c.advanceToPhase(phase)

	}

	// Phase 1-6: Core TEE protocol - start and wait for completion
	reportProgress(PhaseHandshaking, "Starting TLS handshake with target server")

	// Set provider params in client (equivalent to what StartProtocol does)
	c.providerParams = providerData.Params
	c.providerSecretParams = providerData.SecretParams

	// Decode the optional attestor auth request before the attestor client is created.
	if err := c.setAttestorAuthRequest(providerData.AuthRequest); err != nil {
		c.resetProtocolStart()
		return nil, err
	}

	// Connect to TEEs (equivalent to Connect())
	if err := c.connectToTEEs(); err != nil {
		c.resetProtocolStart()
		return nil, fmt.Errorf("failed to connect to TEEs: %v", err)
	}

	// Start the protocol (equivalent to RequestHTTP)
	if err := c.RequestHTTP(); err != nil {
		return nil, fmt.Errorf("failed to start HTTP request: %v", err)
	}
	defer func() {
		if retErr != nil {
			c.Close()
		}
	}()

	// Wait for the core protocol to complete
	if err := c.waitForCoreProtocol(); err != nil {
		return nil, err
	}
	c.logger.Info("Core TEE protocol completed successfully")

	// The core protocol is now complete (at PhaseComplete), continue with post-protocol work
	// Note: No phase transitions here since the protocol naturally completed

	// Phase 7-8: OPRF Processing and ZK Proof Generation (65-84%) - Optional based on redaction ranges
	hasOPRFRanges := len(c.oprfRedactionRanges) > 0
	if hasOPRFRanges {
		// Get or create the attestor client
		attestorClient, err := c.getAttestorClient()
		if err != nil {
			return nil, fmt.Errorf("failed to get attestor client: %v", err)
		}

		// Progress reporting is handled inside ProcessOPRFForHashedRanges for each operation
		if err := c.ProcessOPRFForHashedRanges(attestorClient); err != nil {
			return nil, fmt.Errorf("OPRF processing failed: %v", err)
		}

		// Log final summary
		oprfRanges := c.GetOPRFRanges()
		zkProofCount := 0
		for _, oprfData := range oprfRanges {
			if len(oprfData.ZKProof) > 0 {
				zkProofCount++
			}
		}

		c.logger.Info("OPRF and ZK proof processing completed",
			zap.Int("oprf_ranges", len(c.oprfRedactionRanges)),
			zap.Int("zk_proofs", zkProofCount))
	}

	// Phase 9: Building Verification Bundle (85%)
	reportProgress(PhaseBuildingBundle, "Building verification bundle with OPRF data")

	// Get or create the attestor client for building bundle
	attestorClient, err := c.getAttestorClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get attestor client: %v", err)
	}

	bundleData, err := c.BuildVerificationBundleData(attestorClient, providerData.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to build verification bundle: %v", err)
	}

	c.logger.Info("Verification bundle built successfully",
		zap.Int("bundle_size", len(bundleData)))

	// Phase 10: Submitting to Attestor (90%)
	reportProgress(PhaseSubmittingAttest, "Submitting verification bundle to attestor")

	claimParams := ClaimTeeBundleParams{
		Provider:   providerData.Name,
		Parameters: providerData.Params,
		Context:    providerData.Context,
	}

	result, err = c.SubmitToAttestorCore(claimParams)
	if err != nil {
		return nil, fmt.Errorf("attestor submission failed: %v", err)
	}

	// Phase 11: Claim Received (95-100%)
	reportProgress(PhaseReceivingClaim, "Claim received from attestor")

	c.logger.Info("Claim received successfully",
		zap.String("claim_id", result.Claim.Identifier),
		zap.String("provider", result.Claim.Provider),
		zap.Bool("has_signatures", result.Signature != nil))

	// Phase 12: Complete (100%)
	reportProgress(PhaseComplete, "Protocol execution completed successfully")

	return result, nil
}

func (c *Client) waitForCoreProtocol() error {
	err := <-c.WaitForCompletion()
	if err != nil {
		return fmt.Errorf("protocol terminated with error: %v", err)
	}
	return nil
}

// getPhaseDescription returns a human-readable description for each phase
func (c *Client) getPhaseDescription(phase ProtocolPhase) string {
	switch phase {
	case PhaseHandshaking:
		return "Establishing secure TLS connection"
	case PhaseCollectingResponses:
		return "Sending HTTP request and collecting responses"
	case PhaseReceivingDecryption:
		return "Receiving decrypted response data"
	case PhaseSendingRedaction:
		return "Processing redaction specifications"
	case PhaseReceivingRedacted:
		return "Receiving redacted response streams"
	case PhaseValidating:
		return "Validating transcripts and signatures"
	case PhaseProcessingOPRF:
		return "Processing OPRF for hashed data ranges"
	case PhaseGeneratingZKProofs:
		return "Generating zero-knowledge proofs for OPRF data"
	case PhaseBuildingBundle:
		return "Building verification bundle with OPRF data"
	case PhaseSubmittingAttest:
		return "Submitting verification bundle to attestor"
	case PhaseReceivingClaim:
		return "Receiving claim from attestor"
	case PhaseComplete:
		return "Protocol execution completed successfully"
	default:
		return "Processing protocol phase"
	}
}
