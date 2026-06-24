package client

import (
	"encoding/json"
	"fmt"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
	wsConn   *websocket.Conn // Protected by wsWriteMutex
	teetConn *websocket.Conn // Protected by teetWriteMutex
	tcpConn  net.Conn

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
	capturedTraffic   [][]byte     // Append guarded by capturedTrafficMu (three writer goroutines).
	capturedTrafficMu sync.Mutex
	handshakeComplete atomic.Bool // Routing boundary for captured records; Store after responseSeqNum write.

	// Attestor client (created lazily when needed)
	attestorClient *AttestorClient
	attestorOnce   sync.Once // Ensure attestor client is created only once

	// Phase 4: Response handling
	responseSeqNum       uint64 // TLS sequence number for response AEAD
	firstApplicationData bool   // Track if this is the first ApplicationData record
	requestSeqNum        uint64 // TLS sequence number for request AEAD (starts at 1 after handshake)
	fragmentsReceived    int    // Number of request fragments received from TEE_T
	expectedFragments    int    // Total number of request fragments expected (set by first fragment)

	// Protocol completion signaling
	completionChan chan error // Signals when protocol is complete (nil = success, non-nil = error)

	completionOnce sync.Once // Ensures completion channel is only closed once

	completionFlags int64 // Atomic bit flags for completion state tracking

	protocolPhase          ProtocolPhase // Current protocol phase
	teeKTranscriptReceived bool          // TEE_K transcript received
	teeTTranscriptReceived bool          // TEE_T transcript received
	protocolStateMutex     sync.RWMutex  // Protect simple state

	// Track HTTP request/response lifecycle
	httpRequestSent       atomic.Bool                 // Set after final fragment written to TCP; read by TCP reader goroutine.
	httpResponseExpected  bool                        // Track if we should expect HTTP response
	parsedResponseBySeq   map[uint64]*TLSResponseData // Store parsed TLS response data by sequence
	responseContentMutex  sync.Mutex                  // For all response maps
	ciphertextBySeq       map[uint64][]byte           // Store encrypted response data by sequence
	decryptionStreamBySeq map[uint64][]byte           // Store decryption streams by sequence

	// Batched response tracking (collection until EOF)
	batchedResponses []shared.EncryptedResponseData // Collect response packets until EOF

	// Response processing success tracking
	responseProcessingSuccessful bool // Track if response was successfully processed
	reconstructedResponseSize    int  // Size of reconstructed response data

	// Track redaction ranges so we can prettify later and include in bundle
	requestRedactionRanges []shared.RequestRedactionRange

	// Library interface fields
	clientMode ClientMode // Client operational mode (enclave vs standalone)

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
	fullRedactedResponse    []byte // final redacted HTTP response (concatenated)
	expectedRedactedStreams int    // expected number of redacted streams from response sequences

	// commitment opening for proof (R_SP streams only, as per protocol)
	proofStream []byte // Concatenated R_SP streams
	proofKey    []byte // First R_SP key (protocol assumes single K_SP)

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

	// MPC OPRF state
	oprfMpcRangesSent    bool                      // Track if ranges were sent
	oprfMpcRangesSpec    []*teeproto.OPRFRangeSpec // Ranges sent to TEEs
	oprfMpcRangeMappings []OPRFMPCRangeMapping     // HTTP <-> TLS position mappings for OPRF
}

func NewClient(teekURL string) *Client {
	// Use the shared Flutter-enabled logger
	logger := GetLogger("client", false)

	return &Client{
		logger:          logger,
		teekURL:         teekURL,
		teetURL:         "wss://tee-t-gcp.reclaimprotocol.org/ws", // Default TEE_T URL (enclave mode)
		completionChan:  make(chan error, 1),                      // buffered to avoid blocking
		completionFlags: 0,

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
		proofStream:                 nil,
		proofKey:                    nil,
		expectedRedactedStreams:     0,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (c *Client) SetTEETURL(url string) {
	c.teetURL = url
}

// SetRouterJWT installs the allocation JWT the client received from the
// router. When set, ConnectToTEEK / ConnectToTEET send a ClientAuth
// envelope as the first message before any other protocol traffic.
func (c *Client) SetRouterJWT(jwt string) {
	c.routerJWT = jwt
}

// SetMode sets the client operational mode
func (c *Client) SetMode(mode ClientMode) {
	c.clientMode = mode
}

// getAttestorClient returns the attestor client, creating it lazily if needed
func (c *Client) getAttestorClient() (*AttestorClient, error) {
	var clientErr error
	c.attestorOnce.Do(func() {
		if c.attestorURL == "" {
			clientErr = fmt.Errorf("attestor URL not configured")
			return
		}

		// Generate private key for attestor communication
		privateKey, err := shared.GenerateKey()
		if err != nil {
			clientErr = fmt.Errorf("failed to generate private key: %v", err)
			return
		}

		c.attestorClient = NewAttestorClient(c.attestorURL, privateKey, c.logger)
	})

	if clientErr != nil {
		return nil, clientErr
	}
	return c.attestorClient, nil
}

func (c *Client) RequestHTTP() error {
	// Extract hostname and port from provider params
	hostname, port, err := c.getHostPortFromProviderParams()
	if err != nil {
		return fmt.Errorf("failed to extract host and port from provider params: %v", err)
	}

	c.targetHost = hostname
	c.targetPort = port

	c.logger.Info("Requesting connection",
		zap.String("hostname", hostname),
		zap.Int("port", port))

	// Generate request data and redaction ranges automatically from provider params
	if err := c.generateAutomaticRequestData(); err != nil {
		return fmt.Errorf("failed to generate automatic request data: %v", err)
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
		return c.sendPendingConnectionRequest()
	}

	// Otherwise, request will be sent when session ID is received in handleSessionReady
	return nil
}

// setCompletionFlag atomically sets a completion flag
func (c *Client) setCompletionFlag(flag int64) {
	atomic.StoreInt64(&c.completionFlags, atomic.LoadInt64(&c.completionFlags)|flag)
}

// hasCompletionFlag atomically checks if a completion flag is set
func (c *Client) hasCompletionFlag(flag int64) bool {
	return atomic.LoadInt64(&c.completionFlags)&flag != 0
}

// setCompletionFlags atomically sets multiple completion flags
func (c *Client) setCompletionFlags(flags int64) {
	atomic.StoreInt64(&c.completionFlags, atomic.LoadInt64(&c.completionFlags)|flags)
}

// hasAllCompletionFlags atomically checks if all specified completion flags are set
func (c *Client) hasAllCompletionFlags(flags int64) bool {
	return atomic.LoadInt64(&c.completionFlags)&flags == flags
}

// getBatchState returns current batch state based on protocol phase (thread-safe)
func (c *Client) getBatchState() (collectionComplete, sentToTEET, decryptionReceived bool) {
	c.protocolStateMutex.RLock()
	defer c.protocolStateMutex.RUnlock()

	// Derive batch state from protocol phase
	collectionComplete = c.protocolPhase >= PhaseReceivingDecryption
	sentToTEET = c.protocolPhase >= PhaseReceivingDecryption
	decryptionReceived = c.protocolPhase >= PhaseSendingRedaction
	return
}

// isBatchProcessingComplete checks if all batch operations are complete
func (c *Client) isBatchProcessingComplete() bool {
	collection, sent, decryption := c.getBatchState()
	return collection && sent && decryption
}

// getCurrentPhase returns the current protocol phase (thread-safe)
func (c *Client) getCurrentPhase() ProtocolPhase {
	c.protocolStateMutex.RLock()
	defer c.protocolStateMutex.RUnlock()
	return c.protocolPhase
}

// advanceToPhase transitions to a new protocol phase (thread-safe)
func (c *Client) advanceToPhase(newPhase ProtocolPhase) {
	c.protocolStateMutex.Lock()
	oldPhase := c.protocolPhase
	c.protocolPhase = newPhase
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
	if newPhase == PhaseValidating {
		c.completionOnce.Do(func() {
			c.logger.Info("Core protocol validation complete - signaling success")
			select {
			case c.completionChan <- nil: // nil = success
			default:
				// Channel might be full, but that's ok
			}
		})
	}
}

// markTEEKTranscriptReceived marks TEE_K transcript as received and checks for completion
func (c *Client) markTEEKTranscriptReceived() {
	c.protocolStateMutex.Lock()
	c.teeKTranscriptReceived = true
	c.protocolStateMutex.Unlock()
	c.logger.Info("TEE_K transcript received", zap.Bool("tee_k", true), zap.Bool("tee_t", c.teeTTranscriptReceived))
	c.checkForProtocolCompletion()
}

// markTEETTranscriptReceived marks TEE_T transcript as received and checks for completion
func (c *Client) markTEETTranscriptReceived() {
	c.protocolStateMutex.Lock()
	c.teeTTranscriptReceived = true
	c.protocolStateMutex.Unlock()
	c.logger.Info("TEE_T transcript received", zap.Bool("tee_k", c.teeKTranscriptReceived), zap.Bool("tee_t", true))
	c.checkForProtocolCompletion()
}

// checkForProtocolCompletion checks if protocol can be completed
func (c *Client) checkForProtocolCompletion() {
	if c.teeKTranscriptReceived && c.teeTTranscriptReceived {
		c.logger.Info("Both transcripts received AND redacted streams processed - core protocol validation complete")
		c.advanceToPhase(PhaseValidating)
	} else {
		c.logger.Info("Waiting for both transcripts...")
	}
}

// getProtocolState returns current phase and transcript count (thread-safe)
func (c *Client) getProtocolState() (ProtocolPhase, int) {
	c.protocolStateMutex.RLock()
	defer c.protocolStateMutex.RUnlock()

	// Convert boolean flags to count for backward compatibility
	count := 0
	if c.teeKTranscriptReceived {
		count++
	}
	if c.teeTTranscriptReceived {
		count++
	}

	return c.protocolPhase, count
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
			dataToProcess := response.FullResponse[r.Start : r.Start+r.Length]

			if r.Hash == *providers.HASH_TYPE_OPRF {
				// Client-side TOPRF processing
				c.oprfRedactionRanges[r.Start] = r.Length
				c.logger.Info("Marked range for TOPRF processing",
					zap.Int("start", r.Start),
					zap.Int("length", r.Length),
					zap.String("hash_type", r.Hash),
					zap.String("data", string(dataToProcess)))
			} else if r.Hash == *providers.HASH_TYPE_OPRF_MPC {
				// TEE-to-TEE MPC OPRF processing
				c.oprfMpcRedactionRanges[r.Start] = r.Length
				c.logger.Info("Marked range for MPC OPRF processing",
					zap.Int("start", r.Start),
					zap.Int("length", r.Length),
					zap.String("hash_type", r.Hash),
					zap.String("data", string(dataToProcess)))
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
	return signedMsg.GetEthAddress()
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
	defer attestorClient.Close()

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

			// Log the updated parameters
			if updatedParamsJSON, err := json.Marshal(params.Parameters); err == nil {
				c.logger.Info("Updated parameters with OPRF replacements",
					zap.String("parameters", string(updatedParamsJSON)))
			}
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
) (*ClaimWithSignatures, error) {
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

	// Connect to TEEs (equivalent to Connect())
	if err := c.ConnectToTEEK(); err != nil {
		return nil, fmt.Errorf("failed to connect to TEE_K: %v", err)
	}
	if err := c.ConnectToTEET(); err != nil {
		return nil, fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	// Start the protocol (equivalent to RequestHTTP)
	if err := c.RequestHTTP(); err != nil {
		return nil, fmt.Errorf("failed to start HTTP request: %v", err)
	}

	// Wait for the core protocol to complete
	select {
	case err := <-c.WaitForCompletion():
		if err != nil {
			return nil, fmt.Errorf("protocol terminated with error: %v", err)
		}
		c.logger.Info("Core TEE protocol completed successfully")
	case <-time.After(1 * time.Minute):
		return nil, fmt.Errorf("core TEE protocol timed out")
	}

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

	result, err := c.SubmitToAttestorCore(claimParams)
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
