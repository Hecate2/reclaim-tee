package client

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/joho/godotenv"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

func init() {
	// Load .env file if present (ignore error if absent)
	_ = godotenv.Load()
}

// ClientMode represents the operational mode of the client
type ClientMode int

const (
	ModeAuto ClientMode = iota // Auto-detect based on URLs
	ModeEnclave
	ModeStandalone
)

// ReclaimClient is the internal implementation of ReclaimClient
type ReclaimClient struct {
	Client *Client
	config ClientConfig
	logger *shared.Logger
}

// NewReclaimClient creates a new ReclaimClient with the given configuration
func NewReclaimClient(config ClientConfig) *ReclaimClient {
	// Apply defaults if not specified
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Mode == ModeAuto {
		config.Mode = detectMode(config.TEEKURL, config.TEETURL)
	}

	// Create internal client with TEE_K URL
	client := NewClient(config.TEEKURL)

	// Use provided logger if available and store requestId
	if config.Logger != nil {
		client.logger = config.Logger
	}
	// Store request ID for tracking
	if config.RequestId != "" {
		client.requestId = config.RequestId
	}

	// Configure TEE_T URL if provided
	if config.TEETURL != "" {
		client.SetTEETURL(config.TEETURL)
	}

	// Store attestor URL
	client.attestorURL = config.AttestorURL

	// Store config for later use
	client.forceTLSVersion = config.ForceTLSVersion
	client.forceCipherSuite = config.ForceCipherSuite
	client.proxyURL = shared.GetHTTPSProxyURL()
	client.SetMode(config.Mode)

	// Set provider params for automatic response redactions
	client.providerParams = config.ProviderParams
	client.providerSecretParams = config.ProviderSecretParams

	// Initialize logger with Flutter callback support
	isEnclaveMode := client.clientMode == ModeEnclave
	logger := GetLogger("client", isEnclaveMode)

	return &ReclaimClient{
		Client: client,
		config: config,
		logger: logger,
	}
}

// ConfigJSON represents optional configuration for the client
type ConfigJSON struct {
	AttestorURL string `json:"attestorUrl,omitempty"`
	TEEKURL     string `json:"teekUrl,omitempty"`
	TEETURL     string `json:"teetUrl,omitempty"`
	RequestID   string `json:"requestId,omitempty"`
}

// Default URLs for TEE services
const (
	DefaultAttestorURL = "wss://eu.attestor.reclaimprotocol.org:444/ws"
	DefaultTEEKURL     = "wss://eu.tk.reclaimprotocol.org/ws"
	DefaultTEETURL     = "wss://eu.tt.reclaimprotocol.org/ws"
)

// NewReclaimClientFromJSON creates a new ReclaimClient with JSON-encoded provider params and optional config
func NewReclaimClientFromJSON(providerParamsJSON string, configJSON string) (*ReclaimClient, error) {
	// First parse to extract provider name and raw JSON for validation
	var rawData map[string]json.RawMessage
	if err := json.Unmarshal([]byte(providerParamsJSON), &rawData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request JSON: %v", err)
	}

	// Extract provider name
	var providerName string
	if nameRaw, ok := rawData["name"]; ok {
		if err := json.Unmarshal(nameRaw, &providerName); err != nil {
			return nil, fmt.Errorf("failed to unmarshal provider name: %v", err)
		}
	} else {
		return nil, fmt.Errorf("provider name not found in request JSON")
	}

	// Validate and unmarshal params
	var params providers.HTTPProviderParams
	if paramsRaw, ok := rawData["params"]; ok && paramsRaw != nil {
		if err := providers.ValidateAndUnmarshalParams(providerName, paramsRaw, &params); err != nil {
			return nil, fmt.Errorf("parameter validation failed: %v", err)
		}
	} else {
		return nil, fmt.Errorf("parameters not found in request JSON")
	}

	// Validate and unmarshal secret params if provided
	var secretParams *providers.HTTPProviderSecretParams
	if secretParamsRaw, ok := rawData["secretParams"]; ok && secretParamsRaw != nil && string(secretParamsRaw) != "null" {
		var sp providers.HTTPProviderSecretParams
		if err := providers.ValidateAndUnmarshalSecretParams(providerName, secretParamsRaw, &sp); err != nil {
			return nil, fmt.Errorf("secret parameter validation failed: %v", err)
		}
		secretParams = &sp
	}

	// Extract context if provided
	var context string
	if contextRaw, ok := rawData["context"]; ok && contextRaw != nil && string(contextRaw) != "null" {
		if err := json.Unmarshal(contextRaw, &context); err != nil {
			// Context is optional, so we can ignore errors
			context = ""
		}
	}

	// Parse config with defaults
	attestorURL := DefaultAttestorURL
	teekURL := DefaultTEEKURL
	teetURL := DefaultTEETURL
	var requestID string

	if configJSON != "" {
		var cfg ConfigJSON
		if err := json.Unmarshal([]byte(configJSON), &cfg); err == nil {
			if cfg.AttestorURL != "" {
				attestorURL = cfg.AttestorURL
			}
			if cfg.TEEKURL != "" {
				teekURL = cfg.TEEKURL
			}
			if cfg.TEETURL != "" {
				teetURL = cfg.TEETURL
			}
			requestID = cfg.RequestID
		}
		// Ignore parse errors - use defaults
	}

	// Initialize logger
	logger := GetLogger("libreclaim", false)

	// Create a child logger with requestId if provided
	if requestID != "" {
		zapWithRequestId := logger.Logger.With(zap.String("requestId", requestID))
		logger = &shared.Logger{
			Logger: zapWithRequestId,
		}
	}

	// Create config with validated provider params
	config := ClientConfig{
		TEEKURL:              teekURL,
		TEETURL:              teetURL,
		AttestorURL:          attestorURL,
		Timeout:              30 * time.Second,
		Mode:                 ModeAuto,
		ProviderParams:       &params,
		ProviderSecretParams: secretParams,
		ProviderContext:      context,
		Logger:               logger,
		RequestId:            requestID,
	}

	return NewReclaimClient(config), nil
}

// Connect establishes connections to both TEE_K and TEE_T
func (r *ReclaimClient) Connect() error {
	// Connect to TEE_K
	if err := r.Client.ConnectToTEEK(); err != nil {
		return NewConnectionError("TEE_K", err)
	}

	// Connect to TEE_T
	if err := r.Client.ConnectToTEET(); err != nil {
		return NewConnectionError("TEE_T", err)
	}

	// Session coordination happens automatically in background via WebSocket messages
	r.logger.Info("Connection established - session coordination will happen naturally")

	return nil
}

// StartProtocol executes the complete TEE+MPC protocol with JSON-encoded provider params
func (r *ReclaimClient) StartProtocol(providerParamsJSON string) error {
	// Parse provider params from JSON
	var providerData ProviderRequestData
	if err := json.Unmarshal([]byte(providerParamsJSON), &providerData); err != nil {
		return fmt.Errorf("failed to parse provider params JSON: %v", err)
	}

	if providerData.Params == nil {
		return fmt.Errorf("params required in provider params JSON")
	}

	// Validate provider params using production validation functions
	if err := providers.ValidateProviderParams(providerData.Name, providerData.Params); err != nil {
		return fmt.Errorf("invalid provider params: %v", err)
	}

	if providerData.SecretParams != nil {
		if err := providers.ValidateProviderSecretParams(providerData.Name, providerData.SecretParams); err != nil {
			return fmt.Errorf("invalid provider secret params: %v", err)
		}
	}

	// Update client with validated provider params
	r.Client.providerParams = providerData.Params
	r.Client.providerSecretParams = providerData.SecretParams

	// Execute the complete protocol: Connect -> RequestHTTP
	if err := r.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	if err := r.RequestHTTP(); err != nil {
		return fmt.Errorf("failed to request HTTP: %v", err)
	}

	return nil
}

// RequestHTTP initiates an HTTP request through the TEE+MPC protocol
func (r *ReclaimClient) RequestHTTP() error {
	return r.Client.RequestHTTP()
}

// WaitForCompletion returns a channel that signals when the protocol is complete
func (r *ReclaimClient) WaitForCompletion() <-chan error {
	return r.Client.WaitForCompletion()
}

// Close closes the client connections
func (r *ReclaimClient) Close() error {
	r.Client.Close()
	return nil
}

// GetProtocolResult returns the complete protocol execution results
func (r *ReclaimClient) GetProtocolResult() (*ProtocolResult, error) {
	return r.Client.buildProtocolResult()
}

// GetTranscripts returns the signed transcripts from both TEE_K and TEE_T
func (r *ReclaimClient) GetTranscripts() (*TranscriptResults, error) {
	return r.Client.buildTranscriptResults()
}

// GetValidationResults returns the validation results for transcripts and attestations
func (r *ReclaimClient) GetValidationResults() (*ValidationResults, error) {
	return r.Client.buildValidationResults()
}

// GetResponseResults returns the HTTP response data and proof claims
func (r *ReclaimClient) GetResponseResults() (*ResponseResults, error) {
	return r.Client.buildResponseResults()
}

func (r *ReclaimClient) PrepareZKProofForTOPRF(httpRangeStart, httpRangeEnd int, toprfMask []byte, toprfOutput []byte, toprfResponse *teeproto.TOPRFResponse) (map[string]any, error) {
	return r.Client.PrepareZKProofForTOPRF(httpRangeStart, httpRangeEnd, toprfMask, toprfOutput, toprfResponse)
}

// ExecuteCompleteProtocol runs the complete protocol from start to claim receipt with progress reporting
func (r *ReclaimClient) ExecuteCompleteProtocol(
	providerData *ProviderRequestData,
) (*ClaimWithSignatures, error) {
	return r.Client.ExecuteCompleteProtocol(providerData)
}

// detectMode automatically detects the client mode based on URLs
func detectMode(teekURL, teetURL string) ClientMode {
	if (teekURL != "" && teekURL[:4] == "wss:") || (teetURL != "" && teetURL[:4] == "wss:") {
		return ModeEnclave
	}
	return ModeStandalone
}
