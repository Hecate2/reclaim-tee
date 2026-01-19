package client

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"sync"
	"tee-mpc/providers"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/utils"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// AttestorClient handles communication with attestor-core for TEE bundle submission
type AttestorClient struct {
	url        string
	conn       *websocket.Conn
	privateKey *ecdsa.PrivateKey
	address    shared.Address
	logger     *shared.Logger
	mu         sync.Mutex
	connOnce   sync.Once // Ensure connection happens only once
}

// NewAttestorClient creates a new client for communicating with attestor-core
func NewAttestorClient(attestorURL string, privateKey *ecdsa.PrivateKey, logger *shared.Logger) *AttestorClient {
	address := shared.PubkeyToAddress(&privateKey.PublicKey)

	return &AttestorClient{
		url:        attestorURL,
		privateKey: privateKey,
		address:    address,
		logger:     logger,
	}
}

// GetPrivateKey returns the private key used by this attestor client
func (ac *AttestorClient) GetPrivateKey() *ecdsa.PrivateKey {
	return ac.privateKey
}

// ensureConnected establishes connection lazily when needed
func (ac *AttestorClient) ensureConnected() error {
	var connErr error
	ac.connOnce.Do(func() {
		connErr = ac.connect()
	})
	return connErr
}

// connect is the internal implementation that actually establishes the connection
func (ac *AttestorClient) connect() error {
	u, err := url.Parse(ac.url)
	if err != nil {
		return fmt.Errorf("failed to parse attestor URL: %v", err)
	}

	ac.logger.Info("Connecting to attestor-core WebSocket", zap.String("url", ac.url))

	// Connect to attestor-core
	var conn *websocket.Conn
	if strings.HasPrefix(ac.url, "wss://") {
		// Production environment
		ac.logger.Info("Using WSS connection")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	} else {
		// Local development
		ac.logger.Info("Using WS connection")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to attestor-core: %v", err)
	}

	ac.conn = conn
	ac.logger.Info("WebSocket connection established, starting initialization")

	// Initialize the connection with an InitRequest
	if err := ac.initializeConnection(); err != nil {
		ac.conn.Close()
		return fmt.Errorf("failed to initialize connection: %v", err)
	}

	ac.logger.Info("AttestorClient connection and initialization complete")
	return nil
}

// initializeConnection sends the required InitRequest to attestor-core
func (ac *AttestorClient) initializeConnection() error {
	ac.logger.Info("Creating InitRequest")

	// Create InitRequest
	initRequest := &teeproto.RPCMessage_InitRequest{
		InitRequest: &teeproto.InitRequest{
			ClientVersion: teeproto.AttestorVersion_ATTESTOR_VERSION_3_0_0, // Latest version
			SignatureType: teeproto.ServiceSignatureType_SERVICE_SIGNATURE_TYPE_ETH,
			Auth:          nil, // No authentication for now
		},
	}

	ac.logger.Info("Sending InitRequest")

	// Send using centralized RPC message handler
	responseMessages, err := ac.sendRPCMessage(initRequest)
	if err != nil {
		return fmt.Errorf("failed to send init request: %v", err)
	}

	ac.logger.Info("Received init response")

	if len(responseMessages.Messages) == 0 {
		return fmt.Errorf("received empty RPCMessages array")
	}

	responseMessage := responseMessages.Messages[0]

	ac.logger.Info("Parsed init response",
		zap.Uint64("response_id", responseMessage.Id),
		zap.Bool("has_error", responseMessage.GetRequestError() != nil),
		zap.Bool("has_init_response", responseMessage.GetInitResponse() != nil))

	// Check for error in response
	if reqErr := responseMessage.GetRequestError(); reqErr != nil {
		ac.logger.Error("Init request failed",
			zap.Int32("error_code", int32(reqErr.Code)),
			zap.String("error_message", reqErr.Message))
		return fmt.Errorf("init request failed: %s", reqErr.Message)
	}

	// Verify we got an init response
	if responseMessage.GetInitResponse() == nil {
		ac.logger.Error("Unexpected response type - expected init response")
		return fmt.Errorf("expected init response, got different message type")
	}

	ac.logger.Info("InitRequest completed successfully")
	return nil
}

// Close closes the WebSocket connection
func (ac *AttestorClient) Close() error {
	if ac.conn != nil {
		return ac.conn.Close()
	}
	return nil
}

// ClaimTeeBundleParams contains parameters for claim submission
type ClaimTeeBundleParams struct {
	Provider   string                        // Provider name (e.g., "http")
	Parameters *providers.HTTPProviderParams // Provider-specific parameters
	Context    string                        // Optional context (JSON string)
}

// logAttestorViewOfRedactedResponse reconstructs what the attestor will see as the redacted response
func (ac *AttestorClient) logAttestorViewOfRedactedResponse(bundle *teeproto.VerificationBundle) {
	ac.logger.Info("=== ATTESTOR VIEW: Reconstructing redacted response ===")

	// Extract TEE_K payload (contains keystream and redaction ranges)
	if bundle.TeekSigned == nil {
		ac.logger.Error("No TEE_K signed message in bundle")
		return
	}

	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(bundle.TeekSigned.GetBody(), &kPayload); err != nil {
		ac.logger.Error("Failed to unmarshal TEE_K payload", zap.Error(err))
		return
	}

	keystream := kPayload.GetConsolidatedResponseKeystream()
	redactionRanges := kPayload.GetResponseRedactionRanges()

	ac.logger.Info("TEE_K data extracted",
		zap.Int("keystream_bytes", len(keystream)),
		zap.Int("redaction_ranges", len(redactionRanges)))

	// Extract TEE_T payload (contains ciphertext)
	if bundle.TeetSigned == nil {
		ac.logger.Error("No TEE_T signed message in bundle")
		return
	}

	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(bundle.TeetSigned.GetBody(), &tPayload); err != nil {
		ac.logger.Error("Failed to unmarshal TEE_T payload", zap.Error(err))
		return
	}

	ciphertext := tPayload.GetConsolidatedResponseCiphertext()
	ac.logger.Info("TEE_T data extracted",
		zap.Int("ciphertext_bytes", len(ciphertext)))

	// Check length match
	if len(keystream) != len(ciphertext) {
		ac.logger.Error("Keystream and ciphertext length mismatch",
			zap.Int("keystream_len", len(keystream)),
			zap.Int("ciphertext_len", len(ciphertext)))
		return
	}

	// Step 1: XOR to get plaintext
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ keystream[i]
	}

	ac.logger.Info("Plaintext reconstructed via XOR",
		zap.Int("plaintext_bytes", len(plaintext)))

	// Step 2: Apply redactions (replace with asterisks)
	redactedResponse := make([]byte, len(plaintext))
	copy(redactedResponse, plaintext)

	totalRedacted := 0
	for _, r := range redactionRanges {
		start := int(r.Start)
		length := int(r.Length)
		end := start + length

		if end > len(redactedResponse) {
			ac.logger.Warn("Redaction range exceeds response length",
				zap.Int("start", start),
				zap.Int("length", length),
				zap.Int("end", end),
				zap.Int("response_len", len(redactedResponse)))
			end = len(redactedResponse)
			length = end - start
		}

		for i := start; i < end; i++ {
			redactedResponse[i] = '*'
		}
		totalRedacted += length
	}

	// totalRevealed := len(redactedResponse) - totalRedacted

	// Debug logging (commented out for production)
	// ac.logger.Info("=== ATTESTOR REDACTION STATISTICS ===",
	// 	zap.Int("total_bytes", len(redactedResponse)),
	// 	zap.Int("redacted_bytes", totalRedacted),
	// 	zap.Int("revealed_bytes", totalRevealed),
	// 	zap.Int("num_ranges", len(redactionRanges)))

	// Log each range
	// for i, r := range redactionRanges {
	// 	ac.logger.Info("Attestor Redaction Range",
	// 		zap.Int("index", i),
	// 		zap.Int32("start", r.Start),
	// 		zap.Int32("length", r.Length),
	// 		zap.Int32("end", r.Start+r.Length))
	// }

	// Log the full redacted response as attestor sees it
	// ac.logger.Info("=== ATTESTOR VIEW: FULL REDACTED RESPONSE (asterisks show redacted parts) ===")
	// ac.logger.Info(string(redactedResponse))
	// ac.logger.Info("=== END ATTESTOR VIEW ===")
}

// SubmitTeeBundle submits a TEE verification bundle to attestor-core for claim validation
// ClaimWithSignatures contains both the claim data and attestor signatures
type ClaimWithSignatures struct {
	Claim     *teeproto.ProviderClaimData
	Signature *teeproto.ClaimTeeBundleResponse_Signature
}

func (ac *AttestorClient) SubmitTeeBundle(verificationBundle *teeproto.VerificationBundle, params ClaimTeeBundleParams) (*ClaimWithSignatures, error) {
	// Ensure connection is established (lazy connect)
	if err := ac.ensureConnected(); err != nil {
		return nil, fmt.Errorf("failed to connect to attestor: %v", err)
	}

	// DEBUG: Log the redacted response as the attestor will see it
	// ac.logAttestorViewOfRedactedResponse(verificationBundle)

	// 1. Serialize the verification bundle
	bundleBytes, err := proto.Marshal(verificationBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification bundle: %v", err)
	}

	// Save proof bundle to local file for testing
	// bundleFile := "proof_bundle.bin"
	// if err := os.WriteFile(bundleFile, bundleBytes, 0644); err != nil {
	// 	ac.logger.Warn("Failed to save proof bundle to file", zap.String("file", bundleFile), zap.Error(err))
	// } else {
	// 	ac.logger.Info("Saved proof bundle to file", zap.String("file", bundleFile), zap.Int("bytes", len(bundleBytes)))
	// }

	// 2. Prepare parameters and context as JSON
	parametersJson, err := json.Marshal(params.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal parameters: %v", err)
	}

	contextJson := "{}"
	if params.Context != "" {
		contextJson = params.Context
	}

	// 3. Create claim request data with consistent timestamp
	timestamp := uint32(time.Now().Unix())
	claimData := &teeproto.ClaimRequestData{
		Provider:   params.Provider,
		Parameters: string(parametersJson),
		Owner:      ac.address.Hex(),
		TimestampS: timestamp,
		Context:    contextJson,
	}

	// 5. Create request without signatures for signing

	request := &teeproto.ClaimTeeBundleRequest{
		VerificationBundle: bundleBytes,
		Data:               claimData,
	}

	// 6. Sign the request
	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request for signing: %v", err)
	}

	// Use personal_sign compatible signature (same as ethers.js wallet.signMessage)
	signature, err := shared.Sign(shared.TextHash(requestBytes), ac.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %v", err)
	}

	// Log signature creation details
	ac.logger.Info("TEE Bundle signature details",
		zap.Int("signatureLength", len(signature)),
		zap.String("signatureHex", hex.EncodeToString(signature[:min(10, len(signature))])+"..."),
		zap.String("textHashHex", hex.EncodeToString(shared.TextHash(requestBytes))),
		zap.String("recoveryId", fmt.Sprintf("%d", signature[64])),
	)

	// Convert to ethers.js compatible format: add 27 to recovery ID for ethers.js
	if len(signature) == 65 {
		signature[64] += 27
		ac.logger.Info("Converted signature for ethers.js compatibility",
			zap.String("newRecoveryId", fmt.Sprintf("%d", signature[64])),
		)
	}

	ac.logger.Info("Sending TEE bundle claim request",
		zap.String("provider", params.Provider),
		zap.String("owner", ac.address.Hex()),
		zap.Int("bundle_bytes", len(bundleBytes)),
		zap.Int("signature_bytes", len(signature)))

	// 8. Send the request
	ac.logger.Info("Sending ClaimTeeBundleRequest")
	responseMessages, err := ac.sendRPCMessage(&teeproto.RPCMessage_ClaimTeeBundleRequest{ClaimTeeBundleRequest: request})
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	ac.logger.Info("Received ClaimTeeBundleResponse")

	// 9. Process the response
	if len(responseMessages.Messages) == 0 {
		return nil, fmt.Errorf("received empty RPCMessages array")
	}

	responseMessage := responseMessages.Messages[0]

	// Check for error
	if reqErr := responseMessage.GetRequestError(); reqErr != nil {
		return nil, fmt.Errorf("claim failed: %s (code: %d)",
			reqErr.Message,
			reqErr.Code)
	}

	// Extract claim from ClaimTeeBundleResponse
	claimResponse := responseMessage.GetClaimTeeBundleResponse()
	if claimResponse == nil {
		return nil, fmt.Errorf("expected ClaimTeeBundleResponse, got different message type")
	}

	if claimErr := claimResponse.GetError(); claimErr != nil {
		return nil, fmt.Errorf("claim failed: %s (code: %d)",
			claimErr.Message,
			claimErr.Code)
	}

	claim := claimResponse.GetClaim()
	if claim == nil {
		return nil, fmt.Errorf("no claim returned in response")
	}

	// Get signatures from response (required)
	signatures := claimResponse.GetSignatures()
	if signatures == nil {
		return nil, fmt.Errorf("no signatures returned in ClaimTeeBundleResponse")
	}

	return &ClaimWithSignatures{
		Claim:     claim,
		Signature: signatures,
	}, nil
}

// SendOPRFRequest sends a threshold OPRF request to the attestor and returns the response
func (ac *AttestorClient) SendOPRFRequest(data []byte, domainSeparator []byte, zkEngine teeproto.ZKProofEngine) (interface{}, *teeproto.TOPRFResponse, error) {
	// Ensure connection is established (lazy connect)
	if err := ac.ensureConnected(); err != nil {
		return nil, nil, fmt.Errorf("failed to connect to attestor: %v", err)
	}

	// Generate OPRF request using the utils function
	oprfRequest, err := utils.OPRFGenerateRequest(data, string(domainSeparator))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate OPRF request: %v", err)
	}

	// Serialize the OPRF request to send to attestor
	// The MaskedData point needs to be serialized as bytes
	maskedDataBytesArray := oprfRequest.MaskedData.Bytes()
	maskedDataBytes := maskedDataBytesArray[:] // Convert array to slice

	ac.logger.Info("Generated OPRF request",
		zap.Int("data_length", len(data)),
		zap.Int("masked_data_length", len(maskedDataBytes)),
		zap.String("masked_data_hex", hex.EncodeToString(maskedDataBytes[:min(32, len(maskedDataBytes))]))) // Log first 32 bytes

	// Create TOPRF request
	toprfRequest := &teeproto.RPCMessage_ToprfRequest{ToprfRequest: &teeproto.TOPRFRequest{
		MaskedData: maskedDataBytes,
		Engine:     zkEngine,
	}}

	// Send using centralized RPC message handler
	ac.logger.Info("Sending TOPRF request")
	responseMessages, err := ac.sendRPCMessage(toprfRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send TOPRF request: %v", err)
	}

	ac.logger.Info("Received TOPRF response")

	// Process response
	if len(responseMessages.Messages) == 0 {
		return nil, nil, fmt.Errorf("received empty RPCMessages array")
	}

	responseMessage := responseMessages.Messages[0]

	// Check for error
	if reqErr := responseMessage.GetRequestError(); reqErr != nil {
		return nil, nil, fmt.Errorf("TOPRF request failed: %s (code: %d)",
			reqErr.Message,
			reqErr.Code)
	}

	// Extract TOPRF response
	toprfResponse := responseMessage.GetToprfResponse()
	if toprfResponse == nil {
		return nil, nil, fmt.Errorf("expected TOPRFResponse, got different message type")
	}

	ac.logger.Info("Successfully received TOPRF response",
		zap.Int("public_key_share_length", len(toprfResponse.PublicKeyShare)),
		zap.Int("evaluated_length", len(toprfResponse.Evaluated)),
		zap.Int("c_length", len(toprfResponse.C)),
		zap.Int("r_length", len(toprfResponse.R)))

	// Log the response details for debugging
	ac.logger.Info("TOPRF Response details",
		zap.String("public_key_share", hex.EncodeToString(toprfResponse.PublicKeyShare)),
		zap.String("evaluated", hex.EncodeToString(toprfResponse.Evaluated)),
		zap.String("c", hex.EncodeToString(toprfResponse.C)),
		zap.String("r", hex.EncodeToString(toprfResponse.R)))

	return oprfRequest, toprfResponse, nil
}

// sendRPCMessage sends a generic RPC message and waits for response
func (ac *AttestorClient) sendRPCMessage(message teeproto.IsRPCMessage) (*teeproto.RPCMessages, error) {
	// Generate unique RPC ID
	rpcID := rand.Uint32()

	// Create RPC message with the appropriate wrapper based on message type
	rpcMessage := &teeproto.RPCMessage{
		Id:      uint64(rpcID),
		Message: message,
	}

	// Wrap in RPCMessages array as expected by attestor-core
	rpcMessages := &teeproto.RPCMessages{
		Messages: []*teeproto.RPCMessage{rpcMessage},
	}

	// Serialize and send
	messageBytes, err := proto.Marshal(rpcMessages)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RPC message: %v", err)
	}

	ac.logger.Info("Sending RPC message over WebSocket",
		zap.Int("message_size", len(messageBytes)),
		zap.Uint64("rpc_id", rpcMessage.Id))

	ac.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	ac.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

	if err := ac.conn.WriteMessage(websocket.BinaryMessage, messageBytes); err != nil {
		return nil, fmt.Errorf("failed to send RPC message: %v", err)
	}

	// Read response
	_, responseBytes, err := ac.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read RPC response: %v", err)
	}

	ac.logger.Info("Received RPC response", zap.Int("response_size", len(responseBytes)))

	// Parse response - attestor sends RPCMessages array
	var responseMessages teeproto.RPCMessages
	if err := proto.Unmarshal(responseBytes, &responseMessages); err != nil {
		// Try parsing as single message
		var singleMessage teeproto.RPCMessage
		if err2 := proto.Unmarshal(responseBytes, &singleMessage); err2 == nil {
			responseMessages.Messages = []*teeproto.RPCMessage{&singleMessage}
		} else {
			return nil, fmt.Errorf("failed to unmarshal RPC response: %v", err)
		}
	}

	if len(responseMessages.Messages) == 0 {
		return nil, fmt.Errorf("received empty RPCMessages array")
	}

	// Check for errors in the response
	responseMessage := responseMessages.Messages[0]

	// Verify response ID matches request ID
	if responseMessage.Id != uint64(rpcID) {
		return nil, fmt.Errorf("RPC ID mismatch: sent %d, received %d", rpcID, responseMessage.Id)
	}

	if reqErr := responseMessage.GetRequestError(); reqErr != nil {
		return nil, fmt.Errorf("RPC request failed: %s (code: %d)",
			reqErr.Message,
			reqErr.Code)
	}

	return &responseMessages, nil
}
