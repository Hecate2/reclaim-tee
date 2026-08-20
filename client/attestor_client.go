package client

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/providers"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/utils"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// AttestorClient handles communication with attestor-core for TEE bundle submission
type AttestorClient struct {
	url            string
	conn           *websocket.Conn
	privateKey     *ecdsa.PrivateKey
	address        shared.Address
	logger         *shared.Logger
	connMutex      sync.Mutex                            // Owns connection publication and reconnect state
	rpcMutex       sync.Mutex                            // Attestor RPC is strict write/read request-response
	dial           func(string) (*websocket.Conn, error) // test hook
	closed         bool
	connecting     bool
	connectingConn *websocket.Conn
	connectDone    chan struct{}
	// authRequest is forwarded to the attestor in the InitRequest when non-nil.
	authRequest *teeproto.AuthenticationRequest
}

// NewAttestorClient creates a new client for communicating with attestor-core
func NewAttestorClient(attestorURL string, privateKey *ecdsa.PrivateKey, authRequest *teeproto.AuthenticationRequest, logger *shared.Logger) *AttestorClient {
	address := shared.PubkeyToAddress(&privateKey.PublicKey)

	return &AttestorClient{
		url:         attestorURL,
		privateKey:  privateKey,
		address:     address,
		authRequest: authRequest,
		logger:      logger,
	}
}

// GetPrivateKey returns the private key used by this attestor client
func (ac *AttestorClient) GetPrivateKey() *ecdsa.PrivateKey {
	return ac.privateKey
}

// ensureConnected establishes connection lazily when needed
func (ac *AttestorClient) ensureConnected() error {
	for {
		ac.connMutex.Lock()
		if ac.closed {
			ac.connMutex.Unlock()
			return fmt.Errorf("attestor client is closed")
		}
		if ac.conn != nil {
			ac.connMutex.Unlock()
			return nil
		}
		if ac.connecting {
			done := ac.connectDone
			ac.connMutex.Unlock()
			<-done
			continue
		}
		ac.connecting = true
		ac.connectDone = make(chan struct{})
		ac.connMutex.Unlock()
		return ac.connect()
	}
}

// connect establishes and initializes one candidate. The candidate is exposed
// only to Close, which can detach and close it to interrupt initialization;
// RPC callers cannot observe it until initialization succeeds.
func (ac *AttestorClient) connect() error {
	u, err := url.Parse(ac.url)
	if err != nil {
		return ac.finishConnect(nil, fmt.Errorf("failed to parse attestor URL: %v", err))
	}

	ac.logger.Info("Connecting to attestor-core WebSocket", zap.String("url", ac.url))

	// Connect to attestor-core
	var conn *websocket.Conn
	if ac.dial != nil {
		conn, err = ac.dial(u.String())
	} else if strings.HasPrefix(ac.url, "wss://") {
		// Production environment
		ac.logger.Info("Using WSS connection")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	} else {
		// Local development
		ac.logger.Info("Using WS connection")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	}

	if err != nil {
		return ac.finishConnect(nil, fmt.Errorf("failed to connect to attestor-core: %v", err))
	}
	installWebSocketReadLimit(conn)

	ac.connMutex.Lock()
	if ac.closed {
		ac.connMutex.Unlock()
		_ = conn.Close()
		return ac.finishConnect(nil, fmt.Errorf("attestor client is closed"))
	}
	ac.connectingConn = conn
	ac.connMutex.Unlock()

	ac.logger.Info("WebSocket connection established, starting initialization")

	// Initialize the connection with an InitRequest
	if err := ac.initializeConnection(conn); err != nil {
		return ac.finishConnect(conn, fmt.Errorf("failed to initialize connection: %v", err))
	}

	if err := ac.finishConnect(conn, nil); err != nil {
		return err
	}
	ac.logger.Info("AttestorClient connection and initialization complete")
	return nil
}

func (ac *AttestorClient) finishConnect(candidate *websocket.Conn, connectErr error) error {
	ac.connMutex.Lock()
	closed := ac.closed
	if ac.connectingConn == candidate {
		ac.connectingConn = nil
	}
	if connectErr == nil && !closed {
		ac.conn = candidate
	}
	done := ac.connectDone
	ac.connectDone = nil
	ac.connecting = false
	if done != nil {
		close(done)
	}
	ac.connMutex.Unlock()

	if connectErr != nil || closed {
		if candidate != nil {
			_ = candidate.Close()
		}
		if closed {
			return fmt.Errorf("attestor client is closed")
		}
		return connectErr
	}
	return nil
}

// initializeConnection sends the required InitRequest to attestor-core
func (ac *AttestorClient) initializeConnection(conn *websocket.Conn) error {
	ac.logger.Info("Creating InitRequest")

	// Create InitRequest
	initRequest := &teeproto.RPCMessage_InitRequest{
		InitRequest: &teeproto.InitRequest{
			ClientVersion: teeproto.AttestorVersion_ATTESTOR_VERSION_3_2_0, // Latest version
			SignatureType: teeproto.ServiceSignatureType_SERVICE_SIGNATURE_TYPE_ETH,
			Auth:          ac.authRequest,
		},
	}

	ac.logger.Info("Sending InitRequest")

	// Send using centralized RPC message handler
	responseMessages, err := ac.sendRPCMessageOnConn(conn, initRequest)
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
	ac.connMutex.Lock()
	conn := ac.conn
	candidate := ac.connectingConn
	ac.conn = nil
	ac.connectingConn = nil
	ac.closed = true
	ac.connMutex.Unlock()
	if candidate != nil && candidate != conn {
		_ = candidate.Close()
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// ClaimTeeBundleParams contains parameters for claim submission
type ClaimTeeBundleParams struct {
	Provider   string                        // Provider name (e.g., "http")
	Parameters *providers.HTTPProviderParams // Provider-specific parameters
	Context    string                        // Optional context (JSON string)
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
	parametersJson, err := json.Marshal(params.Parameters, json.Deterministic(true))
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
func (ac *AttestorClient) SendOPRFRequest(data []byte, domainSeparator []byte, zkEngine teeproto.ZKProofEngine) (any, *teeproto.TOPRFResponse, error) {
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
	ac.rpcMutex.Lock()
	defer ac.rpcMutex.Unlock()
	// Connection admission belongs inside the same serialization boundary as
	// the write/read exchange. If the preceding RPC detached an ambiguous
	// stream, this distinct call establishes a fresh initialized connection;
	// the failed request itself is never retried.
	if err := ac.ensureConnected(); err != nil {
		return nil, fmt.Errorf("failed to connect to attestor: %v", err)
	}

	ac.connMutex.Lock()
	conn := ac.conn
	ac.connMutex.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("attestor connection is not initialized")
	}

	response, err := ac.sendRPCMessageOnConn(conn, message)
	if err != nil {
		// An RPC failure may have occurred after a write. Never retry that request
		// implicitly; detach this exact stream so a later, distinct call can make
		// a fresh initialized connection.
		ac.connMutex.Lock()
		if ac.conn == conn {
			ac.conn = nil
		}
		ac.connMutex.Unlock()
		_ = conn.Close()
		return nil, err
	}
	return response, nil
}

func (ac *AttestorClient) sendRPCMessageOnConn(conn *websocket.Conn, message teeproto.IsRPCMessage) (*teeproto.RPCMessages, error) {
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

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

	if err := conn.WriteMessage(websocket.BinaryMessage, messageBytes); err != nil {
		return nil, fmt.Errorf("failed to send RPC message: %v", err)
	}

	// Read response
	_, responseBytes, err := conn.ReadMessage()
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
