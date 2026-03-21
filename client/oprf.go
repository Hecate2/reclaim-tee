package client

import (
	"encoding/json"
	"fmt"
	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/consensys/gnark/logger"
	prover "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/oprf"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/utils"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

func init() {
	logger.Disable() // disable gnark logger
}

// OPRFRangeData stores all OPRF-related data for a single hashed range
type OPRFRangeData struct {
	// Original range information
	Start  int
	Length int
	Data   []byte // The actual data from this range

	// OPRF request data
	Request *utils.OPRFRequest // Original OPRF request
	Mask    []byte             // TOPRF mask used

	// OPRF response from attestor
	Response *teeproto.TOPRFResponse

	// OPRF finalized output
	FinalOutput []byte

	// ZK proof data
	ZKProofParams *prover.InputParams // Parameters for ZK proof generation
	ZKProof       []byte              // The actual ZK proof (binary)

	// MPC OPRF flag - if true, hash is kept at full length (not truncated)
	IsMPC bool
}

// ProcessOPRFForHashedRanges processes OPRF for all hashed ranges
// This should be called right before building the verification bundle
func (c *Client) ProcessOPRFForHashedRanges(attestorClient *AttestorClient) error {
	c.logger.Info("Starting OPRF processing for redaction ranges",
		zap.Int("num_ranges", len(c.oprfRedactionRanges)))

	if len(c.oprfRedactionRanges) == 0 {
		c.logger.Info("No redaction ranges to process for OPRF")
		return nil
	}

	// Check if OPRF processing was already done
	if len(c.oprfRanges) > 0 {
		c.logger.Info("OPRF processing already completed, skipping",
			zap.Int("existing_ranges", len(c.oprfRanges)))
		return nil
	}

	// Get response results to access the actual HTTP response data
	responseResults, err := c.buildResponseResults()
	if err != nil {
		return fmt.Errorf("failed to get response results for OPRF: %v", err)
	}

	if responseResults.HTTPResponse == nil || len(responseResults.HTTPResponse.FullResponse) == 0 {
		return fmt.Errorf("no HTTP response data available for OPRF processing")
	}

	// Pre-load ZK circuit BEFORE opening attestor connection
	// Circuit loading can be slow, so we do it first to avoid WebSocket timeout
	cipherName, err := c.getTOPRFCipherName()
	if err != nil {
		return fmt.Errorf("failed to determine cipher for ZK circuit: %v", err)
	}
	c.logger.Info("Pre-loading ZK circuit before attestor connection", zap.String("cipher", cipherName))
	if err := EnsureAlgorithmInitialized(cipherName); err != nil {
		return fmt.Errorf("failed to pre-load ZK circuit: %v", err)
	}
	c.logger.Info("ZK circuit loaded, proceeding with OPRF processing")

	// Convert oprfRedactionRanges to OPRFRangeData
	c.oprfRanges = make(map[int]*OPRFRangeData)
	domainSeparator := []byte("reclaim")

	// Calculate progress increments
	totalRanges := len(c.oprfRedactionRanges)
	oprfPhaseStart := 65 // ProcessingOPRF starts at 65%
	oprfPhaseEnd := 74   // ProcessingOPRF ends at 74%
	zkPhaseStart := 75   // GeneratingZKProofs starts at 75%
	zkPhaseEnd := 84     // GeneratingZKProofs ends at 84% (before BuildingBundle at 85%)

	// Process each redaction range
	rangeIndex := 0
	for rangeStart, rangeLength := range c.oprfRedactionRanges {
		// Calculate progress percentage for OPRF processing (65% - 75%)
		// Progress from start to end of this specific operation
		oprfProgress := oprfPhaseStart + ((rangeIndex+1)*(oprfPhaseEnd-oprfPhaseStart))/totalRanges

		logFields := []zap.Field{
			zap.String("phase", "ProcessingOPRF"),
			zap.Int("progress_percentage", oprfProgress),
			zap.String("progress_description", fmt.Sprintf("Processing OPRF %d/%d for range [%d:%d]", rangeIndex+1, totalRanges, rangeStart, rangeStart+rangeLength)),
			zap.String("description", fmt.Sprintf("Processing OPRF %d/%d for range [%d:%d]", rangeIndex+1, totalRanges, rangeStart, rangeStart+rangeLength)),
		}
		if c.requestId != "" {
			logFields = append(logFields, zap.String("requestId", c.requestId))
		}
		c.logger.Info("Protocol progress", logFields...)

		c.logger.Info("Processing OPRF for redaction range",
			zap.Int("start", rangeStart),
			zap.Int("length", rangeLength))

		// Extract the data for this range
		if rangeStart < 0 || rangeStart+rangeLength > len(responseResults.HTTPResponse.FullResponse) {
			return fmt.Errorf("invalid range [%d:%d] for response length %d",
				rangeStart, rangeStart+rangeLength, len(responseResults.HTTPResponse.FullResponse))
		}

		rangeData := responseResults.HTTPResponse.FullResponse[rangeStart : rangeStart+rangeLength]

		// Create OPRFRangeData structure
		oprfData := &OPRFRangeData{
			Start:  rangeStart,
			Length: rangeLength,
			Data:   rangeData,
		}

		// Send OPRF request to attestor
		// IMPORTANT: Make a copy of the data because OPRF library modifies it in-place
		oprfDataCopy := make([]byte, len(rangeData))
		copy(oprfDataCopy, rangeData)

		oprfRequest, toprfResponse, err := attestorClient.SendOPRFRequest(
			oprfDataCopy,
			domainSeparator,
			teeproto.ZKProofEngine_ZK_ENGINE_GNARK,
		)
		if err != nil {
			return fmt.Errorf("OPRF request failed for range [%d:%d]: %v",
				rangeStart, rangeStart+rangeLength, err)
		}

		// Store OPRF request and response
		utilsOprfRequest, ok := oprfRequest.(*utils.OPRFRequest)
		if !ok {
			return fmt.Errorf("failed to cast OPRF request to utils.OPRFRequest for range [%d:%d]",
				rangeStart, rangeStart+rangeLength)
		}

		oprfData.Request = utilsOprfRequest
		oprfData.Mask = utilsOprfRequest.Mask.Bytes()
		oprfData.Response = toprfResponse

		// Finalize OPRF
		finalOutput, err := c.finalizeOPRF(utilsOprfRequest, toprfResponse)
		if err != nil {
			return fmt.Errorf("OPRF finalization failed for range [%d:%d]: %v",
				rangeStart, rangeStart+rangeLength, err)
		}
		oprfData.FinalOutput = finalOutput

		c.logger.Info("OPRF completed for range",
			zap.Int("start", rangeStart),
			zap.Int("length", rangeLength),
			zap.String("output", fmt.Sprintf("%x", finalOutput[:min(32, len(finalOutput))])))

		// Prepare ZK proof parameters
		zkParams, err := c.prepareZKProofForRange(oprfData)
		if err != nil {
			return fmt.Errorf("failed to prepare ZK proof for range [%d:%d]: %v",
				rangeStart, rangeStart+rangeLength, err)
		}
		oprfData.ZKProofParams = zkParams

		// Calculate progress percentage for ZK proof generation (75% - 82%)
		// Progress from start to end of this specific operation
		zkProgress := zkPhaseStart + ((rangeIndex+1)*(zkPhaseEnd-zkPhaseStart))/totalRanges

		logFields2 := []zap.Field{
			zap.String("phase", "GeneratingZKProofs"),
			zap.Int("progress_percentage", zkProgress),
			zap.String("progress_description", fmt.Sprintf("Generating ZK proof %d/%d for range [%d:%d]", rangeIndex+1, totalRanges, rangeStart, rangeStart+rangeLength)),
			zap.String("description", fmt.Sprintf("Generating ZK proof %d/%d for range [%d:%d]", rangeIndex+1, totalRanges, rangeStart, rangeStart+rangeLength)),
		}
		if c.requestId != "" {
			logFields2 = append(logFields2, zap.String("requestId", c.requestId))
		}
		c.logger.Info("Protocol progress", logFields2...)

		// Generate ZK proof (placeholder for now)
		zkProof, err := c.generateZKProof(zkParams)
		if err != nil {
			return fmt.Errorf("failed to generate ZK proof for range [%d:%d]: %v",
				rangeStart, rangeStart+rangeLength, err)
		}
		oprfData.ZKProof = zkProof

		// Store the complete OPRF data
		c.oprfRanges[rangeStart] = oprfData

		// Increment range index for next iteration
		rangeIndex++
	}

	c.logger.Info("OPRF processing completed successfully",
		zap.Int("num_ranges_processed", len(c.oprfRanges)))

	return nil
}

// finalizeOPRF finalizes the OPRF with the attestor's response
func (c *Client) finalizeOPRF(oprfRequest *utils.OPRFRequest, toprfResponse *teeproto.TOPRFResponse) ([]byte, error) {
	// Convert utils.OPRFRequest to oprf.OPRFRequest format
	maskedDataBytes := oprfRequest.MaskedData.Bytes()
	oprfRequestForFinalize := &oprf.OPRFRequest{
		Mask:       oprfRequest.Mask.Bytes(),
		MaskedData: maskedDataBytes[:],
		SecretElements: [][]byte{
			oprfRequest.SecretElements[0].Bytes(),
			oprfRequest.SecretElements[1].Bytes(),
		},
	}

	// Prepare finalize parameters
	finalizeParams := &oprf.InputTOPRFFinalizeParams{
		ServerPublicKey: toprfResponse.PublicKeyShare,
		Request:         oprfRequestForFinalize,
		Responses: []*oprf.OPRFResponse{
			{
				Index:          0,
				PublicKeyShare: toprfResponse.PublicKeyShare,
				Evaluated:      toprfResponse.Evaluated,
				C:              toprfResponse.C,
				R:              toprfResponse.R,
			},
		},
	}

	// Marshal parameters to JSON
	finalizeParamsJSON, err := json.Marshal(finalizeParams)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal finalize parameters: %v", err)
	}

	// Call TOPRFFinalize
	finalResultBytes := oprf.TOPRFFinalize(finalizeParamsJSON)

	// Parse the final output
	var finalResult struct {
		Output []byte `json:"output"`
	}
	if err := json.Unmarshal(finalResultBytes, &finalResult); err != nil {
		return nil, fmt.Errorf("failed to parse finalize result: %v", err)
	}

	return finalResult.Output, nil
}

// prepareZKProofForRange prepares ZK proof parameters for a specific OPRF range
func (c *Client) prepareZKProofForRange(oprfData *OPRFRangeData) (*prover.InputParams, error) {
	// Ensure we have the necessary data
	if c.teekSignedMessage == nil {
		return nil, fmt.Errorf("no TEE_K signed message available")
	}

	packetMetadata := c.teekSignedMessage.GetResponsePackets()
	serverKey := c.teekSignedMessage.GetServerAppKey()
	cipherSuite := uint16(c.teekSignedMessage.GetCipherSuite())

	// Get consolidated ciphertext from TEE_T
	if c.teetSignedMessage == nil {
		return nil, fmt.Errorf("no TEE_T signed message available")
	}

	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TEE_T payload: %v", err)
	}

	// Convert HTTP range to TLS ciphertext position
	httpRangeStart := oprfData.Start
	httpRangeEnd := oprfData.Start + oprfData.Length
	tlsStart, err := c.httpPositionToTlsPosition(httpRangeStart)
	if err != nil {
		return nil, fmt.Errorf("failed to convert HTTP range start to TLS: %w", err)
	}
	tlsEnd, err := c.httpPositionToTlsPosition(httpRangeEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to convert HTTP range end to TLS: %w", err)
	}

	c.logger.Info("OPRF range mapping",
		zap.Int("http_start", httpRangeStart),
		zap.Int("http_end", httpRangeEnd),
		zap.Int("tls_start", tlsStart),
		zap.Int("tls_end", tlsEnd),
		zap.String("data", string(oprfData.Data)))

	// Get the ideal blocks for TOPRF using the existing function
	inputParams, err := c.getIdealBlocksForTOPRF(tlsStart, tlsEnd, packetMetadata, cipherSuite, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get TOPRF blocks: %v", err)
	}

	// Fill in the TOPRF-specific fields
	if inputParams.TOPRF != nil {
		inputParams.TOPRF.Mask = oprfData.Mask
		inputParams.TOPRF.Output = oprfData.FinalOutput

		// Add the TOPRF response
		if oprfData.Response != nil {
			inputParams.TOPRF.Responses = []*prover.TOPRFResponse{
				{
					Index:          0,
					PublicKeyShare: oprfData.Response.PublicKeyShare,
					Evaluated:      oprfData.Response.Evaluated,
					C:              oprfData.Response.C,
					R:              oprfData.Response.R,
				},
			}
		}
	}

	return inputParams, nil
}

// generateZKProof generates the actual ZK proof
func (c *Client) generateZKProof(inputParams *prover.InputParams) ([]byte, error) {
	// Ensure algorithm is initialized (lazy loading via callback if needed)
	if err := EnsureAlgorithmInitialized(inputParams.Cipher); err != nil {
		return nil, fmt.Errorf("algorithm initialization failed: %v", err)
	}

	// Marshal the ZK parameters
	zkJSON, err := json.Marshal(inputParams)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ZK parameters: %v", err)
	}

	c.logger.Debug("Generating ZK proof", zap.String("params", string(zkJSON)))

	// Generate the proof
	proof := prover.Prove(zkJSON)

	// Parse the output
	var outParams *prover.OutputParams
	err = json.Unmarshal(proof, &outParams)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal zk proof: %v", err)
	}

	return outParams.Proof, nil
}

// GetOPRFRanges returns the OPRF range data for external access
func (c *Client) GetOPRFRanges() map[int]*OPRFRangeData {
	return c.oprfRanges
}

// GetTOPRFCipherInfo returns the TOPRF cipher name and required blocks for a cipher suite
func GetTOPRFCipherInfo(cipherSuite uint16) (cipherName string, requiredBlocks int, err error) {
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo == nil {
		return "", 0, fmt.Errorf("unknown cipher suite: %x", cipherSuite)
	}

	if minitls.IsChaCha20(cipherSuite) {
		if cipherInfo.KeySize == 32 {
			return "chacha20-toprf", 2, nil // 128 bytes for ChaCha20
		}
		return "", 0, fmt.Errorf("unsupported ChaCha20 variant")
	} else if cipherInfo.KeySize == 16 {
		return "aes-128-ctr-toprf", 5, nil // 80 bytes for AES-128
	} else if cipherInfo.KeySize == 32 {
		return "aes-256-ctr-toprf", 5, nil // 80 bytes for AES-256
	}

	return "", 0, fmt.Errorf("unsupported cipher configuration")
}

// getTOPRFCipherName returns the TOPRF cipher name based on the TLS cipher suite
func (c *Client) getTOPRFCipherName() (string, error) {
	if c.teekSignedMessage == nil {
		return "", fmt.Errorf("no TEE_K signed message available")
	}

	cipherSuite := uint16(c.teekSignedMessage.GetCipherSuite())
	cipherName, _, err := GetTOPRFCipherInfo(cipherSuite)
	return cipherName, err
}
