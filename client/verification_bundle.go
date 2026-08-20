package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"

	"github.com/mr-tron/base58"
	prover "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// Local types for JSON serialization (matching verifier expected format)
// These avoid importing the verifier package while producing identical JSON output

type zkInputVerifyParams struct {
	Cipher        string          `json:"cipher"`
	Proof         []uint8         `json:"proof"`
	PublicSignals json.RawMessage `json:"publicSignals"`
}

type zkInputTOPRFParams struct {
	Blocks []prover.Block      `json:"blocks"`
	TOPRF  *prover.TOPRFParams `json:"toprf"`
}

// GenerateKeystreamWithMetadata generates the keystream using packet metadata from TEE_K
func (c *Client) GenerateKeystreamWithMetadata() ([]byte, error) {
	// Get packet metadata and server key from TEE_K SignedMessage
	responsePackets := c.teekSignedMessage.GetResponsePackets()
	serverAppKey := c.teekSignedMessage.GetServerAppKey()
	cipherSuite := c.teekSignedMessage.GetCipherSuite()

	if len(responsePackets) == 0 {
		return nil, fmt.Errorf("no packet metadata from TEE_K")
	}
	if len(serverAppKey) == 0 {
		return nil, fmt.Errorf("no server app key from TEE_K")
	}
	// No need for server app IV - the nonces from TEE_K already contain all needed info

	// Generate keystream for each packet using the nonces from TEE_K
	consolidatedKeystream := make([]byte, 0)

	for i, packetInfo := range responsePackets {
		c.logger.Info("Generating keystream for packet",
			zap.Int("index", i),
			zap.Uint64("seq_num", packetInfo.SeqNum),
			zap.Uint32("position", packetInfo.Position),
			zap.Uint32("length", packetInfo.Length),
			zap.Binary("nonce", packetInfo.Nonce))

		// Use exact key and nonce from TEE_K with the same keystream functions
		var keystream []byte
		var err error

		// Use centralized keystream generation
		keystream, err = minitls.GenerateKeystream(uint16(cipherSuite), serverAppKey, packetInfo.Nonce, int(packetInfo.Length))

		if err != nil {
			return nil, fmt.Errorf("failed to generate keystream for packet %d: %v", i, err)
		}

		consolidatedKeystream = append(consolidatedKeystream, keystream...)
	}

	return consolidatedKeystream, nil
}

// PrepareZKProofForTOPRF prepares the ZK proof parameters for a TOPRF'd data range
func (c *Client) PrepareZKProofForTOPRF(httpRangeStart, httpRangeEnd int, toprfMask []byte, toprfOutput []byte, toprfResponse *teeproto.TOPRFResponse) (map[string]any, error) {
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
	tlsStart, err := c.httpPositionToTlsPosition(httpRangeStart)
	if err != nil {
		return nil, fmt.Errorf("failed to convert HTTP range start to TLS: %w", err)
	}
	tlsEnd, err := c.httpPositionToTlsPosition(httpRangeEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to convert HTTP range end to TLS: %w", err)
	}

	// Get the ideal blocks for TOPRF
	inputParams, err := c.getIdealBlocksForTOPRF(tlsStart, tlsEnd, packetMetadata, cipherSuite, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get TOPRF blocks: %v", err)
	}

	// Fill in the TOPRF-specific fields
	if inputParams.TOPRF != nil {
		inputParams.TOPRF.Mask = toprfMask
		inputParams.TOPRF.Output = toprfOutput

		// Add the TOPRF response
		if toprfResponse != nil {
			inputParams.TOPRF.Responses = []*prover.TOPRFResponse{
				{
					Index:          0,
					PublicKeyShare: toprfResponse.PublicKeyShare,
					Evaluated:      toprfResponse.Evaluated,
					C:              toprfResponse.C,
					R:              toprfResponse.R,
				},
			}
		}
	}

	// Convert InputParams to map for backward compatibility
	// Marshal to JSON then unmarshal to map
	jsonData, err := json.Marshal(inputParams)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal InputParams: %v", err)
	}

	var zkParams map[string]any
	if err := json.Unmarshal(jsonData, &zkParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to map: %v", err)
	}

	return zkParams, nil
}

// BuildVerificationBundleData collects all artefacts and processes OPRF for hashed ranges
func (c *Client) BuildVerificationBundleData(attestorClient *AttestorClient, providerParams *providers.HTTPProviderParams) ([]byte, error) {
	// Verify MPC OPRF outputs match between TEE_K and TEE_T
	if err := c.verifyOPRFMPCOutputsMatch(); err != nil {
		return nil, fmt.Errorf("MPC OPRF verification failed: %w", err)
	}

	// Process OPRF for all hashed ranges first (client-side TOPRF)
	if err := c.ProcessOPRFForHashedRanges(attestorClient); err != nil {
		return nil, fmt.Errorf("failed to process OPRF for hashed ranges: %v", err)
	}

	// Replace ParamValues with OPRF outputs for attestor validation
	if providerParams != nil && providerParams.ParamValues != nil {
		c.replaceParamValuesWithOPRF(providerParams)
	}

	// Then build the verification bundle
	return c.buildVerificationBundle()
}

// verifyOPRFMPCOutputsMatch verifies that MPC OPRF outputs from both TEEs match
func (c *Client) verifyOPRFMPCOutputsMatch() error {
	// Skip if no MPC OPRF was used
	if len(c.oprfMpcRedactionRanges) == 0 {
		return nil
	}

	// Ensure we have both signed messages
	if c.teekSignedMessage == nil {
		return fmt.Errorf("missing TEE_K signed message")
	}
	if c.teetSignedMessage == nil {
		return fmt.Errorf("missing TEE_T signed message")
	}

	// Extract OPRF outputs from signed payloads
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(c.teekSignedMessage.GetBody(), &kPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_K payload: %w", err)
	}

	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_T payload: %w", err)
	}

	kOutputs := kPayload.GetOprfOutputs()
	tOutputs := tPayload.GetOprfOutputs()

	// Count must match
	if len(kOutputs) != len(tOutputs) {
		return fmt.Errorf("MPC OPRF count mismatch: K=%d T=%d", len(kOutputs), len(tOutputs))
	}

	// Each output must match (both TEEs computed same result)
	for i := range kOutputs {
		if kOutputs[i].TlsStart != tOutputs[i].TlsStart ||
			kOutputs[i].TlsLength != tOutputs[i].TlsLength {
			return fmt.Errorf("MPC OPRF range mismatch at index %d", i)
		}
		if !bytes.Equal(kOutputs[i].HashOutput, tOutputs[i].HashOutput) {
			return fmt.Errorf("MPC OPRF hash mismatch at index %d", i)
		}
	}

	c.logger.Info("Verified MPC OPRF outputs match between TEE_K and TEE_T",
		zap.Int("count", len(kOutputs)))

	// Populate oprfRanges for ParamValue replacement
	return c.populateOPRFMPCRanges(kOutputs)
}

// populateOPRFMPCRanges populates oprfRanges from MPC OPRF outputs
// This enables replaceParamValuesWithOPRF to work with MPC OPRF just like ZK OPRF
func (c *Client) populateOPRFMPCRanges(oprfOutputs []*teeproto.OPRFOutput) error {
	if len(oprfOutputs) == 0 {
		return nil
	}

	// Need HTTP response data to extract original values
	if c.lastResponseData == nil || len(c.lastResponseData.FullResponse) == 0 {
		return fmt.Errorf("no HTTP response data available for MPC OPRF ParamValue replacement")
	}

	// Need mappings from buildMPCOPRFRanges
	if len(c.oprfMpcRangeMappings) != len(oprfOutputs) {
		return fmt.Errorf("MPC OPRF mapping count mismatch: mappings=%d outputs=%d",
			len(c.oprfMpcRangeMappings), len(oprfOutputs))
	}

	additions := make(map[int]*OPRFRangeData, len(oprfOutputs))

	// Match OPRF outputs to HTTP positions using stored mappings
	// Both are ordered by TLS position (sorted in buildMPCOPRFRanges)
	for i, output := range oprfOutputs {
		mapping := c.oprfMpcRangeMappings[i]

		// Verify TLS positions match
		if int(output.TlsStart) != mapping.TLSStart || int(output.TlsLength) != mapping.TLSLength {
			return fmt.Errorf("MPC OPRF position mismatch at index %d: expected TLS[%d:%d], got TLS[%d:%d]",
				i, mapping.TLSStart, mapping.TLSStart+mapping.TLSLength,
				output.TlsStart, output.TlsStart+output.TlsLength)
		}

		// Extract original data from HTTP response
		httpEnd := mapping.HTTPStart + mapping.HTTPLength
		if httpEnd > len(c.lastResponseData.FullResponse) {
			return fmt.Errorf("MPC OPRF HTTP range exceeds response data: start=%d length=%d response_len=%d",
				mapping.HTTPStart, mapping.HTTPLength, len(c.lastResponseData.FullResponse))
		}
		originalData := append([]byte(nil), c.lastResponseData.FullResponse[mapping.HTTPStart:httpEnd]...)

		// Create OPRFRangeData with MPC OPRF output
		// Note: Only Data and FinalOutput are used by replaceParamValuesWithOPRF
		additions[mapping.HTTPStart] = &OPRFRangeData{
			Start:       mapping.HTTPStart,
			Length:      mapping.HTTPLength,
			Data:        originalData,
			FinalOutput: output.HashOutput, // MPC OPRF uses SHA256(CMAC) as final output
			IsMPC:       true,              // MPC OPRF keeps full hash length
		}

		c.logger.Debug("Populated MPC OPRF range for ParamValue replacement",
			zap.Int("http_start", mapping.HTTPStart),
			zap.Int("http_length", mapping.HTTPLength),
			zap.Int("hash_len", len(output.HashOutput)))
	}

	// Publish only after every output and mapping has validated. A failure at
	// range N must not leave ranges 0..N-1 observable or poison a retry.
	c.oprfMutex.Lock()
	workingRanges := cloneOPRFRanges(c.oprfRanges)
	if workingRanges == nil {
		workingRanges = make(map[int]*OPRFRangeData)
	}
	maps.Copy(workingRanges, additions)
	c.oprfRanges = workingRanges
	c.oprfMutex.Unlock()

	c.logger.Info("Populated oprfRanges from MPC OPRF outputs",
		zap.Int("count", len(oprfOutputs)))
	return nil
}

// stripUnsignedFields creates a copy of SignedMessage with only the signed fields.
// This removes ResponsePackets, ServerAppKey, and CipherSuite which are used
// only for client-side operations and should not be sent to the attestor.
// The attestor only verifies the signature over Body and ignores these fields anyway,
// but we strip them to avoid sending unnecessary data (especially ServerAppKey).
func stripUnsignedFields(msg *teeproto.SignedMessage) *teeproto.SignedMessage {
	if msg == nil {
		return nil
	}
	return &teeproto.SignedMessage{
		BodyType:          msg.BodyType,
		Body:              append([]byte(nil), msg.Body...),
		EthAddress:        append([]byte(nil), msg.EthAddress...),
		Signature:         append([]byte(nil), msg.Signature...),
		AttestationReport: cloneAttestationReport(msg.AttestationReport),
		// ResponsePackets, ServerAppKey, CipherSuite intentionally omitted
	}
}

func cloneAttestationReport(report *teeproto.AttestationReport) *teeproto.AttestationReport {
	if report == nil {
		return nil
	}
	return proto.Clone(report).(*teeproto.AttestationReport)
}

// extractCertHashFromAttestation extracts a cert hash nonce from a GCP attestation JWT.
// The JWT's eat_nonce claim may be a string or array; this searches for a nonce matching
// the given prefix (e.g. "tee_k_cert_hash:") and returns the hex hash value.
// buildVerificationBundle creates the actual verification bundle
// SECURITY: This function validates that required data is present before creating bundle
func (c *Client) buildVerificationBundle() ([]byte, error) {
	bundle := &teeproto.VerificationBundle{}
	c.protocolStateMutex.RLock()
	var teekSignedMessage, teetSignedMessage *teeproto.SignedMessage
	if c.teekSignedMessage != nil {
		teekSignedMessage = proto.Clone(c.teekSignedMessage).(*teeproto.SignedMessage)
	}
	if c.teetSignedMessage != nil {
		teetSignedMessage = proto.Clone(c.teetSignedMessage).(*teeproto.SignedMessage)
	}
	teekValid := c.teeKSignatureValid
	teetValid := c.teeTSignatureValid
	c.protocolStateMutex.RUnlock()

	// SECURITY: Validate that we have the required signed messages
	if teekSignedMessage == nil {
		return nil, fmt.Errorf("SECURITY ERROR: missing TEE_K signed message - protocol incomplete")
	}
	if teetSignedMessage == nil {
		return nil, fmt.Errorf("SECURITY ERROR: missing TEE_T signed message - protocol incomplete")
	}
	if !teekValid || !teetValid {
		return nil, fmt.Errorf("SECURITY ERROR: TEE signed message validation was not completed")
	}

	// Channel<->attestation SPKI binding intentionally NOT checked here: TEE keys
	// rotate on every attestation refresh, so a session can outlive the cert its
	// channel froze on. Genuineness is covered by the RA-TLS handshake check and
	// the attestor's independent attestation+signature verification on the bundle.

	// TEE_K signed message (K_OUTPUT) - strip unsigned metadata fields before sending to attestor
	// The unsigned fields (ResponsePackets, ServerAppKey, CipherSuite) are only used client-side
	bundle.TeekSigned = stripUnsignedFields(teekSignedMessage)

	// TEE_T signed message (T_OUTPUT) - strip unsigned metadata fields before sending to attestor
	bundle.TeetSigned = stripUnsignedFields(teetSignedMessage)

	// OPRF verification data handles two types:
	// 1. Legacy TOPRF (oprfRedactionRanges) - uses ZK proofs, requires ZKProofParams
	// 2. MPC OPRF (oprfMpcRedactionRanges) - verified via TEE signatures in teekSigned/teetSigned
	// Both populate oprfRanges for ParamValue replacement, but only legacy TOPRF goes in bundle.OprfVerifications
	expectedOprfCount := len(c.oprfRedactionRanges) + len(c.oprfMpcRedactionRanges)
	if expectedOprfCount > 0 {
		c.oprfMutex.RLock()
		oprfRanges := cloneOPRFRanges(c.oprfRanges)
		c.oprfMutex.RUnlock()
		if len(oprfRanges) == 0 {
			return nil, fmt.Errorf("SECURITY ERROR: OPRF redaction ranges present but OPRF processing was not completed")
		}
		if len(oprfRanges) != expectedOprfCount {
			return nil, fmt.Errorf("SECURITY ERROR: OPRF range count mismatch - expected %d (legacy=%d + mpc=%d), got %d",
				expectedOprfCount, len(c.oprfRedactionRanges), len(c.oprfMpcRedactionRanges), len(oprfRanges))
		}
		c.logger.Info("OPRF ranges ready for bundle",
			zap.Int("total_oprf_ranges", len(oprfRanges)),
			zap.Int("legacy_toprf", len(c.oprfRedactionRanges)),
			zap.Int("mpc_oprf", len(c.oprfMpcRedactionRanges)))

		// Sort by range start for consistent ordering
		var sortedStarts []int
		for start := range oprfRanges {
			sortedStarts = append(sortedStarts, start)
		}
		sort.Ints(sortedStarts)

		// Create OPRF verification entries (only for legacy TOPRF with ZK proofs)
		// MPC OPRF ranges don't have ZKProofParams - they're verified via TEE signatures
		legacyToprfCount := 0
		for _, start := range sortedStarts {
			oprfData := oprfRanges[start]

			// Skip MPC OPRF ranges (no ZK proofs - verified via TEE signatures)
			if oprfData.ZKProofParams == nil || len(oprfData.ZKProofParams.Input) == 0 {
				c.logger.Debug("Skipping MPC OPRF range in bundle verification entries",
					zap.Int("range_start", oprfData.Start))
				continue
			}
			legacyToprfCount++

			// The stream position and length must match exactly what was extracted for ZK proof
			// This is the actual length without padding - boundary fields handle incomplete blocks
			streamInputLength := uint32(len(oprfData.ZKProofParams.Input))

			// Find which blocks contain this range and calculate the block-aligned stream position
			// This requires understanding the block structure used in getIdealBlocksForTOPRF
			streamPos, err := c.calculateBlockAlignedStreamPosition(oprfData.ZKProofParams)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate block-aligned stream position for range %d: %v", oprfData.Start, err)
			}

			streamLength := streamInputLength

			// Verification: Check if Input now matches extracted stream data
			if teetSignedMessage != nil {
				var tPayload teeproto.TOutputPayload
				if err := proto.Unmarshal(teetSignedMessage.GetBody(), &tPayload); err == nil {
					consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()

					if int(streamPos+streamLength) <= len(consolidatedCiphertext) {
						extractedFromStream := consolidatedCiphertext[streamPos : streamPos+streamLength]
						zkInput := oprfData.ZKProofParams.Input

						if bytes.Equal(extractedFromStream, zkInput) {
							c.logger.Info("INPUT MATCHES - attestor range is correct!",
								zap.Int("range_start", oprfData.Start),
								zap.Uint32("stream_pos", streamPos),
								zap.Uint32("stream_length", streamLength),
								zap.String("first_16_bytes", fmt.Sprintf("%x", extractedFromStream[:min(16, len(extractedFromStream))])))
						} else {
							c.logger.Error("INPUT MISMATCH - range calculation is wrong",
								zap.Int("range_start", oprfData.Start),
								zap.Uint32("stream_pos", streamPos),
								zap.Uint32("stream_length", streamLength),
								zap.Int("extracted_len", len(extractedFromStream)),
								zap.Int("zk_input_len", len(zkInput)),
								zap.String("extracted_first_16", fmt.Sprintf("%x", extractedFromStream[:min(16, len(extractedFromStream))])),
								zap.String("zk_input_first_16", fmt.Sprintf("%x", zkInput[:min(16, len(zkInput))])))

							return nil, fmt.Errorf("INPUT MISMATCH: extracted %d bytes != zk_input %d bytes",
								len(extractedFromStream), len(zkInput))
						}
					} else {
						return nil, fmt.Errorf("stream range [%d:%d] exceeds ciphertext length %d",
							streamPos, streamPos+streamLength, len(consolidatedCiphertext))
					}
				}
			}

			// Build public signals using prover types directly (no conversion needed)
			// The JSON output is identical to what the verifier expects
			publicSignalsStruct := zkInputTOPRFParams{
				Blocks: oprfData.ZKProofParams.Blocks,
				// Input is intentionally omitted - attestor will extract from TEE signed stream
				TOPRF: &prover.TOPRFParams{
					Locations:       oprfData.ZKProofParams.TOPRF.Locations,
					DomainSeparator: []byte("reclaim"),
					Output:          oprfData.FinalOutput,
					Responses: []*prover.TOPRFResponse{
						{
							Index:          0,
							PublicKeyShare: oprfData.Response.PublicKeyShare,
							Evaluated:      oprfData.Response.Evaluated,
							C:              oprfData.Response.C,
							R:              oprfData.Response.R,
						},
					},
				},
			}

			// Marshal public signals to JSON
			publicSignalsJSON, err := json.Marshal(publicSignalsStruct)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal public signals for range %d: %v", oprfData.Start, err)
			}

			// Create verification params wrapper
			verifyParams := zkInputVerifyParams{
				Cipher:        oprfData.ZKProofParams.Cipher,
				Proof:         oprfData.ZKProof,
				PublicSignals: json.RawMessage(publicSignalsJSON),
			}

			// Marshal the complete verify params
			verifyParamsJSON, err := json.Marshal(verifyParams)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal public signals for range %d: %v", oprfData.Start, err)
			}

			// Add OPRF verification entry
			bundle.OprfVerifications = append(bundle.OprfVerifications, &teeproto.OPRFVerificationData{
				StreamPos:         streamPos,
				StreamLength:      streamLength,
				PublicSignalsJson: verifyParamsJSON,
			})

			c.logger.Debug("Added OPRF verification",
				zap.Int("http_start", oprfData.Start),
				zap.Int("http_length", oprfData.Length),
				zap.Uint32("stream_pos", streamPos),
				zap.Uint32("stream_length", streamLength))
		}

		// Validate we processed the expected number of legacy TOPRF ranges
		if legacyToprfCount != len(c.oprfRedactionRanges) {
			return nil, fmt.Errorf("SECURITY ERROR: legacy TOPRF count mismatch - expected %d, processed %d",
				len(c.oprfRedactionRanges), legacyToprfCount)
		}
		c.logger.Info("Added OPRF verification entries to bundle",
			zap.Int("legacy_toprf_entries", legacyToprfCount))
	}

	// Verify that keystream generation using metadata produces same result as TEE_K
	// This happens when both messages are available
	// c.verifyKeystreamGeneration()

	// Serialize to protobuf data
	data, err := proto.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bundle: %v", err)
	}

	return data, nil
}

// httpPositionToTlsPosition converts HTTP response position to TLS stream position
// Returns an error if no mapping is found for the position
func (c *Client) httpPositionToTlsPosition(httpPos int) (int, error) {
	for _, mapping := range c.httpToTlsMapping {
		mappingEnd := mapping.HTTPPos + mapping.Length
		if httpPos >= mapping.HTTPPos && httpPos < mappingEnd {
			// Position is within this mapping
			offset := httpPos - mapping.HTTPPos
			return mapping.TLSPos + offset, nil
		}
	}

	return -1, fmt.Errorf("no HTTP-to-TLS mapping found for position %d", httpPos)
}

// getIdealBlocksForTOPRF extracts the ideal cipher blocks for TOPRF proof generation
func (c *Client) getIdealBlocksForTOPRF(rangeStart, rangeEnd int, packetMetadata []*teeproto.TLSPacketInfo, cipherSuite uint16, serverKey []byte) (*prover.InputParams, error) {

	// Build the original unredacted ciphertext from ciphertextBySeq
	c.responseContentMutex.Lock()
	var seqNums []uint64
	for seqNum := range c.ciphertextBySeq {
		seqNums = append(seqNums, seqNum)
	}
	slices.Sort(seqNums)

	var originalCiphertext []byte
	for _, seqNum := range seqNums {
		if ciphertext, exists := c.ciphertextBySeq[seqNum]; exists {
			originalCiphertext = append(originalCiphertext, ciphertext...)
		}
	}
	c.responseContentMutex.Unlock()

	// Determine cipher parameters based on cipher suite
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo == nil {
		return nil, fmt.Errorf("unknown cipher suite: %x", cipherSuite)
	}

	blockSize := cipherInfo.BlockSize
	cipherName, requiredBlocks, err := GetTOPRFCipherInfo(cipherSuite)
	if err != nil {
		return nil, err
	}

	// Check data size limit (62 bytes max for TOPRF)
	dataLength := rangeEnd - rangeStart
	if dataLength > 62 {
		return nil, fmt.Errorf("data size %d exceeds maximum of 62 bytes for TOPRF", dataLength)
	}

	// STEP 1: Find all packets that overlap with the data range
	// A 14-byte range can span multiple TLS packets (e.g., bytes 1358-1372 might be split across packets)
	c.logger.Debug("Searching for packets overlapping range",
		zap.Int("range_start", rangeStart),
		zap.Int("range_end", rangeEnd),
		zap.Int("num_packets", len(packetMetadata)))

	type PacketSegment struct {
		packet        *teeproto.TLSPacketInfo
		segmentStart  int // Position in consolidated stream where this segment starts
		segmentEnd    int // Position in consolidated stream where this segment ends
		offsetInPkt   int // Offset within the packet where range data starts
		dataLen       int // Length of data in this packet segment
		firstBlockNum int // First block number in this packet that contains data
		lastBlockNum  int // Last block number in this packet that contains data
	}

	var segments []PacketSegment

	for i, pkt := range packetMetadata {
		pktStart := int(pkt.GetPosition())
		pktEnd := pktStart + int(pkt.GetLength())

		c.logger.Debug("Checking packet",
			zap.Int("index", i),
			zap.Uint64("seq", pkt.GetSeqNum()),
			zap.Int("pkt_start", pktStart),
			zap.Int("pkt_end", pktEnd))

		// Check if this packet contains any part of our data range
		if rangeEnd > pktStart && rangeStart < pktEnd {
			segStart := max(rangeStart, pktStart)
			segEnd := min(rangeEnd, pktEnd)
			offsetInPkt := segStart - pktStart
			dataLen := segEnd - segStart

			firstBlock := offsetInPkt / blockSize
			lastBlock := (offsetInPkt + dataLen - 1) / blockSize

			seg := PacketSegment{
				packet:        pkt,
				segmentStart:  segStart,
				segmentEnd:    segEnd,
				offsetInPkt:   offsetInPkt,
				dataLen:       dataLen,
				firstBlockNum: firstBlock,
				lastBlockNum:  lastBlock,
			}
			segments = append(segments, seg)

			c.logger.Debug("Packet overlaps with range",
				zap.Uint64("seq", pkt.GetSeqNum()),
				zap.Int("seg_start", segStart),
				zap.Int("seg_end", segEnd),
				zap.Int("data_len", dataLen),
				zap.Int("first_block", firstBlock),
				zap.Int("last_block", lastBlock))
		}
	}

	if len(segments) == 0 {
		c.logger.Error("No packets found containing range",
			zap.Int("range_start", rangeStart),
			zap.Int("range_end", rangeEnd),
			zap.Int("num_packets", len(packetMetadata)))
		return nil, fmt.Errorf("could not find packet containing range [%d:%d]", rangeStart, rangeEnd)
	}

	c.logger.Info("Found packets for TOPRF range",
		zap.Int("range_start", rangeStart),
		zap.Int("range_end", rangeEnd),
		zap.Int("num_segments", len(segments)))

	// STEP 2: Build a list of all cipher blocks that contain our data
	// Each segment may span multiple blocks within its packet
	// Important: Each block gets its nonce from its packet (not from a global counter)
	type BlockInfo struct {
		packet      *teeproto.TLSPacketInfo
		blockNum    int // Block number within the packet (used for counter calculation)
		streamStart int // Where this block starts in consolidated stream
		streamEnd   int // Where this block ends in consolidated stream
	}

	var allDataBlocks []BlockInfo
	for _, seg := range segments {
		pktStart := int(seg.packet.GetPosition())
		for blockNum := seg.firstBlockNum; blockNum <= seg.lastBlockNum; blockNum++ {
			blockStreamStart := pktStart + blockNum*blockSize
			blockStreamEnd := min(blockStreamStart+blockSize, pktStart+int(seg.packet.GetLength()))

			allDataBlocks = append(allDataBlocks, BlockInfo{
				packet:      seg.packet,
				blockNum:    blockNum,
				streamStart: blockStreamStart,
				streamEnd:   blockStreamEnd,
			})
		}
	}

	c.logger.Debug("Data spans blocks",
		zap.Int("num_data_blocks", len(allDataBlocks)),
		zap.Int("required_blocks", requiredBlocks))

	// STEP 3: Select exactly requiredBlocks for the ZK prover
	// ZK circuit requires exactly 5 blocks for AES or 2 blocks for ChaCha20
	// If data spans fewer blocks, we include adjacent blocks to reach the requirement
	var selectedBlocks []BlockInfo

	if len(allDataBlocks) >= requiredBlocks {
		// Easy case: data already spans enough blocks
		selectedBlocks = allDataBlocks[:requiredBlocks]
	} else {
		// Need to pad with extra blocks from the same packet(s)
		selectedBlocks = allDataBlocks
		firstSeg := segments[0]
		pktStart := int(firstSeg.packet.GetPosition())

		// Strategy: prepend blocks before the data to reach requiredBlocks
		blocksNeeded := requiredBlocks - len(selectedBlocks)
		firstDataBlock := firstSeg.firstBlockNum

		for i := 0; i < blocksNeeded && firstDataBlock-i-1 >= 0; i++ {
			blockNum := firstDataBlock - i - 1
			blockStreamStart := pktStart + blockNum*blockSize
			blockStreamEnd := min(blockStreamStart+blockSize, pktStart+int(firstSeg.packet.GetLength()))

			selectedBlocks = append([]BlockInfo{{
				packet:      firstSeg.packet,
				blockNum:    blockNum,
				streamStart: blockStreamStart,
				streamEnd:   blockStreamEnd,
			}}, selectedBlocks...)
		}

		// If still short, append blocks after the data
		if len(selectedBlocks) < requiredBlocks && len(segments) > 0 {
			lastSeg := segments[len(segments)-1]
			pktStart := int(lastSeg.packet.GetPosition())
			pktBlocks := int(lastSeg.packet.GetLength()+uint32(blockSize)-1) / blockSize

			blocksNeeded := requiredBlocks - len(selectedBlocks)
			lastDataBlock := lastSeg.lastBlockNum

			for i := 0; i < blocksNeeded && lastDataBlock+i+1 < pktBlocks; i++ {
				blockNum := lastDataBlock + i + 1
				blockStreamStart := pktStart + blockNum*blockSize
				blockStreamEnd := min(blockStreamStart+blockSize, pktStart+int(lastSeg.packet.GetLength()))

				selectedBlocks = append(selectedBlocks, BlockInfo{
					packet:      lastSeg.packet,
					blockNum:    blockNum,
					streamStart: blockStreamStart,
					streamEnd:   blockStreamEnd,
				})
			}
		}
	}

	if len(selectedBlocks) < requiredBlocks {
		return nil, fmt.Errorf("cannot extract enough blocks: need %d, got %d", requiredBlocks, len(selectedBlocks))
	}

	// STEP 4: Extract ciphertext and build Block structures for the prover
	// Each block needs: nonce (from packet), counter (from block position), and optional boundary
	blocks := make([]prover.Block, 0, len(selectedBlocks))
	var ciphertextBlocks []byte

	for _, blk := range selectedBlocks {
		blockCiphertext := originalCiphertext[blk.streamStart:blk.streamEnd]
		ciphertextBlocks = append(ciphertextBlocks, blockCiphertext...)

		// Counter is calculated based on block position within its packet
		counter := minitls.GetBlockCounter(cipherSuite, blk.blockNum)
		c.logger.Debug("Building block",
			zap.Uint64("packet_seq", blk.packet.GetSeqNum()),
			zap.Int("block_num", blk.blockNum),
			zap.Uint32("counter", counter),
			zap.Int("stream_start", blk.streamStart),
			zap.Int("stream_end", blk.streamEnd),
			zap.Int("block_bytes", len(blockCiphertext)))

		block := prover.Block{
			Nonce:   blk.packet.GetNonce(), // Each packet has its own nonce
			Counter: counter,
		}

		// Boundary marks how many bytes in this block are valid (nil = full block)
		if len(blockCiphertext) < blockSize {
			block.Boundary = new(uint32(len(blockCiphertext)))
		}

		blocks = append(blocks, block)
	}

	// Calculate where our data starts within the concatenated blocks
	// Example: if blocks start at position 1280 and data starts at 1358, offset is 78
	positionInBlocks := rangeStart - selectedBlocks[0].streamStart

	// Build the InputParams structure
	inputParams := &prover.InputParams{
		Cipher: cipherName,
		Key:    serverKey,
		Blocks: blocks,
		Input:  ciphertextBlocks,
		TOPRF: &prover.TOPRFParams{
			Locations: []prover.Location{
				{
					Pos: uint32(positionInBlocks),
					Len: uint32(dataLength),
				},
			},
			// These will be filled by the caller who has the TOPRF results
			DomainSeparator: []byte("reclaim"),
			// Mask, Output, and Responses will be filled later
		},
	}

	c.logger.Info("Generated TOPRF block parameters",
		zap.String("cipher", cipherName),
		zap.Int("required_blocks", requiredBlocks),
		zap.Int("data_position", positionInBlocks),
		zap.Int("data_length", dataLength),
		zap.Int("total_ciphertext_bytes", len(ciphertextBlocks)))

	return inputParams, nil
}

// calculateBlockAlignedStreamPosition calculates where the ZK Input blocks start in the consolidated stream
func (c *Client) calculateBlockAlignedStreamPosition(zkParams *prover.InputParams) (uint32, error) {
	// Instead of recalculating the complex block extraction logic, we can determine the position
	// based on the first block's counter and nonce from zkParams

	if len(zkParams.Blocks) == 0 {
		return 0, fmt.Errorf("no blocks in ZK params")
	}

	// Get packet metadata to find which packet contains the first block
	packetMetadata := c.teekSignedMessage.GetResponsePackets()
	cipherSuite := uint16(c.teekSignedMessage.GetCipherSuite())

	// Find the packet that has the same nonce as our first block
	firstBlock := zkParams.Blocks[0]
	var targetPacket *teeproto.TLSPacketInfo

	for _, pkt := range packetMetadata {
		if bytes.Equal(pkt.GetNonce(), firstBlock.Nonce) {
			targetPacket = pkt
			break
		}
	}

	if targetPacket == nil {
		return 0, fmt.Errorf("could not find packet with matching nonce for first block")
	}

	// Calculate block parameters
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo == nil {
		return 0, fmt.Errorf("unknown cipher suite: %x", cipherSuite)
	}
	blockSize := cipherInfo.BlockSize

	// Reverse-engineer the block index from the counter
	// GetBlockCounter adds offset: ChaCha20 adds 1, AES-GCM adds 2
	pktStart := int(targetPacket.GetPosition())

	var firstBlockIndex int
	if minitls.IsChaCha20(cipherSuite) {
		// ChaCha20: counter = blockNum + 1, so blockNum = counter - 1
		firstBlockIndex = int(firstBlock.Counter) - 1
	} else {
		// AES-GCM: counter = blockNum + 2, so blockNum = counter - 2
		firstBlockIndex = int(firstBlock.Counter) - 2
	}

	blockAlignedStreamPos := pktStart + (firstBlockIndex * blockSize)

	return uint32(blockAlignedStreamPos), nil
}

// replaceParamValuesWithOPRF replaces ParamValues that match hashed range data with OPRF outputs
// This ensures the attestor receives the correct values for validation
func (c *Client) replaceParamValuesWithOPRF(providerParams *providers.HTTPProviderParams) {
	if providerParams == nil || providerParams.ParamValues == nil {
		return
	}
	c.oprfMutex.RLock()
	oprfRanges := cloneOPRFRanges(c.oprfRanges)
	c.oprfMutex.RUnlock()
	if len(oprfRanges) == 0 {
		return
	}
	updatedValues := make(map[string]string, len(providerParams.ParamValues))
	maps.Copy(updatedValues, providerParams.ParamValues)

	c.logger.Info("Replacing ParamValues with OPRF outputs",
		zap.Int("num_oprf_ranges", len(oprfRanges)),
		zap.Int("num_param_values", len(providerParams.ParamValues)))

	// For each OPRF range, check if its data matches any ParamValue.
	sortedStarts := make([]int, 0, len(oprfRanges))
	for start := range oprfRanges {
		sortedStarts = append(sortedStarts, start)
	}
	sort.Ints(sortedStarts)
	for _, start := range sortedStarts {
		oprfData := oprfRanges[start]
		originalData := string(oprfData.Data)

		// Look for matching ParamValue
		for key, value := range updatedValues {
			if value == originalData {
				var finalOPRF string
				if oprfData.IsMPC {
					// MPC OPRF: use base58 encoding, keep full hash length
					finalOPRF = base58.Encode(oprfData.FinalOutput)
				} else {
					// TOPRF: use base64 encoding, adjust length to match original string
					oprfBase64 := base64.StdEncoding.EncodeToString(oprfData.FinalOutput)
					finalOPRF = adjustBase64Length(oprfBase64, len(originalData))
				}

				// Replace in-place
				updatedValues[key] = finalOPRF

				c.logger.Info("Replaced ParamValue with OPRF output",
					zap.String("key", key),
					zap.Int("original_length", len(originalData)),
					zap.Int("oprf_length", len(finalOPRF)),
					zap.Bool("is_mpc", oprfData.IsMPC))
			}
		}
	}
	providerParams.ParamValues = updatedValues
}

// adjustBase64Length adjusts base64 string to match target length
// If shorter: repeats the string until it fits
// If longer: truncates from the end
func adjustBase64Length(base64Str string, targetLength int) string {
	if len(base64Str) == targetLength {
		return base64Str
	}

	if len(base64Str) < targetLength {
		// Repeat until it fits
		result := base64Str
		for len(result) < targetLength {
			remaining := targetLength - len(result)
			if remaining >= len(base64Str) {
				result += base64Str
			} else {
				result += base64Str[:remaining]
			}
		}
		return result
	}

	// Truncate from the end
	return base64Str[:targetLength]
}
