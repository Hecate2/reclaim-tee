package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"tee-mpc/minitls"
	teeproto "tee-mpc/proto"
	"tee-mpc/providers"

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

// getStreamPosition calculates the position of an HTTP range in the consolidated TLS stream
func (c *Client) getStreamPosition(httpStart int) (uint32, error) {
	// Convert HTTP position to TLS position
	tlsPosition := c.httpPositionToTlsPosition(httpStart)

	// The TLS position is already the position in the consolidated stream
	// since httpPositionToTlsPosition maps HTTP offsets to TLS stream offsets
	return uint32(tlsPosition), nil
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
func (c *Client) PrepareZKProofForTOPRF(httpRangeStart, httpRangeEnd int, toprfMask []byte, toprfOutput []byte, toprfResponse *teeproto.TOPRFResponse) (map[string]interface{}, error) {
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
	tlsStart := c.httpPositionToTlsPosition(httpRangeStart)
	tlsEnd := c.httpPositionToTlsPosition(httpRangeEnd)

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

	var zkParams map[string]interface{}
	if err := json.Unmarshal(jsonData, &zkParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to map: %v", err)
	}

	return zkParams, nil
}

// BuildVerificationBundleData collects all artefacts and processes OPRF for hashed ranges
func (c *Client) BuildVerificationBundleData(attestorClient *AttestorClient, providerParams *providers.HTTPProviderParams) ([]byte, error) {
	// Process OPRF for all hashed ranges first
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

// buildVerificationBundle creates the actual verification bundle
// SECURITY: This function validates that required data is present before creating bundle
func (c *Client) buildVerificationBundle() ([]byte, error) {
	bundle := &teeproto.VerificationBundle{}

	// SECURITY: Validate that we have the required signed messages
	if c.teekSignedMessage == nil {
		return nil, fmt.Errorf("SECURITY ERROR: missing TEE_K signed message - protocol incomplete")
	}
	if c.teetSignedMessage == nil {
		return nil, fmt.Errorf("SECURITY ERROR: missing TEE_T signed message - protocol incomplete")
	}

	// TEE_K signed message (K_OUTPUT) - use original protobuf SignedMessage
	bundle.TeekSigned = c.teekSignedMessage

	// TEE_T signed message (T_OUTPUT) - use original protobuf SignedMessage
	bundle.TeetSigned = c.teetSignedMessage

	// OPRF verification data is required if there were OPRF redaction ranges
	if len(c.oprfRedactionRanges) > 0 {
		if len(c.oprfRanges) == 0 {
			return nil, fmt.Errorf("SECURITY ERROR: OPRF redaction ranges present but OPRF processing was not completed")
		}
		if len(c.oprfRanges) != len(c.oprfRedactionRanges) {
			return nil, fmt.Errorf("SECURITY ERROR: OPRF range count mismatch - expected %d, got %d", len(c.oprfRedactionRanges), len(c.oprfRanges))
		}
		c.logger.Info("Adding OPRF verification data to bundle",
			zap.Int("num_ranges", len(c.oprfRanges)))

		// Sort by range start for consistent ordering
		var sortedStarts []int
		for start := range c.oprfRanges {
			sortedStarts = append(sortedStarts, start)
		}
		sort.Ints(sortedStarts)

		// Create OPRF verification entries
		for _, start := range sortedStarts {
			oprfData := c.oprfRanges[start]

			// Get stream range that corresponds to the ZK Input blocks
			// The attestor needs to extract the same block structure used for ZK proof
			if oprfData.ZKProofParams == nil || len(oprfData.ZKProofParams.Input) == 0 {
				return nil, fmt.Errorf("missing ZK proof input for range %d", oprfData.Start)
			}

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
			if c.teetSignedMessage != nil {
				var tPayload teeproto.TOutputPayload
				if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err == nil {
					consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()

					if int(streamPos+streamLength) <= len(consolidatedCiphertext) {
						extractedFromStream := consolidatedCiphertext[streamPos : streamPos+streamLength]
						zkInput := oprfData.ZKProofParams.Input

						if bytes.Equal(extractedFromStream, zkInput) {
							c.logger.Info("✅ INPUT MATCHES - attestor range is correct!",
								zap.Int("range_start", oprfData.Start),
								zap.Uint32("stream_pos", streamPos),
								zap.Uint32("stream_length", streamLength),
								zap.String("first_16_bytes", fmt.Sprintf("%x", extractedFromStream[:min(16, len(extractedFromStream))])))
						} else {
							c.logger.Error("❌ INPUT MISMATCH - range calculation is wrong",
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

// verifyKeystreamGeneration verifies that we can independently decrypt responses
// using packet metadata from TEE_K and consolidated ciphertext from TEE_T
func (c *Client) verifyKeystreamGeneration() {
	// Only verify if we have packet metadata
	if len(c.teekSignedMessage.GetResponsePackets()) == 0 {
		c.logger.Debug("No packet metadata available for verification")
		return
	}

	// Log packet metadata info
	c.logger.Info("Using packet metadata to generate keystream",
		zap.Int("packet_count", len(c.teekSignedMessage.GetResponsePackets())),
		zap.Int("server_key_len", len(c.teekSignedMessage.GetServerAppKey())),
		zap.Uint32("cipher_suite", c.teekSignedMessage.GetCipherSuite()))

	// Generate keystream using packet metadata
	generatedKeystream, err := c.GenerateKeystreamWithMetadata()
	if err != nil {
		c.logger.Error("Failed to generate keystream with metadata", zap.Error(err))
		return
	}

	c.logger.Info("Generated keystream from packet metadata",
		zap.Int("keystream_bytes", len(generatedKeystream)))

	// Compare with TEE_K's keystream for debugging
	c.compareWithTEEKKeystream(generatedKeystream)

	// Map OPRF ranges to cryptographic blocks and packets for OPRF
	if len(c.oprfRedactionRanges) > 0 {
		// Get consolidated ciphertext from TEE_T's signed message
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err == nil {
			consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()

			// First, let's verify what's at position 38245 in the normal decryption
			if len(generatedKeystream) > 38269 && len(consolidatedCiphertext) > 38269 {
				normalDecrypt := make([]byte, 100)
				for i := 0; i < 100 && 38245+i < len(consolidatedCiphertext); i++ {
					normalDecrypt[i] = consolidatedCiphertext[38245+i] ^ generatedKeystream[38245+i]
				}
				c.logger.Info("Normal decryption at position 38245",
					zap.String("text", string(normalDecrypt[:24])),
					zap.Binary("binary", normalDecrypt[:24]))
			}

			c.mapHashedRangesToBlocks(c.teekSignedMessage.GetResponsePackets(), uint16(c.teekSignedMessage.GetCipherSuite()))
		}
	}

	// Now decrypt the consolidated ciphertext from TEE_T using our generated keystream
	c.verifyDecryptionWithGeneratedKeystream(generatedKeystream)
}

// verifyDecryptionWithGeneratedKeystream verifies that XORing generated keystream with TEE_T's
// unredacted ciphertext produces the same unredacted plaintext the client originally received
func (c *Client) verifyDecryptionWithGeneratedKeystream(keystream []byte) {
	// Get consolidated ciphertext from TEE_T
	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err != nil {
		c.logger.Error("Failed to unmarshal T payload for plaintext verification", zap.Error(err))
		return
	}

	consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()

	if len(keystream) != len(consolidatedCiphertext) {
		c.logger.Error("Keystream and ciphertext length mismatch",
			zap.Int("keystream_len", len(keystream)),
			zap.Int("ciphertext_len", len(consolidatedCiphertext)))
		return
	}

	// XOR to get plaintext
	plaintext := make([]byte, len(consolidatedCiphertext))
	for i := range consolidatedCiphertext {
		plaintext[i] = consolidatedCiphertext[i] ^ keystream[i]
	}

	// The plaintext includes session tickets and other non-application data
	// Let's check if the plaintext contains the HTTP response
	httpIndex := bytes.Index(plaintext, []byte("HTTP/"))
	if httpIndex >= 0 {
		c.logger.Info("✅ Successfully decrypted using packet metadata - found HTTP response",
			zap.Int("total_plaintext_bytes", len(plaintext)),
			zap.Int("http_offset", httpIndex))

		// Compare with what we stored (which is just the HTTP application data)
		if c.lastResponseData != nil && len(c.lastResponseData.FullResponse) > 0 {
			// Check if our stored HTTP data appears in the decrypted plaintext
			if bytes.Contains(plaintext, c.lastResponseData.FullResponse) {
				c.logger.Info("✅ PERFECT MATCH: Decrypted plaintext contains exact HTTP response from original flow",
					zap.Int("http_app_data_bytes", len(c.lastResponseData.FullResponse)))
			} else {
				// Try to find how much matches
				matchLen := 0
				mismatchIndex := -1
				for i := 0; i < len(c.lastResponseData.FullResponse) && httpIndex+i < len(plaintext); i++ {
					if plaintext[httpIndex+i] == c.lastResponseData.FullResponse[i] {
						matchLen++
					} else {
						mismatchIndex = i
						break
					}
				}
				c.logger.Info("Partial HTTP match in decrypted plaintext",
					zap.Int("matched_bytes", matchLen),
					zap.Int("total_http_bytes", len(c.lastResponseData.FullResponse)),
					zap.Int("mismatch_at", mismatchIndex))

				// Log the mismatch details
				if mismatchIndex >= 0 && mismatchIndex < len(c.lastResponseData.FullResponse) {
					c.logger.Debug("Mismatch details",
						zap.ByteString("expected", c.lastResponseData.FullResponse[mismatchIndex:min(mismatchIndex+20, len(c.lastResponseData.FullResponse))]),
						zap.ByteString("got", plaintext[httpIndex+mismatchIndex:min(httpIndex+mismatchIndex+20, len(plaintext))]))
				}
			}
		}

		// Show what we decrypted
		previewLen := 100
		if len(plaintext[httpIndex:]) < previewLen {
			previewLen = len(plaintext[httpIndex:])
		}
		c.logger.Info("Decrypted HTTP preview",
			zap.ByteString("http_start", plaintext[httpIndex:httpIndex+previewLen]))
	} else {
		c.logger.Error("Failed to find HTTP response in decrypted plaintext",
			zap.Int("plaintext_len", len(plaintext)))
	}
}

// compareWithTEEKKeystream compares our generated keystream with TEE_K's unredacted keystreams we received earlier
func (c *Client) compareWithTEEKKeystream(generatedKeystream []byte) {
	// Build consolidated unredacted keystream from the individual streams we received earlier
	// NOT from the signed message which contains REDACTED streams
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	// Get sequence numbers in order
	var seqNums []uint64
	for seqNum := range c.decryptionStreamBySeq {
		seqNums = append(seqNums, seqNum)
	}
	sort.Slice(seqNums, func(i, j int) bool { return seqNums[i] < seqNums[j] })

	// Build consolidated unredacted keystream from what we received earlier
	var teekKeystream []byte
	for _, seqNum := range seqNums {
		if stream, exists := c.decryptionStreamBySeq[seqNum]; exists {
			teekKeystream = append(teekKeystream, stream...)
		}
	}

	if len(generatedKeystream) != len(teekKeystream) {
		c.logger.Error("Keystream length mismatch with TEE_K",
			zap.Int("generated_len", len(generatedKeystream)),
			zap.Int("teek_len", len(teekKeystream)))
		return
	}

	// Compare byte by byte
	mismatchCount := 0
	firstMismatch := -1
	for i := 0; i < len(generatedKeystream); i++ {
		if generatedKeystream[i] != teekKeystream[i] {
			mismatchCount++
			if firstMismatch == -1 {
				firstMismatch = i
			}
		}
	}

	if mismatchCount == 0 {
		c.logger.Info("✅ Perfect keystream match with TEE_K!",
			zap.Int("bytes_compared", len(generatedKeystream)))
	} else {
		c.logger.Error("❌ Keystream mismatch with TEE_K",
			zap.Int("total_mismatches", mismatchCount),
			zap.Int("first_mismatch_at", firstMismatch),
			zap.Int("total_bytes", len(generatedKeystream)))

		// Show the first few mismatched bytes
		if firstMismatch >= 0 {
			endIdx := min(firstMismatch+10, len(generatedKeystream))
			c.logger.Info("Keystream mismatch details",
				zap.Int("mismatch_offset", firstMismatch),
				zap.Binary("generated", generatedKeystream[firstMismatch:endIdx]),
				zap.Binary("teek_expected", teekKeystream[firstMismatch:endIdx]))
		}

		// Keystream mismatch is a critical verification failure
		c.terminateConnectionWithError("Keystream verification failed", fmt.Errorf("keystream mismatch detected: %d mismatches at offset %d", mismatchCount, firstMismatch))
	}
}

// httpPositionToTlsPosition converts HTTP response position to TLS stream position
func (c *Client) httpPositionToTlsPosition(httpPos int) int {
	for _, mapping := range c.httpToTlsMapping {
		mappingEnd := mapping.HTTPPos + mapping.Length
		if httpPos >= mapping.HTTPPos && httpPos < mappingEnd {
			// Position is within this mapping
			offset := httpPos - mapping.HTTPPos
			return mapping.TLSPos + offset
		}
	}

	panic("No HTTP-to-TLS mapping found for position")
}

// getIdealBlocksForTOPRF extracts the ideal cipher blocks for TOPRF proof generation
func (c *Client) getIdealBlocksForTOPRF(rangeStart, rangeEnd int, packetMetadata []*teeproto.TLSPacketInfo, cipherSuite uint16, serverKey []byte) (*prover.InputParams, error) {

	// Build the original unredacted ciphertext from ciphertextBySeq
	c.responseContentMutex.Lock()
	var seqNums []uint64
	for seqNum := range c.ciphertextBySeq {
		seqNums = append(seqNums, seqNum)
	}
	sort.Slice(seqNums, func(i, j int) bool { return seqNums[i] < seqNums[j] })

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
			boundary := uint32(len(blockCiphertext))
			block.Boundary = &boundary
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
	if len(c.oprfRanges) == 0 || providerParams == nil || providerParams.ParamValues == nil {
		return
	}

	c.logger.Info("Replacing ParamValues with OPRF outputs",
		zap.Int("num_oprf_ranges", len(c.oprfRanges)),
		zap.Int("num_param_values", len(providerParams.ParamValues)))

	// For each OPRF range, check if its data matches any ParamValue
	for _, oprfData := range c.oprfRanges {
		originalData := string(oprfData.Data)

		// Look for matching ParamValue
		for key, value := range providerParams.ParamValues {
			if value == originalData {
				// Convert OPRF output to base64
				oprfBase64 := base64.StdEncoding.EncodeToString(oprfData.FinalOutput)

				// Adjust length to match original string
				adjustedOPRF := adjustBase64Length(oprfBase64, len(originalData))

				// Replace in-place
				providerParams.ParamValues[key] = adjustedOPRF

				c.logger.Info("Replaced ParamValue with OPRF output",
					zap.String("key", key),
					zap.String("original", originalData),
					zap.String("oprf_base64", adjustedOPRF),
					zap.Int("original_length", len(originalData)),
					zap.Int("oprf_length", len(adjustedOPRF)))
			}
		}
	}
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

// mapHashedRangesToBlocks maps hashed redaction ranges to their cryptographic blocks and packets
// This provides the information needed for OPRF implementation in ZK circuits
func (c *Client) mapHashedRangesToBlocks(packetMetadata []*teeproto.TLSPacketInfo, cipherSuite uint16) {
	// Determine block size based on cipher suite
	blockSize := 16 // AES default
	var cipherName string

	// Use centralized cipher suite info
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo == nil {
		return // Unknown cipher suite, can't process
	}

	blockSize = cipherInfo.BlockSize
	if minitls.IsChaCha20(cipherSuite) {
		cipherName = "ChaCha20"
	} else {
		cipherName = "AES"
	}

	// IMPORTANT: The hashed ranges are positions in the HTTP response,
	// but consolidated ciphertext includes TLS framing.
	// Use the stored HTTP-to-TLS mapping from response analysis

	c.logger.Info("Mapping hashed ranges to cryptographic blocks",
		zap.String("cipher", cipherName),
		zap.Int("block_size", blockSize),
		zap.Int("oprf_ranges", len(c.oprfRedactionRanges)))

	// Process each OPRF range
	for rangeStart, rangeLength := range c.oprfRedactionRanges {
		// Convert HTTP position to TLS position using stored mapping
		adjustedStart := c.httpPositionToTlsPosition(rangeStart)
		adjustedEnd := adjustedStart + rangeLength

		c.logger.Info("Processing OPRF range",
			zap.Int("original_start", rangeStart),
			zap.Int("adjusted_start", adjustedStart),
			zap.Int("adjusted_end", adjustedEnd),
			zap.Int("range_length", rangeLength))

		// Find which packets this range spans
		for _, pkt := range packetMetadata {
			pktStart := int(pkt.GetPosition())
			pktEnd := pktStart + int(pkt.GetLength())

			// Check if this packet overlaps with the adjusted hashed range
			if adjustedStart < pktEnd && adjustedEnd > pktStart {
				// Calculate overlap
				overlapStart := max(adjustedStart, pktStart)
				overlapEnd := min(adjustedEnd, pktEnd)
				overlapLength := overlapEnd - overlapStart

				if overlapLength > 0 {
					// Calculate block positions within this packet
					offsetInPacket := overlapStart - pktStart

					// Calculate which blocks are affected
					firstBlockInPacket := offsetInPacket / blockSize
					lastBlockInPacket := (overlapStart + overlapLength - 1 - pktStart) / blockSize

					c.logger.Info("Hashed range maps to packet",
						zap.Uint64("seq_num", pkt.GetSeqNum()),
						zap.Int("packet_start", pktStart),
						zap.Int("packet_end", pktEnd),
						zap.Int("overlap_start", overlapStart),
						zap.Int("overlap_end", overlapEnd),
						zap.Int("overlap_length", overlapLength),
						zap.Int("offset_in_packet", offsetInPacket))

					// Process each affected block within this packet
					for blockNum := firstBlockInPacket; blockNum <= lastBlockInPacket; blockNum++ {
						// Calculate positions within this block
						blockStart := pktStart + (blockNum * blockSize)
						blockEnd := min(blockStart+blockSize, pktEnd)

						// Calculate overlap with hashed range within this block
						blockOverlapStart := max(overlapStart, blockStart)
						blockOverlapEnd := min(overlapEnd, blockEnd)
						blockOverlapLength := blockOverlapEnd - blockOverlapStart

						if blockOverlapLength > 0 {
							offsetInBlock := blockOverlapStart - blockStart

							c.logger.Info("OPRF Block Mapping",
								zap.String("cipher", cipherName),
								zap.Uint64("packet_seq_num", pkt.GetSeqNum()),
								zap.Binary("packet_nonce", pkt.GetNonce()),
								zap.Int("block_number", blockNum),
								zap.Int("block_size", blockSize),
								zap.Int("offset_in_block", offsetInBlock),
								zap.Int("length_in_block", blockOverlapLength),
								zap.Int("global_start", blockOverlapStart),
								zap.Int("global_end", blockOverlapEnd))
						}
					}
				}
			}
		}

		// TODO: Update decryptAndVerifyHashedBlocks for OPRF if needed
		// Currently commented out as it references old Hash field
		// c.decryptAndVerifyHashedBlocks(adjustedStart, adjustedEnd, rangeLength, packetMetadata,
		//	cipherSuite, consolidatedCiphertext, serverKey)
	}
}

// decryptAndVerifyHashedBlocks decrypts individual blocks for an OPRF range to verify OPRF computation
// TODO: Update this function to work with OPRF ranges instead of hashed ranges
func (c *Client) decryptAndVerifyHashedBlocks(rangeStart, rangeEnd int, packetMetadata []*teeproto.TLSPacketInfo, cipherSuite uint16, consolidatedCiphertext, serverKey []byte) {

	// Determine block size based on cipher suite
	blockSize := 16 // AES default
	var cipherName string

	// Use centralized cipher suite info
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo == nil {
		return // Unknown cipher suite, can't process
	}

	blockSize = cipherInfo.BlockSize
	if minitls.IsChaCha20(cipherSuite) {
		cipherName = "ChaCha20"
	} else {
		cipherName = "AES"
	}

	var decryptedBlocks []byte

	// Find which packets this range spans and decrypt relevant blocks
	for _, pkt := range packetMetadata {
		pktStart := int(pkt.GetPosition())
		pktEnd := pktStart + int(pkt.GetLength())

		// Check if this packet overlaps with the hashed range
		if rangeStart < pktEnd && rangeEnd > pktStart {
			// Calculate overlap
			overlapStart := max(rangeStart, pktStart)
			overlapEnd := min(rangeEnd, pktEnd)
			overlapLength := overlapEnd - overlapStart

			if overlapLength > 0 {
				// Calculate block positions within this packet
				offsetInPacket := overlapStart - pktStart

				// Calculate which blocks are affected
				firstBlockInPacket := offsetInPacket / blockSize
				lastBlockInPacket := (overlapStart + overlapLength - 1 - pktStart) / blockSize

				// Process each affected block within this packet
				for blockNum := firstBlockInPacket; blockNum <= lastBlockInPacket; blockNum++ {
					// Calculate positions within this block
					blockStart := pktStart + (blockNum * blockSize)
					// For cipher block extraction, we need the full block size for keystream generation
					// But we're limited by the actual ciphertext available
					blockEnd := min(blockStart+blockSize, len(consolidatedCiphertext))

					// Calculate overlap with hashed range within this block
					blockOverlapStart := max(overlapStart, blockStart)
					blockOverlapEnd := min(overlapEnd, blockEnd)
					blockOverlapLength := blockOverlapEnd - blockOverlapStart

					if blockOverlapLength > 0 {
						// Extract the ciphertext block
						availableCiphertext := consolidatedCiphertext[blockStart:blockEnd]

						// For ChaCha20, pad incomplete blocks to full block size with zeros
						ciphertextBlock := make([]byte, blockSize)
						copy(ciphertextBlock, availableCiphertext)
						// The rest remains zero-padded

						// Generate keystream for this specific block
						nonce := pkt.GetNonce()
						// Calculate counter based on cipher suite
						counter := minitls.GetBlockCounter(cipherSuite, blockNum)

						// Generate keystream for this block using centralized function
						blockKeystream, err := minitls.GenerateSingleBlockKeystream(cipherSuite, serverKey, nonce, counter)
						if err != nil {
							c.logger.Error("Failed to generate block keystream",
								zap.Error(err),
								zap.Int("block_number", blockNum))
							continue
						}

						// Decrypt the block (only process actual ciphertext, not zero padding)
						decryptedBlock := make([]byte, len(availableCiphertext))
						for i := range availableCiphertext {
							decryptedBlock[i] = availableCiphertext[i] ^ blockKeystream[i]
						}

						// Extract the relevant portion of the decrypted block
						offsetInBlock := blockOverlapStart - blockStart
						relevantData := decryptedBlock[offsetInBlock : offsetInBlock+blockOverlapLength]
						decryptedBlocks = append(decryptedBlocks, relevantData...)

						c.logger.Info("OPRF Block Decryption",
							zap.String("cipher", cipherName),
							zap.Uint64("packet_seq_num", pkt.GetSeqNum()),
							zap.Int("block_number", blockNum),
							zap.Uint32("counter", counter),
							zap.Binary("nonce", nonce),
							zap.Int("offset_in_block", offsetInBlock),
							zap.Int("length_in_block", blockOverlapLength),
							zap.Int("block_start_global", blockStart),
							zap.Binary("ciphertext_block", ciphertextBlock[:min(16, len(ciphertextBlock))]),
							zap.Binary("keystream_block", blockKeystream[:min(16, len(blockKeystream))]),
							zap.Binary("decrypted_block", decryptedBlock[:min(16, len(decryptedBlock))]),
							zap.Binary("decrypted_snippet", relevantData[:min(8, len(relevantData))]))
					}
				}
			}
		}
	}

	// Show the complete decrypted data for this hashed range
	if len(decryptedBlocks) > 0 {
		c.logger.Info("OPRF Decrypted Range Verification",
			zap.Int("range_start", rangeStart),
			zap.Int("range_end", rangeEnd),
			zap.Int("total_decrypted_bytes", len(decryptedBlocks)),
			zap.String("decrypted_data", string(decryptedBlocks)))

	}
}
