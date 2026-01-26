package client

import (
	"fmt"
	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"time"

	"go.uber.org/zap"
)

// handleHandshakeComplete processes handshake completion messages from TEE_K
func (c *Client) handleHandshakeComplete(msg *shared.Message) {
	var completeData shared.HandshakeCompleteData
	if err := msg.UnmarshalData(&completeData); err != nil {
		c.logger.Error("Failed to unmarshal handshake complete data", zap.Error(err))
		return
	}

	if completeData.Success {
		cs := minitls.GetCipherSuiteInfo(completeData.CipherSuite)
		if cs != nil {
			c.logger.Info("Handshake completed successfully",
				zap.String("cipher_suite", cs.Name),
				zap.Bool("tls13", cs.IsTLS13))
		}

		// Store cipher suite for consolidated verification (replaces handshakeDisclosure)
		c.cipherSuite = completeData.CipherSuite

		// Move essential logic from handleHandshakeKeyDisclosure here
		// Mark handshake as complete for response handling
		c.handshakeComplete = true

		c.advanceToPhase(PhaseCollectingResponses)

		if minitls.IsTLS13CipherSuite(completeData.CipherSuite) {
			c.responseSeqNum = 0
		} else {
			c.responseSeqNum = 1
		}

		// Phase 3: Redaction System - Send redacted HTTP request to TEE_K for encryption
		c.sendRedactedRequest()

	} else {
		c.logger.Error("Handshake completed with errors")
		c.terminateConnectionWithError("TLS handshake failed", fmt.Errorf("handshake completed with errors"))
	}
}

// sendRedactedRequest creates and sends the redacted HTTP request to TEE_K
func (c *Client) sendRedactedRequest() {
	// Create redacted HTTP request using the redaction system
	redactedData, streamsData, err := c.createRedactedRequest(nil)
	if err != nil {
		c.logger.Error("Failed to create redacted request", zap.Error(err))
		return
	}

	c.logger.Info("Sending redacted HTTP request to TEE_K")

	// Log what TEE_K will see (the redacted request)
	c.logger.Info("TEE_K will receive redacted request",
		zap.Int("redacted_request_length", len(redactedData.RedactedRequest)),
		zap.Int("redaction_ranges_count", len(redactedData.RedactionRanges)),
		zap.Int("commitments_count", len(redactedData.Commitments)))

	// Show the redacted request content that TEE_K will see
	prettyRedactedRequest := make([]byte, len(redactedData.RedactedRequest))
	copy(prettyRedactedRequest, redactedData.RedactedRequest)

	// Overlay '*' over redacted ranges for display
	for _, r := range redactedData.RedactionRanges {
		end := r.Start + r.Length
		if r.Start >= 0 && end <= len(prettyRedactedRequest) {
			for i := r.Start; i < end; i++ {
				prettyRedactedRequest[i] = '*'
			}
		}
	}

	// Log redaction ranges details
	for i, r := range redactedData.RedactionRanges {
		c.logger.Info("Redaction range for TEE_K",
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("length", r.Length),
			zap.String("type", r.Type))
	}

	// Send redacted request to TEE_K for validation and encryption
	// Convert redaction ranges to protobuf format
	var pbRanges []*teeproto.RequestRedactionRange
	for _, r := range redactedData.RedactionRanges {
		pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
			Start:  int32(r.Start),
			Length: int32(r.Length),
			Type:   r.Type,
		})
	}

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_RedactedRequest{
			RedactedRequest: &teeproto.RedactedRequest{
				RedactedRequest: redactedData.RedactedRequest,
				Commitments:     redactedData.Commitments,
				RedactionRanges: pbRanges,
			},
		},
	}

	if err := c.sendEnvelope(env); err != nil {
		c.logger.Error("Failed to send redacted request to TEE_K", zap.Error(err))
		return
	}

	// Send redaction streams to TEE_T for stream application
	c.logger.Info("Sending redaction streams to TEE_T")

	c.logger.Info("EXPECTING redaction verification result from TEE_T")

	env = &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_RedactionStreams{
			RedactionStreams: &teeproto.RedactionStreams{
				Streams:        streamsData.Streams,
				CommitmentKeys: streamsData.CommitmentKeys,
			},
		},
	}

	if err := c.sendEnvelopeToTEET(env); err != nil {
		c.logger.Error("Failed to send redaction streams to TEE_T", zap.Error(err))
		return
	}
}

// processSingleTLSRecord handles a single, complete TLS record
func (c *Client) processTLSRecordData(record []byte, recordType byte, recordLength int) {
	switch recordType {
	case minitls.RecordTypeApplicationData: // ApplicationData
		// fmt.Printf("[Client] → ApplicationData record, processing with split AEAD\n")
		c.processTLSRecord(record)

	case minitls.RecordTypeChangeCipherSpec: // ChangeCipherSpec
		break

	case minitls.RecordTypeAlert: // Alert
		c.logger.Info("→ Processing alert record with split AEAD")
		c.processTLSRecord(record)

	case minitls.RecordTypeHandshake: // Handshake
		c.logger.Info("→ Handshake record (post-handshake message)")
		if recordLength >= 1 {
			handshakeType := record[5]
			c.logger.Info("Handshake type", zap.Int("type", int(handshakeType)))
		}

	default:
		c.logger.Info("→ Unknown record type", zap.Int("type", int(recordType)))
	}
}

// processTLSRecord processes a single TLS ApplicationData record using split AEAD protocol
func (c *Client) processTLSRecord(record []byte) {
	// Extract encrypted payload and tag (skip 5-byte header)
	encryptedPayload := record[5:]

	// For AES-GCM, tag is last 16 bytes of encrypted payload
	if len(encryptedPayload) < 16 {
		c.logger.Error("CRITICAL: Invalid TLS record - payload too short", zap.Int("payload_length", len(encryptedPayload)))
		// This is a protocol violation - should terminate the session
		c.isClosing = true
		return
	}

	tagSize := 16 // AES-GCM tag size
	tag := encryptedPayload[len(encryptedPayload)-tagSize:]

	// Extract explicit IV and encrypted data for TLS 1.2 AES-GCM
	var encryptedData []byte
	var explicitIV []byte

	// Check if this is TLS 1.2 AES-GCM response (needs explicit IV extraction)
	isTLS12AESGCMResponse := c.cipherSuite != 0 &&
		minitls.IsTLS12AESGCMCipherSuite(c.cipherSuite)

	if isTLS12AESGCMResponse {
		// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
		if len(encryptedPayload) < 8+tagSize {
			c.logger.Error("CRITICAL: Invalid TLS 1.2 AES-GCM record - payload too short for explicit IV", zap.Int("payload_length", len(encryptedPayload)))
			// This is a protocol violation - should terminate the session
			c.isClosing = true
			return
		}

		explicitIV = encryptedPayload[:8]
		encryptedData = encryptedPayload[8 : len(encryptedPayload)-tagSize]

		// fmt.Printf("[Client] TLS 1.2 AES-GCM: extracted explicit IV (%d bytes) and encrypted data (%d bytes), tag (%d bytes)\n",
		// 	len(explicitIV), len(encryptedData), len(tag))
		// fmt.Printf("[Client] Explicit IV: %x\n", explicitIV)
	} else {
		// TLS 1.3 or ChaCha: no explicit IV
		encryptedData = encryptedPayload[:len(encryptedPayload)-tagSize]

		// fmt.Printf("[Client] Processing TLS record: %d bytes encrypted data, %d bytes tag\n",
		// 	len(encryptedData), len(tag))
	}

	if c.isClosing {
		c.logger.Info("System is shutting down")
		return
	}

	teetConnState := c.teetConn != nil
	if !teetConnState {
		c.logger.Info("TEE_T connection closed")
		return
	}

	// Store ciphertext by sequence number for later decryption
	// Use the correct shared mutex to prevent race conditions
	c.responseContentMutex.Lock()
	c.ciphertextBySeq[c.responseSeqNum] = encryptedData
	c.responseContentMutex.Unlock()

	// Prepare data to send to TEE_T for tag verification
	encryptedResponseData := shared.EncryptedResponseData{
		EncryptedData: encryptedData,
		Tag:           tag,
		RecordHeader:  record[:5], // Include actual TLS record header from server
		SeqNum:        c.responseSeqNum,
		ExplicitIV:    explicitIV, // TLS 1.2 AES-GCM explicit IV (nil for TLS 1.3)
	}

	// Always batch responses - never send individually
	c.batchedResponses = append(c.batchedResponses, encryptedResponseData)

	// c.logger.Debug("Added response packet to batch",
	// 	zap.Int("batch_size", len(c.batchedResponses)),
	// 	zap.Uint64("seq_num", c.responseSeqNum))

	// Increment sequence number for next response
	c.responseSeqNum++
}

// Send batched responses when EOF is detected
func (c *Client) sendBatchedResponses() error {

	if len(c.batchedResponses) == 0 {
		c.logger.Info("No response packets to send")
		return nil
	}

	// Create batched message using new data structure
	batchedData := shared.BatchedEncryptedResponseData{
		Responses:  c.batchedResponses,
		SessionID:  c.sessionID,
		TotalCount: len(c.batchedResponses),
	}

	// Send batch to TEE_T using new message type
	// Convert responses to protobuf format
	var pbResponses []*teeproto.EncryptedResponseData
	for _, r := range batchedData.Responses {
		pbResponses = append(pbResponses, &teeproto.EncryptedResponseData{
			EncryptedData: r.EncryptedData,
			Tag:           r.Tag,
			RecordHeader:  r.RecordHeader,
			SeqNum:        r.SeqNum,
			ExplicitIv:    r.ExplicitIV,
		})
	}

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedEncryptedResponses{
			BatchedEncryptedResponses: &teeproto.BatchedEncryptedResponses{
				Responses:  pbResponses,
				SessionId:  batchedData.SessionID,
				TotalCount: int32(batchedData.TotalCount),
			},
		},
	}

	if err := c.sendEnvelopeToTEET(env); err != nil {
		return fmt.Errorf("failed to send batched responses to TEE_T: %v", err)
	}

	c.logger.Info("Successfully sent batch to TEE_T", zap.Int("packets", len(c.batchedResponses)))

	c.expectedRedactedStreams = len(c.batchedResponses)
	c.logger.Info("Expecting redacted streams based on batch size", zap.Int("expected_streams", c.expectedRedactedStreams))

	c.advanceToPhase(PhaseReceivingDecryption)

	// Clear the batch after successful send
	c.batchedResponses = make([]shared.EncryptedResponseData, 0)
	return nil
}

// removeTLSPadding removes TLS 1.3 padding from decrypted content (TLS 1.2 has no padding)
func (c *Client) removeTLSPadding(data []byte) ([]byte, byte) {
	if len(data) == 0 {
		return nil, 0
	}

	// Check TLS version from cipher suite in handshake disclosure
	isTLS12 := c.cipherSuite != 0 && minitls.IsTLS12CipherSuite(c.cipherSuite)

	if isTLS12 {
		// TLS 1.2: No inner content type or padding, content type comes from record header
		// All decrypted data is actual content, content type is always ApplicationData (0x17)
		return data, 0x17
	} else {
		// TLS 1.3: Has inner content type byte + zero padding
		// Find the last non-zero byte which indicates the content type
		lastNonZero := len(data) - 1
		zeroPaddingCount := 0
		for lastNonZero >= 0 && data[lastNonZero] == 0 {
			lastNonZero--
			zeroPaddingCount++
		}

		if lastNonZero < 0 {
			// All zeros, likely a padding-only record
			c.logger.Warn("TLS 1.3 padding removed - all zeros",
				zap.Int("original_length", len(data)),
				zap.Int("zero_padding_bytes", zeroPaddingCount))
			return nil, 0
		}

		// The byte at lastNonZero is the content type
		contentType := data[lastNonZero]
		// The data before that byte is the actual content
		actualContent := data[:lastNonZero]

		// Calculate bytes stripped
		// contentTypeByte := 1
		// totalBytesStripped := contentTypeByte + zeroPaddingCount

		// Debug logging (commented out for production)
		// c.logger.Info("🔍 TLS 1.3 Padding Stripped",
		// 	zap.Int("original_length", len(data)),
		// 	zap.Int("stripped_length", len(actualContent)),
		// 	zap.Uint8("content_type_byte", contentType),
		// 	zap.Int("zero_padding_bytes", zeroPaddingCount),
		// 	zap.Int("total_bytes_stripped", totalBytesStripped))

		return actualContent, contentType
	}
}

// State for processing TLS records directly from TCP data
type tlsRecordState struct {
	buffer       []byte
	expectedSize int
	recordType   byte
}

var recordProcessingState = &tlsRecordState{
	buffer:       make([]byte, 0),
	expectedSize: 0,
}

// processTLSRecordFromData processes TLS records directly from raw TCP data
func (c *Client) processTLSRecordFromData(data []byte) {
	// Add new data to our processing buffer
	recordProcessingState.buffer = append(recordProcessingState.buffer, data...)

	// Process all complete records in the buffer
	for len(recordProcessingState.buffer) >= 5 {
		// Check if we have a complete TLS record header
		if recordProcessingState.expectedSize == 0 {
			// Parse TLS record header: type (1) + version (2) + length (2)
			recordProcessingState.recordType = recordProcessingState.buffer[0]
			recordLength := int(recordProcessingState.buffer[3])<<8 | int(recordProcessingState.buffer[4])
			recordProcessingState.expectedSize = 5 + recordLength
		}

		// Check if we have a complete record
		if len(recordProcessingState.buffer) >= recordProcessingState.expectedSize {
			// Extract the complete record
			record := make([]byte, recordProcessingState.expectedSize)
			copy(record, recordProcessingState.buffer[:recordProcessingState.expectedSize])

			// Remove the processed record from buffer
			recordProcessingState.buffer = recordProcessingState.buffer[recordProcessingState.expectedSize:]
			recordProcessingState.expectedSize = 0

			// Process the complete record
			recordType := record[0]
			recordLength := int(record[3])<<8 | int(record[4])
			c.processTLSRecordData(record, recordType, recordLength)
		} else {
			// Not enough data for complete record, wait for more
			break
		}
	}
}
