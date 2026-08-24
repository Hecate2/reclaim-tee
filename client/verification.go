package client

import (
	"fmt"
	"slices"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

func (c *Client) handleAuthenticatedTLS12CBCResponse(sessionID string, response *teeproto.AuthenticatedCBCResponse) error {
	c.cbcMutex.Lock()
	hasBinding := c.cbcBinding != nil
	c.cbcMutex.Unlock()
	if !hasBinding || !minitls.IsTLS12CBCCipherSuite(c.cipherSuite) {
		return fmt.Errorf("authenticated CBC response received outside a TLS 1.2 CBC session")
	}
	if sessionID == "" || sessionID != c.sessionID {
		return fmt.Errorf("authenticated CBC response session mismatch")
	}
	fragments := response.GetFragments()
	if len(fragments) == 0 || len(fragments) > shared.MaxEncryptedFragments {
		return fmt.Errorf("invalid authenticated CBC response fragment count: %d", len(fragments))
	}

	closeNotify := false
	applicationRecords := 0
	plaintextLengths := make([]uint32, 0, len(fragments))
	parsedBySeq := make(map[uint64]*TLSResponseData, len(fragments))
	plaintextBySeq := make(map[uint64][]byte, len(fragments))
	for i, fragment := range fragments {
		if fragment == nil {
			return fmt.Errorf("nil authenticated CBC response fragment at index %d", i)
		}
		if closeNotify {
			return fmt.Errorf("authenticated CBC response fragment follows close_notify")
		}
		wantSeq := uint64(i + 1)
		if fragment.GetSeqNum() != wantSeq {
			return fmt.Errorf("authenticated CBC response sequence is %d, want %d", fragment.GetSeqNum(), wantSeq)
		}
		contentType := byte(fragment.GetRecordType())
		plaintext := fragment.GetPlaintext()
		switch contentType {
		case minitls.RecordTypeApplicationData:
			applicationRecords++
			plaintextLengths = append(plaintextLengths, uint32(len(plaintext)))
			plaintextBySeq[wantSeq] = append([]byte(nil), plaintext...)
			parsedBySeq[wantSeq] = &TLSResponseData{
				ActualContent: append([]byte(nil), plaintext...), ContentType: contentType, OriginalLen: len(plaintext),
			}
		case minitls.RecordTypeAlert:
			if len(plaintext) != 2 {
				return fmt.Errorf("invalid authenticated CBC alert length %d", len(plaintext))
			}
			alertLevel, alertDesc := plaintext[0], plaintext[1]
			if alertLevel == 2 && alertDesc != 0 {
				return fmt.Errorf("TLS alert received: level=%d, desc=%d (%s)", alertLevel, alertDesc, minitls.AlertDescriptionString(alertDesc))
			}
			if alertDesc == 0 {
				closeNotify = true
			}
			plaintextBySeq[wantSeq] = append([]byte(nil), plaintext...)
			parsedBySeq[wantSeq] = &TLSResponseData{
				ActualContent: append([]byte(nil), plaintext...), ContentType: contentType, OriginalLen: len(plaintext),
			}
		default:
			return fmt.Errorf("unsupported authenticated CBC response record type %d", contentType)
		}
	}
	if applicationRecords == 0 {
		return fmt.Errorf("authenticated CBC response contains no application data")
	}
	if response.GetCloseNotify() != closeNotify {
		return fmt.Errorf("authenticated CBC response close_notify flag mismatch")
	}
	c.responseContentMutex.Lock()
	if len(c.parsedResponseBySeq) != 0 || len(c.ciphertextBySeq) != 0 {
		c.responseContentMutex.Unlock()
		return fmt.Errorf("authenticated CBC response state is not empty")
	}
	for seq, plaintext := range plaintextBySeq {
		c.ciphertextBySeq[seq] = plaintext
		c.parsedResponseBySeq[seq] = parsedBySeq[seq]
	}
	c.responseContentMutex.Unlock()
	c.cbcMutex.Lock()
	c.cbcResponsePlaintextLengths = plaintextLengths
	c.cbcResponseCloseNotify = closeNotify
	c.cbcMutex.Unlock()

	if err := c.reconstructHTTPResponseFromDecryptedData(); err != nil {
		return fmt.Errorf("reconstruct authenticated CBC HTTP response: %w", err)
	}
	c.responseReconstructed = true
	c.advanceToPhase(PhaseSendingRedaction)
	if err := c.sendRedactionSpec(); err != nil {
		return fmt.Errorf("send authenticated CBC response redaction spec: %w", err)
	}
	return nil
}

// handleBatchedDecryptionStreams handles batched decryption streams
func (c *Client) handleBatchedDecryptionStreams(msg *shared.Message) {
	var batchedStreams shared.BatchedDecryptionStreamData
	if err := msg.UnmarshalData(&batchedStreams); err != nil {
		c.logger.Error("Failed to unmarshal batched decryption streams", zap.Error(err))
		return
	}

	c.logger.Info("Processing batch of decryption streams", zap.Int("streams_count", len(batchedStreams.DecryptionStreams)))

	if len(batchedStreams.DecryptionStreams) == 0 {
		c.logger.Info("No batched decryption streams to process")
		return
	}

	// Process each decryption stream
	for _, streamData := range batchedStreams.DecryptionStreams {
		ciphertext, exists := c.storeDecryptionStreamAndSnapshotCiphertext(streamData.SeqNum, streamData.DecryptionStream)

		// Decrypt and parse plaintext
		if exists {
			// A buggy/compromised TEE_K could send a short stream; without
			// the length check this panics (OOB) and the Go runtime tears
			// down the whole client process (no recover() in /client).
			if len(streamData.DecryptionStream) < len(ciphertext) {
				c.logger.Error("DecryptionStream shorter than ciphertext — TEE_K bug or compromise",
					zap.Uint64("seq", streamData.SeqNum),
					zap.Int("stream_len", len(streamData.DecryptionStream)),
					zap.Int("ciphertext_len", len(ciphertext)))
				continue
			}
			plaintext := make([]byte, len(ciphertext))
			for j := range ciphertext {
				plaintext[j] = ciphertext[j] ^ streamData.DecryptionStream[j]
			}

			c.responseContentMutex.Lock()

			// Capture original length before stripping (this matches TEE_T's view)
			originalLen := len(plaintext)

			// Parse TLS padding once and store all data
			actualContent, contentType := c.removeTLSPadding(plaintext)

			// Trim ciphertext to match TEE_T's consolidated stream length
			// TLS 1.3: TEE_T strips last byte from encrypted data (originalLen - 1)
			//          Structure is [content][type][padding], last byte is end of padding
			// TLS 1.2: TEE_T keeps full encrypted data (originalLen)
			var teetStreamLen int
			if minitls.IsTLS13CipherSuite(c.cipherSuite) {
				teetStreamLen = originalLen - 1
			} else {
				teetStreamLen = originalLen
			}
			if teetStreamLen < 0 || teetStreamLen > len(ciphertext) {
				c.responseContentMutex.Unlock()
				err := fmt.Errorf("invalid TEE_T stream length %d for ciphertext length %d and cipher %x",
					teetStreamLen, len(ciphertext), c.cipherSuite)
				c.terminateConnectionWithError("Invalid decryption stream data", err)
				return
			}

			// Debug logging (commented out for production)
			// c.logger.Info("📏 Ciphertext Trimming Decision",
			// 	zap.Uint64("seq_num", streamData.SeqNum),
			// 	zap.Int("original_ciphertext_len", len(c.ciphertextBySeq[streamData.SeqNum])),
			// 	zap.Int("original_plaintext_len", originalLen),
			// 	zap.Int("actual_content_len", len(actualContent)),
			// 	zap.Int("teet_stream_len", teetStreamLen),
			// 	zap.Bool("is_tls13", minitls.IsTLS13CipherSuite(c.cipherSuite)),
			// 	zap.Int("bytes_trimmed_from_ciphertext", len(c.ciphertextBySeq[streamData.SeqNum])-teetStreamLen))

			c.ciphertextBySeq[streamData.SeqNum] = c.ciphertextBySeq[streamData.SeqNum][:teetStreamLen]

			c.parsedResponseBySeq[streamData.SeqNum] = &TLSResponseData{
				ActualContent: actualContent,
				ContentType:   contentType,
				OriginalLen:   originalLen, // Store original length to match TEE_T's view
			}

			c.responseContentMutex.Unlock()

		} else {
			c.logger.Error("No ciphertext found for sequence", zap.Uint64("seq_num", streamData.SeqNum))
		}
	}

	// Reconstruct HTTP response if we haven't already
	if !c.responseReconstructed {
		if err := c.reconstructHTTPResponseFromDecryptedData(); err != nil {
			c.logger.Error("Failed to reconstruct HTTP response", zap.Error(err))
			c.terminateConnectionWithError("Failed to reconstruct HTTP response", err)
			return
		}

		// Check if connection was terminated during reconstruction (e.g., non-2XX response)
		if !c.hasTEEConnection("TEE_K") {
			c.logger.Info("Connection terminated during response reconstruction - stopping processing")
			return
		}

		c.logger.Info("HTTP response reconstruction completed, callback executed")
	}

	// continue to redaction
	c.advanceToPhase(PhaseSendingRedaction)

	c.logger.Info("Entering redaction phase - automatically sending redaction specification")
	if err := c.sendRedactionSpec(); err != nil {
		c.logger.Error("Failed to send redaction spec", zap.Error(err))
		c.terminateConnectionWithError("Failed to send redaction spec", err)
		return
	}
}

// storeDecryptionStreamAndSnapshotCiphertext keeps the TLS writer's map
// publication and the decryption reader's lookup in one ownership domain. The
// ciphertext copy is stable after unlock while later records are captured.
func (c *Client) storeDecryptionStreamAndSnapshotCiphertext(seqNum uint64, decryptionStream []byte) ([]byte, bool) {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()
	c.decryptionStreamBySeq[seqNum] = append([]byte(nil), decryptionStream...)
	ciphertext, exists := c.ciphertextBySeq[seqNum]
	return append([]byte(nil), ciphertext...), exists
}

// getContentTypeName returns a human-readable name for TLS content type
func getContentTypeName(contentType uint8) string {
	switch contentType {
	case 20:
		return "ChangeCipherSpec"
	case 21:
		return "Alert"
	case 22:
		return "Handshake"
	case 23:
		return "ApplicationData"
	default:
		return fmt.Sprintf("Unknown(%d)", contentType)
	}
}

// reconstructHTTPResponseFromDecryptedData reconstructs HTTP response from all parsed response data
func (c *Client) reconstructHTTPResponseFromDecryptedData() error {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	if len(c.parsedResponseBySeq) == 0 {
		c.logger.Error("No parsed response data to reconstruct")
		return fmt.Errorf("no parsed response data available")
	}

	// Sort sequence numbers and concatenate response data
	var seqNums []uint64
	for seqNum := range c.parsedResponseBySeq {
		seqNums = append(seqNums, seqNum)
	}
	slices.Sort(seqNums)

	var fullResponse []byte
	for _, seqNum := range seqNums {
		parsed := c.parsedResponseBySeq[seqNum]

		// Log what we're processing
		c.logger.Debug("Processing sequence",
			zap.Uint64("seq_num", seqNum),
			zap.Uint8("content_type", parsed.ContentType),
			zap.Int("content_length", len(parsed.ActualContent)))

		// Only include application data, skip handshake and alerts
		if parsed.ContentType == minitls.RecordTypeApplicationData && len(parsed.ActualContent) > 0 {
			c.logger.Debug("Decrypted ApplicationData content",
				zap.Uint64("seq_num", seqNum),
				zap.Int("length", len(parsed.ActualContent)))

			fullResponse = append(fullResponse, parsed.ActualContent...)
		} else if parsed.ContentType != minitls.RecordTypeApplicationData {
			c.logger.Debug("Skipping non-ApplicationData content",
				zap.Uint64("seq_num", seqNum),
				zap.Uint8("content_type", parsed.ContentType),
				zap.String("content_type_name", getContentTypeName(parsed.ContentType)),
				zap.Int("content_length", len(parsed.ActualContent)))

			// If this is an alert (other than close_notify), it indicates an error
			if parsed.ContentType == minitls.RecordTypeAlert && len(parsed.ActualContent) >= 2 {
				alertLevel := parsed.ActualContent[0]
				alertDesc := parsed.ActualContent[1]

				// close_notify (desc=0) is a graceful shutdown regardless of level —
				// per RFC 8446 §6.1 the level field is implicit in TLS 1.3 and many servers
				// send close_notify with level=fatal. Treat any other fatal alert as an error.
				if alertLevel == 2 && alertDesc != 0 {
					alertName := minitls.AlertDescriptionString(alertDesc)
					err := fmt.Errorf("TLS alert received: level=%d, desc=%d (%s)", alertLevel, alertDesc, alertName)
					c.logger.Error("Server sent TLS alert instead of HTTP response",
						zap.Uint8("alert_level", alertLevel),
						zap.Uint8("alert_desc", alertDesc),
						zap.String("alert_name", alertName))
					return err
				}
			}
		}
	}

	c.logger.Info("Reconstructed HTTP response", zap.Int("total_bytes", len(fullResponse)))

	// Parse HTTP response and set success flags
	if len(fullResponse) == 0 {
		c.logger.Error("Reconstructed response is empty")
		return fmt.Errorf("reconstructed response is empty")
	}

	if len(fullResponse) > 0 {
		responseStr := string(fullResponse)

		// Search for HTTP status line anywhere in the response, not just at the beginning
		// This handles cases where redacted session tickets prefix the response with asterisks
		httpIndex := strings.Index(responseStr, "HTTP/1.1 ")
		if httpIndex == -1 {
			httpIndex = strings.Index(responseStr, "HTTP/1.0 ")
		}
		if httpIndex == -1 {
			httpIndex = strings.Index(responseStr, "HTTP/2 ")
		}

		if httpIndex != -1 {
			c.logger.Info("HTTP response reconstruction successful", zap.Int("offset", httpIndex))

			// Extract the actual HTTP response
			actualHTTPResponse := responseStr[httpIndex:]

			// Set success flags for results reporting
			c.responseProcessingSuccessful = true
			c.reconstructedResponseSize = len(actualHTTPResponse)

			// Parse the HTTP response and store it for later use
			httpResponse := c.parseHTTPResponse([]byte(actualHTTPResponse))
			c.lastResponseData = httpResponse

			// Check for non-2xx status code and fail early
			// This prevents continuing to attestation with error responses (403, 500, etc.)
			if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
				c.terminateConnectionWithError(
					fmt.Sprintf("HTTP response status %d is not a success status", httpResponse.StatusCode),
					fmt.Errorf("received HTTP %d, expected 2xx", httpResponse.StatusCode),
				)
				return fmt.Errorf("non-2xx HTTP status code: %d", httpResponse.StatusCode)
			}

			// Display the raw HTTP response (redaction will be handled at TLS record level)
			c.logger.Info("Raw HTTP response preview",
				zap.Int("total_bytes", len(actualHTTPResponse)))

			// Set success flags
			c.logger.Info("Response processing successful", zap.Int("response_bytes", len(actualHTTPResponse)))
			return nil
		} else {
			c.logger.Error("Reconstructed response doesn't look like HTTP", zap.Int("response_bytes", len(responseStr)))
			return fmt.Errorf("corrupted response: no HTTP status line found")
		}
	} else {
		return fmt.Errorf("response is empty")
	}
}
