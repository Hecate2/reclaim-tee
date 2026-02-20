package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// verifyTagForResponse verifies the authentication tag for a response
func (t *TEET) verifyTagForResponse(sessionID string, encryptedResp *shared.EncryptedResponseData, tagSecretsData *struct {
	TagSecrets []byte `json:"tag_secrets"`
	SeqNum     uint64 `json:"seq_num"`
}) shared.ResponseTagVerificationData {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return shared.ResponseTagVerificationData{Success: false, SeqNum: encryptedResp.SeqNum, Message: fmt.Sprintf("Failed to get TEE_T session state: %v", err)}
	}
	var additionalData []byte
	cipherSuite := teetState.CipherSuite
	if cipherSuite == 0 {
		return shared.ResponseTagVerificationData{Success: false, SeqNum: encryptedResp.SeqNum, Message: "CipherSuite not available in session state"}
	}
	// Check if TLS 1.3 cipher suite
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo != nil && cipherInfo.IsTLS13 {
		tagSize := 16
		ciphertextLength := len(encryptedResp.EncryptedData) + tagSize
		var recordType byte = 0x17
		if len(encryptedResp.RecordHeader) >= 1 {
			recordType = encryptedResp.RecordHeader[0]
		}
		additionalData = []byte{recordType, 0x03, 0x03, byte(ciphertextLength >> 8), byte(ciphertextLength & 0xFF)}
		t.logger.Debug("Constructed TLS 1.3 AAD for tag verification",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", tagSecretsData.SeqNum),
			zap.Uint8("record_type", recordType),
			zap.Int("ciphertext_tag_len", ciphertextLength))
	} else {
		// TLS 1.2 AEAD needs sequence number and plaintext length
		plaintextLength := len(encryptedResp.EncryptedData)
		additionalData = minitls.CreateAdditionalDataTLS12(encryptedResp.SeqNum, plaintextLength)
		// Override record type if provided in record header
		if len(encryptedResp.RecordHeader) >= 1 {
			additionalData[8] = encryptedResp.RecordHeader[0]
		}
		t.logger.Debug("Constructed TLS 1.2 AAD for tag verification",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", encryptedResp.SeqNum),
			zap.Uint8("record_type", additionalData[8]),
			zap.Int("plaintext_len", len(encryptedResp.EncryptedData)))
	}
	computedTag, err := minitls.ComputeTagFromSecrets(
		encryptedResp.EncryptedData,
		tagSecretsData.TagSecrets,
		cipherSuite,
		additionalData,
	)
	var success bool
	if err != nil {
		t.logger.Error("Failed to compute authentication tag",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", encryptedResp.SeqNum),
			zap.Error(err))
		success = false
	} else {
		success = subtle.ConstantTimeCompare(computedTag, encryptedResp.Tag) == 1
		if success {
			t.logger.Info("Tag verification succeeded",
				zap.String("session_id", sessionID),
				zap.Uint64("seq_num", encryptedResp.SeqNum))
		} else {
			t.logger.Error("Tag verification failed - computed tag does not match",
				zap.String("session_id", sessionID),
				zap.Uint64("seq_num", encryptedResp.SeqNum),
				zap.Binary("computed_tag", computedTag),
				zap.Binary("expected_tag", encryptedResp.Tag))
		}
	}

	// Consolidate response ciphertext immediately after successful verification
	if success {
		if cipherInfo != nil && cipherInfo.IsTLS13 {
			teetState.AppendResponseCiphertext(encryptedResp.EncryptedData[:len(encryptedResp.EncryptedData)-1]) // strip content type byte
		} else {
			teetState.AppendResponseCiphertext(encryptedResp.EncryptedData)
		}

		t.logger.Debug("Appended response ciphertext to consolidated stream",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", tagSecretsData.SeqNum),
			zap.Int("response_ciphertext_bytes", len(encryptedResp.EncryptedData)),
			zap.Int("total_consolidated_response_bytes", len(teetState.ConsolidatedResponseCiphertext)))
	}

	verificationData := shared.ResponseTagVerificationData{Success: success, SeqNum: tagSecretsData.SeqNum}
	if !success {
		verificationData.Message = "Authentication tag verification failed"
	}
	return verificationData
}

// verifyCommitmentsIfReady verifies commitments if both streams and expected commitments are available
func (t *TEET) verifyCommitmentsIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %v", err)
	}
	if session.RedactionState == nil {
		return fmt.Errorf("critical security failure: no redaction state available for commitment verification in session %s", sessionID)
	}
	hasStreams := len(session.RedactionState.RedactionStreams) > 0 && len(session.RedactionState.CommitmentKeys) > 0
	hasCommitments := len(session.RedactionState.ExpectedCommitments) > 0
	if !hasStreams {
		t.logger.Info("Redaction streams not yet available for commitment verification, deferring",
			zap.String("session_id", sessionID))
		return nil
	}
	if !hasCommitments {
		t.logger.Info("Expected commitments not yet available for verification, deferring",
			zap.String("session_id", sessionID))
		return nil
	}
	t.logger.Info("Stream collections and expected commitments both available - verifying commitments",
		zap.String("session_id", sessionID),
		zap.Int("streams_count", len(session.RedactionState.RedactionStreams)),
		zap.Int("expected_commitments_count", len(session.RedactionState.ExpectedCommitments)))
	if err := t.verifyCommitments(session.RedactionState.RedactionStreams, session.RedactionState.CommitmentKeys, session.RedactionState.ExpectedCommitments); err != nil {
		return fmt.Errorf("commitment verification failed: %v", err)
	}
	t.logger.Info("Commitment verification completed successfully", zap.String("session_id", sessionID))
	return nil
}

// verifyCommitments verifies HMAC commitments for redaction streams
func (t *TEET) verifyCommitments(streams, keys, expectedCommitments [][]byte) error {
	if len(streams) != len(keys) {
		return fmt.Errorf("streams and keys length mismatch: %d vs %d", len(streams), len(keys))
	}
	if len(expectedCommitments) != len(streams) {
		return fmt.Errorf("expected commitments length mismatch: expected %d, got %d", len(streams), len(expectedCommitments))
	}
	for i := range streams {
		h := hmac.New(sha256.New, keys[i])
		h.Write(streams[i])
		computedCommitment := h.Sum(nil)
		t.logger.Debug("Computed stream commitment",
			zap.Int("stream_index", i),
			zap.Binary("computed_commitment", computedCommitment),
			zap.Binary("expected_commitment", expectedCommitments[i]))
		if len(computedCommitment) != len(expectedCommitments[i]) {
			return fmt.Errorf("commitment %d length mismatch: computed %d bytes, expected %d bytes",
				i, len(computedCommitment), len(expectedCommitments[i]))
		}
		if !hmac.Equal(computedCommitment, expectedCommitments[i]) {
			return fmt.Errorf("commitment %d verification failed: HMAC(stream_%d, key_%d) does not match expected commitment from TEE_K", i, i, i)
		}
		t.logger.Info("Stream commitment verified successfully",
			zap.Int("stream_index", i),
			zap.Int("commitment_length", len(computedCommitment)))
	}
	t.logger.Info("All redaction commitments verified successfully",
		zap.Int("total_commitments", len(streams)))
	return nil
}

// reconstructFullRequestWithStreams reconstructs the original request data using redaction streams
func (t *TEET) reconstructFullRequestWithStreams(encryptedRedacted []byte, ranges []shared.RequestRedactionRange, redactionStreams [][]byte) ([]byte, error) {
	reconstructed := make([]byte, len(encryptedRedacted))
	copy(reconstructed, encryptedRedacted)
	t.logger.Debug("Starting redaction stream application with provided streams",
		zap.Binary("redacted_preview", encryptedRedacted[:min(64, len(encryptedRedacted))]),
		zap.Int("redaction_ranges", len(ranges)),
		zap.Int("available_streams", len(redactionStreams)))
	for i, r := range ranges {
		if i >= len(redactionStreams) {
			continue
		}
		stream := redactionStreams[i]
		t.logger.Debug("Applying redaction stream to range",
			zap.Int("stream_index", i),
			zap.Int("range_start", r.Start),
			zap.Int("range_end", r.Start+r.Length),
			zap.Binary("stream_preview", stream[:min(16, len(stream))]))
		for j := 0; j < r.Length && r.Start+j < len(reconstructed) && j < len(stream); j++ {
			reconstructed[r.Start+j] ^= stream[j]
		}
	}
	t.logger.Debug("Completed redaction stream application",
		zap.Binary("reconstructed_preview", reconstructed[:min(64, len(reconstructed))]),
		zap.Int("total_bytes", len(reconstructed)))
	return reconstructed, nil
}
