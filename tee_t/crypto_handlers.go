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
			t.logger.WithSession(sessionID).Debug("Tag verification succeeded")
		} else {
			var recHdr0 byte
			if len(encryptedResp.RecordHeader) >= 1 {
				recHdr0 = encryptedResp.RecordHeader[0]
			}
			t.logger.WithSession(sessionID).Error("Tag verification failed",
				zap.Uint64("client_seq", encryptedResp.SeqNum),
				zap.Uint64("tag_seq", tagSecretsData.SeqNum),
				zap.Int("inner_len", len(encryptedResp.EncryptedData)),
				zap.Int("tag_len", len(encryptedResp.Tag)),
				zap.Uint8("rec_hdr0", recHdr0),
				zap.Bool("tls13", cipherInfo != nil && cipherInfo.IsTLS13))
		}
	}

	// Consolidate response ciphertext immediately after successful verification
	if success {
		if cipherInfo != nil && cipherInfo.IsTLS13 {
			if len(encryptedResp.EncryptedData) < 1 {
				return shared.ResponseTagVerificationData{Success: false, SeqNum: tagSecretsData.SeqNum, Message: "TLS 1.3 EncryptedData empty"}
			}
			teetState.AppendResponseCiphertext(encryptedResp.EncryptedData[:len(encryptedResp.EncryptedData)-1]) // strip content type byte
		} else {
			teetState.AppendResponseCiphertext(encryptedResp.EncryptedData)
		}

		t.logger.WithSession(sessionID).Debug("Appended response ciphertext")
	}

	verificationData := shared.ResponseTagVerificationData{Success: success, SeqNum: tagSecretsData.SeqNum}
	if !success {
		verificationData.Message = "Authentication tag verification failed"
	}
	return verificationData
}

// classifyTagFailure re-verifies a failed record's ciphertext against the tag
// secrets of neighbouring seqs. Authenticating at seq+k means a sequence/count
// drift of k (a dropped/merged record upstream); no match means the ciphertext
// bytes are corrupt. TLS 1.3 only (its AAD is nonce-independent). Diagnostic
// only: it never marks the record valid, so the caller still fails the batch.
func (t *TEET) classifyTagFailure(sessionID string, failed *shared.EncryptedResponseData, tagSecretBySeq map[uint64][]byte) {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return
	}
	cipherSuite := teetState.CipherSuite
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo == nil || !cipherInfo.IsTLS13 {
		t.logger.WithSession(sessionID).Warn("tag-fail classifier: skipped (TLS 1.2)")
		return
	}
	var recordType byte = 0x17
	if len(failed.RecordHeader) >= 1 {
		recordType = failed.RecordHeader[0]
	}
	ctLen := len(failed.EncryptedData) + 16
	aad := []byte{recordType, 0x03, 0x03, byte(ctLen >> 8), byte(ctLen & 0xFF)}
	for k := -8; k <= 8; k++ {
		if k == 0 {
			continue
		}
		var candSeq uint64
		if k < 0 {
			if failed.SeqNum < uint64(-k) {
				continue
			}
			candSeq = failed.SeqNum - uint64(-k)
		} else {
			candSeq = failed.SeqNum + uint64(k)
		}
		cand := tagSecretBySeq[candSeq]
		if cand == nil {
			continue
		}
		computed, cerr := minitls.ComputeTagFromSecrets(failed.EncryptedData, cand, cipherSuite, aad)
		if cerr == nil && subtle.ConstantTimeCompare(computed, failed.Tag) == 1 {
			t.logger.WithSession(sessionID).Error("tag-fail classifier: SEQUENCE/COUNT DRIFT",
				zap.Uint64("failed_seq", failed.SeqNum),
				zap.Int("drift", k),
				zap.Int("inner_len", len(failed.EncryptedData)))
			return
		}
	}
	t.logger.WithSession(sessionID).Error("tag-fail classifier: CONTENT CORRUPTION (no neighbouring nonce authenticates)",
		zap.Uint64("failed_seq", failed.SeqNum),
		zap.Int("inner_len", len(failed.EncryptedData)))
}

// verifyCommitmentsIfReady verifies commitments if both streams and expected commitments are available
// Note: Streams arrive from client, commitments arrive from TEE_K - they may arrive in any order.
// Deferral is correct when waiting for the other piece. TEE_K enforces commitment presence before forwarding.
func (t *TEET) verifyCommitmentsIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %v", err)
	}
	if session.RedactionState == nil {
		return fmt.Errorf("critical security failure: no redaction state available for commitment verification in session %s", sessionID)
	}
	// Both writers (client streams and TEE_K commitments) may still race;
	// snapshot under lock so the two len() checks see a consistent state.
	streams, keys, expected := session.RedactionState.SnapshotForCommitmentCheck()
	hasStreams := len(streams) > 0 && len(keys) > 0
	hasCommitments := len(expected) > 0

	// If no streams yet, defer verification until they arrive from client
	if !hasStreams {
		t.logger.WithSession(sessionID).Debug("Deferring - streams not available")
		return nil
	}

	// If no commitments yet, defer verification until they arrive from TEE_K
	// Note: TEE_K validates that commitments are present before forwarding, so if streams
	// exist but commitments never arrive, something is wrong with message ordering
	if !hasCommitments {
		t.logger.WithSession(sessionID).Debug("Deferring commitment verification")
		return nil
	}

	// SECURITY: Once both are present, commitment count must match stream count
	if len(expected) != len(streams) {
		return fmt.Errorf("SECURITY ERROR: commitment count (%d) does not match stream count (%d)",
			len(expected), len(streams))
	}
	t.logger.WithSession(sessionID).Debug("Verifying commitments")
	if err := t.verifyCommitments(streams, keys, expected); err != nil {
		return fmt.Errorf("commitment verification failed: %v", err)
	}
	t.logger.WithSession(sessionID).Debug("Commitment verification completed")
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
		t.logger.Debug("Stream commitment verified", zap.Int("index", i))
	}
	t.logger.Debug("All redaction commitments verified")
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
		// TEE_K validates ranges via validateRedactionPositions, but TEE_T
		// must not trust that — a buggy/compromised K with r.Start<0 or
		// r.Length<0 would panic (negative index, OOB) and kill the pair.
		if r.Start < 0 || r.Length < 0 || r.Start > len(reconstructed) || r.Start+r.Length > len(reconstructed) {
			return nil, fmt.Errorf("invalid redaction range %d: start=%d length=%d (data length %d)",
				i, r.Start, r.Length, len(reconstructed))
		}
		stream := redactionStreams[i]
		t.logger.Debug("Applying redaction stream to range",
			zap.Int("stream_index", i),
			zap.Int("range_start", r.Start),
			zap.Int("range_end", r.Start+r.Length),
			zap.Binary("stream_preview", stream[:min(16, len(stream))]))
		for j := 0; j < r.Length && j < len(stream); j++ {
			reconstructed[r.Start+j] ^= stream[j]
		}
	}
	t.logger.Debug("Completed redaction stream application",
		zap.Binary("reconstructed_preview", reconstructed[:min(64, len(reconstructed))]),
		zap.Int("total_bytes", len(reconstructed)))
	return reconstructed, nil
}
