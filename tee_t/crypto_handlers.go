package main

import (
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

// tagOK recomputes the TLS 1.3 AEAD tag for a record under a candidate tag
// secret and reports whether it matches. AAD is intrinsic to the record.
func (t *TEET) tagOK(cipherSuite uint16, resp *shared.EncryptedResponseData, secret []byte) bool {
	if secret == nil {
		return false
	}
	var recordType byte = 0x17
	if len(resp.RecordHeader) >= 1 {
		recordType = resp.RecordHeader[0]
	}
	ctLen := len(resp.EncryptedData) + 16
	aad := []byte{recordType, 0x03, 0x03, byte(ctLen >> 8), byte(ctLen & 0xFF)}
	computed, err := minitls.ComputeTagFromSecrets(resp.EncryptedData, secret, cipherSuite, aad)
	return err == nil && subtle.ConstantTimeCompare(computed, resp.Tag) == 1
}

// classifyTagFailure buckets a verification failure without changing the batch
// result. It scans the contiguous tail from the first failure (the verify loop
// breaks, so only the first is otherwise seen), then decides: only one record =
// ISOLATED; a tail where the first record authenticates under a shifted nonce
// (same key) = SEQ_DRIFT of k; a tail where no neighbouring nonce authenticates
// = KEY_CHANGE (a mid-stream rekey; a ~6-byte predecessor points to it). TLS 1.3.
func (t *TEET) classifyTagFailure(sessionID string, failed *shared.EncryptedResponseData, tagSecretBySeq map[uint64][]byte, pendingBySeq map[uint64]*shared.EncryptedResponseData) {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return
	}
	cipherSuite := teetState.CipherSuite
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
	if cipherInfo == nil || !cipherInfo.IsTLS13 {
		t.logger.WithSession(sessionID).Warn("resp-diag: skipped (TLS 1.2)")
		return
	}
	n := failed.SeqNum

	tailFailed, tailTotal, lastSeq := 0, 0, n
	for seq := n; ; seq++ {
		resp := pendingBySeq[seq]
		if resp == nil {
			break
		}
		tailTotal++
		lastSeq = seq
		if !t.tagOK(cipherSuite, resp, tagSecretBySeq[seq]) {
			tailFailed++
		}
	}

	drift, driftFound := 0, false
	for k := -8; k <= 8 && !driftFound; k++ {
		if k == 0 {
			continue
		}
		var candSeq uint64
		if k < 0 {
			if n < uint64(-k) {
				continue
			}
			candSeq = n - uint64(-k)
		} else {
			candSeq = n + uint64(k)
		}
		if t.tagOK(cipherSuite, failed, tagSecretBySeq[candSeq]) {
			drift, driftFound = k, true
		}
	}

	prev := []int{}
	for _, d := range []uint64{1, 2} {
		if n >= d {
			if r := pendingBySeq[n-d]; r != nil {
				prev = append(prev, len(r.EncryptedData))
			}
		}
	}

	verdict := "ISOLATED"
	if tailFailed > 1 && driftFound {
		verdict = "SEQ_DRIFT"
	} else if tailFailed > 1 {
		verdict = "KEY_CHANGE"
	}
	t.logger.WithSession(sessionID).Error("resp-diag",
		zap.String("verdict", verdict),
		zap.Uint64("first_seq", n),
		zap.Uint64("last_seq", lastSeq),
		zap.Int("tail_failed", tailFailed),
		zap.Int("tail_total", tailTotal),
		zap.Bool("drift_found", driftFound),
		zap.Int("drift", drift),
		zap.Int("inner_len", len(failed.EncryptedData)),
		zap.Ints("prev_inner", prev))
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
