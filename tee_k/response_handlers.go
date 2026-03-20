package main

import (
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// handleBatchedResponseLengths handles batched response lengths from TEE_T
func (t *TEEK) handleBatchedResponseLengths(sessionID string, msg *shared.Message) error {
	var batchedLengths shared.BatchedResponseLengthData
	if err := msg.UnmarshalData(&batchedLengths); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched response lengths")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Received batched response lengths",
		zap.Int("total_count", batchedLengths.TotalCount))

	// Get session to store response lengths
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session for batched lengths")
		return err
	}

	// Initialize ResponseState if needed
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
		}
	}

	// Process each length in the batch and generate tag secrets
	var tagSecrets []struct {
		TagSecrets []byte `json:"tag_secrets"`
		SeqNum     uint64 `json:"seq_num"`
	}

	session.ResponseState.ResponsesMutex.Lock()
	for _, lengthData := range batchedLengths.Lengths {
		// Store response lengths in session state for later decryption stream generation
		session.ResponseState.ResponseLengthBySeq[lengthData.SeqNum] = lengthData.Length

		// Store explicit IV for TLS 1.2 AES-GCM decryption stream generation
		if lengthData.ExplicitIV != nil {
			session.ResponseState.ExplicitIVBySeq[lengthData.SeqNum] = lengthData.ExplicitIV
		}

		// Generate tag secrets for this response
		tagSecretsBytes, nonce, err := t.generateResponseTagSecrets(
			sessionID,
			lengthData.Length,
			lengthData.SeqNum,
			lengthData.RecordHeader,
			lengthData.ExplicitIV,
		)
		if err != nil {
			session.ResponseState.ResponsesMutex.Unlock()
			t.terminateSessionWithError(sessionID, shared.ReasonCryptoTagComputationFailed, err, "Failed to generate tag secrets for sequence in batch")
			return err
		}

		// Store the nonce for later use in transcript
		if session.ResponseState.NonceBySeq == nil {
			session.ResponseState.NonceBySeq = make(map[uint64][]byte)
		}
		session.ResponseState.NonceBySeq[lengthData.SeqNum] = nonce

		tagSecrets = append(tagSecrets, struct {
			TagSecrets []byte `json:"tag_secrets"`
			SeqNum     uint64 `json:"seq_num"`
		}{
			TagSecrets: tagSecretsBytes,
			SeqNum:     lengthData.SeqNum,
		})
	}
	session.ResponseState.ResponsesMutex.Unlock()

	t.logger.WithSession(sessionID).Debug("Generated batched tag secrets",
		zap.Int("count", len(tagSecrets)))

	// Send all tag secrets as a batch to TEE_T
	// Convert tag secrets to protobuf format
	var pbTagSecrets []*teeproto.BatchedTagSecrets_TagSecret
	for _, ts := range tagSecrets {
		pbTagSecrets = append(pbTagSecrets, &teeproto.BatchedTagSecrets_TagSecret{
			TagSecrets: ts.TagSecrets,
			SeqNum:     ts.SeqNum,
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedTagSecrets{
			BatchedTagSecrets: &teeproto.BatchedTagSecrets{
				TagSecrets: pbTagSecrets,
				SessionId:  sessionID,
				TotalCount: int32(len(tagSecrets)),
			},
		},
	}

	if err := t.sendEnvelopeToTEET(sessionID, env); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send batched tag secrets to TEE_T")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Successfully sent batched tag secrets to TEE_T",
		zap.Int("count", len(tagSecrets)))
	return nil
}

// handleBatchedTagVerifications handles batched tag verifications from TEE_T
func (t *TEEK) handleBatchedTagVerifications(sessionID string, msg *shared.Message) error {
	var batchedVerification shared.BatchedTagVerificationData
	if err := msg.UnmarshalData(&batchedVerification); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched tag verification")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Received batched tag verification",
		zap.Int("total_count", batchedVerification.TotalCount),
		zap.Bool("all_successful", batchedVerification.AllSuccessful))

	// Generate decryption streams based on verification results
	var decryptionStreams []shared.ResponseDecryptionStreamData

	if batchedVerification.AllSuccessful {
		// All verifications passed - generate streams for all responses
		responseState, err := t.getSessionResponseState(sessionID)
		if err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get response state")
			return err
		}

		// Generate decryption streams for all response sequences
		for seqNum, responseLength := range responseState.ResponseLengthBySeq {
			// Generate decryption stream using session-aware logic
			decryptionStream, err := t.generateSingleDecryptionStream(sessionID, responseLength, seqNum)
			if err != nil {
				t.terminateSessionWithError(sessionID, shared.ReasonCryptoStreamGenerationFailed, err, "Failed to generate decryption stream for sequence")
				return err
			}

			// Create decryption stream data
			streamData := shared.ResponseDecryptionStreamData{
				DecryptionStream: decryptionStream,
				SeqNum:           seqNum,
				Length:           responseLength,
			}

			decryptionStreams = append(decryptionStreams, streamData)
		}
	} else {
		err := fmt.Errorf("tag verification failed")
		t.terminateSessionWithError(sessionID, shared.ReasonCryptoTagVerificationFailed, err, "Tag verification failed")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Generated batched decryption streams",
		zap.Int("count", len(decryptionStreams)))

	// Send all decryption streams as a batch to client
	streams := make([]*teeproto.ResponseDecryptionStreamData, 0, len(decryptionStreams))
	for _, s := range decryptionStreams {
		streams = append(streams, &teeproto.ResponseDecryptionStreamData{DecryptionStream: s.DecryptionStream, SeqNum: s.SeqNum, Length: int32(s.Length)})
	}
	envStreams := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedDecryptionStreams{BatchedDecryptionStreams: &teeproto.BatchedDecryptionStreams{DecryptionStreams: streams, SessionId: sessionID, TotalCount: int32(len(streams))}},
	}

	if err := t.sessionManager.RouteToClient(sessionID, envStreams); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send batched decryption streams to client")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Successfully sent batched decryption streams to client",
		zap.Int("count", len(decryptionStreams)))
	return nil
}

// checkAndSendSignatureIfReady checks if all processing is complete and sends signature if ready
func (t *TEEK) checkAndSendSignatureIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Get TEE_K state for OPRF check
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("TEE_K session state not found: %v", err)
	}

	// Check if all required processing is complete and atomically set signature flag
	session.StreamsMutex.Lock()

	session.TranscriptMutex.Lock()
	transcriptReady := len(session.TranscriptData) > 0
	session.TranscriptMutex.Unlock()

	redactionComplete := session.RedactionProcessingComplete
	hasRedactedStreams := len(session.RedactedStreams) > 0
	signatureAlreadySent := session.SignatureSent

	// Check if OPRF is ready (complete, not needed, or failed)
	oprfReady := isOPRFReady(teekState.OPRFState)

	// All processing is complete when:
	// 1. We have transcript data (from finished message)
	// 2. Redaction processing is complete
	// 3. We have redacted streams
	// 4. We haven't already sent a signature
	// 5. OPRF processing is complete (or not needed)
	allProcessingComplete := transcriptReady && redactionComplete && hasRedactedStreams && !signatureAlreadySent && oprfReady

	if allProcessingComplete {
		t.logger.WithSession(sessionID).Debug("All processing complete, generating and sending signature")
		// Mark signature as sent to prevent duplicates
		session.SignatureSent = true
		// Release lock before calling generateComprehensiveSignatureAndSendTranscript
		session.StreamsMutex.Unlock()
		return t.generateComprehensiveSignatureAndSendTranscript(sessionID)
	} else {
		t.logger.WithSession(sessionID).Debug("Not ready to send signature yet",
			zap.Bool("transcript_ready", transcriptReady),
			zap.Bool("redaction_complete", redactionComplete),
			zap.Bool("has_redacted_streams", hasRedactedStreams),
			zap.Bool("signature_already_sent", signatureAlreadySent),
			zap.Bool("oprf_ready", oprfReady))
		// Don't set SignatureSent = true if we're not actually sending a signature
		session.StreamsMutex.Unlock()
	}

	return nil
}
