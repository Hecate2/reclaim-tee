package main

import (
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// handleBatchedResponseLengths handles batched response lengths from TEE_T
func (t *TEEK) handleBatchedResponseLengths(identity *teekSessionIdentity, msg *shared.Message) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID
	var batchedLengths shared.BatchedResponseLengthData
	if err := msg.UnmarshalData(&batchedLengths); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched response lengths")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Received batched response lengths",
		zap.Int("total_count", batchedLengths.TotalCount))

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

	// TLS 1.3: TEE_K owns the server-app-seq, ignoring the client's seq for
	// nonce purposes. See [[tcpdata-ack-protocol-2026-06-10]] / Option 3.
	// TLS 1.2: client's seq is correct (no NSTs to throw off alignment).
	tlsState, tlsErr := t.sessionManager.stateForSession(session)
	if tlsErr != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonInternalError, tlsErr, "Failed to get TLS state for tag-secret generation")
		return tlsErr
	}
	useTEEKSeq := minitls.IsTLS13CipherSuite(tlsState.CipherSuite)

	session.ResponseState.ResponsesMutex.Lock()
	for _, lengthData := range batchedLengths.Lengths {
		// Store response lengths in session state for later decryption stream generation
		session.ResponseState.ResponseLengthBySeq[lengthData.SeqNum] = lengthData.Length

		// Store explicit IV for TLS 1.2 AES-GCM decryption stream generation
		if lengthData.ExplicitIV != nil {
			session.ResponseState.ExplicitIVBySeq[lengthData.SeqNum] = lengthData.ExplicitIV
		}

		nonceSeq := lengthData.SeqNum
		if useTEEKSeq {
			nonceSeq = tlsState.NextResponseTagSeq()
		}

		// nonce_seq is the actual server-app-seq used; client_seq is what the
		// tag secret is labelled with. Their gap = the NST offset (drift if != ).
		t.logger.WithSession(sessionID).Debug("Response tag-secret nonce",
			zap.Uint64("client_seq", lengthData.SeqNum),
			zap.Uint64("nonce_seq", nonceSeq))

		// Generate tag secrets for this response
		tagSecretsBytes, nonce, err := t.generateResponseTagSecrets(
			tlsState,
			lengthData.Length,
			nonceSeq,
			lengthData.RecordHeader,
			lengthData.ExplicitIV,
		)
		if err != nil {
			session.ResponseState.ResponsesMutex.Unlock()
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, "Failed to generate tag secrets for sequence in batch")
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

	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := t.connManager.SendOnExactSession(identity, env); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send batched tag secrets to TEE_T")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Successfully sent batched tag secrets to TEE_T",
		zap.Int("count", len(tagSecrets)))
	return nil
}

// handleBatchedTagVerifications handles batched tag verifications from TEE_T
func (t *TEEK) handleBatchedTagVerifications(identity *teekSessionIdentity, msg *shared.Message) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID
	var batchedVerification shared.BatchedTagVerificationData
	if err := msg.UnmarshalData(&batchedVerification); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched tag verification")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Received batched tag verification",
		zap.Int("total_count", batchedVerification.TotalCount),
		zap.Bool("all_successful", batchedVerification.AllSuccessful))

	// Generate decryption streams based on verification results
	var decryptionStreams []shared.ResponseDecryptionStreamData

	if batchedVerification.AllSuccessful {
		// All verifications passed - generate streams for all responses
		responseState := session.ResponseState
		if responseState == nil {
			err := fmt.Errorf("response state is not initialized")
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionNotFound, err, "Failed to get response state")
			return err
		}

		// Generate decryption streams for all response sequences
		for seqNum, responseLength := range responseState.ResponseLengthBySeq {
			// Generate decryption stream using session-aware logic
			decryptionStream, err := t.generateSingleDecryptionStreamForIdentity(identity, responseLength, seqNum)
			if err != nil {
				t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoStreamGenerationFailed, err, "Failed to generate decryption stream for sequence")
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
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagVerificationFailed, err, "Tag verification failed")
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

	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := t.routeToClientForSession(session, envStreams); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send batched decryption streams to client")
		return err
	}

	t.logger.WithSession(sessionID).Debug("Successfully sent batched decryption streams to client",
		zap.Int("count", len(decryptionStreams)))
	return nil
}

func (t *TEEK) checkAndSendSignatureIfReadyForIdentity(identity *teekSessionIdentity) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	teekState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		return fmt.Errorf("TEE_K session state not found: %v", err)
	}
	if !finalSignaturePrerequisitesReady(session, teekState) {
		return nil
	}
	session.StreamsMutex.Lock()
	if !session.TryBeginFinalSignature() {
		session.StreamsMutex.Unlock()
		return nil
	}
	session.StreamsMutex.Unlock()

	t.logger.WithSession(session.ID).Debug("All processing complete, generating and sending signature")
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := t.generateComprehensiveSignatureForIdentity(identity); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoSigningFailed, err, "Final signature generation or delivery failed")
		return err
	}
	if !session.MarkFinalSignatureSent() {
		err := fmt.Errorf("final signature state changed after successful client delivery")
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Final signature state transition failed")
		return err
	}
	return nil
}

func finalSignaturePrerequisitesReady(session *shared.Session, teekState *TEEKSessionState) bool {
	if session == nil || teekState == nil {
		return false
	}
	session.TranscriptMutex.Lock()
	transcriptReady := len(session.TranscriptData) > 0
	session.TranscriptMutex.Unlock()
	session.StreamsMutex.Lock()
	ready := session.RedactionProcessingComplete && len(session.RedactedStreams) > 0 && isOPRFReady(teekState.OPRFState.Load())
	session.StreamsMutex.Unlock()
	return transcriptReady && ready
}

// checkAndSendSignatureIfReady checks if all processing is complete and sends signature if ready
func (t *TEEK) checkAndSendSignatureIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}
	teekState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		return fmt.Errorf("TEE_K session state not found: %v", err)
	}
	if !finalSignaturePrerequisitesReady(session, teekState) {
		return nil
	}
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}
	identity, err := t.connManager.identityForSession(session)
	if err != nil {
		return fmt.Errorf("bind final signature to TEE_T session: %w", err)
	}
	return t.checkAndSendSignatureIfReadyForIdentity(identity)
}
