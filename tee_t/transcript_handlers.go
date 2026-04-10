package main

import (
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// addToTranscript safely adds data with explicit type to the session's transcript
func (t *TEET) addToTranscript(sessionID string, data []byte, dataType string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session for transcript")
		return err
	}
	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	session.TranscriptData = append(session.TranscriptData, dataCopy)
	session.TranscriptDataTypes = append(session.TranscriptDataTypes, dataType)
	t.logger.Debug("Added data to session transcript",
		zap.String("session_id", sessionID),
		zap.Int("data_bytes", len(data)),
		zap.String("data_type", dataType),
		zap.Int("total_data", len(session.TranscriptData)))
	return nil
}

// Transcript handling simplified - using structured data in SignedMessage

// handleFinishedFromTEEK handles finished message from TEE_K and triggers transcript signing
func (t *TEET) handleFinishedFromTEEK(msg *shared.Message) error {
	t.logger.Debug("Handling finished message from TEE_K",
		zap.String("session_id", msg.SessionID))
	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		t.terminateSessionWithError(msg.SessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal finished message from TEE_K")
		return err
	}
	t.logger.Debug("Received finished command from TEE_K",
		zap.String("session_id", msg.SessionID))
	sessionID := msg.SessionID
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session for TEE_K finished tracking")
		return err
	}
	session.FinishedStateMutex.Lock()
	session.TEEKFinished = true
	session.FinishedStateMutex.Unlock()
	return t.checkFinishedCondition(sessionID)
}

// checkFinishedCondition checks if conditions are met for transcript signing and sends signed transcript
func (t *TEET) checkFinishedCondition(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session for finished condition check")
		return err
	}

	// Get TEE_T state for OPRF check
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state for finished condition check")
		return err
	}

	session.FinishedStateMutex.Lock()
	teekFinished := session.TEEKFinished
	session.FinishedStateMutex.Unlock()

	// Check if OPRF is ready (complete, not needed, or failed)
	oprfReady := isOPRFReadyT(teetState.OPRFState.Load())

	if teekFinished && oprfReady {
		t.logger.Debug("TEE_K has sent finished and OPRF ready - starting transcript signing",
			zap.String("session_id", sessionID),
			zap.String("oprf_state", shared.OPRFSessionState(teetState.OPRFState.Load()).String()))

		// teetState already obtained above for OPRF check

		if len(teetState.ConsolidatedResponseCiphertext) == 0 {
			t.logger.WarnIf("No consolidated response ciphertext to sign for session",
				zap.String("session_id", sessionID))
			// This is not an error - just means no response data to sign
			return nil
		}
		if t.signingKeyPair == nil {
			err := fmt.Errorf("no signing key pair available")
			t.terminateSessionWithError(sessionID, shared.ReasonCryptoKeyGenerationFailed, err, "No signing key pair available for transcript signing")
			return err
		}
		ethAddress := t.signingKeyPair.GetEthAddress()

		// teetState already obtained above for consolidated ciphertext check

		timestampMs := time.Now().UnixMilli()
		tOutput := &teeproto.TOutputPayload{
			SessionId:                      sessionID,                                // Bind to session for cross-TEE verification
			ConsolidatedResponseCiphertext: teetState.ConsolidatedResponseCiphertext, // Consolidated response ciphertext
			RequestProofStreams:            teetState.RequestProofStreams,            // TEE_T signs R_SP streams
			TimestampMs:                    uint64(timestampMs),                      // Include signed timestamp
		}

		// Include OPRF outputs in signed payload
		oprfOutputs := t.buildOPRFOutputsForSigning(teetState)
		if len(oprfOutputs) > 0 {
			tOutput.OprfOutputs = oprfOutputs
			t.logger.WithSession(sessionID).Debug("Included OPRF outputs in TEE_T signed payload", zap.Int("count", len(oprfOutputs)))
		}

		t.logger.Debug("Including consolidated response ciphertext and R_SP streams in TEE_T signature",
			zap.String("session_id", sessionID),
			zap.Int("consolidated_response_ciphertext_bytes", len(teetState.ConsolidatedResponseCiphertext)),
			zap.Int("proof_streams_count", len(teetState.RequestProofStreams)))

		body, err := proto.Marshal(tOutput)
		if err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to marshal TOutputPayload")
			return err
		}
		signature, err := t.signingKeyPair.SignData(body)
		if err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonCryptoKeyGenerationFailed, err, "Failed to sign protobuf body")
			return err
		}
		t.logger.Debug("Successfully signed protobuf body",
			zap.String("session_id", sessionID),
			zap.Int("body_bytes", len(body)),
			zap.Int("signature_bytes", len(signature)))
		var attestationReport *teeproto.AttestationReport
		var publicKeyForStandalone []byte
		if t.enclaveManager != nil {
			var err error
			attestationReport, err = t.generateAttestationReport(sessionID)
			if err != nil {
				t.terminateSessionWithError(sessionID, shared.ReasonAttestationVerificationFailed, err, "Failed to generate attestation report")
				return err
			}
			t.logger.Debug("Including attestation report in SignedMessage", zap.String("session_id", sessionID))
		} else {
			publicKeyForStandalone = []byte(ethAddress.String())
			t.logger.Debug("Including ETH address in SignedMessage (standalone mode)",
				zap.String("session_id", sessionID))
		}
		// Create signed message (timestamp is now inside signed body)
		sm := &teeproto.SignedMessage{
			BodyType:          teeproto.BodyType_BODY_TYPE_T_OUTPUT,
			Body:              body,
			EthAddress:        publicKeyForStandalone,
			Signature:         signature,
			AttestationReport: attestationReport,
		}
		env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: timestampMs, Payload: &teeproto.Envelope_SignedMessage{SignedMessage: sm}}
		if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send SignedMessage (T_OUTPUT) to client")
			return err
		}
		t.logger.Debug("Sent SignedMessage (T_OUTPUT) to client",
			zap.String("session_id", sessionID))
	} else {
		t.logger.Debug("Waiting for finished from TEE_K",
			zap.String("session_id", sessionID),
			zap.Bool("teek_finished", teekFinished))
	}
	return nil
}
