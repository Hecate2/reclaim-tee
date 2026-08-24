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
func (t *TEET) addToTranscript(identity *teetSessionIdentity, data []byte, dataType string) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID
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
func (t *TEET) handleFinishedFromTEEK(identity *teetSessionIdentity, msg *shared.Message) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	t.logger.Debug("Handling finished message from TEE_K",
		zap.String("session_id", msg.SessionID))
	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal finished message from TEE_K")
		return err
	}
	t.logger.Debug("Received finished command from TEE_K",
		zap.String("session_id", msg.SessionID))
	session := identity.session
	session.FinishedStateMutex.Lock()
	session.TEEKFinished = true
	session.FinishedStateMutex.Unlock()
	return t.checkFinishedCondition(identity)
}

// checkFinishedCondition checks if conditions are met for transcript signing and sends signed transcript
func (t *TEET) checkFinishedCondition(identity *teetSessionIdentity) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID

	// Get TEE_T state for OPRF check
	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state for finished condition check")
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

		cbcSnapshot := teetState.snapshotTLS12CBCSigningState()
		isCBC := cbcSnapshot.active
		// Snapshot the legacy consolidated ciphertext under the same mutex that
		// guards its append. CBC response state is immutable after the one-shot
		// terminal batch and is copied directly.
		var ciphertext []byte
		if isCBC {
			ciphertext = cbcSnapshot.response
		} else if session.ResponseState != nil {
			session.ResponseState.ResponsesMutex.Lock()
			if n := len(teetState.ConsolidatedResponseCiphertext); n > 0 {
				ciphertext = make([]byte, n)
				copy(ciphertext, teetState.ConsolidatedResponseCiphertext)
			}
			session.ResponseState.ResponsesMutex.Unlock()
		}

		if len(ciphertext) == 0 {
			t.logger.Warn("No consolidated response ciphertext to sign for session",
				zap.String("session_id", sessionID))
			// This is not an error - just means no response data to sign
			return nil
		}

		// Sign the TOutput at most once: this path can be reached from both the
		// peer finished and OPRF completion. The CAS loser returns without signing.
		if !teetState.TOutputSigned.CompareAndSwap(false, true) {
			t.logger.Debug("TOutput already signed for session, skipping",
				zap.String("session_id", sessionID))
			return nil
		}
		// Snapshot the signing keypair together with its attestation. Both
		// rotate on every refresh, so they must be read as one epoch — the
		// bundle is signed by keyPair and carries attestationReport, which
		// binds keyPair's ETH address.
		keyPair, attestationReport, err := t.signingEpoch(sessionID)
		if err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonAttestationVerificationFailed, err, "Failed to snapshot signing epoch")
			return err
		}
		if keyPair == nil {
			err = fmt.Errorf("no signing key pair available")
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoKeyGenerationFailed, err, "No signing key pair available for transcript signing")
			return err
		}
		ethAddress := keyPair.GetEthAddress()

		// teetState already obtained above for consolidated ciphertext check

		timestampMs := time.Now().UnixMilli()
		signedAttestationType := ""
		if t.ratls != nil {
			signedAttestationType = attestationReportType()
		}
		tOutput := &teeproto.TOutputPayload{
			SessionId:       sessionID,
			TimestampMs:     uint64(timestampMs),
			AttestationType: signedAttestationType,
		}
		if isCBC {
			if len(cbcSnapshot.redactedResponse) != len(ciphertext) || len(cbcSnapshot.digest) != 32 {
				return fmt.Errorf("TLS 1.2 CBC signed response transcript is incomplete")
			}
			tOutput.Tls12Cbc = &teeproto.TLS12CBCTOutput{
				Binding:                       cbcSnapshot.binding,
				AuthenticatedRedactedResponse: cbcSnapshot.redactedResponse,
				ResponseRecordsSha256:         cbcSnapshot.digest,
				ResponseRedactionRanges:       cbcSnapshot.ranges,
				PlaintextRecordLengths:        cbcSnapshot.plaintextLengths,
			}
		} else {
			tOutput.ConsolidatedResponseCiphertext = ciphertext
			tOutput.RequestProofStreams = teetState.RequestProofStreams
		}

		// Include OPRF outputs in signed payload
		oprfOutputs := t.buildOPRFOutputsForSigning(teetState)
		if len(oprfOutputs) > 0 {
			tOutput.OprfOutputs = oprfOutputs
			t.logger.WithSession(sessionID).Debug("Included OPRF outputs in TEE_T signed payload", zap.Int("count", len(oprfOutputs)))
		}

		t.logger.Debug("Including authenticated response transcript in TEE_T signature",
			zap.String("session_id", sessionID),
			zap.Int("consolidated_response_ciphertext_bytes", len(ciphertext)),
			zap.Int("proof_streams_count", len(teetState.RequestProofStreams)))

		body, err := proto.Marshal(tOutput)
		if err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to marshal TOutputPayload")
			return err
		}
		signature, err := keyPair.SignData(body)
		if err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoKeyGenerationFailed, err, "Failed to sign protobuf body")
			return err
		}
		t.logger.Debug("Successfully signed protobuf body",
			zap.String("session_id", sessionID),
			zap.Int("body_bytes", len(body)),
			zap.Int("signature_bytes", len(signature)))
		// attestationReport (router mode) was snapshotted with keyPair above so
		// the two stay in the same epoch; standalone uses the ETH address.
		var publicKeyForStandalone []byte
		if t.ratls != nil {
			if attestationReport == nil {
				err = fmt.Errorf("no attestation available for SignedMessage")
				t.terminateSessionWithErrorForIdentity(identity, shared.ReasonAttestationVerificationFailed, err, "No attestation available")
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
		if err := identity.ensureCurrent(); err != nil {
			return err
		}
		if err := t.routeToClientForSession(session, env); err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send SignedMessage (T_OUTPUT) to client")
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
