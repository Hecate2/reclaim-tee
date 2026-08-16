package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// handleRedactionStreams handles redaction streams from client
func (t *TEET) handleRedactionStreams(identity *teetSessionIdentity, msg *shared.Message) error {
	if identity == nil || identity.session == nil || identity.session.ID == "" {
		err := fmt.Errorf("redaction streams message missing session ID")
		return err
	}
	session := identity.session
	sessionID := session.ID
	if err := identity.ensureCurrent(); err != nil {
		return err
	}

	t.logger.Debug("Handling redaction streams for session", zap.String("session_id", sessionID))

	var streamsData shared.RedactionStreamsData
	if err := msg.UnmarshalData(&streamsData); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal redaction streams")
		return err
	}

	t.logger.Debug("Received redaction streams for session",
		zap.String("session_id", sessionID),
		zap.Int("streams_count", len(streamsData.Streams)))

	if err := identity.ensureCurrent(); err != nil {
		return err
	}

	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}

	session.RedactionState.SetStreams(streamsData.Streams)

	t.logger.Debug("Redaction streams stored for session", zap.String("session_id", sessionID))

	if procErr := t.processIfBothPartsArrived(identity); procErr != nil {
		return procErr
	}

	t.logger.Debug("handleRedactionStreams completed for session",
		zap.String("session_id", sessionID))

	return nil
}

// Counter-at-join: caller that bumps RequestPartsArrived to 2 dispatches.
func (t *TEET) processIfBothPartsArrived(identity *teetSessionIdentity) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID
	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		// Session might already be gone (e.g., terminated). Don't escalate.
		t.logger.Debug("processIfBothPartsArrived: session state missing", zap.String("session_id", sessionID))
		return nil
	}
	count := teetState.RequestPartsArrived.Add(1)
	if count != 2 {
		t.logger.Debug("Request parts arrival incomplete, waiting",
			zap.String("session_id", sessionID),
			zap.Int32("arrived", count))
		return nil
	}

	t.logger.Debug("Both request parts arrived, processing", zap.String("session_id", sessionID))

	// R_SP capture (signed in TEE_T's transcript). Both halves are now
	// present, so ranges (from TEE_K) and streams (from client) are
	// visible via the counter-at-join happens-before edge. We pull
	// ranges from session.RedactionState — the authoritative copy
	// TEE_K validated — rather than re-trusting the client.
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if session.RedactionState != nil {
		teetState.RequestProofStreams = teetState.RequestProofStreams[:0]
		ranges := session.RedactionState.Ranges
		streams := session.RedactionState.RedactionStreams
		for i, r := range ranges {
			if r.Type == shared.RedactionTypeSensitiveProof && i < len(streams) {
				teetState.RequestProofStreams = append(teetState.RequestProofStreams, streams[i])
			}
		}
		t.logger.Debug("R_SP stream capture completed",
			zap.String("session_id", sessionID),
			zap.Int("proof_streams_count", len(teetState.RequestProofStreams)))
	}

	// Prefer fragments path; fall back to legacy single-request path.
	if len(teetState.PendingEncryptedFragments) > 0 {
		if procErr := t.processEncryptedFragmentsWithStreams(identity); procErr != nil {
			return procErr
		}
		teetState.PendingEncryptedFragments = make(map[uint64]*shared.EncryptedRequestData)
		return nil
	}
	if teetState.PendingEncryptedRequest != nil {
		if procErr := t.processEncryptedRequestWithStreams(identity, teetState.PendingEncryptedRequest); procErr != nil {
			return procErr
		}
		teetState.PendingEncryptedRequest = nil
		return nil
	}

	// Counter hit 2 but no data — programmer error.
	err = fmt.Errorf("both parts marked arrived but no encrypted request data present")
	t.logger.Error("processIfBothPartsArrived: invariant violated",
		zap.String("session_id", sessionID))
	t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Counter-join invariant violated")
	return err
}

// handleBatchedEncryptedResponses handles batched encrypted responses from client
func (t *TEET) handleBatchedEncryptedResponses(identity *teetSessionIdentity, msg *shared.Message) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID
	t.logger.Debug("Handling encrypted responses for session", zap.String("session_id", sessionID))

	var batchedResponses shared.BatchedEncryptedResponseData
	if err := msg.UnmarshalData(&batchedResponses); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched encrypted responses")
		return err
	}

	t.logger.Debug("Received batch of encrypted responses",
		zap.String("session_id", sessionID),
		zap.Int("total_count", batchedResponses.TotalCount))

	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}
	if !teetState.ResponseBatchReceived.CompareAndSwap(false, true) {
		err = fmt.Errorf("multiple encrypted response batches received for session")
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonProtocolViolation, err, "Multiple encrypted response batches received")
		return err
	}

	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	var responseLengths []struct {
		Length       int    `json:"length"`
		RecordHeader []byte `json:"record_header"`
		SeqNum       uint64 `json:"seq_num"`
		ExplicitIV   []byte `json:"explicit_iv,omitempty"`
	}

	session.ResponseState.ResponsesMutex.Lock()

	// Sort responses by sequence number to ensure deterministic transcript order
	sortedResponses := make([]shared.EncryptedResponseData, len(batchedResponses.Responses))
	copy(sortedResponses, batchedResponses.Responses)
	sort.Slice(sortedResponses, func(i, j int) bool {
		return sortedResponses[i].SeqNum < sortedResponses[j].SeqNum
	})

	for _, encryptedResp := range sortedResponses {
		// Per-record fingerprint: identical fp on consecutive seqs = duplicate
		// record captured by client (suspected trailing-record tag-fail cause).
		fpSum := sha256.Sum256(append(append([]byte{}, encryptedResp.EncryptedData...), encryptedResp.Tag...))
		var recHdr0 byte
		if len(encryptedResp.RecordHeader) >= 1 {
			recHdr0 = encryptedResp.RecordHeader[0]
		}
		t.logger.WithSession(sessionID).Debug("Response record fingerprint",
			zap.Uint64("seq_num", encryptedResp.SeqNum),
			zap.Int("enc_len", len(encryptedResp.EncryptedData)),
			zap.Int("tag_len", len(encryptedResp.Tag)),
			zap.Uint8("rec_hdr0", recHdr0),
			zap.String("fp", fmt.Sprintf("%x", fpSum[:10])))
		session.ResponseState.PendingEncryptedResponses[encryptedResp.SeqNum] = &encryptedResp
		if err := t.addSingleResponseToTranscript(identity, &encryptedResp); err != nil {
			session.ResponseState.ResponsesMutex.Unlock()
			return err
		}
		lengthData := struct {
			Length       int    `json:"length"`
			RecordHeader []byte `json:"record_header"`
			SeqNum       uint64 `json:"seq_num"`
			ExplicitIV   []byte `json:"explicit_iv,omitempty"`
		}{
			Length:       len(encryptedResp.EncryptedData),
			RecordHeader: encryptedResp.RecordHeader,
			SeqNum:       encryptedResp.SeqNum,
			ExplicitIV:   encryptedResp.ExplicitIV,
		}
		responseLengths = append(responseLengths, lengthData)
	}
	session.ResponseState.ResponsesMutex.Unlock()

	t.logger.Debug("BATCHING: Processed encrypted responses",
		zap.String("session_id", sessionID),
		zap.Int("total_count", len(batchedResponses.Responses)))

	var lengths []*teeproto.BatchedResponseLengths_Length
	for _, l := range responseLengths {
		lengths = append(lengths, &teeproto.BatchedResponseLengths_Length{
			Length:       int32(l.Length),
			RecordHeader: l.RecordHeader,
			SeqNum:       l.SeqNum,
			ExplicitIv:   l.ExplicitIV,
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedResponseLengths{
			BatchedResponseLengths: &teeproto.BatchedResponseLengths{
				Lengths:    lengths,
				SessionId:  sessionID,
				TotalCount: int32(len(responseLengths)),
			},
		},
	}

	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := t.routeToTEEKForSession(session, env); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send batched lengths to TEE_K")
		return err
	}

	t.logger.Debug("BATCHING: Successfully sent batch of response lengths to TEE_K",
		zap.String("session_id", sessionID),
		zap.Int("total_count", len(responseLengths)))

	return nil
}

// handleSessionCreation handles session creation from TEE_K
func (t *TEET) handleSessionCreation(msg *shared.Message) error {
	var sessionData map[string]any
	if err := msg.UnmarshalData(&sessionData); err != nil {
		t.terminateSessionWithError("", shared.ReasonMessageParsingFailed, err, "Failed to unmarshal session creation data")
		return err
	}
	sessionID, ok := sessionData["session_id"].(string)
	if !ok {
		err := fmt.Errorf("invalid session_id in session creation message")
		t.terminateSessionWithError("", shared.ReasonMessageParsingFailed, err, "Invalid session_id in session creation")
		return err
	}
	if err := t.registerSession(sessionID); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionManagerFailure, err, "Failed to register session")
		return err
	}
	return nil
}

func (t *TEET) registerSession(sessionID string) error {
	_, err := t.registerSessionForControl(sessionID, 0)
	return err
}

func (t *TEET) registerSessionForControl(sessionID string, controlGeneration uint64) (*shared.Session, error) {
	if err := t.sessionManager.RegisterSession(sessionID); err != nil {
		return nil, err
	}
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		_ = t.sessionManager.CloseSession(sessionID)
		return nil, fmt.Errorf("get registered session: %w", err)
	}
	t.activeSessions.Add(1)
	teetState := &TEETSessionState{session: session, controlGeneration: controlGeneration}
	t.sessionManager.SetTEETSessionState(sessionID, teetState)
	t.logger.Info("Session registered", zap.String("sid", shared.TruncateSessionID(sessionID)))
	return session, nil
}

// handleKeyShareRequestSession handles key share request from TEE_K
func (t *TEET) handleKeyShareRequestSession(identity *teetSessionIdentity, msg *shared.Message) error {
	if identity == nil || identity.session == nil || identity.session.ID == "" {
		err := fmt.Errorf("key share request missing session ID")
		return err
	}
	session := identity.session
	sessionID := session.ID
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	t.logger.Debug("Handling key share request for session", zap.String("session_id", sessionID))
	var keyReq shared.KeyShareRequestData
	if err := msg.UnmarshalData(&keyReq); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal key share request")
		return err
	}
	keyShare := make([]byte, keyReq.KeyLength)
	if _, err := rand.Read(keyShare); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoKeyGenerationFailed, err, "Failed to generate key share")
		return err
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}
	teetState.KeyShare = keyShare
	t.logger.Debug("Generated key share for session",
		zap.String("session_id", sessionID),
		zap.Int("key_length", len(keyShare)))
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_KeyShareResponse{KeyShareResponse: &teeproto.KeyShareResponse{KeyShare: keyShare, Success: true}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to marshal key share response")
		return err
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session.ConnMutex.RLock()
	wsConn, ok := session.TEEKConn.(*shared.WSConnection)
	session.ConnMutex.RUnlock()
	if !ok {
		return fmt.Errorf("TEE_K connection is not a WebSocket connection")
	}
	// Use wrapper's WriteMessage which has internal mutex for thread safety
	if err = wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send key share response")
		return err
	}
	return nil
}

// handleBatchedEncryptedRequest handles batched encrypted request from TEE_K
func (t *TEET) handleBatchedEncryptedRequest(identity *teetSessionIdentity, msg *shared.Message) error {
	if identity == nil || identity.session == nil || identity.session.ID == "" {
		err := fmt.Errorf("batched encrypted request missing session ID")
		return err
	}
	session := identity.session
	sessionID := session.ID
	if err := identity.ensureCurrent(); err != nil {
		return err
	}

	t.logger.Debug("Handling batched encrypted request for session", zap.String("session_id", sessionID))

	var batchedReq shared.BatchedEncryptedRequestData
	if err := msg.UnmarshalData(&batchedReq); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched encrypted request")
		return err
	}

	t.logger.Debug("Received batched encrypted request",
		zap.String("session_id", sessionID),
		zap.Int("fragment_count", len(batchedReq.Fragments)),
		zap.Uint64("base_seq_num", batchedReq.BaseSeqNum))

	if len(batchedReq.Fragments) > shared.MaxEncryptedFragments {
		err := fmt.Errorf("too many fragments: %d (max %d)", len(batchedReq.Fragments), shared.MaxEncryptedFragments)
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonProtocolViolation, err, "Too many fragments")
		return err
	}

	if len(batchedReq.Fragments) > 0 && len(batchedReq.Fragments[0].RedactionRanges) > shared.MaxRedactionRanges {
		err := fmt.Errorf("too many redaction ranges: %d (max %d)", len(batchedReq.Fragments[0].RedactionRanges), shared.MaxRedactionRanges)
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonProtocolViolation, err, "Too many redaction ranges")
		return err
	}

	if err := identity.ensureCurrent(); err != nil {
		return err
	}

	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	// Store redaction ranges from the first fragment
	if len(batchedReq.Fragments) > 0 {
		session.RedactionState.SetRanges(batchedReq.Fragments[0].RedactionRanges)

		t.logger.Debug("Stored redaction ranges from batched request",
			zap.String("session_id", sessionID),
			zap.Int("range_count", len(batchedReq.Fragments[0].RedactionRanges)))
	}

	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}

	// Initialize fragment map if needed
	if teetState.PendingEncryptedFragments == nil {
		teetState.PendingEncryptedFragments = make(map[uint64]*shared.EncryptedRequestData)
	}

	// Store all fragments
	for i, fragment := range batchedReq.Fragments {
		seqNum := batchedReq.BaseSeqNum + uint64(i)
		// Update fragment with calculated sequence number and cipher suite
		fragmentCopy := fragment
		fragmentCopy.SeqNum = seqNum
		fragmentCopy.CipherSuite = batchedReq.CipherSuite
		teetState.PendingEncryptedFragments[seqNum] = &fragmentCopy

		t.logger.Debug("Stored fragment from batch",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", seqNum),
			zap.Int("fragment_index", i))
	}

	t.logger.Debug("Stored all fragments from batched request",
		zap.String("session_id", sessionID),
		zap.Int("total_fragments", len(batchedReq.Fragments)))

	return t.processIfBothPartsArrived(identity)
}

// handleBatchedTagSecrets handles batched tag secrets from TEE_K
func (t *TEET) handleBatchedTagSecrets(identity *teetSessionIdentity, msg *shared.Message) error {
	if identity == nil || identity.session == nil || identity.session.ID == "" {
		err := fmt.Errorf("batched tag secrets missing session ID")
		return err
	}
	session := identity.session
	sessionID := session.ID
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	t.logger.Debug("Handling batched tag secrets for session",
		zap.String("session_id", sessionID))
	var batchedTagSecrets shared.BatchedTagSecretsData
	if err := msg.UnmarshalData(&batchedTagSecrets); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched tag secrets")
		return err
	}
	t.logger.Debug("Received batch of tag secrets",
		zap.String("session_id", sessionID),
		zap.Int("batch_count", batchedTagSecrets.TotalCount))
	if session.ResponseState == nil {
		err := fmt.Errorf("no response state for session")
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "No response state for session")
		return err
	}
	var verifications []shared.ResponseTagVerificationData
	allSuccessful := true
	totalCount := len(batchedTagSecrets.TagSecrets)
	session.ResponseState.ResponsesMutex.Lock()

	// Sort tag secrets by sequence number to ensure deterministic processing order
	type tagSecretWithSeq struct {
		TagSecrets []byte `json:"tag_secrets"`
		SeqNum     uint64 `json:"seq_num"`
	}
	var sortedTagSecrets []tagSecretWithSeq
	for _, ts := range batchedTagSecrets.TagSecrets {
		sortedTagSecrets = append(sortedTagSecrets, tagSecretWithSeq{
			TagSecrets: ts.TagSecrets,
			SeqNum:     ts.SeqNum,
		})
	}
	// Sort by sequence number for deterministic order
	sort.Slice(sortedTagSecrets, func(i, j int) bool {
		return sortedTagSecrets[i].SeqNum < sortedTagSecrets[j].SeqNum
	})

	// seq -> tag secret, so a failed record can be re-verified against
	// neighbouring nonces (drift classifier below).
	tagSecretBySeq := make(map[uint64][]byte, len(sortedTagSecrets))
	for _, ts := range sortedTagSecrets {
		tagSecretBySeq[ts.SeqNum] = ts.TagSecrets
	}

	for _, tagSecretsData := range sortedTagSecrets {
		encryptedResp := session.ResponseState.PendingEncryptedResponses[tagSecretsData.SeqNum]
		if encryptedResp == nil {
			session.ResponseState.ResponsesMutex.Unlock()
			err := fmt.Errorf("critical security failure: missing encrypted response for seq %d", tagSecretsData.SeqNum)
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Missing encrypted response in batch")
			return err
		}
		// Convert to the expected struct type for verifyTagForResponse
		tagSecretStruct := &struct {
			TagSecrets []byte `json:"tag_secrets"`
			SeqNum     uint64 `json:"seq_num"`
		}{
			TagSecrets: tagSecretsData.TagSecrets,
			SeqNum:     tagSecretsData.SeqNum,
		}
		verificationResult := t.verifyTagForResponse(identity, encryptedResp, tagSecretStruct)
		if !verificationResult.Success {
			allSuccessful = false
			verifications = append(verifications, verificationResult)
			t.classifyTagFailure(identity, encryptedResp, tagSecretBySeq, session.ResponseState.PendingEncryptedResponses)
			break // Exit loop to send results - this is OK
		}
		t.logger.Debug("Tag verification completed",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", tagSecretsData.SeqNum),
			zap.Bool("success", verificationResult.Success))
	}
	session.ResponseState.ResponsesMutex.Unlock()
	t.logger.Debug("Completed batch tag verification",
		zap.String("session_id", sessionID),
		zap.Int("total_count", totalCount),
		zap.Bool("all_successful", allSuccessful))
	var pbVerifications []*teeproto.BatchedTagVerifications_Verification
	for _, v := range verifications {
		pbVerifications = append(pbVerifications, &teeproto.BatchedTagVerifications_Verification{
			Success: v.Success,
			SeqNum:  v.SeqNum,
			Message: v.Message,
		})
	}
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedTagVerifications{
			BatchedTagVerifications: &teeproto.BatchedTagVerifications{
				Verifications: pbVerifications,
				SessionId:     sessionID,
				TotalCount:    int32(totalCount),
				AllSuccessful: allSuccessful,
			},
		},
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := t.routeToTEEKForSession(session, env); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send batch verification results to TEE_K")
		return err
	}
	t.logger.Debug("Successfully sent batch verification results",
		zap.String("session_id", sessionID))
	if !allSuccessful {
		err := fmt.Errorf("tag verification failed for batch")
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagVerificationFailed, err, "Tag verification failed")
		return err
	}
	return nil
}

// processEncryptedRequestWithStreams processes encrypted request with available redaction streams
func (t *TEET) processEncryptedRequestWithStreams(identity *teetSessionIdentity, encReq *shared.EncryptedRequestData) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID
	t.logger.Debug("Processing encrypted request with available redaction streams for session",
		zap.String("session_id", sessionID))
	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}
	teetState.CipherSuite = encReq.CipherSuite
	t.logger.Debug("Stored CipherSuite in session state",
		zap.String("session_id", sessionID),
		zap.Uint16("cipher_suite", encReq.CipherSuite))
	if session.RedactionState == nil {
		err := fmt.Errorf("no redaction state available for session")
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "No redaction state available")
		return err
	}
	reconstructedData, err := t.reconstructFullRequestWithStreams(encReq.EncryptedData, encReq.RedactionRanges, session.RedactionState.RedactionStreams)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, "Failed to reconstruct full request")
		return err
	}
	t.logger.Debug("Successfully reconstructed original request data",
		zap.String("session_id", sessionID))
	var additionalData []byte
	// Check if TLS 1.3 cipher suite
	cipherInfo := minitls.GetCipherSuiteInfo(uint16(encReq.CipherSuite))
	if cipherInfo != nil && cipherInfo.IsTLS13 {
		tagSize := 16
		recordLength := len(reconstructedData) + tagSize
		additionalData = minitls.CreateAdditionalDataTLS13(recordLength)
	} else {
		plaintextLength := len(reconstructedData)
		additionalData = minitls.CreateAdditionalDataTLS12(encReq.SeqNum, plaintextLength)
	}
	authTag, err := minitls.ComputeTagFromSecrets(reconstructedData, encReq.TagSecrets, encReq.CipherSuite, additionalData)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, "Failed to compute authentication tag")
		return err
	}
	t.logger.Debug("Computed split AEAD tag",
		zap.String("session_id", sessionID),
		zap.Int("data_length", len(reconstructedData)))
	isTLS12AESGCMCipher := minitls.IsTLS12AESGCMCipherSuite(encReq.CipherSuite)
	var payload []byte
	if isTLS12AESGCMCipher {
		payload = minitls.CreateTLS12AEADPayload(encReq.SeqNum, reconstructedData, authTag)
		t.logger.Debug("Constructed TLS 1.2 AES-GCM record with explicit IV",
			zap.String("session_id", sessionID),
			zap.Binary("explicit_iv", payload[:8]))
	} else {
		payload = minitls.CreateTLS13AEADPayload(reconstructedData, authTag)
	}
	tlsRecord := minitls.CreateApplicationDataRecord(payload)
	// for verification against TEE_K's redacted streams
	t.logger.Debug("Constructed TLS request record (not added to transcript for verification)",
		zap.String("session_id", sessionID),
		zap.Int("record_length", len(tlsRecord)))
	t.logger.Debug("Sending reconstructed encrypted data to client session",
		zap.String("session_id", sessionID),
		zap.Int("data_length", len(reconstructedData)))
	envResp := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedEncryptedData{BatchedEncryptedData: &teeproto.BatchedEncryptedDataResponse{
			Fragments:  []*teeproto.EncryptedDataResponse{{EncryptedData: reconstructedData, AuthTag: authTag, Success: true}},
			BaseSeqNum: encReq.SeqNum,
			Success:    true,
		}},
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := t.routeToClientForSession(session, envResp); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send encrypted data to client")
		return err
	}
	return nil
}

// processEncryptedFragmentsWithStreams processes multiple encrypted fragments with available redaction streams
func (t *TEET) processEncryptedFragmentsWithStreams(identity *teetSessionIdentity) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID

	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}

	if len(teetState.PendingEncryptedFragments) == 0 {
		t.logger.Debug("No fragments to process", zap.String("session_id", sessionID))
		return nil
	}

	if len(teetState.PendingEncryptedFragments) == 1 {
		// Single fragment - use existing logic
		for _, fragment := range teetState.PendingEncryptedFragments {
			return t.processEncryptedRequestWithStreams(identity, fragment)
		}
	}

	t.logger.Debug("Processing multiple encrypted fragments with available redaction streams",
		zap.String("session_id", sessionID),
		zap.Int("fragment_count", len(teetState.PendingEncryptedFragments)))

	// Sort fragments by sequence number
	var seqNums []uint64
	for seqNum := range teetState.PendingEncryptedFragments {
		seqNums = append(seqNums, seqNum)
	}
	for i := 0; i < len(seqNums)-1; i++ {
		for j := i + 1; j < len(seqNums); j++ {
			if seqNums[i] > seqNums[j] {
				seqNums[i], seqNums[j] = seqNums[j], seqNums[i]
			}
		}
	}

	// Verify we have consecutive fragments starting from some base
	baseSeq := seqNums[0]
	for i, seqNum := range seqNums {
		if seqNum != baseSeq+uint64(i) {
			err := fmt.Errorf("non-consecutive fragments: expected %d, got %d", baseSeq+uint64(i), seqNum)
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, "Non-consecutive fragments")
			return err
		}
	}

	// Process each fragment and collect results
	var allReconstructedData []byte
	var allAuthTags []byte
	cipherSuite := teetState.PendingEncryptedFragments[seqNums[0]].CipherSuite

	for _, seqNum := range seqNums {
		fragment := teetState.PendingEncryptedFragments[seqNum]

		// Verify cipher suite consistency
		if fragment.CipherSuite != cipherSuite {
			err := fmt.Errorf("cipher suite mismatch in fragment %d: expected %d, got %d", seqNum, cipherSuite, fragment.CipherSuite)
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, "Cipher suite mismatch")
			return err
		}

		// Process this fragment
		reconstructedData, err := t.reconstructFullRequestWithStreams(fragment.EncryptedData, fragment.RedactionRanges, session.RedactionState.RedactionStreams)
		if err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, fmt.Sprintf("Failed to reconstruct fragment %d", seqNum))
			return err
		}

		// Compute tag for this fragment
		var additionalData []byte
		cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
		if cipherInfo != nil && cipherInfo.IsTLS13 {
			tagSize := 16
			recordLength := len(reconstructedData) + tagSize
			additionalData = minitls.CreateAdditionalDataTLS13(recordLength)
		} else {
			plaintextLength := len(reconstructedData)
			additionalData = minitls.CreateAdditionalDataTLS12(fragment.SeqNum, plaintextLength)
		}

		authTag, err := minitls.ComputeTagFromSecrets(reconstructedData, fragment.TagSecrets, cipherSuite, additionalData)
		if err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, fmt.Sprintf("Failed to compute tag for fragment %d", seqNum))
			return err
		}

		t.logger.Debug("Processed fragment",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", seqNum),
			zap.Int("data_bytes", len(reconstructedData)))

		// Accumulate data and tags
		allReconstructedData = append(allReconstructedData, reconstructedData...)
		allAuthTags = append(allAuthTags, authTag...)
	}

	teetState.CipherSuite = cipherSuite
	t.logger.Debug("Successfully processed all fragments",
		zap.String("session_id", sessionID),
		zap.Int("total_data_bytes", len(allReconstructedData)),
		zap.Int("total_tag_bytes", len(allAuthTags)))

	// Process all fragments and send in a single batch
	var fragments []*teeproto.EncryptedDataResponse

	for _, seqNum := range seqNums {
		fragment := teetState.PendingEncryptedFragments[seqNum]

		// Process this specific fragment
		fragmentReconstructed, err := t.reconstructFullRequestWithStreams(fragment.EncryptedData, fragment.RedactionRanges, session.RedactionState.RedactionStreams)
		if err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, fmt.Sprintf("Failed to reconstruct fragment %d for response", seqNum))
			return err
		}

		// Compute tag for this specific fragment
		var additionalData []byte
		cipherInfo := minitls.GetCipherSuiteInfo(cipherSuite)
		if cipherInfo != nil && cipherInfo.IsTLS13 {
			tagSize := 16
			recordLength := len(fragmentReconstructed) + tagSize
			additionalData = minitls.CreateAdditionalDataTLS13(recordLength)
		} else {
			plaintextLength := len(fragmentReconstructed)
			additionalData = minitls.CreateAdditionalDataTLS12(seqNum, plaintextLength)
		}

		authTag, err := minitls.ComputeTagFromSecrets(fragmentReconstructed, fragment.TagSecrets, cipherSuite, additionalData)
		if err != nil {
			t.terminateSessionWithErrorForIdentity(identity, shared.ReasonCryptoTagComputationFailed, err, fmt.Sprintf("Failed to compute tag for fragment %d response", seqNum))
			return err
		}

		fragments = append(fragments, &teeproto.EncryptedDataResponse{
			EncryptedData: fragmentReconstructed,
			AuthTag:       authTag,
			Success:       true,
		})
	}

	// Send all fragments in a single message
	envResp := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedEncryptedData{
			BatchedEncryptedData: &teeproto.BatchedEncryptedDataResponse{
				Fragments:  fragments,
				BaseSeqNum: seqNums[0], // First sequence number
				Success:    true,
			},
		},
	}

	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := t.routeToClientForSession(session, envResp); err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonNetworkFailure, err, "Failed to send batched encrypted data to client")
		return err
	}

	t.logger.Debug("Sent batched fragments to client",
		zap.String("session_id", sessionID),
		zap.Int("fragment_count", len(fragments)),
		zap.Uint64("base_seq_num", seqNums[0]))

	return nil
}

// addSingleResponseToTranscript adds a single response to the session transcript
func (t *TEET) addSingleResponseToTranscript(identity *teetSessionIdentity, encryptedResp *shared.EncryptedResponseData) error {
	sessionID := identity.session.ID
	teetState, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}
	isTLS12AESGCMCipher := minitls.IsTLS12AESGCMCipherSuite(teetState.CipherSuite)
	var payload []byte
	if isTLS12AESGCMCipher && encryptedResp.ExplicitIV != nil && len(encryptedResp.ExplicitIV) == 8 {
		payload = make([]byte, 8+len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload[0:8], encryptedResp.ExplicitIV)
		copy(payload[8:8+len(encryptedResp.EncryptedData)], encryptedResp.EncryptedData)
		copy(payload[8+len(encryptedResp.EncryptedData):], encryptedResp.Tag)
		t.logger.Debug("Added explicit IV to TLS 1.2 AES-GCM response transcript record",
			zap.String("session_id", sessionID),
			zap.Binary("explicit_iv", encryptedResp.ExplicitIV))
	} else {
		payload = make([]byte, len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload, encryptedResp.EncryptedData)
		copy(payload[len(encryptedResp.EncryptedData):], encryptedResp.Tag)
	}
	recordLength := len(payload)
	if recordLength > 0xFFFF {
		t.logger.Warn("TLS record too large, truncating length",
			zap.String("session_id", sessionID),
			zap.Int("original_length", recordLength),
			zap.Int("truncated_length", 0xFFFF))
		recordLength = 0xFFFF
	}
	record := make([]byte, 5+recordLength)
	if len(encryptedResp.RecordHeader) >= 1 {
		record[0] = encryptedResp.RecordHeader[0]
	} else {
		record[0] = 0x17
	}
	record[1] = 0x03
	record[2] = 0x03
	record[3] = byte(recordLength >> 8)
	record[4] = byte(recordLength & 0xFF)
	copy(record[5:], payload)
	if err := t.addToTranscript(identity, record, shared.TranscriptDataTypeTLSRecord); err != nil {
		return err
	}
	t.logger.Debug("Added response packet to session transcript",
		zap.String("session_id", sessionID),
		zap.Uint64("seq_num", encryptedResp.SeqNum),
		zap.Int("record_length", len(record)))
	return nil
}
