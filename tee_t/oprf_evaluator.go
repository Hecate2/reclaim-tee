package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// handleOPRFRangesFromClient handles OPRFRangesSubmission from client
func (t *TEET) handleOPRFRangesFromClient(sessionID string, msg *teeproto.OPRFRangesSubmission) error {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_T session state: %w", err)
	}

	t.logger.WithSession(sessionID).Info("Received OPRF ranges from client",
		zap.Int("range_count", len(msg.GetRanges())))

	// If no ranges, mark OPRF as not needed
	if len(msg.GetRanges()) == 0 {
		teetState.OPRFState = shared.OPRFStateNone
		t.logger.WithSession(sessionID).Info("No OPRF ranges - skipping MPC OPRF")
		// Check if we can finalize now
		t.checkFinishedCondition(sessionID)
		return nil
	}

	// Validate ranges against consolidated ciphertext
	for i, r := range msg.GetRanges() {
		if r.TlsStart < 0 || r.TlsLength <= 0 || r.TlsLength > 64 {
			return fmt.Errorf("invalid range %d: start=%d length=%d", i, r.TlsStart, r.TlsLength)
		}
		if int(r.TlsStart+r.TlsLength) > len(teetState.ConsolidatedResponseCiphertext) {
			return fmt.Errorf("range %d exceeds ciphertext (end=%d, ciphertext_len=%d)",
				i, r.TlsStart+r.TlsLength, len(teetState.ConsolidatedResponseCiphertext))
		}
	}

	// Initialize OPRF state
	teetState.ClientOPRFRanges = msg.GetRanges()
	teetState.ClientRangesReceived = true
	teetState.OPRFState = shared.OPRFStateInProgress
	teetState.OPRFExpectedCount = len(msg.GetRanges())
	teetState.EvaluatorSessions = make(map[int]*oprfmpc.CMACEvaluatorSession)
	teetState.OPRFResults = make(map[int]*shared.OPRFResult)

	// Generate OPRF key share if not already set
	if len(teetState.OPRFKeyShare) == 0 {
		teetState.OPRFKeyShare = make([]byte, 16)
		if _, err := rand.Read(teetState.OPRFKeyShare); err != nil {
			return fmt.Errorf("failed to generate OPRF key share: %w", err)
		}
	}

	// TLS session hash will be cached from the first Round1 message from TEE_K
	// TEE_K has access to ClientHello/ServerHello which TEE_T doesn't have

	// Process any queued Round1 messages that arrived before client ranges (thread-safe)
	pendingRound1s := teetState.GetAndClearPendingRound1s()
	if len(pendingRound1s) > 0 {
		t.logger.WithSession(sessionID).Info("Processing queued Round1 messages",
			zap.Int("count", len(pendingRound1s)))
		for _, round1 := range pendingRound1s {
			if err := t.processOPRFRound1(sessionID, teetState, round1); err != nil {
				return err
			}
		}
	}

	return nil
}

// handleOPRFRound1 handles Round1 from TEE_K
func (t *TEET) handleOPRFRound1(sessionID string, msg *teeproto.OPRFMPCRound1) error {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_T session state: %w", err)
	}

	// Queue if client ranges not yet received (thread-safe)
	if !teetState.ClientRangesReceived {
		t.logger.WithSession(sessionID).Info("Queueing Round1 - waiting for client ranges",
			zap.Int("range_index", int(msg.RangeIndex)))
		teetState.AddPendingRound1(msg)
		return nil
	}

	return t.processOPRFRound1(sessionID, teetState, msg)
}

// processOPRFRound1 processes a Round1 message after client ranges are received
func (t *TEET) processOPRFRound1(sessionID string, teetState *TEETSessionState, msg *teeproto.OPRFMPCRound1) error {
	// SECURITY: Cache TLS session hash from first Round1, verify consistency for subsequent
	// TEE_K computes this from ClientHello/ServerHello which TEE_T doesn't have access to
	if len(teetState.TLSSessionHash) == 0 {
		// First Round1 - cache the hash from TEE_K
		teetState.TLSSessionHash = msg.TlsSessionHash
		t.logger.WithSession(sessionID).Info("Cached TLS session hash from TEE_K",
			zap.Int("hash_len", len(msg.TlsSessionHash)))
	} else {
		// Subsequent Round1 - verify same hash (prevents mixing sessions)
		if !bytes.Equal(msg.TlsSessionHash, teetState.TLSSessionHash) {
			return fmt.Errorf("TLS session hash mismatch - possible replay attack")
		}
	}

	// SECURITY: Verify position matches what client sent
	rangeIndex := int(msg.RangeIndex)
	if rangeIndex < 0 || rangeIndex >= len(teetState.ClientOPRFRanges) {
		return fmt.Errorf("invalid range index %d (have %d ranges)", rangeIndex, len(teetState.ClientOPRFRanges))
	}

	clientRange := teetState.ClientOPRFRanges[rangeIndex]
	if msg.TlsStart != clientRange.TlsStart || msg.TlsLength != clientRange.TlsLength {
		return fmt.Errorf("position mismatch: TEE_K [%d:%d] vs client [%d:%d]",
			msg.TlsStart, msg.TlsStart+msg.TlsLength,
			clientRange.TlsStart, clientRange.TlsStart+clientRange.TlsLength)
	}

	t.logger.WithSession(sessionID).Info("Processing MPC OPRF Round1",
		zap.Int("range_index", rangeIndex),
		zap.Int32("tls_start", msg.TlsStart),
		zap.Int32("tls_length", msg.TlsLength))

	// Extract ciphertext for range
	ciphertext := teetState.ConsolidatedResponseCiphertext[msg.TlsStart : msg.TlsStart+msg.TlsLength]

	// Pad to 64 bytes using oprfmpc.PadZeros64
	paddedCiphertext, _ := oprfmpc.PadZeros64(ciphertext, int(msg.TlsLength))

	// Build evaluator input: [64 bytes data][16 bytes key]
	var evaluatorInput [80]byte
	copy(evaluatorInput[:64], paddedCiphertext[:])
	copy(evaluatorInput[64:], teetState.OPRFKeyShare)

	// Deserialize Round1 payload
	round1, err := oprfmpc.DeserializeRound1(msg.OtSetup)
	if err != nil {
		return fmt.Errorf("failed to deserialize Round1: %w", err)
	}

	// Generate Round2
	round2, evalState, err := oprfmpc.CMACEvaluatorRound2(rand.Reader, elliptic.P256(), round1, evaluatorInput)
	if err != nil {
		return fmt.Errorf("CMACEvaluatorRound2 failed: %w", err)
	}

	teetState.SetEvaluatorSession(rangeIndex, evalState)

	// Serialize Round2 payload
	round2Bytes := oprfmpc.SerializeRound2(round2)

	// Send Round2 to TEE_K
	return t.sendOPRFMPCRound2ToTEEK(sessionID, &teeproto.OPRFMPCRound2{
		SessionId:     sessionID,
		OprfSessionId: msg.OprfSessionId,
		OtChoices:     round2Bytes,
	})
}

// handleOPRFRound3 handles Round3 from TEE_K
func (t *TEET) handleOPRFRound3(sessionID string, msg *teeproto.OPRFMPCRound3) error {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_T session state: %w", err)
	}

	// Find evaluator session by OPRF session ID (with locking)
	teetState.LockOPRF()
	var rangeIndex int = -1
	var evalSession *oprfmpc.CMACEvaluatorSession
	for idx, es := range teetState.EvaluatorSessions {
		if es.SessionID == msg.OprfSessionId {
			rangeIndex = idx
			evalSession = es
			break
		}
	}
	teetState.UnlockOPRF()

	if rangeIndex < 0 {
		return fmt.Errorf("no evaluator session found for OPRF session %d", msg.OprfSessionId)
	}

	t.logger.WithSession(sessionID).Info("Processing MPC OPRF Round3",
		zap.Int("range_index", rangeIndex),
		zap.Uint64("oprf_session_id", msg.OprfSessionId))

	// Deserialize Round3 payload
	round3, err := oprfmpc.DeserializeRound3(msg.GarbledCircuit)
	if err != nil {
		return fmt.Errorf("failed to deserialize Round3: %w", err)
	}

	// Evaluate the garbled circuit (Round4)
	cmacResult, err := oprfmpc.CMACEvaluatorRound4(elliptic.P256(), evalSession, round3)
	if err != nil {
		return fmt.Errorf("CMACEvaluatorRound4 failed: %w", err)
	}

	// Compute hash of CMAC output
	hashOutput := sha256.Sum256(cmacResult[:])

	// Store result locally (thread-safe)
	r := teetState.ClientOPRFRanges[rangeIndex]
	teetState.SetOPRFResult(rangeIndex, &shared.OPRFResult{
		RangeIndex: rangeIndex,
		TLSStart:   int(r.TlsStart),
		TLSLength:  int(r.TlsLength),
		CMACOutput: cmacResult,
		HashOutput: hashOutput,
	})

	t.logger.WithSession(sessionID).Info("MPC OPRF evaluation complete",
		zap.Int("range_index", rangeIndex),
		zap.String("cmac_preview", fmt.Sprintf("%x", cmacResult[:4])))

	// Send result back to TEE_K
	if err := t.sendOPRFMPCResultToTEEK(sessionID, &teeproto.OPRFMPCResult{
		SessionId:     sessionID,
		OprfSessionId: msg.OprfSessionId,
		RangeIndex:    int32(rangeIndex),
		CmacOutput:    cmacResult[:],
		HashOutput:    hashOutput[:],
	}); err != nil {
		return err
	}

	// Check if all OPRF computations are complete (thread-safe)
	if teetState.GetOPRFResultCount() >= teetState.OPRFExpectedCount {
		teetState.OPRFState = shared.OPRFStateComplete
		t.logger.WithSession(sessionID).Info("All MPC OPRF computations complete",
			zap.Int("count", len(teetState.OPRFResults)))

		// Check if we can finalize now
		t.checkFinishedCondition(sessionID)
	}

	return nil
}

// sendOPRFMPCRound2ToTEEK sends Round2 message to TEE_K
func (t *TEET) sendOPRFMPCRound2ToTEEK(sessionID string, round2 *teeproto.OPRFMPCRound2) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	if session.TEEKConn == nil {
		return fmt.Errorf("no TEE_K connection for session")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfMpcRound2{
			OprfMpcRound2: round2,
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal Round2: %w", err)
	}

	wsConn, ok := session.TEEKConn.(*shared.WSConnection)
	if !ok {
		return fmt.Errorf("TEE_K connection is not a WebSocket connection")
	}

	return wsConn.WriteMessage(websocket.BinaryMessage, data)
}

// sendOPRFMPCResultToTEEK sends the final OPRF result to TEE_K
func (t *TEET) sendOPRFMPCResultToTEEK(sessionID string, result *teeproto.OPRFMPCResult) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	if session.TEEKConn == nil {
		return fmt.Errorf("no TEE_K connection for session")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfMpcResult{
			OprfMpcResult: result,
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal OPRF result: %w", err)
	}

	wsConn, ok := session.TEEKConn.(*shared.WSConnection)
	if !ok {
		return fmt.Errorf("TEE_K connection is not a WebSocket connection")
	}

	return wsConn.WriteMessage(websocket.BinaryMessage, data)
}

// buildOPRFOutputsForSigning builds OPRF outputs for inclusion in signed payload
// IMPORTANT: Iterates over ClientOPRFRanges slice (not OPRFResults map) for deterministic ordering
// ZERO ERROR POLICY: Returns nil if any expected result is missing (caller should check)
func (t *TEET) buildOPRFOutputsForSigning(teetState *TEETSessionState) []*teeproto.OPRFOutput {
	// Get snapshot of results with lock
	oprfResults := teetState.GetAllOPRFResults()

	if teetState.OPRFState != shared.OPRFStateComplete || len(oprfResults) == 0 {
		return nil
	}

	var outputs []*teeproto.OPRFOutput

	// Iterate over ranges slice for deterministic ordering
	for i, r := range teetState.ClientOPRFRanges {
		result, ok := oprfResults[i]
		if !ok {
			// ZERO ERROR POLICY: Missing result when state is Complete is a critical error
			// This should never happen - return nil to signal failure
			t.logger.Error("CRITICAL: Missing OPRF result for range",
				zap.Int("range_index", i),
				zap.Int("expected_count", len(teetState.ClientOPRFRanges)),
				zap.Int("actual_count", len(oprfResults)))
			return nil
		}
		outputs = append(outputs, &teeproto.OPRFOutput{
			TlsStart:   r.TlsStart,
			TlsLength:  r.TlsLength,
			HashOutput: result.HashOutput[:],
		})
	}

	return outputs
}

// isOPRFReadyT checks if OPRF processing is complete or not needed
// ZERO ERROR POLICY: Failed state is NOT ready - session should have been terminated
func isOPRFReadyT(state shared.OPRFSessionState) bool {
	return state == shared.OPRFStateNone ||
		state == shared.OPRFStateComplete
}
