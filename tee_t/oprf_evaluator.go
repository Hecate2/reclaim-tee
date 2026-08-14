package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// handleOPRFOnlineFull handles online round 1 from TEE_K.
// TEE_K is the authoritative, mutually-attested source of ranges: it relays the
// client's ranges here (with TotalRanges), so TEE_T derives all OPRF state from
// this single TCP-ordered stream rather than racing a separate client message.
func (t *TEET) handleOPRFOnlineFull(identity *teetSessionIdentity, msg *teeproto.OPRFOnlineFull) error {
	startTime := time.Now()
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID
	if msg.GetSessionId() != sessionID {
		return fmt.Errorf("OPRF round 1 session ID mismatch")
	}

	teetState, err := t.sessionManager.stateForSession(session)
	if err != nil {
		return fmt.Errorf("failed to get TEE_T session state: %w", err)
	}

	// SECURITY: Cache TLS session hash from first message, verify consistency for subsequent
	if len(teetState.TLSSessionHash) == 0 {
		teetState.TLSSessionHash = msg.TlsSessionHash
		t.logger.WithSession(sessionID).Debug("Cached TLS session hash from TEE_K",
			zap.Int("hash_len", len(msg.TlsSessionHash)))
	} else {
		if !bytes.Equal(msg.TlsSessionHash, teetState.TLSSessionHash) {
			return fmt.Errorf("TLS session hash mismatch - possible replay attack")
		}
	}

	if len(t.oprfKeyShare) != 16 {
		return fmt.Errorf("OPRF key share length %d, want 16", len(t.oprfKeyShare))
	}
	total := int(msg.TotalRanges)
	if total <= 0 {
		return fmt.Errorf("OPRFOnlineFull with non-positive total_ranges %d", total)
	}
	rangeIndex := int(msg.RangeIndex)
	if rangeIndex < 0 || rangeIndex >= total {
		return fmt.Errorf("range_index %d out of bounds (total_ranges=%d)", rangeIndex, total)
	}

	// Initialize OPRF state on the first message. Messages are processed
	// serially on the per-session connection, so no lock is needed here.
	if teetState.OPRFResults == nil {
		teetState.OPRFExpectedCount = total
		teetState.OPRFResults = make(map[int]*shared.OPRFResult)
		teetState.PendingOPRF = make(map[int]*pendingOPRFEvaluation)
		teetState.OPRFKeyShare = t.oprfKeyShare
		teetState.OPRFState.Store(int32(shared.OPRFStateInProgress))
	} else if total != teetState.OPRFExpectedCount {
		return fmt.Errorf("total_ranges changed mid-session: %d vs %d", total, teetState.OPRFExpectedCount)
	}

	// Validate range against the consolidated response ciphertext.
	if msg.TlsStart < 0 || msg.TlsLength <= 0 || msg.TlsLength > 64 {
		return fmt.Errorf("invalid range: start=%d length=%d", msg.TlsStart, msg.TlsLength)
	}
	if int(msg.TlsStart)+int(msg.TlsLength) > len(teetState.ConsolidatedResponseCiphertext) {
		return fmt.Errorf("range exceeds ciphertext (end=%d, ciphertext_len=%d)",
			int(msg.TlsStart)+int(msg.TlsLength), len(teetState.ConsolidatedResponseCiphertext))
	}

	// Check OT receiver pool is ready
	if !t.isOTReceiverPoolReady() {
		return fmt.Errorf("OT receiver pool not ready - precomputation may have failed")
	}

	validationDone := time.Now()

	t.logger.WithSession(sessionID).Info("OPRF timing: round 1 started",
		zap.Int("range_index", rangeIndex),
		zap.Int("msg_size_bytes", len(msg.GarbledTables)),
		zap.Int64("validation_ms", validationDone.Sub(startTime).Milliseconds()))

	// Extract ciphertext for range
	start := int(msg.TlsStart)
	end := start + int(msg.TlsLength)
	ciphertext := teetState.ConsolidatedResponseCiphertext[start:end]

	// Pad to 64 bytes
	paddedCiphertext, err := mpc.PadZeros64(ciphertext, int(msg.TlsLength))
	if err != nil {
		return fmt.Errorf("failed to pad ciphertext: %w", err)
	}

	// Build evaluator input: [64 bytes data][16 bytes key]
	var evaluatorInput [80]byte
	copy(evaluatorInput[:64], paddedCiphertext[:])
	copy(evaluatorInput[64:], teetState.OPRFKeyShare)

	// Deserialize online payload
	payload, err := mpc.UnmarshalOnlinePayload(msg.GarbledTables)
	if err != nil {
		return fmt.Errorf("failed to deserialize online payload: %w", err)
	}
	if payload.SessionID != msg.GetOprfSessionId() {
		return fmt.Errorf("OPRF round 1 session mismatch for range %d", rangeIndex)
	}
	if payload.OTStartIndex != uint64(msg.GetOtStartIndex()) {
		return fmt.Errorf("OPRF OT start index mismatch: payload=%d message=%d",
			payload.OTStartIndex, msg.GetOtStartIndex())
	}

	deserializePayloadDone := time.Now()

	// Consume the single-use OTs only after the complete payload and its
	// duplicated metadata pass validation.
	otEntries, err := t.consumeOTReceiverEntriesForIdentity(identity, session.Context, uint64(msg.OtStartIndex), mpc.OTsPerOPRF, waitForReceiverPrecompute)
	if err != nil {
		return fmt.Errorf("failed to consume OT entries: %w", err)
	}

	otDone := time.Now()

	evaluatorSession, corrections, err := mpc.EvaluatorPrepare(payload, evaluatorInput, otEntries)
	if err != nil {
		return fmt.Errorf("failed to prepare evaluator OT corrections: %w", err)
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := teetState.SetPendingOPRF(rangeIndex, &pendingOPRFEvaluation{
		Session:   evaluatorSession,
		TLSStart:  int(msg.TlsStart),
		TLSLength: int(msg.TlsLength),
	}); err != nil {
		return err
	}
	serializedCorrections, err := mpc.MarshalChoiceCorrections(corrections)
	if err != nil {
		return fmt.Errorf("failed to serialize choice corrections: %w", err)
	}

	if err := t.sendOPRFChoiceCorrectionsToTEEK(identity, &teeproto.OPRFMPCRound2{
		SessionId:         sessionID,
		OprfSessionId:     msg.OprfSessionId,
		RangeIndex:        int32(rangeIndex),
		ChoiceCorrections: serializedCorrections,
	}); err != nil {
		return err
	}

	preparedDone := time.Now()

	t.logger.WithSession(sessionID).Info("OPRF timing: round 1 prepared",
		zap.Int("range_index", rangeIndex),
		zap.Int64("deserialize_payload_ms", deserializePayloadDone.Sub(validationDone).Milliseconds()),
		zap.Int64("ot_consume_ms", otDone.Sub(deserializePayloadDone).Milliseconds()),
		zap.Int64("prepare_and_send_ms", preparedDone.Sub(otDone).Milliseconds()),
		zap.Int64("total_ms", preparedDone.Sub(startTime).Milliseconds()))

	return nil
}

// handleOPRFMasks handles online round 3 and completes circuit evaluation.
func (t *TEET) handleOPRFMasks(identity *teetSessionIdentity, msg *teeproto.OPRFMPCRound3) error {
	startTime := time.Now()
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	sessionID := identity.session.ID
	if msg.GetSessionId() != sessionID {
		return fmt.Errorf("OPRF round 3 session ID mismatch")
	}

	teetState, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return fmt.Errorf("failed to get TEE_T session state: %w", err)
	}
	rangeIndex := int(msg.GetRangeIndex())
	if rangeIndex < 0 || rangeIndex >= teetState.OPRFExpectedCount {
		return fmt.Errorf("range_index %d out of bounds (expected=%d)", rangeIndex, teetState.OPRFExpectedCount)
	}

	pending, ok := teetState.TakePendingOPRF(rangeIndex)
	if !ok {
		return fmt.Errorf("no pending OPRF evaluation for range %d", rangeIndex)
	}
	if pending.Session.SessionID != msg.GetOprfSessionId() {
		return fmt.Errorf("OPRF round 3 session mismatch for range %d", rangeIndex)
	}

	masks, err := mpc.UnmarshalOTMasks(msg.GetOtMasks())
	if err != nil {
		return fmt.Errorf("failed to deserialize OT masks: %w", err)
	}
	deserializeDone := time.Now()

	result, err := mpc.EvaluatorOnline(pending.Session, masks)
	if err != nil {
		return fmt.Errorf("CMACEvaluatorOnline failed: %w", err)
	}
	evalDone := time.Now()
	hashOutput := sha256.Sum256(result.CMACOutput[:])

	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	teetState.SetOPRFResult(rangeIndex, &shared.OPRFResult{
		RangeIndex: rangeIndex,
		TLSStart:   pending.TLSStart,
		TLSLength:  pending.TLSLength,
		CMACOutput: result.CMACOutput,
		HashOutput: hashOutput,
	})

	serializedOutputLabels, err := mpc.MarshalOutputLabels(result.OutputLabels)
	if err != nil {
		return fmt.Errorf("failed to serialize output labels: %w", err)
	}
	if err := t.sendOPRFMPCResultToTEEK(identity, &teeproto.OPRFMPCResult{
		SessionId:     sessionID,
		OprfSessionId: msg.OprfSessionId,
		RangeIndex:    int32(rangeIndex),
		OutputLabels:  serializedOutputLabels,
	}); err != nil {
		return err
	}
	sendDone := time.Now()

	t.logger.WithSession(sessionID).Info("OPRF timing: evaluation complete",
		zap.Int("range_index", rangeIndex),
		zap.Int64("deserialize_masks_ms", deserializeDone.Sub(startTime).Milliseconds()),
		zap.Int64("circuit_eval_ms", evalDone.Sub(deserializeDone).Milliseconds()),
		zap.Int64("send_result_ms", sendDone.Sub(evalDone).Milliseconds()),
		zap.Int64("total_ms", sendDone.Sub(startTime).Milliseconds()))

	// Check if all OPRF computations are complete (atomic check-and-set)
	if teetState.TryMarkOPRFComplete() {
		t.logger.WithSession(sessionID).Info("All MPC OPRF computations complete",
			zap.Int("count", teetState.GetOPRFResultCount()))

		// Check if we can finalize now
		t.checkFinishedCondition(identity)
	}

	return nil
}

// sendOPRFChoiceCorrectionsToTEEK sends online round 2 to TEE_K.
func (t *TEET) sendOPRFChoiceCorrectionsToTEEK(identity *teetSessionIdentity, msg *teeproto.OPRFMPCRound2) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfMpcRound2{
			OprfMpcRound2: msg,
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal OPRF choice corrections: %w", err)
	}

	session.ConnMutex.RLock()
	conn := session.TEEKConn
	session.ConnMutex.RUnlock()
	wsConn, ok := conn.(*shared.WSConnection)
	if !ok {
		return fmt.Errorf("TEE_K connection is not a WebSocket connection")
	}
	return wsConn.WriteMessage(websocket.BinaryMessage, data)
}

// sendOPRFMPCResultToTEEK sends the final OPRF result to TEE_K
func (t *TEET) sendOPRFMPCResultToTEEK(identity *teetSessionIdentity, result *teeproto.OPRFMPCResult) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	sessionID := session.ID

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

	session.ConnMutex.RLock()
	conn := session.TEEKConn
	session.ConnMutex.RUnlock()
	wsConn, ok := conn.(*shared.WSConnection)
	if !ok {
		return fmt.Errorf("TEE_K connection is not a WebSocket connection")
	}

	// Use wrapper's WriteMessage which has internal mutex for thread safety
	return wsConn.WriteMessage(websocket.BinaryMessage, data)
}

// buildOPRFOutputsForSigning builds OPRF outputs for inclusion in signed payload
// IMPORTANT: Iterates by range index 0..ExpectedCount for deterministic ordering
// ZERO ERROR POLICY: Returns nil if any expected result is missing (caller should check)
func (t *TEET) buildOPRFOutputsForSigning(teetState *TEETSessionState) []*teeproto.OPRFOutput {
	// Get snapshot of results with lock
	oprfResults := teetState.GetAllOPRFResults()

	if shared.OPRFSessionState(teetState.OPRFState.Load()) != shared.OPRFStateComplete || len(oprfResults) == 0 {
		return nil
	}

	var outputs []*teeproto.OPRFOutput

	for i := 0; i < teetState.OPRFExpectedCount; i++ {
		result, ok := oprfResults[i]
		if !ok {
			// ZERO ERROR POLICY: Missing result when state is Complete is a critical error
			// This should never happen - return nil to signal failure
			t.logger.Error("CRITICAL: Missing OPRF result for range",
				zap.Int("range_index", i),
				zap.Int("expected_count", teetState.OPRFExpectedCount),
				zap.Int("actual_count", len(oprfResults)))
			return nil
		}
		outputs = append(outputs, &teeproto.OPRFOutput{
			TlsStart:   int32(result.TLSStart),
			TlsLength:  int32(result.TLSLength),
			HashOutput: result.HashOutput[:],
		})
	}

	return outputs
}

// isOPRFReadyT checks if OPRF processing is complete or not needed
// ZERO ERROR POLICY: Failed state is NOT ready - session should have been terminated
func isOPRFReadyT(state int32) bool {
	s := shared.OPRFSessionState(state)
	return s == shared.OPRFStateNone || s == shared.OPRFStateComplete
}
