package main

import (
	"bytes"
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

// handleOPRFOnlineFull handles the 2-round online OPRF message from TEE_K.
// TEE_K is the authoritative, mutually-attested source of ranges: it relays the
// client's ranges here (with TotalRanges), so TEE_T derives all OPRF state from
// this single TCP-ordered stream rather than racing a separate client message.
func (t *TEET) handleOPRFOnlineFull(sessionID string, msg *teeproto.OPRFOnlineFull) error {
	// TIMING: Start of OPRF processing
	startTime := time.Now()
	msgSize := len(msg.GarbledTables) + len(msg.DualMasks)

	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
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

	if len(t.oprfKeyShare) == 0 {
		return fmt.Errorf("OPRF key share not initialized")
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

	// TIMING: After validation
	validationDone := time.Now()

	t.logger.WithSession(sessionID).Info("OPRF timing: started",
		zap.Int("range_index", rangeIndex),
		zap.Int("msg_size_bytes", msgSize),
		zap.Int64("validation_ms", validationDone.Sub(startTime).Milliseconds()))

	// Extract ciphertext for range
	start := int(msg.TlsStart)
	end := start + int(msg.TlsLength)
	ciphertext := teetState.ConsolidatedResponseCiphertext[start:end]

	// Pad to 64 bytes
	paddedCiphertext, err := oprfmpc.PadZeros64(ciphertext, int(msg.TlsLength))
	if err != nil {
		return fmt.Errorf("failed to pad ciphertext: %w", err)
	}

	// Build evaluator input: [64 bytes data][16 bytes key]
	var evaluatorInput [80]byte
	copy(evaluatorInput[:64], paddedCiphertext[:])
	copy(evaluatorInput[64:], teetState.OPRFKeyShare)

	// Consume OT receiver entries from precomputed pool
	otEntries, err := t.consumeOTReceiverEntries(int(msg.OtStartIndex), oprfmpc.OTsPerOPRF)
	if err != nil {
		return fmt.Errorf("failed to consume OT entries: %w", err)
	}

	// TIMING: After OT consumption
	otDone := time.Now()

	// Deserialize online payload
	payload, err := oprfmpc.DeserializeOnlinePayload(msg.GarbledTables)
	if err != nil {
		return fmt.Errorf("failed to deserialize online payload: %w", err)
	}

	// TIMING: After garbled tables deserialization
	deserializePayloadDone := time.Now()

	// Deserialize dual masks
	dualMasks, err := oprfmpc.DeserializeDualMasks(msg.DualMasks)
	if err != nil {
		return fmt.Errorf("failed to deserialize dual masks: %w", err)
	}

	// TIMING: After dual masks deserialization
	deserializeMasksDone := time.Now()

	// Add dual masks to payload for evaluation
	payload.DualMasks = dualMasks

	// Evaluate the garbled circuit using 2-round online function
	// Use the curve from OT receiver state
	curve := t.otReceiverState.curve
	result, err := oprfmpc.CMACEvaluatorOnline(curve, payload, evaluatorInput, otEntries)
	if err != nil {
		return fmt.Errorf("CMACEvaluatorOnline failed: %w", err)
	}

	// TIMING: After circuit evaluation
	evalDone := time.Now()

	// Compute hash of CMAC output
	hashOutput := sha256.Sum256(result.CMACOutput[:])

	// Store result locally (thread-safe)
	teetState.SetOPRFResult(rangeIndex, &shared.OPRFResult{
		RangeIndex: rangeIndex,
		TLSStart:   int(msg.TlsStart),
		TLSLength:  int(msg.TlsLength),
		CMACOutput: result.CMACOutput,
		HashOutput: hashOutput,
	})

	// Serialize output labels for garbler verification (MANDATORY)
	outputLabelsBytes := oprfmpc.SerializeOutputLabels(result.OutputLabels)

	// Send only the labels — TEE_K derives CMAC and HashOutput from them.
	if err := t.sendOPRFMPCResultToTEEK(sessionID, &teeproto.OPRFMPCResult{
		SessionId:     sessionID,
		OprfSessionId: msg.OprfSessionId,
		RangeIndex:    int32(rangeIndex),
		OutputLabels:  outputLabelsBytes,
	}); err != nil {
		return err
	}

	// TIMING: After sending result
	sendDone := time.Now()

	t.logger.WithSession(sessionID).Info("OPRF timing: complete",
		zap.Int("range_index", rangeIndex),
		zap.Int64("ot_consume_ms", otDone.Sub(validationDone).Milliseconds()),
		zap.Int64("deserialize_payload_ms", deserializePayloadDone.Sub(otDone).Milliseconds()),
		zap.Int64("deserialize_masks_ms", deserializeMasksDone.Sub(deserializePayloadDone).Milliseconds()),
		zap.Int64("circuit_eval_ms", evalDone.Sub(deserializeMasksDone).Milliseconds()),
		zap.Int64("send_result_ms", sendDone.Sub(evalDone).Milliseconds()),
		zap.Int64("total_ms", sendDone.Sub(startTime).Milliseconds()))

	// Check if all OPRF computations are complete (atomic check-and-set)
	if teetState.TryMarkOPRFComplete() {
		t.logger.WithSession(sessionID).Info("All MPC OPRF computations complete",
			zap.Int("count", teetState.GetOPRFResultCount()))

		// Check if we can finalize now
		t.checkFinishedCondition(sessionID)
	}

	return nil
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
