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

// handleOPRFRangesFromClient handles OPRFRangesSubmission from client
func (t *TEET) handleOPRFRangesFromClient(sessionID string, msg *teeproto.OPRFRangesSubmission) error {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_T session state: %w", err)
	}

	t.logger.WithSession(sessionID).Debug("Received OPRF ranges from client",
		zap.Int("range_count", len(msg.GetRanges())))

	// If no ranges, mark OPRF as not needed
	if len(msg.GetRanges()) == 0 {
		teetState.OPRFState = shared.OPRFStateNone
		t.logger.WithSession(sessionID).Debug("No OPRF ranges - skipping MPC OPRF")
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
	teetState.OPRFResults = make(map[int]*shared.OPRFResult)

	// Use persistent OPRF key share from TEET instance
	if len(t.oprfKeyShare) == 0 {
		return fmt.Errorf("OPRF key share not initialized")
	}
	teetState.OPRFKeyShare = t.oprfKeyShare

	// In 2-round protocol, we just wait for OPRFOnlineFull messages from TEE_K
	// No queueing needed - online messages contain everything needed for evaluation

	return nil
}

// handleOPRFOnlineFull handles the 2-round online OPRF message from TEE_K
// This is the only message in the online phase - contains all circuit data
func (t *TEET) handleOPRFOnlineFull(sessionID string, msg *teeproto.OPRFOnlineFull) error {
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

	// Wait for client ranges if not yet received
	if !teetState.ClientRangesReceived {
		// In 2-round protocol, TEE_K should wait for keystream before sending online messages
		// If we get here before client ranges, something is wrong with the protocol order
		return fmt.Errorf("received OPRFOnlineFull before client ranges - protocol order violation")
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

	// Check OT receiver pool is ready
	if !t.isOTReceiverPoolReady() {
		return fmt.Errorf("OT receiver pool not ready - precomputation may have failed")
	}

	t.logger.WithSession(sessionID).Debug("Processing MPC OPRF online",
		zap.Int("range_index", rangeIndex),
		zap.Int32("tls_start", msg.TlsStart),
		zap.Int32("tls_length", msg.TlsLength),
		zap.Uint32("ot_start_index", msg.OtStartIndex))

	// Extract ciphertext for range
	ciphertext := teetState.ConsolidatedResponseCiphertext[msg.TlsStart : msg.TlsStart+msg.TlsLength]

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

	// Deserialize online payload
	payload, err := oprfmpc.DeserializeOnlinePayload(msg.GarbledTables)
	if err != nil {
		return fmt.Errorf("failed to deserialize online payload: %w", err)
	}

	// Deserialize dual masks
	dualMasks, err := oprfmpc.DeserializeDualMasks(msg.DualMasks)
	if err != nil {
		return fmt.Errorf("failed to deserialize dual masks: %w", err)
	}

	// Add dual masks to payload for evaluation
	payload.DualMasks = dualMasks

	// Evaluate the garbled circuit using 2-round online function
	// Use the curve from OT receiver state
	curve := t.otReceiverState.curve
	result, err := oprfmpc.CMACEvaluatorOnline(curve, payload, evaluatorInput, otEntries)
	if err != nil {
		return fmt.Errorf("CMACEvaluatorOnline failed: %w", err)
	}

	// Compute hash of CMAC output
	hashOutput := sha256.Sum256(result.CMACOutput[:])

	// Store result locally (thread-safe)
	r := teetState.ClientOPRFRanges[rangeIndex]
	teetState.SetOPRFResult(rangeIndex, &shared.OPRFResult{
		RangeIndex: rangeIndex,
		TLSStart:   int(r.TlsStart),
		TLSLength:  int(r.TlsLength),
		CMACOutput: result.CMACOutput,
		HashOutput: hashOutput,
	})

	t.logger.WithSession(sessionID).Debug("MPC OPRF evaluation complete",
		zap.Int("range_index", rangeIndex))

	// Serialize output labels for garbler verification (MANDATORY)
	outputLabelsBytes := oprfmpc.SerializeOutputLabels(result.OutputLabels)

	// Send result back to TEE_K with output labels (MANDATORY for verification)
	if err := t.sendOPRFMPCResultToTEEK(sessionID, &teeproto.OPRFMPCResult{
		SessionId:     sessionID,
		OprfSessionId: msg.OprfSessionId,
		RangeIndex:    int32(rangeIndex),
		CmacOutput:    result.CMACOutput[:],
		HashOutput:    hashOutput[:],
		OutputLabels:  outputLabelsBytes, // MANDATORY: for garbler verification
	}); err != nil {
		return err
	}

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
