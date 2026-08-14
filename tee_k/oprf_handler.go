package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// handleOPRFRangesFromClient handles OPRFRangesSubmission from client
func (t *TEEK) handleOPRFRangesFromClient(sessionID string, msg *teeproto.OPRFRangesSubmission) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	// Ranges are submitted exactly once per session. Reject any resubmission:
	// re-entering below would re-init OPRF maps the peer goroutine reads locked.
	if !teekState.OPRFRangesSubmitted.CompareAndSwap(false, true) {
		err := fmt.Errorf("OPRF ranges already submitted")
		t.terminateSessionWithError(sessionID, shared.ReasonProtocolViolation, err, "OPRF ranges already submitted")
		return err
	}

	t.logger.WithSession(sessionID).Info("OPRF ranges received", zap.Int("count", len(msg.GetRanges())))

	// If no ranges, mark OPRF as not needed
	if len(msg.GetRanges()) == 0 {
		teekState.OPRFState.Store(int32(shared.OPRFStateNone))
		t.logger.WithSession(sessionID).Debug("No OPRF ranges")
		// Check if we can send signature now
		return t.checkAndSendSignatureIfReady(sessionID)
	}

	// Use persistent OPRF key share from TEEK instance
	if len(t.oprfKeyShare) != 16 {
		return fmt.Errorf("OPRF key share length %d, want 16", len(t.oprfKeyShare))
	}

	// Initialize OPRF state. All non-atomic writes precede the publish.
	teekState.OPRFRanges = msg.GetRanges()
	teekState.OPRFState.Store(int32(shared.OPRFStateInProgress))
	teekState.OPRFExpectedCount = len(msg.GetRanges())
	teekState.GarblerOnlineSessions = make(map[int]*mpc.GarblerSession)
	teekState.OPRFResults = make(map[int]*shared.OPRFResult)
	teekState.OPRFKeyShare = t.oprfKeyShare
	teekState.ClientRangesReceived.Store(true)

	// If keystream not yet available, processing will happen later
	// when processQueuedOPRFRanges is called after keystream is set
	if len(teekState.ConsolidatedKeystream) == 0 {
		t.logger.WithSession(sessionID).Debug("OPRF queued, waiting for keystream")
		return nil
	}

	// Keystream available, process immediately
	return t.processQueuedOPRFRanges(sessionID, teekState)
}

// processQueuedOPRFRanges processes OPRF ranges that were waiting for keystream
func (t *TEEK) processQueuedOPRFRanges(sessionID string, teekState *TEEKSessionState) error {
	if !teekState.ClientRangesReceived.Load() || len(teekState.OPRFRanges) == 0 {
		return nil // No ranges to process
	}
	if shared.OPRFSessionState(teekState.OPRFState.Load()) != shared.OPRFStateInProgress {
		return nil // Already processed or not needed
	}
	if len(teekState.GarblerOnlineSessions) > 0 {
		return nil // Already initiated
	}

	// Check if OT pool is ready
	if !t.isOTPoolReady() {
		return fmt.Errorf("OT pool not ready - precomputation may have failed")
	}

	t.logger.WithSession(sessionID).Debug("Processing queued OPRF ranges")

	// Validate ranges and initiate MPC for each
	for i, r := range teekState.OPRFRanges {
		if r.TlsStart < 0 || r.TlsLength <= 0 || r.TlsLength > 64 {
			return fmt.Errorf("invalid range %d: start=%d length=%d", i, r.TlsStart, r.TlsLength)
		}
		rangeEnd := int(r.TlsStart) + int(r.TlsLength)
		if rangeEnd > len(teekState.ConsolidatedKeystream) {
			return fmt.Errorf("range %d exceeds keystream (end=%d, keystream_len=%d)",
				i, rangeEnd, len(teekState.ConsolidatedKeystream))
		}

		if err := t.initiateOPRFForRange(sessionID, teekState, i, r); err != nil {
			return fmt.Errorf("failed to initiate OPRF for range %d: %w", i, err)
		}
	}

	return nil
}

// initiateOPRFForRange starts MPC OPRF for a single range using precomputed
// random OT. The evaluator returns its choice corrections in round 2.
func (t *TEEK) initiateOPRFForRange(sessionID string, teekState *TEEKSessionState, rangeIndex int, r *teeproto.OPRFRangeSpec) error {
	// Reserve OT entries from the precomputed pool
	startIdx, otEntries, err := t.reserveOTEntries(mpc.OTsPerOPRF)
	if err != nil {
		return fmt.Errorf("failed to reserve OT entries: %w", err)
	}

	// Extract keystream for range and build garbler input
	start := int(r.TlsStart)
	keystream := teekState.ConsolidatedKeystream[start : start+int(r.TlsLength)]
	paddedKeystream, err := mpc.PadZeros64(keystream, int(r.TlsLength))
	if err != nil {
		return fmt.Errorf("failed to pad keystream: %w", err)
	}

	var garblerInput [80]byte
	copy(garblerInput[:64], paddedKeystream[:])
	copy(garblerInput[64:], teekState.OPRFKeyShare)

	// Generate the online payload from compact precomputed random OTs. The
	// online path performs no elliptic-curve operations.
	payload, garblerSession, err := mpc.GarblerOnline(rand.Reader, garblerInput, otEntries, startIdx)
	if err != nil {
		return fmt.Errorf("CMACGarblerOnline failed: %w", err)
	}
	defer payload.Release()

	// Store garbler session for output verification later
	teekState.SetGarblerOnlineSession(rangeIndex, garblerSession)

	// Compute TLS session hash for replay protection
	tlsSessionHash, err := t.computeTLSSessionHash(sessionID)
	if err != nil {
		return fmt.Errorf("failed to compute TLS session hash: %w", err)
	}

	serializedPayload, err := mpc.MarshalOnlinePayload(payload)
	if err != nil {
		return fmt.Errorf("failed to serialize online payload: %w", err)
	}

	t.logger.WithSession(sessionID).Debug("Sending OPRF online full",
		zap.Int("range", rangeIndex),
		zap.Uint64("ot_start_index", startIdx))

	// Send OPRFOnlineFull to TEE_T
	return t.sendOPRFOnlineFullToTEET(sessionID, &teeproto.OPRFOnlineFull{
		SessionId:      sessionID,
		OprfSessionId:  garblerSession.SessionID,
		RangeIndex:     int32(rangeIndex),
		TlsStart:       r.TlsStart,
		TlsLength:      r.TlsLength,
		TlsSessionHash: tlsSessionHash,
		GarbledTables:  serializedPayload, // Contains all circuit data
		OtStartIndex:   uint32(startIdx),
		TotalRanges:    int32(len(teekState.OPRFRanges)),
	})
}

// handleOPRFChoiceCorrections applies c=d XOR b to the precomputed random OT
// pads and returns masks that let TEE_T recover only its selected wire labels.
func (t *TEEK) handleOPRFChoiceCorrections(identity *teekSessionIdentity, msg *teeproto.OPRFMPCRound2) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	sessionID := identity.session.ID
	if msg.GetSessionId() != sessionID {
		return fmt.Errorf("OPRF round 2 session ID mismatch")
	}

	teekState, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	rangeIndex := int(msg.GetRangeIndex())
	if rangeIndex < 0 || rangeIndex >= len(teekState.OPRFRanges) {
		return fmt.Errorf("invalid range index %d", rangeIndex)
	}

	garblerSession, ok := teekState.GetGarblerOnlineSession(rangeIndex)
	if !ok {
		return fmt.Errorf("no garbler session found for range %d", rangeIndex)
	}
	if msg.GetOprfSessionId() != garblerSession.SessionID {
		return fmt.Errorf("OPRF round 2 session mismatch for range %d", rangeIndex)
	}

	corrections, err := mpc.UnmarshalChoiceCorrections(msg.GetChoiceCorrections())
	if err != nil {
		return fmt.Errorf("failed to deserialize choice corrections: %w", err)
	}
	masks, err := mpc.ApplyCorrections(garblerSession, corrections)
	if err != nil {
		return fmt.Errorf("failed to apply choice corrections: %w", err)
	}

	serializedMasks, err := mpc.MarshalOTMasks(masks)
	if err != nil {
		return fmt.Errorf("failed to serialize OT masks: %w", err)
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return t.sendOPRFMasksToExactTEET(identity, &teeproto.OPRFMPCRound3{
		SessionId:     sessionID,
		OprfSessionId: garblerSession.SessionID,
		OtMasks:       serializedMasks,
		RangeIndex:    int32(rangeIndex),
	})
}

// handleOPRFResult handles the final OPRF result from TEE_T
func (t *TEEK) handleOPRFResult(identity *teekSessionIdentity, msg *teeproto.OPRFMPCResult) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	sessionID := identity.session.ID
	if msg.GetSessionId() != sessionID {
		return fmt.Errorf("OPRF result session ID mismatch")
	}

	teekState, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	rangeIndex := int(msg.RangeIndex)
	if rangeIndex < 0 || rangeIndex >= len(teekState.OPRFRanges) {
		return fmt.Errorf("invalid range index %d", rangeIndex)
	}

	// MANDATORY: Verify output labels
	garblerSession, ok := teekState.GetGarblerOnlineSession(rangeIndex)
	if !ok {
		return fmt.Errorf("no garbler session found for range %d", rangeIndex)
	}
	if msg.GetOprfSessionId() != garblerSession.SessionID {
		return fmt.Errorf("OPRF result session mismatch for range %d", rangeIndex)
	}

	// Deserialize output labels
	outputLabels, err := mpc.UnmarshalOutputLabels(msg.GetOutputLabels())
	if err != nil {
		return fmt.Errorf("failed to deserialize output labels: %w", err)
	}

	// Verify output labels AND derive CMAC bytes from them. We deliberately
	// ignore msg.CmacOutput/msg.HashOutput — a compromised TEE_T could send
	// any bytes there. The labels are the only thing we cryptographically
	// verified, so they're the only thing we trust.
	cmacOutput, err := mpc.VerifyOutput(garblerSession, outputLabels)
	if err != nil {
		return fmt.Errorf("CRITICAL: output label verification failed - possible attack: %w", err)
	}
	hashOutput := sha256.Sum256(cmacOutput[:])
	if err := identity.ensureCurrent(); err != nil {
		return err
	}

	r := teekState.OPRFRanges[rangeIndex]

	t.logger.WithSession(sessionID).Debug("Received OPRF result (verified)",
		zap.Int("range", rangeIndex))

	teekState.SetOPRFResult(rangeIndex, &shared.OPRFResult{
		RangeIndex: rangeIndex,
		TLSStart:   int(r.TlsStart),
		TLSLength:  int(r.TlsLength),
		CMACOutput: cmacOutput,
		HashOutput: hashOutput,
	})

	// Check if all OPRF computations are complete (atomic check-and-set)
	if teekState.TryMarkOPRFComplete() {
		t.logger.WithSession(sessionID).Info("OPRF complete", zap.Int("count", teekState.GetOPRFResultCount()))

		// Check if we can send signature now
		t.checkAndSendSignatureIfReadyForIdentity(identity)
	}

	return nil
}

// computeTLSSessionHash computes a hash of TLS session parameters for replay protection
// Returns (hash, error) to ensure callers handle failures explicitly
func (t *TEEK) computeTLSSessionHash(sessionID string) ([]byte, error) {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session state: %w", err)
	}

	// Include session-specific data that can't be replayed
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write(teekState.ClientHello)
	h.Write(teekState.ServerHello)
	return h.Sum(nil), nil
}

// sendOPRFOnlineFullToTEET sends OPRFOnlineFull message to TEE_T via per-session connection
func (t *TEEK) sendOPRFOnlineFullToTEET(sessionID string, msg *teeproto.OPRFOnlineFull) error {
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfOnlineFull{
			OprfOnlineFull: msg,
		},
	}

	t.logger.WithSession(sessionID).Info("Sending to TEE_T",
		zap.String("type", "OprfOnlineFull"))

	// Send on per-session connection
	return t.connManager.SendOnSession(sessionID, env)
}

// sendOPRFMasksToTEET sends the correction-aware OT masks to TEE_T.
func (t *TEEK) sendOPRFMasksToTEET(sessionID string, msg *teeproto.OPRFMPCRound3) error {
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfMpcRound3{
			OprfMpcRound3: msg,
		},
	}

	return t.connManager.SendOnSession(sessionID, env)
}

func (t *TEEK) sendOPRFMasksToExactTEET(identity *teekSessionIdentity, msg *teeproto.OPRFMPCRound3) error {
	env := &teeproto.Envelope{
		SessionId: identity.session.ID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfMpcRound3{OprfMpcRound3: msg},
	}
	return t.connManager.SendOnExactSession(identity, env)
}

// buildOPRFOutputsForSigning builds OPRF outputs for inclusion in signed payload
// IMPORTANT: Iterates over OPRFRanges slice (not OPRFResults map) for deterministic ordering
// ZERO ERROR POLICY: Returns nil if any expected result is missing (caller should check)
func (t *TEEK) buildOPRFOutputsForSigning(teekState *TEEKSessionState) []*teeproto.OPRFOutput {
	// Get snapshot of results with lock
	oprfResults := teekState.GetAllOPRFResults()

	if shared.OPRFSessionState(teekState.OPRFState.Load()) != shared.OPRFStateComplete || len(oprfResults) == 0 {
		return nil
	}

	var outputs []*teeproto.OPRFOutput

	// Iterate over ranges slice for deterministic ordering
	for i, r := range teekState.OPRFRanges {
		result, ok := oprfResults[i]
		if !ok {
			// ZERO ERROR POLICY: Missing result when state is Complete is a critical error
			// This should never happen - return nil to signal failure
			t.logger.Error("CRITICAL: Missing OPRF result for range",
				zap.Int("range_index", i),
				zap.Int("expected_count", len(teekState.OPRFRanges)),
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

// isOPRFReady checks if OPRF processing is complete or not needed
// ZERO ERROR POLICY: Failed state is NOT ready - session should have been terminated
func isOPRFReady(state int32) bool {
	s := shared.OPRFSessionState(state)
	return s == shared.OPRFStateNone || s == shared.OPRFStateComplete
}

// handleCiphertextReady verifies ciphertext length matches keystream
func (t *TEEK) handleCiphertextReady(identity *teekSessionIdentity, msg *teeproto.CiphertextReady) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	sessionID := identity.session.ID
	teekState, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	keystreamLen := len(teekState.ConsolidatedKeystream)
	ciphertextLen := int(msg.TotalLength)

	if keystreamLen != ciphertextLen {
		return fmt.Errorf("keystream length %d != ciphertext length %d", keystreamLen, ciphertextLen)
	}

	t.logger.WithSession(sessionID).Debug("Ciphertext ready confirmed")

	return nil
}
