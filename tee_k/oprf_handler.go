package main

import (
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
func (t *TEEK) handleOPRFRangesFromClient(sessionID string, msg *teeproto.OPRFRangesSubmission) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	t.logger.WithSession(sessionID).Info("OPRF ranges received", zap.Int("count", len(msg.GetRanges())))

	// If no ranges, mark OPRF as not needed
	if len(msg.GetRanges()) == 0 {
		teekState.OPRFState = shared.OPRFStateNone
		t.logger.WithSession(sessionID).Debug("No OPRF ranges")
		// Check if we can send signature now
		t.checkAndSendSignatureIfReady(sessionID)
		return nil
	}

	// Initialize OPRF state
	teekState.OPRFRanges = msg.GetRanges()
	teekState.ClientRangesReceived = true
	teekState.OPRFState = shared.OPRFStateInProgress
	teekState.OPRFExpectedCount = len(msg.GetRanges())
	teekState.GarblerSessions = make(map[int]*oprfmpc.CMACGarblerSession)
	teekState.OPRFResults = make(map[int]*shared.OPRFResult)

	// Use persistent OPRF key share from TEEK instance
	if len(t.oprfKeyShare) == 0 {
		return fmt.Errorf("OPRF key share not initialized")
	}
	teekState.OPRFKeyShare = t.oprfKeyShare

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
	if !teekState.ClientRangesReceived || len(teekState.OPRFRanges) == 0 {
		return nil // No ranges to process
	}
	if teekState.OPRFState != shared.OPRFStateInProgress {
		return nil // Already processed or not needed
	}
	if len(teekState.GarblerSessions) > 0 {
		return nil // Already initiated
	}

	t.logger.WithSession(sessionID).Debug("Processing queued OPRF ranges")

	// Validate ranges and initiate MPC for each
	for i, r := range teekState.OPRFRanges {
		if r.TlsStart < 0 || r.TlsLength <= 0 || r.TlsLength > 64 {
			return fmt.Errorf("invalid range %d: start=%d length=%d", i, r.TlsStart, r.TlsLength)
		}
		if int(r.TlsStart+r.TlsLength) > len(teekState.ConsolidatedKeystream) {
			return fmt.Errorf("range %d exceeds keystream (end=%d, keystream_len=%d)",
				i, r.TlsStart+r.TlsLength, len(teekState.ConsolidatedKeystream))
		}

		if err := t.initiateOPRFForRange(sessionID, teekState, i, r); err != nil {
			return fmt.Errorf("failed to initiate OPRF for range %d: %w", i, err)
		}
	}

	return nil
}

// initiateOPRFForRange starts MPC OPRF for a single range
func (t *TEEK) initiateOPRFForRange(sessionID string, teekState *TEEKSessionState, rangeIndex int, r *teeproto.OPRFRangeSpec) error {
	// Generate Round1 (no input needed at this stage)
	round1, garblerState, err := oprfmpc.CMACGarblerRound1(rand.Reader, elliptic.P256())
	if err != nil {
		return fmt.Errorf("CMACGarblerRound1 failed: %w", err)
	}

	teekState.SetGarblerSession(rangeIndex, garblerState)

	// Compute TLS session hash for replay protection
	tlsSessionHash, err := t.computeTLSSessionHash(sessionID)
	if err != nil {
		return fmt.Errorf("failed to compute TLS session hash: %w", err)
	}

	t.logger.WithSession(sessionID).Debug("Sending OPRF Round1", zap.Int("range", rangeIndex))

	// Serialize Round1 payload
	round1Bytes := oprfmpc.SerializeRound1(round1)

	// Send Round1 to TEE_T
	return t.sendOPRFMPCRound1ToTEET(sessionID, &teeproto.OPRFMPCRound1{
		SessionId:      sessionID,
		OprfSessionId:  garblerState.SessionID,
		OtSetup:        round1Bytes,
		RangeIndex:     int32(rangeIndex),
		TlsStart:       r.TlsStart,
		TlsLength:      r.TlsLength,
		TlsSessionHash: tlsSessionHash,
	})
}

// handleOPRFRound2 handles Round2 response from TEE_T
func (t *TEEK) handleOPRFRound2(sessionID string, msg *teeproto.OPRFMPCRound2) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	// Find garbler session by OPRF session ID (with locking)
	teekState.LockOPRF()
	var rangeIndex int = -1
	var garblerSession *oprfmpc.CMACGarblerSession
	for idx, gs := range teekState.GarblerSessions {
		if gs.SessionID == msg.OprfSessionId {
			rangeIndex = idx
			garblerSession = gs
			break
		}
	}
	teekState.UnlockOPRF()

	if rangeIndex < 0 {
		return fmt.Errorf("no garbler session found for OPRF session %d", msg.OprfSessionId)
	}

	t.logger.WithSession(sessionID).Debug("Received OPRF Round2", zap.Int("range", rangeIndex))

	// Extract keystream for range and build garbler input
	r := teekState.OPRFRanges[rangeIndex]
	keystream := teekState.ConsolidatedKeystream[r.TlsStart : r.TlsStart+r.TlsLength]
	// PadZeros64 pads to 64 bytes - error only occurs if length > 64, which is validated earlier
	paddedKeystream, err := oprfmpc.PadZeros64(keystream, int(r.TlsLength))
	if err != nil {
		return fmt.Errorf("failed to pad keystream: %w", err)
	}

	var garblerInput [80]byte
	copy(garblerInput[:64], paddedKeystream[:])
	copy(garblerInput[64:], teekState.OPRFKeyShare)

	// Deserialize Round2 payload
	round2, err := oprfmpc.DeserializeRound2(msg.OtChoices)
	if err != nil {
		return fmt.Errorf("failed to deserialize Round2: %w", err)
	}

	// Generate Round3
	round3, err := oprfmpc.CMACGarblerRound3(rand.Reader, elliptic.P256(), garblerSession, garblerInput, round2)
	if err != nil {
		return fmt.Errorf("CMACGarblerRound3 failed: %w", err)
	}

	// Serialize Round3 payload
	round3Bytes := oprfmpc.SerializeRound3(round3)

	// Send Round3 to TEE_T
	return t.sendOPRFMPCRound3ToTEET(sessionID, &teeproto.OPRFMPCRound3{
		SessionId:      sessionID,
		OprfSessionId:  msg.OprfSessionId,
		GarbledCircuit: round3Bytes, // Full serialized payload
		GarblerInputs:  nil,         // Included in serialized payload
		OtCiphertexts:  nil,         // Included in serialized payload
		OutputHints:    nil,         // Included in serialized payload
	})
}

// handleOPRFResult handles the final OPRF result from TEE_T
func (t *TEEK) handleOPRFResult(sessionID string, msg *teeproto.OPRFMPCResult) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	rangeIndex := int(msg.RangeIndex)
	if rangeIndex < 0 || rangeIndex >= len(teekState.OPRFRanges) {
		return fmt.Errorf("invalid range index %d", rangeIndex)
	}

	r := teekState.OPRFRanges[rangeIndex]

	t.logger.WithSession(sessionID).Debug("Received OPRF result", zap.Int("range", rangeIndex))

	// Store the result (thread-safe)
	var cmacOutput [16]byte
	var hashOutput [32]byte
	copy(cmacOutput[:], msg.CmacOutput)
	copy(hashOutput[:], msg.HashOutput)

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
		t.checkAndSendSignatureIfReady(sessionID)
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

// sendOPRFMPCRound1ToTEET sends Round1 message to TEE_T
func (t *TEEK) sendOPRFMPCRound1ToTEET(sessionID string, round1 *teeproto.OPRFMPCRound1) error {
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no shared TEE_T connection available")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfMpcRound1{
			OprfMpcRound1: round1,
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal Round1: %w", err)
	}

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// sendOPRFMPCRound3ToTEET sends Round3 message to TEE_T
func (t *TEEK) sendOPRFMPCRound3ToTEET(sessionID string, round3 *teeproto.OPRFMPCRound3) error {
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no shared TEE_T connection available")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OprfMpcRound3{
			OprfMpcRound3: round3,
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal Round3: %w", err)
	}

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// buildOPRFOutputsForSigning builds OPRF outputs for inclusion in signed payload
// IMPORTANT: Iterates over OPRFRanges slice (not OPRFResults map) for deterministic ordering
// ZERO ERROR POLICY: Returns nil if any expected result is missing (caller should check)
func (t *TEEK) buildOPRFOutputsForSigning(teekState *TEEKSessionState) []*teeproto.OPRFOutput {
	// Get snapshot of results with lock
	oprfResults := teekState.GetAllOPRFResults()

	if teekState.OPRFState != shared.OPRFStateComplete || len(oprfResults) == 0 {
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
func isOPRFReady(state shared.OPRFSessionState) bool {
	return state == shared.OPRFStateNone ||
		state == shared.OPRFStateComplete
}

// handleCiphertextReady verifies ciphertext length matches keystream
func (t *TEEK) handleCiphertextReady(sessionID string, msg *teeproto.CiphertextReady) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
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

// sendCiphertextReadyToTEET notifies TEE_T that ciphertext consolidation is complete
func (t *TEEK) sendCiphertextReadyToTEET(sessionID string, totalLength int) error {
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no shared TEE_T connection available")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_CiphertextReady{
			CiphertextReady: &teeproto.CiphertextReady{
				SessionId:   sessionID,
				TotalLength: int32(totalLength),
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal CiphertextReady: %w", err)
	}

	return conn.WriteMessage(websocket.BinaryMessage, data)
}
