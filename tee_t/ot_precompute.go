package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/markkurossi/mpc/ot"
	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// OTReceiverState holds the OT receiver state for a TEE_K connection
type OTReceiverState struct {
	pool  *oprfmpc.OTReceiverPool
	ready bool
	epoch string // Pool identity from TEE_K; matched on resume to confirm same pool
}

// NewOTReceiverState creates a new OT receiver state
func NewOTReceiverState() *OTReceiverState {
	return &OTReceiverState{
		pool:  oprfmpc.NewOTReceiverPool(oprfmpc.OTPoolInitialSize),
		ready: false,
	}
}

// handleOTPrecomputeRequest handles OT precomputation requests from TEE_K
// This is used for both initial setup and extension (unified handler)
func (t *TEET) handleOTPrecomputeRequest(conn *shared.WSConnection, msg *teeproto.OTPrecomputeRequest) error {
	t.logger.Info("Received OT precompute request",
		zap.Uint32("count", msg.Count),
		zap.Bool("is_initial", msg.IsInitial))

	// Deserialize sender setups
	senderSetups, err := oprfmpc.DeserializeBulkCOSenderSetup(msg.OtSenderSetup)
	if err != nil {
		return fmt.Errorf("failed to deserialize sender setups: %w", err)
	}

	if len(senderSetups) != int(msg.Count) {
		return fmt.Errorf("sender setup count mismatch: expected %d, got %d", msg.Count, len(senderSetups))
	}

	t.otReceiverStateMu.Lock()
	receiverState := t.otReceiverState
	t.otReceiverStateMu.Unlock()

	// For initial setup, create new state
	if msg.IsInitial {
		receiverState = NewOTReceiverState()
		receiverState.epoch = msg.GetEpoch()
		t.otReceiverStateMu.Lock()
		t.otReceiverState = receiverState
		t.otReceiverStateMu.Unlock()
	} else {
		// For extension, receiver state must already exist
		if receiverState == nil {
			return fmt.Errorf("OT receiver state not initialized - cannot extend")
		}
	}

	// Generate receiver choices for each OT
	startTime := time.Now()
	receiverData, entries, err := t.generateReceiverChoices(senderSetups, oprfmpc.Curve())
	if err != nil {
		return fmt.Errorf("failed to generate receiver choices: %w", err)
	}

	t.logger.Info("Generated OT receiver choices",
		zap.Int("count", len(entries)),
		zap.Duration("duration", time.Since(startTime)))

	// Add entries to pool
	receiverState.pool.AddEntries(entries)

	// Serialize receiver data
	serializedData := oprfmpc.SerializeBulkOTReceiverData(receiverData)

	// Send response to TEE_K
	env := &teeproto.Envelope{
		SessionId:   "ot_precompute",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeResponse{
			OtPrecomputeResponse: &teeproto.OTPrecomputeResponse{
				Count:          msg.Count,
				OtReceiverData: serializedData,
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal OT precompute response: %w", err)
	}

	// Use wrapper's WriteMessage which has internal mutex for thread safety
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("failed to send OT precompute response: %w", err)
	}

	t.logger.Info("Sent OT precompute response to TEE_K",
		zap.Bool("is_initial", msg.IsInitial),
		zap.Int("pool_size", receiverState.pool.Available()))

	return nil
}

// generateReceiverChoices generates receiver choices for all OTs
// Returns the receiver data to send to garbler and entries to store locally
func (t *TEET) generateReceiverChoices(senderSetups []oprfmpc.SenderPublicSetup, curve elliptic.Curve) (*oprfmpc.OTReceiverData, []*oprfmpc.OTReceiverEntry, error) {
	if len(senderSetups) == 0 {
		return nil, nil, fmt.Errorf("no sender setups provided")
	}

	// Use the first setup's curve info
	curveName := senderSetups[0].CurveName
	ax := senderSetups[0].Ax
	ay := senderSetups[0].Ay

	entries := make([]*oprfmpc.OTReceiverEntry, len(senderSetups))
	points := make([]ot.ECPoint, len(senderSetups))

	// For precomputation, we generate random choice bits
	// These will be derandomized during online phase
	for i := range senderSetups {
		setup := senderSetups[i]

		// Generate random choice bit for precomputation
		var choiceBuf [1]byte
		if _, err := rand.Read(choiceBuf[:]); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random choice: %w", err)
		}
		choiceBit := (choiceBuf[0] & 1) == 1

		// Build choice for this OT
		// We need to generate B = g^b or B = A * g^b based on choice
		bundle, choicePoints, err := ot.BuildCOChoices(rand.Reader, curve, setup.Ax, setup.Ay, []bool{choiceBit})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build choice at index %d: %w", i, err)
		}

		// Store the bundle for later decryption
		// Also store the sender's public point A for ECDH-based label derivation
		entries[i] = &oprfmpc.OTReceiverEntry{
			ReceiverBundle:    bundle,
			SenderPublicPoint: ot.ECPoint{X: setup.Ax, Y: setup.Ay},
			Index:             i,
			Used:              false,
		}

		// Store the choice point
		points[i] = choicePoints[0]
	}

	receiverData := &oprfmpc.OTReceiverData{
		CurveName: curveName,
		Ax:        ax,
		Ay:        ay,
		Points:    points,
	}

	return receiverData, entries, nil
}

// handleOTPrecomputeComplete handles the completion acknowledgment from TEE_K
func (t *TEET) handleOTPrecomputeComplete(msg *teeproto.OTPrecomputeComplete) error {
	t.logger.Info("OT precomputation complete",
		zap.Uint32("pool_size", msg.PoolSize))

	t.otReceiverStateMu.Lock()
	if t.otReceiverState != nil {
		t.otReceiverState.ready = true
	}
	t.otReceiverStateMu.Unlock()

	t.otReady.Store(true)

	return nil
}

// isOTReceiverPoolReady checks if the OT receiver pool is ready for use
func (t *TEET) isOTReceiverPoolReady() bool {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	return t.otReceiverState != nil && t.otReceiverState.ready
}

// consumeOTReceiverEntries consumes OT receiver entries for an OPRF operation
func (t *TEET) consumeOTReceiverEntries(startIndex int, count int) ([]*oprfmpc.OTReceiverEntry, error) {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()

	if t.otReceiverState == nil {
		return nil, fmt.Errorf("OT receiver state not initialized")
	}
	if !t.otReceiverState.ready {
		return nil, fmt.Errorf("OT receiver pool not ready")
	}

	return t.otReceiverState.pool.Consume(startIndex, count)
}

// clearOTReceiverPool clears the OT receiver pool on disconnect
func (t *TEET) clearOTReceiverPool() {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()

	if t.otReceiverState != nil {
		t.otReceiverState.pool.Clear()
		t.otReceiverState.ready = false
	}
	t.otReady.Store(false)
	t.logger.Info("Cleared OT receiver pool")
}

// suspendOTReceiverPoolForReconnect is called on control disconnect. A ready
// pool is RETAINED so TEE_K can resume it on reconnect; the per-entry Used
// flags carry the replay defense across the gap. A not-ready pool is cleared.
func (t *TEET) suspendOTReceiverPoolForReconnect() {
	t.otReceiverStateMu.Lock()
	ready := t.otReceiverState != nil && t.otReceiverState.ready
	epoch := ""
	if t.otReceiverState != nil {
		epoch = t.otReceiverState.epoch
	}
	t.otReceiverStateMu.Unlock()

	if ready {
		t.logger.Info("Retained OT receiver pool across disconnect for resume", zap.String("epoch", epoch))
		return
	}
	t.clearOTReceiverPool()
}

// canResumeOTPool reports whether TEE_T still holds a pool TEE_K may resume:
// ready, same non-empty epoch, and long enough to cover TEE_K's next reserve
// index. A false result means TEE_K must run a fresh initial precompute.
func (t *TEET) canResumeOTPool(epoch string, nextIndex uint32) bool {
	t.otReceiverStateMu.Lock()
	defer t.otReceiverStateMu.Unlock()
	return t.otReceiverState != nil &&
		t.otReceiverState.ready &&
		t.otReceiverState.epoch != "" &&
		t.otReceiverState.epoch == epoch &&
		int(nextIndex) <= t.otReceiverState.pool.TotalCount()
}

// handleOTResumeRequest decides whether TEE_T can keep using its retained pool.
// Accept iff it still holds a ready pool with the same epoch that covers TEE_K's
// next reserve index; otherwise deny so TEE_K runs a fresh initial precompute.
func (t *TEET) handleOTResumeRequest(conn *shared.WSConnection, msg *teeproto.OTResumeRequest) error {
	accepted := t.canResumeOTPool(msg.GetEpoch(), msg.GetNextIndex())
	if accepted {
		t.otReady.Store(true)
	}

	t.logger.Info("OT resume request",
		zap.String("epoch", msg.GetEpoch()),
		zap.Uint32("next_index", msg.GetNextIndex()),
		zap.Bool("accepted", accepted))

	env := &teeproto.Envelope{
		SessionId:   "ot_precompute",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtResumeResponse{
			OtResumeResponse: &teeproto.OTResumeResponse{Accepted: accepted},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal OT resume response: %w", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("send OT resume response: %w", err)
	}
	return nil
}
