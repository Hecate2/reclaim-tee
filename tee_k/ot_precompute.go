package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/markkurossi/mpc/ot"
	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// OTPrecomputeState holds the OT precomputation state for the shared TEE_T connection
type OTPrecomputeState struct {
	mu             sync.Mutex
	pool           *oprfmpc.OTPool
	ready          bool
	curve          elliptic.Curve
	lastBatchStart int        // Start index of the last batch (for storing receiver points)
	responseChan   chan error // Signals when OT response is received
}

// NewOTPrecomputeState creates a new OT precomputation state
func NewOTPrecomputeState() *OTPrecomputeState {
	return &OTPrecomputeState{
		pool:         oprfmpc.NewOTPool(oprfmpc.OTPoolInitialSize),
		ready:        false,
		curve:        elliptic.P256(),
		responseChan: make(chan error, 1),
	}
}

// performOTPrecomputation performs OT precomputation and BLOCKS until complete.
// This is used for both initial setup and extension.
// Parameters:
//   - count: number of OTs to precompute
//   - isInitial: true for initial setup (marks pool ready after), false for extension
func (t *TEEK) performOTPrecomputation(count int, isInitial bool) error {
	t.logger.Info("Starting OT precomputation",
		zap.Int("count", count),
		zap.Bool("is_initial", isInitial))

	// Initialize state if not already done
	if t.otPrecomputeState == nil {
		t.otPrecomputeState = NewOTPrecomputeState()
	}

	state := t.otPrecomputeState

	// For extend, check preconditions
	if !isInitial {
		state.mu.Lock()
		if !state.ready {
			state.mu.Unlock()
			return fmt.Errorf("cannot extend: OT pool not ready")
		}
		if state.pool.IsExtendPending() {
			state.mu.Unlock()
			t.logger.Debug("OT extend already pending, skipping")
			return nil
		}
		state.pool.SetExtendPending(true)
		state.mu.Unlock()
	}

	// Generate and serialize OT setups
	startTime := time.Now()
	serializedSetups, err := t.generateAndSerializeOTSetups(count)
	if err != nil {
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("failed to generate OT setups: %w", err)
	}
	t.logger.Info("Generated OT sender setups",
		zap.Int("count", count),
		zap.Duration("duration", time.Since(startTime)))

	// Get connection to TEE_T
	conn := t.getSharedTEETConnection()
	if conn == nil {
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("no TEE_T connection available")
	}

	// Clear response channel before sending
	select {
	case <-state.responseChan:
	default:
	}

	// Send request to TEE_T
	env := &teeproto.Envelope{
		SessionId:   "ot_precompute",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeRequest{
			OtPrecomputeRequest: &teeproto.OTPrecomputeRequest{
				Count:         uint32(count),
				OtSenderSetup: serializedSetups,
				IsInitial:     isInitial,
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("failed to marshal OT precompute request: %w", err)
	}

	t.teetWriteMutex.Lock()
	err = conn.WriteMessage(websocket.BinaryMessage, data)
	t.teetWriteMutex.Unlock()

	if err != nil {
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("failed to send OT precompute request: %w", err)
	}

	t.logger.Info("Sent OT precompute request to TEE_T, waiting for response...")

	// BLOCK until response is received (with timeout)
	timeout := 60 * time.Second
	if count > oprfmpc.OTPoolInitialSize {
		timeout = 120 * time.Second // More time for larger batches
	}

	select {
	case err := <-state.responseChan:
		if err != nil {
			if !isInitial {
				state.pool.SetExtendPending(false)
			}
			return fmt.Errorf("OT precomputation failed: %w", err)
		}
		t.logger.Info("OT precomputation completed successfully",
			zap.Int("pool_available", state.pool.Available()))
		return nil

	case <-time.After(timeout):
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("OT precomputation timed out after %v", timeout)
	}
}

// generateAndSerializeOTSetups generates OT sender setups and serializes them
// This also stores the setups in the pool for later use
func (t *TEEK) generateAndSerializeOTSetups(count int) ([]byte, error) {
	state := t.otPrecomputeState
	state.mu.Lock()
	defer state.mu.Unlock()

	setups := make([]ot.COSenderSetup, count)
	startIdx := state.pool.TotalCount()

	for i := range count {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, state.curve)
		if err != nil {
			return nil, fmt.Errorf("failed to generate OT setup at index %d: %w", i, err)
		}
		setups[i] = setup
	}

	// Track the start index for this batch (needed when we receive receiver points)
	state.lastBatchStart = startIdx

	// Add entries to pool
	if err := state.pool.GenerateEntriesFromSetups(setups, startIdx); err != nil {
		return nil, fmt.Errorf("failed to add entries to pool: %w", err)
	}

	return oprfmpc.SerializeBulkCOSenderSetup(setups), nil
}

// handleOTPrecomputeResponse handles the response from TEE_T after precomputation
func (t *TEEK) handleOTPrecomputeResponse(msg *teeproto.OTPrecomputeResponse) error {
	t.logger.Info("Received OT precompute response",
		zap.Uint32("count", msg.Count))

	state := t.otPrecomputeState
	if state == nil {
		err := fmt.Errorf("OT precompute state not initialized")
		return err
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	// Verify count matches what we sent in this batch
	expectedCount := uint32(state.pool.TotalCount() - state.lastBatchStart)
	if msg.Count != expectedCount {
		err := fmt.Errorf("OT count mismatch: expected %d, got %d", expectedCount, msg.Count)
		// Signal error to waiting goroutine
		select {
		case state.responseChan <- err:
		default:
		}
		return err
	}

	// Deserialize receiver data - we MUST store the receiver points for ECDH
	receiverData, err := oprfmpc.DeserializeBulkOTReceiverData(msg.OtReceiverData)
	if err != nil {
		err = fmt.Errorf("failed to deserialize OT receiver data: %w", err)
		select {
		case state.responseChan <- err:
		default:
		}
		return err
	}

	// Store receiver points in the pool entries for ECDH-based label derivation
	if err := state.pool.StoreReceiverPoints(state.lastBatchStart, receiverData.Points); err != nil {
		err = fmt.Errorf("failed to store receiver points: %w", err)
		select {
		case state.responseChan <- err:
		default:
		}
		return err
	}

	// Clear extend pending flag if this was an extension
	wasExtend := state.pool.IsExtendPending()
	if wasExtend {
		state.pool.SetExtendPending(false)
	}

	// Mark pool as ready (for initial setup) or keep it ready (for extend)
	if !state.ready {
		state.ready = true
		// Send completion acknowledgment to TEE_T (only for initial setup)
		if err := t.sendOTPrecomputeComplete(); err != nil {
			t.logger.Error("Failed to send OT precompute complete", zap.Error(err))
			// Don't fail - pool is still usable
		}
	}

	// Signal success to waiting goroutine
	select {
	case state.responseChan <- nil:
	default:
	}

	t.logger.Info("OT precompute response processed",
		zap.Int("pool_available", state.pool.Available()),
		zap.Bool("was_extend", wasExtend))

	return nil
}

// sendOTPrecomputeComplete sends the completion message to TEE_T
func (t *TEEK) sendOTPrecomputeComplete() error {
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no TEE_T connection available")
	}

	poolSize := uint32(0)
	if t.otPrecomputeState != nil {
		poolSize = uint32(t.otPrecomputeState.pool.Available())
	}

	env := &teeproto.Envelope{
		SessionId:   "ot_precompute",
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeComplete{
			OtPrecomputeComplete: &teeproto.OTPrecomputeComplete{
				PoolSize: poolSize,
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal OT precompute complete: %w", err)
	}

	t.teetWriteMutex.Lock()
	err = conn.WriteMessage(websocket.BinaryMessage, data)
	t.teetWriteMutex.Unlock()

	if err != nil {
		return fmt.Errorf("failed to send OT precompute complete: %w", err)
	}

	t.logger.Info("OT precomputation complete, pool ready",
		zap.Uint32("pool_size", poolSize))

	return nil
}

// isOTPoolReady checks if the OT pool is ready for use
func (t *TEEK) isOTPoolReady() bool {
	if t.otPrecomputeState == nil {
		return false
	}
	t.otPrecomputeState.mu.Lock()
	defer t.otPrecomputeState.mu.Unlock()
	return t.otPrecomputeState.ready
}

// reserveOTEntries reserves OT entries for an OPRF operation
func (t *TEEK) reserveOTEntries(count int) (int, []*oprfmpc.OTPoolEntry, error) {
	if t.otPrecomputeState == nil {
		return 0, nil, fmt.Errorf("OT pool not initialized")
	}

	t.otPrecomputeState.mu.Lock()
	if !t.otPrecomputeState.ready {
		t.otPrecomputeState.mu.Unlock()
		return 0, nil, fmt.Errorf("OT pool not ready")
	}
	t.otPrecomputeState.mu.Unlock()

	startIdx, entries, err := t.otPrecomputeState.pool.Reserve(count)
	if err != nil {
		return 0, nil, err
	}

	// Check if we need to extend (asynchronously)
	if t.otPrecomputeState.pool.NeedsExtend() {
		go func() {
			if err := t.performOTPrecomputation(oprfmpc.OTPoolExtendSize, false); err != nil {
				t.logger.Error("Failed to extend OT pool", zap.Error(err))
			}
		}()
	}

	return startIdx, entries, nil
}

// clearOTPool clears the OT pool on disconnect
func (t *TEEK) clearOTPool() {
	if t.otPrecomputeState != nil {
		t.otPrecomputeState.mu.Lock()
		t.otPrecomputeState.pool.Clear()
		t.otPrecomputeState.ready = false
		t.otPrecomputeState.mu.Unlock()
		t.logger.Info("Cleared OT pool due to disconnect")
	}
}
