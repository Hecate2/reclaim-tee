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
	mu           sync.Mutex
	pool         *oprfmpc.OTPool
	ready        bool
	curve        elliptic.Curve
	responseChan chan error // Signals when OT response is received

	// Pending setups awaiting confirmation (two-phase commit)
	// Setups are stored here after generation, only added to pool when receiver points arrive
	pendingSetups    []ot.COSenderSetup
	pendingStartIdx  int
	pendingIsInitial bool // Tracks whether the in-flight request was an initial precompute
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
	serializedSetups, err := t.generateAndSerializeOTSetups(count, isInitial)
	if err != nil {
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("failed to generate OT setups: %w", err)
	}
	t.logger.Info("Generated OT sender setups",
		zap.Int("count", count),
		zap.Duration("duration", time.Since(startTime)))

	// Get control connection to TEE_T
	if t.connManager == nil {
		t.clearPendingSetups() // Clear pending setups on failure
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("connection manager not initialized")
	}
	conn := t.connManager.GetControlConnection()
	if conn == nil {
		t.clearPendingSetups() // Clear pending setups on failure
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("no TEE_T control connection available")
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
		t.clearPendingSetups() // Clear pending setups on failure
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("failed to marshal OT precompute request: %w", err)
	}

	t.logger.Info("Sending to TEE_T",
		zap.String("type", "OtPrecomputeRequest"),
		zap.Int("bytes", len(data)),
		zap.Bool("is_initial", isInitial))

	// Use wrapper's WriteMessage which has internal mutex for thread safety
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.clearPendingSetups() // Clear pending setups on failure
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
			// Note: pendingSetups already cleared in handleOTPrecomputeResponse on error
			if !isInitial {
				state.pool.SetExtendPending(false)
			}
			return fmt.Errorf("OT precomputation failed: %w", err)
		}
		t.logger.Info("OT precomputation completed successfully",
			zap.Int("pool_available", state.pool.Available()))
		return nil

	case <-time.After(timeout):
		t.clearPendingSetups() // Clear pending setups on timeout
		if !isInitial {
			state.pool.SetExtendPending(false)
		}
		return fmt.Errorf("OT precomputation timed out after %v", timeout)
	}
}

// generateAndSerializeOTSetups generates OT sender setups and stores them as pending.
// Setups are NOT added to the pool until receiver points are received (two-phase commit).
// This prevents "ghost entries" if the extend operation fails.
func (t *TEEK) generateAndSerializeOTSetups(count int, isInitial bool) ([]byte, error) {
	state := t.otPrecomputeState
	state.mu.Lock()
	defer state.mu.Unlock()

	setups := make([]ot.COSenderSetup, count)

	for i := range count {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, state.curve)
		if err != nil {
			return nil, fmt.Errorf("failed to generate OT setup at index %d: %w", i, err)
		}
		setups[i] = setup
	}

	// Store as pending - will be added to pool only when response received.
	// pendingIsInitial drives whether the response handler must send an
	// OtPrecomputeComplete to TEE_T. The old code gated this on !state.ready,
	// which silently dropped the Complete signal when state.ready was stale-true
	// across a reconnect, leaving TEE_T's receiver pool permanently not-ready.
	state.pendingSetups = setups
	state.pendingStartIdx = state.pool.TotalCount()
	state.pendingIsInitial = isInitial

	return oprfmpc.SerializeBulkCOSenderSetup(setups), nil
}

// handleOTPrecomputeResponse handles the response from TEE_T after precomputation.
// This is the second phase of the two-phase commit: entries are added to pool
// atomically with their receiver points, preventing ghost entries on failure.
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

	// Verify we have pending setups
	if len(state.pendingSetups) == 0 {
		err := fmt.Errorf("no pending setups - unexpected response")
		state.pendingIsInitial = false
		t.signalResponseChan(err)
		return err
	}

	// Verify count matches pending setups
	if int(msg.Count) != len(state.pendingSetups) {
		err := fmt.Errorf("OT count mismatch: expected %d, got %d",
			len(state.pendingSetups), msg.Count)
		state.pendingSetups = nil // Clear pending on error
		state.pendingIsInitial = false
		t.signalResponseChan(err)
		return err
	}

	// Deserialize receiver data
	receiverData, err := oprfmpc.DeserializeBulkOTReceiverData(msg.OtReceiverData)
	if err != nil {
		err = fmt.Errorf("failed to deserialize OT receiver data: %w", err)
		state.pendingSetups = nil
		state.pendingIsInitial = false
		t.signalResponseChan(err)
		return err
	}

	// Verify point count matches
	if len(receiverData.Points) != len(state.pendingSetups) {
		err := fmt.Errorf("receiver point count mismatch: expected %d, got %d",
			len(state.pendingSetups), len(receiverData.Points))
		state.pendingSetups = nil
		state.pendingIsInitial = false
		t.signalResponseChan(err)
		return err
	}

	// NOW add entries to pool - atomically with receiver points
	// This is the key fix: entries only added when we have valid receiver points
	startIdx := state.pendingStartIdx
	for i, setup := range state.pendingSetups {
		entry := &oprfmpc.OTPoolEntry{
			SenderSetup:   setup,
			ReceiverPoint: receiverData.Points[i],
			Index:         startIdx + i,
			Used:          false,
		}
		state.pool.AddEntry(entry)
	}

	// Clear pending - successfully committed to pool
	state.pendingSetups = nil
	wasInitial := state.pendingIsInitial
	state.pendingIsInitial = false

	// Clear extend pending flag if this was an extension
	wasExtend := state.pool.IsExtendPending()
	if wasExtend {
		state.pool.SetExtendPending(false)
	}

	// For initial setup, mark pool ready and signal TEE_T to mark its
	// receiver pool ready. TEE_T re-creates its OTReceiverState on every
	// IsInitial request, so we MUST send Complete on every initial response —
	// not just the first one — or TEE_T's receiver pool stays not-ready and
	// rejects clients with "OT receiver pool not ready" until a manual restart.
	if wasInitial {
		state.ready = true
		if err := t.sendOTPrecomputeComplete(); err != nil {
			t.logger.Error("Failed to send OT precompute complete", zap.Error(err))
			// Don't fail - pool is still usable
		}
	}

	// Signal success to waiting goroutine
	t.signalResponseChan(nil)

	t.logger.Info("OT precompute response processed",
		zap.Int("pool_available", state.pool.Available()),
		zap.Bool("was_extend", wasExtend))

	return nil
}

// signalResponseChan signals the response channel with result (nil for success, error for failure)
// Must be called with state.mu held or from a context where channel access is safe
func (t *TEEK) signalResponseChan(err error) {
	select {
	case t.otPrecomputeState.responseChan <- err:
	default:
	}
}

// sendOTPrecomputeComplete sends the completion message to TEE_T
func (t *TEEK) sendOTPrecomputeComplete() error {
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}
	conn := t.connManager.GetControlConnection()
	if conn == nil {
		return fmt.Errorf("no TEE_T control connection available")
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

	t.logger.Info("Sending to TEE_T",
		zap.String("type", "OtPrecomputeComplete"),
		zap.Int("bytes", len(data)))

	// Use wrapper's WriteMessage which has internal mutex for thread safety
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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
		t.otPrecomputeState.pendingSetups = nil // Also clear any pending setups
		t.otPrecomputeState.pendingIsInitial = false
		t.otPrecomputeState.ready = false
		t.otPrecomputeState.mu.Unlock()
		t.logger.Info("Cleared OT pool due to disconnect")
	}
}

// clearPendingSetups discards pending setups on extend failure.
// This prevents ghost entries from being left in an inconsistent state.
func (t *TEEK) clearPendingSetups() {
	if t.otPrecomputeState != nil {
		t.otPrecomputeState.mu.Lock()
		t.otPrecomputeState.pendingSetups = nil
		t.otPrecomputeState.pendingIsInitial = false
		t.otPrecomputeState.mu.Unlock()
	}
}
