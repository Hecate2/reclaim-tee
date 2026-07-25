package main

import (
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

type TEETSessionState struct {
	KeyShare                       []byte
	CipherSuite                    uint16
	PendingEncryptedRequest        *shared.EncryptedRequestData            // Legacy: single request
	PendingEncryptedFragments      map[uint64]*shared.EncryptedRequestData // New: multiple fragments by sequence number
	ExpectedFragmentCount          int                                     // Total number of fragments expected
	RequestProofStreams            [][]byte                                // Store R_SP streams for cryptographic signing
	ConsolidatedResponseCiphertext []byte                                  // Response ciphertext consolidation

	// Counter-at-join: each handler increments once; whichever bumps it
	// to 2 dispatches. Replaces a racy "if other half present" pattern.
	RequestPartsArrived atomic.Int32

	// One TOutput signature per session. checkFinishedCondition can fire from
	// both the peer finished and OPRF completion; the CAS winner signs.
	TOutputSigned atomic.Bool

	// MPC OPRF state. TEE_K is the authoritative source of ranges: it relays
	// the client's ranges via OPRFOnlineFull (with TotalRanges), so TEE_T
	// derives everything from that single TCP-ordered stream. handleOPRFOnlineFull
	// initializes these on the first message (OPRFResults == nil guards init).
	OPRFKeyShare      []byte                     // 16-byte key share for MPC OPRF
	OPRFResults       map[int]*shared.OPRFResult // Completed OPRF results by range index
	OPRFState         atomic.Int32               // Current OPRF processing state (shared.OPRFSessionState values)
	OPRFExpectedCount int                        // Number of OPRF results expected
	TLSSessionHash    []byte                     // Cached TLS session hash for replay protection

	// Per-session mutex for thread-safe access to OPRFResults.
	oprfMu sync.Mutex
}

type TEETSessionManager struct {
	*shared.SessionManager
	teetStates map[string]*TEETSessionState
	stateMutex sync.Mutex
}

func NewTEETSessionManager() *TEETSessionManager {
	return &TEETSessionManager{
		SessionManager: shared.NewSessionManager(),
		teetStates:     make(map[string]*TEETSessionState),
	}
}

func (t *TEETSessionManager) GetTEETSessionState(sessionID string) (*TEETSessionState, error) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	state, exists := t.teetStates[sessionID]
	if !exists {
		return nil, fmt.Errorf("TEE_T session state not found for session %s", sessionID)
	}
	return state, nil
}

func (t *TEETSessionManager) SetTEETSessionState(sessionID string, state *TEETSessionState) {
	t.stateMutex.Lock()
	t.teetStates[sessionID] = state
	t.stateMutex.Unlock()
}

func (t *TEETSessionManager) RemoveTEETSessionState(sessionID string) {
	t.stateMutex.Lock()
	delete(t.teetStates, sessionID)
	t.stateMutex.Unlock()
}

func (t *TEETSessionManager) CloseSession(sessionID string) error {
	t.RemoveTEETSessionState(sessionID)
	return t.SessionManager.CloseSession(sessionID)
}

// AppendResponseCiphertext adds response ciphertext to the consolidated stream
func (s *TEETSessionState) AppendResponseCiphertext(ciphertext []byte) {
	s.ConsolidatedResponseCiphertext = append(s.ConsolidatedResponseCiphertext, ciphertext...)
}

// AddRequestProofStream adds an R_SP stream for cryptographic verification
func (s *TEETSessionState) AddRequestProofStream(stream []byte) {
	s.RequestProofStreams = append(s.RequestProofStreams, stream)
}

// LockOPRF acquires the per-session OPRF mutex
func (s *TEETSessionState) LockOPRF() {
	s.oprfMu.Lock()
}

// UnlockOPRF releases the per-session OPRF mutex
func (s *TEETSessionState) UnlockOPRF() {
	s.oprfMu.Unlock()
}

// SetOPRFResult safely sets an OPRF result for the given range index
func (s *TEETSessionState) SetOPRFResult(rangeIdx int, result *shared.OPRFResult) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if s.OPRFResults == nil {
		s.OPRFResults = make(map[int]*shared.OPRFResult)
	}
	s.OPRFResults[rangeIdx] = result
}

// GetOPRFResult safely retrieves an OPRF result for the given range index
func (s *TEETSessionState) GetOPRFResult(rangeIdx int) (*shared.OPRFResult, bool) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	result, ok := s.OPRFResults[rangeIdx]
	return result, ok
}

// GetOPRFResultCount safely returns the number of completed OPRF results
func (s *TEETSessionState) GetOPRFResultCount() int {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	return len(s.OPRFResults)
}

// TryMarkOPRFComplete atomically checks if all OPRF results are received and marks complete
// Returns true if this call transitioned to complete state (caller should trigger next steps)
func (s *TEETSessionState) TryMarkOPRFComplete() bool {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if shared.OPRFSessionState(s.OPRFState.Load()) == shared.OPRFStateComplete {
		return false // Already complete
	}
	if len(s.OPRFResults) >= s.OPRFExpectedCount {
		s.OPRFState.Store(int32(shared.OPRFStateComplete))
		return true
	}
	return false
}

// GetAllOPRFResults safely returns a copy of all OPRF results
func (s *TEETSessionState) GetAllOPRFResults() map[int]*shared.OPRFResult {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	results := make(map[int]*shared.OPRFResult, len(s.OPRFResults))
	maps.Copy(results, s.OPRFResults)
	return results
}
