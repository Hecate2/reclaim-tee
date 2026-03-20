package main

import (
	"fmt"
	"maps"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

type TEETSessionState struct {
	TEETClientConn                 *websocket.Conn
	KeyShare                       []byte
	CipherSuite                    uint16
	PendingEncryptedRequest        *shared.EncryptedRequestData            // Legacy: single request
	PendingEncryptedFragments      map[uint64]*shared.EncryptedRequestData // New: multiple fragments by sequence number
	ExpectedFragmentCount          int                                     // Total number of fragments expected
	RequestProofStreams            [][]byte                                // Store R_SP streams for cryptographic signing
	ConsolidatedResponseCiphertext []byte                                  // Response ciphertext consolidation

	// MPC OPRF state
	OPRFKeyShare         []byte                                // 16-byte key share for MPC OPRF
	EvaluatorSessions    map[int]*oprfmpc.CMACEvaluatorSession // Per-range evaluator sessions
	ClientOPRFRanges     []*teeproto.OPRFRangeSpec             // Client-provided OPRF ranges
	ClientRangesReceived bool                                  // Whether client has sent ranges
	PendingRound1s       []*teeproto.OPRFMPCRound1             // Queued Round1 messages before client ranges arrive
	OPRFResults          map[int]*shared.OPRFResult            // Completed OPRF results by range index
	OPRFState            shared.OPRFSessionState               // Current OPRF processing state
	OPRFExpectedCount    int                                   // Number of OPRF results expected
	TLSSessionHash       []byte                                // Cached TLS session hash for replay protection

	// Per-session mutex for thread-safe access to OPRF state
	// Must be held when accessing EvaluatorSessions, OPRFResults, ClientOPRFRanges, or PendingRound1s
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

// SetEvaluatorSession safely sets an evaluator session for the given range index
func (s *TEETSessionState) SetEvaluatorSession(rangeIdx int, session *oprfmpc.CMACEvaluatorSession) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if s.EvaluatorSessions == nil {
		s.EvaluatorSessions = make(map[int]*oprfmpc.CMACEvaluatorSession)
	}
	s.EvaluatorSessions[rangeIdx] = session
}

// GetEvaluatorSession safely retrieves an evaluator session for the given range index
func (s *TEETSessionState) GetEvaluatorSession(rangeIdx int) (*oprfmpc.CMACEvaluatorSession, bool) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	session, ok := s.EvaluatorSessions[rangeIdx]
	return session, ok
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
	if s.OPRFState == shared.OPRFStateComplete {
		return false // Already complete
	}
	if len(s.OPRFResults) >= s.OPRFExpectedCount {
		s.OPRFState = shared.OPRFStateComplete
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

// AddPendingRound1 safely adds a pending Round1 message
func (s *TEETSessionState) AddPendingRound1(round1 *teeproto.OPRFMPCRound1) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	s.PendingRound1s = append(s.PendingRound1s, round1)
}

// GetAndClearPendingRound1s safely retrieves and clears pending Round1 messages
func (s *TEETSessionState) GetAndClearPendingRound1s() []*teeproto.OPRFMPCRound1 {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	pending := s.PendingRound1s
	s.PendingRound1s = nil
	return pending
}
