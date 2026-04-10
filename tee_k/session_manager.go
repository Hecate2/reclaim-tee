package main

import (
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

type TEEKSessionState struct {
	HandshakeComplete bool
	ClientHello       []byte
	ServerHello       []byte
	MasterSecret      []byte
	KeyBlock          []byte
	KeyShare          []byte
	CipherSuite       uint16

	TLSClient         *minitls.Client
	WSConn2TLS        *WebSocketConn
	CurrentConn       *websocket.Conn
	CurrentRequest    *shared.RequestConnectionData
	TCPReady          chan bool
	CombinedKey       []byte
	ServerSequenceNum uint64

	// MPC OPRF state (2-round protocol with OT precomputation)
	ConsolidatedKeystream []byte                                    // Keystream for response decryption
	OPRFKeyShare          []byte                                    // 16-byte key share for MPC OPRF
	GarblerOnlineSessions map[int]*oprfmpc.CMACGarblerOnlineSession // Per-range garbler sessions
	OPRFRanges            []*teeproto.OPRFRangeSpec                 // Client-provided OPRF ranges
	OPRFResults           map[int]*shared.OPRFResult                // Completed OPRF results by range index
	OPRFState             atomic.Int32                              // Current OPRF processing state (shared.OPRFSessionState values)
	OPRFExpectedCount     int                                       // Number of OPRF results expected
	ClientRangesReceived  bool                                      // Whether client has sent ranges

	// Per-session mutex for thread-safe access to OPRF state
	// Must be held when accessing GarblerOnlineSessions, OPRFResults, or OPRFRanges
	oprfMu sync.Mutex
}

type TEEKSessionManager struct {
	*shared.SessionManager
	teekStates map[string]*TEEKSessionState
	stateMutex sync.Mutex
}

func NewTEEKSessionManager() *TEEKSessionManager {
	return &TEEKSessionManager{
		SessionManager: shared.NewSessionManager(),
		teekStates:     make(map[string]*TEEKSessionState),
	}
}

func (t *TEEKSessionManager) GetTEEKSessionState(sessionID string) (*TEEKSessionState, error) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	state, exists := t.teekStates[sessionID]
	if !exists {
		return nil, fmt.Errorf("TEE_K session state not found for session %s", sessionID)
	}
	return state, nil
}

func (t *TEEKSessionManager) SetTEEKSessionState(sessionID string, state *TEEKSessionState) {
	t.stateMutex.Lock()
	t.teekStates[sessionID] = state
	t.stateMutex.Unlock()
}

func (t *TEEKSessionManager) RemoveTEEKSessionState(sessionID string) {
	t.stateMutex.Lock()
	delete(t.teekStates, sessionID)
	t.stateMutex.Unlock()
}

func (t *TEEKSessionManager) CloseSession(sessionID string) error {
	t.RemoveTEEKSessionState(sessionID)
	return t.SessionManager.CloseSession(sessionID)
}

// LockOPRF acquires the per-session OPRF mutex
func (s *TEEKSessionState) LockOPRF() {
	s.oprfMu.Lock()
}

// UnlockOPRF releases the per-session OPRF mutex
func (s *TEEKSessionState) UnlockOPRF() {
	s.oprfMu.Unlock()
}

// SetGarblerOnlineSession safely sets a garbler session for the given range index
func (s *TEEKSessionState) SetGarblerOnlineSession(rangeIdx int, session *oprfmpc.CMACGarblerOnlineSession) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if s.GarblerOnlineSessions == nil {
		s.GarblerOnlineSessions = make(map[int]*oprfmpc.CMACGarblerOnlineSession)
	}
	s.GarblerOnlineSessions[rangeIdx] = session
}

// GetGarblerOnlineSession safely retrieves a garbler session for the given range index
func (s *TEEKSessionState) GetGarblerOnlineSession(rangeIdx int) (*oprfmpc.CMACGarblerOnlineSession, bool) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	session, ok := s.GarblerOnlineSessions[rangeIdx]
	return session, ok
}

// SetOPRFResult safely sets an OPRF result for the given range index
func (s *TEEKSessionState) SetOPRFResult(rangeIdx int, result *shared.OPRFResult) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if s.OPRFResults == nil {
		s.OPRFResults = make(map[int]*shared.OPRFResult)
	}
	s.OPRFResults[rangeIdx] = result
}

// GetOPRFResult safely retrieves an OPRF result for the given range index
func (s *TEEKSessionState) GetOPRFResult(rangeIdx int) (*shared.OPRFResult, bool) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	result, ok := s.OPRFResults[rangeIdx]
	return result, ok
}

// GetOPRFResultCount safely returns the number of completed OPRF results
func (s *TEEKSessionState) GetOPRFResultCount() int {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	return len(s.OPRFResults)
}

// TryMarkOPRFComplete atomically checks if all OPRF results are received and marks complete
// Returns true if this call transitioned to complete state (caller should trigger next steps)
func (s *TEEKSessionState) TryMarkOPRFComplete() bool {
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
func (s *TEEKSessionState) GetAllOPRFResults() map[int]*shared.OPRFResult {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	results := make(map[int]*shared.OPRFResult, len(s.OPRFResults))
	maps.Copy(results, s.OPRFResults)
	return results
}
