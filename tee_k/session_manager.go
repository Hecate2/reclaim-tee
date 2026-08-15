package main

import (
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

type TEEKSessionState struct {
	session *shared.Session

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

	// Count of TLS-1.3 App records forwarded by client as TCPData (type 0x17).
	AppRecordsViaTCPData atomic.Uint32

	// TEE_K-owned server-app-seq for response tag-secret generation. See
	// [[tcpdata-ack-protocol-2026-06-10]] — Option 3 / final design.
	responseTagSeq     atomic.Uint64
	responseTagSeqInit sync.Once

	// MPC OPRF state with OT precomputation.
	ConsolidatedKeystream []byte                       // Keystream for response decryption
	OPRFKeyShare          []byte                       // 16-byte key share for MPC OPRF
	GarblerOnlineSessions map[int]*mpc.GarblerSession  // Per-range garbler sessions
	OTReservations        map[int]*senderOTReservation // Receiver-consumption confirmations pending by range
	OPRFRanges            []*teeproto.OPRFRangeSpec    // Client-provided OPRF ranges
	OPRFResults           map[int]*shared.OPRFResult   // Completed OPRF results by range index
	OPRFState             atomic.Int32                 // Current OPRF processing state (shared.OPRFSessionState values)
	OPRFExpectedCount     int                          // Number of OPRF results expected
	ClientRangesReceived  atomic.Bool                  // publishes OPRFRanges/OPRFKeyShare/GarblerOnlineSessions/OPRFResults
	OPRFRangesSubmitted   atomic.Bool                  // one-shot: client submits ranges exactly once per session
	OPRFInitiationStarted atomic.Bool                  // one-shot: exactly one queued/immediate caller initiates all ranges

	// Per-session mutex for thread-safe access to OPRF state
	// Must be held when accessing GarblerOnlineSessions, OPRFResults, or OPRFRanges
	oprfMu sync.Mutex
}

type senderOTReservation struct {
	startIndex        uint64
	controlConn       *shared.WSConnection
	controlGeneration uint64
}

type TEEKSessionManager struct {
	*shared.SessionManager
	teekStates map[string]*TEEKSessionState
	stateMutex sync.Mutex
}

type teekSessionIdentity struct {
	session     *shared.Session
	sessionConn *SessionTEETConnection
	validate    func() error

	// beforeDispatch is a request-local synchronization hook used only by
	// deterministic buffered-frame replacement tests.
	beforeDispatch func()
}

func (i *teekSessionIdentity) ensureCurrent() error {
	if i == nil || i.session == nil {
		return fmt.Errorf("TEE_K session identity is incomplete")
	}
	if i.validate != nil {
		return i.validate()
	}
	if i.sessionConn == nil {
		return fmt.Errorf("TEE_K session connection identity is incomplete")
	}
	return nil
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

func (t *TEEKSessionManager) stateForSession(session *shared.Session) (*TEEKSessionState, error) {
	if session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	state := t.teekStates[session.ID]
	if state == nil || state.session != session {
		return nil, fmt.Errorf("TEE_K session state changed for session %s", session.ID)
	}
	return state, nil
}

func (t *TEEKSessionManager) SetTEEKSessionState(sessionID string, state *TEEKSessionState) {
	if state != nil && state.session == nil {
		if session, err := t.SessionManager.GetSession(sessionID); err == nil {
			state.session = session
		}
	}
	t.stateMutex.Lock()
	t.teekStates[sessionID] = state
	t.stateMutex.Unlock()
}

func (t *TEEKSessionManager) RemoveTEEKSessionState(sessionID string) {
	t.stateMutex.Lock()
	state := t.teekStates[sessionID]
	delete(t.teekStates, sessionID)
	t.stateMutex.Unlock()
	state.DestroyOPRFSessions()
}

func (t *TEEKSessionManager) CloseSession(sessionID string) error {
	t.RemoveTEEKSessionState(sessionID)
	return t.SessionManager.CloseSession(sessionID)
}

func (t *TEEKSessionManager) CloseSessionIfCurrent(session *shared.Session) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	t.stateMutex.Lock()
	var removed *TEEKSessionState
	if state := t.teekStates[session.ID]; state != nil && state.session == session {
		removed = state
		delete(t.teekStates, session.ID)
	}
	t.stateMutex.Unlock()
	removed.DestroyOPRFSessions()
	return t.SessionManager.CloseSessionIfCurrent(session)
}

// NextResponseTagSeq returns the next server-app-seq to use for a response
// tag-secret nonce. On first call, initializes from the offset = (App records
// arrived via TCPData) − (App records minitls consumed during handshake).
// Subsequent calls increment. TLS-1.3 only — TLS-1.2 uses client-provided seq.
func (s *TEEKSessionState) NextResponseTagSeq() uint64 {
	s.responseTagSeqInit.Do(func() {
		var consumed uint32
		if s.TLSClient != nil {
			consumed = s.TLSClient.HandshakeAppRecordsConsumed()
		}
		arrived := s.AppRecordsViaTCPData.Load()
		if arrived > consumed {
			s.responseTagSeq.Store(uint64(arrived - consumed))
		}
	})
	return s.responseTagSeq.Add(1) - 1
}

// publishOPRFClientInputs publishes client ranges and decides whether the
// already-published keystream should start initiation in the same transition.
func (s *TEEKSessionState) publishOPRFClientInputs(ranges []*teeproto.OPRFRangeSpec, keyShare []byte) bool {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	s.OPRFRanges = ranges
	s.OPRFState.Store(int32(shared.OPRFStateInProgress))
	s.OPRFExpectedCount = len(ranges)
	s.GarblerOnlineSessions = make(map[int]*mpc.GarblerSession)
	s.OTReservations = make(map[int]*senderOTReservation)
	s.OPRFResults = make(map[int]*shared.OPRFResult)
	s.OPRFKeyShare = keyShare
	s.ClientRangesReceived.Store(true)
	return len(s.ConsolidatedKeystream) != 0
}

// publishOPRFKeystream publishes the keystream and decides whether previously
// published client ranges should start initiation in the same transition.
func (s *TEEKSessionState) publishOPRFKeystream(keystream []byte) bool {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	s.ConsolidatedKeystream = keystream
	return s.ClientRangesReceived.Load() && len(s.OPRFRanges) != 0
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
func (s *TEEKSessionState) SetGarblerOnlineSession(rangeIdx int, session *mpc.GarblerSession) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if s.GarblerOnlineSessions == nil {
		s.GarblerOnlineSessions = make(map[int]*mpc.GarblerSession)
	}
	s.GarblerOnlineSessions[rangeIdx] = session
}

func (s *TEEKSessionState) TrackOTReservation(rangeIdx int, reservation *senderOTReservation) error {
	if reservation == nil {
		return fmt.Errorf("OT reservation is nil")
	}
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if s.OTReservations == nil {
		s.OTReservations = make(map[int]*senderOTReservation)
	}
	if s.OTReservations[rangeIdx] != nil {
		return fmt.Errorf("OT reservation already exists for range %d", rangeIdx)
	}
	s.OTReservations[rangeIdx] = reservation
	return nil
}

func (s *TEEKSessionState) ConfirmOTReservation(rangeIdx int, controlConn *shared.WSConnection, controlGeneration uint64) bool {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	reservation := s.OTReservations[rangeIdx]
	if reservation == nil || reservation.controlConn != controlConn || reservation.controlGeneration != controlGeneration {
		return false
	}
	delete(s.OTReservations, rangeIdx)
	return true
}

func (s *TEEKSessionState) AbandonOTReservation(rangeIdx int, expected *senderOTReservation) *senderOTReservation {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if s.OTReservations[rangeIdx] != expected {
		return nil
	}
	delete(s.OTReservations, rangeIdx)
	return expected
}

func (s *TEEKSessionState) AbandonAllOTReservations() []*senderOTReservation {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	reservations := make([]*senderOTReservation, 0, len(s.OTReservations))
	for rangeIdx, reservation := range s.OTReservations {
		reservations = append(reservations, reservation)
		delete(s.OTReservations, rangeIdx)
	}
	return reservations
}

// GetGarblerOnlineSession safely retrieves a garbler session for the given range index
func (s *TEEKSessionState) GetGarblerOnlineSession(rangeIdx int) (*mpc.GarblerSession, bool) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	session, ok := s.GarblerOnlineSessions[rangeIdx]
	return session, ok
}

// RemoveGarblerOnlineSession removes only the exact session supplied by its
// owner. A delayed failure cannot remove a replacement for the same range.
func (s *TEEKSessionState) RemoveGarblerOnlineSession(rangeIdx int, expected *mpc.GarblerSession) bool {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if expected == nil || s.GarblerOnlineSessions[rangeIdx] != expected {
		return false
	}
	delete(s.GarblerOnlineSessions, rangeIdx)
	return true
}

// TakeGarblerOnlineSession transfers exclusive ownership of one final-output
// session to the caller.
func (s *TEEKSessionState) TakeGarblerOnlineSession(rangeIdx int) (*mpc.GarblerSession, bool) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	session, ok := s.GarblerOnlineSessions[rangeIdx]
	if ok {
		delete(s.GarblerOnlineSessions, rangeIdx)
	}
	return session, ok
}

// DestroyOPRFSessions detaches every map-resident garbler session, then clears
// it outside the map lock. Sessions already taken by a final-output handler
// remain owned by that handler.
func (s *TEEKSessionState) DestroyOPRFSessions() {
	if s == nil {
		return
	}
	s.oprfMu.Lock()
	sessions := make([]*mpc.GarblerSession, 0, len(s.GarblerOnlineSessions))
	for rangeIdx, session := range s.GarblerOnlineSessions {
		sessions = append(sessions, session)
		delete(s.GarblerOnlineSessions, rangeIdx)
	}
	s.GarblerOnlineSessions = nil
	s.oprfMu.Unlock()
	for _, session := range sessions {
		session.Destroy()
	}
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
