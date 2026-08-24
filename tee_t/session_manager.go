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
	"google.golang.org/protobuf/proto"
)

type pendingOPRFEvaluation struct {
	Session   *mpc.EvaluatorSession
	Payload   *mpc.OnlinePayload
	TLSStart  int
	TLSLength int
}

type TEETSessionState struct {
	session           *shared.Session
	controlGeneration uint64

	KeyShare                       []byte
	CipherSuite                    uint16
	PendingEncryptedRequest        *shared.EncryptedRequestData            // Legacy: single request
	PendingEncryptedFragments      map[uint64]*shared.EncryptedRequestData // New: multiple fragments by sequence number
	ExpectedFragmentCount          int                                     // Total number of fragments expected
	RequestProofStreams            [][]byte                                // Store R_SP streams for cryptographic signing
	ConsolidatedResponseCiphertext []byte                                  // Response ciphertext consolidation

	// Trusted-TEE TLS 1.2 CBC state. CBCReadStateReceived and
	// ResponseBatchReceived make the key handoff and response transcript
	// one-shot operations.
	CBCBinding                       *teeproto.TLS12CBCSessionBinding
	CBCReadContext                   *minitls.TLS12CBCContext
	CBCReadStateReceived             atomic.Bool
	CBCAuthenticatedResponse         []byte
	CBCAuthenticatedRedactedResponse []byte
	CBCResponseDigest                []byte
	CBCPlaintextRecordLengths        []uint32
	CBCCloseNotify                   bool
	CBCResponseRedactionRanges       []*teeproto.ResponseRedactionRange
	CBCRedactionSpecReceived         atomic.Bool
	cbcMu                            sync.Mutex

	// Counter-at-join: each handler increments once; whichever bumps it
	// to 2 dispatches. Replaces a racy "if other half present" pattern.
	RequestPartsArrived atomic.Int32

	// One TOutput signature per session. checkFinishedCondition can fire from
	// both the peer finished and OPRF completion; the CAS winner signs.
	TOutputSigned atomic.Bool

	// The client sends all TLS response records in one terminal batch. Accepting
	// another batch would let it replace or extend the response transcript.
	ResponseBatchReceived atomic.Bool

	// MPC OPRF state. TEE_K is the authoritative source of ranges: it relays
	// the client's ranges via OPRFOnlineFull (with TotalRanges), so TEE_T
	// derives everything from that single TCP-ordered stream. handleOPRFOnlineFull
	// initializes these on the first message (OPRFResults == nil guards init).
	OPRFKeyShare      []byte                     // 16-byte key share for MPC OPRF
	OPRFResults       map[int]*shared.OPRFResult // Completed OPRF results by range index
	PendingOPRF       map[int]*pendingOPRFEvaluation
	OPRFState         atomic.Int32 // Current OPRF processing state (shared.OPRFSessionState values)
	OPRFExpectedCount int          // Number of OPRF results expected
	TLSSessionHash    []byte       // Cached TLS session hash for replay protection

	// Per-session mutex for thread-safe access to OPRF state.
	oprfMu sync.Mutex
}

type TEETSessionManager struct {
	*shared.SessionManager
	teetStates map[string]*TEETSessionState
	stateMutex sync.Mutex
}

type teetSessionIdentity struct {
	session           *shared.Session
	controlGeneration uint64
	sessionConn       *SessionTEEKConnection
	validate          func() error

	// beforeOTReceiverConsume is a request-local synchronization hook used by
	// deterministic generation-replacement tests. Production identities leave
	// it nil.
	beforeOTReceiverConsume func()
}

func (i *teetSessionIdentity) ensureCurrent() error {
	if i == nil || i.session == nil {
		return fmt.Errorf("session identity is nil")
	}
	if i.validate != nil {
		return i.validate()
	}
	return nil
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

func (t *TEETSessionManager) stateForSession(session *shared.Session) (*TEETSessionState, error) {
	if session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	state := t.teetStates[session.ID]
	if state == nil || state.session != session {
		return nil, fmt.Errorf("TEE_T session state changed for session %s", session.ID)
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
	state := t.teetStates[sessionID]
	delete(t.teetStates, sessionID)
	t.stateMutex.Unlock()
	state.DestroySessionState()
}

func (t *TEETSessionManager) controlGenerationForSession(session *shared.Session) (uint64, bool) {
	if session == nil {
		return 0, false
	}
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	state := t.teetStates[session.ID]
	if state == nil || state.session != session {
		return 0, false
	}
	return state.controlGeneration, true
}

func (t *TEETSessionManager) isCurrentControlSession(session *shared.Session, controlGeneration uint64) bool {
	generation, ok := t.controlGenerationForSession(session)
	if !ok || generation != controlGeneration {
		return false
	}
	current, err := t.SessionManager.GetSession(session.ID)
	return err == nil && current == session
}

func (t *TEETSessionManager) isCurrentSession(session *shared.Session) bool {
	if session == nil {
		return false
	}
	if _, ok := t.controlGenerationForSession(session); !ok {
		return false
	}
	current, err := t.SessionManager.GetSession(session.ID)
	return err == nil && current == session
}

func (t *TEETSessionManager) closeSessionIfCurrent(session *shared.Session) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	t.stateMutex.Lock()
	state := t.teetStates[session.ID]
	var removed *TEETSessionState
	if state != nil && state.session == session {
		removed = state
		delete(t.teetStates, session.ID)
	}
	t.stateMutex.Unlock()
	removed.DestroySessionState()
	return t.SessionManager.CloseSessionIfCurrent(session)
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

// SetPendingOPRF stores a prepared evaluator session without overwriting an
// existing range or a completed result.
func (s *TEETSessionState) SetPendingOPRF(rangeIdx int, pending *pendingOPRFEvaluation) error {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if pending == nil || pending.Session == nil {
		return fmt.Errorf("nil pending OPRF evaluation")
	}
	if _, ok := s.OPRFResults[rangeIdx]; ok {
		return fmt.Errorf("OPRF range %d already completed", rangeIdx)
	}
	if s.PendingOPRF == nil {
		s.PendingOPRF = make(map[int]*pendingOPRFEvaluation)
	}
	if _, ok := s.PendingOPRF[rangeIdx]; ok {
		return fmt.Errorf("OPRF range %d already pending", rangeIdx)
	}
	s.PendingOPRF[rangeIdx] = pending
	return nil
}

// TakePendingOPRF atomically removes and returns the prepared evaluator state.
func (s *TEETSessionState) TakePendingOPRF(rangeIdx int) (*pendingOPRFEvaluation, bool) {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	pending, ok := s.PendingOPRF[rangeIdx]
	if ok {
		delete(s.PendingOPRF, rangeIdx)
	}
	return pending, ok
}

// RemovePendingOPRF removes only the exact unpublished or failed-send owner.
// A delayed cleanup cannot remove a replacement for the same range.
func (s *TEETSessionState) RemovePendingOPRF(rangeIdx int, expected *pendingOPRFEvaluation) bool {
	s.oprfMu.Lock()
	defer s.oprfMu.Unlock()
	if expected == nil || s.PendingOPRF[rangeIdx] != expected {
		return false
	}
	delete(s.PendingOPRF, rangeIdx)
	return true
}

// DestroyOPRFSessions detaches and clears every map-resident evaluator
// session. A round-3 handler first takes its session and therefore retains
// exclusive ownership through its own deferred Destroy.
func (s *TEETSessionState) DestroyOPRFSessions() {
	if s == nil {
		return
	}
	s.oprfMu.Lock()
	pendings := make([]*pendingOPRFEvaluation, 0, len(s.PendingOPRF))
	for rangeIdx, pending := range s.PendingOPRF {
		if pending != nil {
			pendings = append(pendings, pending)
		}
		delete(s.PendingOPRF, rangeIdx)
	}
	s.PendingOPRF = nil
	s.oprfMu.Unlock()
	for _, pending := range pendings {
		pending.Session.Destroy()
		pending.Payload.Release()
	}
}

func (s *TEETSessionState) DestroySessionState() {
	if s == nil {
		return
	}
	s.DestroyOPRFSessions()
	s.cbcMu.Lock()
	defer s.cbcMu.Unlock()
	s.CBCReadContext.Destroy()
	clear(s.CBCAuthenticatedResponse)
	s.CBCAuthenticatedResponse = nil
	clear(s.CBCAuthenticatedRedactedResponse)
	s.CBCAuthenticatedRedactedResponse = nil
	clear(s.ConsolidatedResponseCiphertext)
	s.ConsolidatedResponseCiphertext = nil
	clear(s.CBCResponseDigest)
	s.CBCResponseDigest = nil
	s.CBCCloseNotify = false
}

type tls12CBCSigningSnapshot struct {
	binding          *teeproto.TLS12CBCSessionBinding
	response         []byte
	redactedResponse []byte
	digest           []byte
	plaintextLengths []uint32
	closeNotify      bool
	ranges           []*teeproto.ResponseRedactionRange
	active           bool
}

// snapshotCBCResponseForOPRF returns the authenticated CBC plaintext while
// holding the mutex that publishes and destroys it. The boolean distinguishes
// a CBC session from the legacy split-AEAD path.
func (s *TEETSessionState) snapshotCBCResponseForOPRF() ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	s.cbcMu.Lock()
	defer s.cbcMu.Unlock()
	if s.CBCBinding == nil {
		return nil, false
	}
	return append([]byte(nil), s.CBCAuthenticatedResponse...), true
}

func (s *TEETSessionState) snapshotTLS12CBCSigningState() tls12CBCSigningSnapshot {
	if s == nil {
		return tls12CBCSigningSnapshot{}
	}
	s.cbcMu.Lock()
	defer s.cbcMu.Unlock()
	if s.CBCBinding == nil || s.CBCReadContext == nil {
		return tls12CBCSigningSnapshot{}
	}
	snapshot := tls12CBCSigningSnapshot{
		binding:          proto.Clone(s.CBCBinding).(*teeproto.TLS12CBCSessionBinding),
		response:         append([]byte(nil), s.CBCAuthenticatedResponse...),
		redactedResponse: append([]byte(nil), s.CBCAuthenticatedRedactedResponse...),
		digest:           append([]byte(nil), s.CBCResponseDigest...),
		plaintextLengths: append([]uint32(nil), s.CBCPlaintextRecordLengths...),
		closeNotify:      s.CBCCloseNotify,
		active:           true,
	}
	for _, item := range s.CBCResponseRedactionRanges {
		snapshot.ranges = append(snapshot.ranges, &teeproto.ResponseRedactionRange{Start: item.GetStart(), Length: item.GetLength()})
	}
	return snapshot
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
