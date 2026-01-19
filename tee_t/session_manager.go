package main

import (
	"fmt"
	"sync"

	"tee-mpc/shared"

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
