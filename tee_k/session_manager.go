package main

import (
	"fmt"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
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
