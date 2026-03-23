package shared

import (
	"context"
	"fmt"
	"sync"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

// SessionManagerInterface defines the interface for session management
type SessionManagerInterface interface {
	CreateSession(clientConn Connection) (string, error)
	RegisterSession(sessionID string) error
	ActivateSession(sessionID string, clientConn Connection) error
	CloseSession(sessionID string) error
	GetSession(sessionID string) (*Session, error)
	GetSessionByConnection(conn Connection) (*Session, error)
	RouteToSession(sessionID string, env *teeproto.Envelope) error
	RouteToTEEK(sessionID string, env *teeproto.Envelope) error
	RouteToClient(sessionID string, env *teeproto.Envelope) error
	StartCleanupRoutine()
	Stop()
}

// MaxSessions is the maximum number of concurrent sessions allowed
const MaxSessions = 100

// SessionManager provides unified session management
type SessionManager struct {
	sessions       map[string]*Session
	sessionsByConn map[Connection]*Session
	mutex          sync.Mutex
	cleanupTicker  *time.Ticker
	cleanupDone    chan bool
	sessionTimeout time.Duration
}

// Verify that SessionManager implements SessionManagerInterface
var _ SessionManagerInterface = (*SessionManager)(nil)

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:       make(map[string]*Session),
		sessionsByConn: make(map[Connection]*Session),
		cleanupDone:    make(chan bool),
		sessionTimeout: 30 * time.Minute, // Default 30 minute timeout
	}
}

// CreateSession creates a new session with secure UUID
func (sm *SessionManager) CreateSession(clientConn Connection) (string, error) {
	sm.mutex.Lock()
	currentCount := len(sm.sessions)
	sm.mutex.Unlock()

	if currentCount >= MaxSessions {
		return "", fmt.Errorf("maximum session limit reached (%d)", MaxSessions)
	}

	sessionID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	session := &Session{
		ID:             sessionID.String(),
		ClientConn:     clientConn,
		CreatedAt:      time.Now(),
		LastActiveAt:   time.Now(),
		State:          SessionStateNew,
		RedactionState: &RedactionSessionState{},
		ResponseState: &ResponseSessionState{
			PendingResponses:          make(map[string][]byte),
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
			PendingEncryptedResponses: make(map[uint64]*EncryptedResponseData),
		},
		Context: ctx,
		Cancel:  cancel,
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.sessions[session.ID] = session
	sm.sessionsByConn[clientConn] = session

	return session.ID, nil
}

// RegisterSession registers a session ID (for TEE_T to prepare for incoming client)
func (sm *SessionManager) RegisterSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if len(sm.sessions) >= MaxSessions {
		return fmt.Errorf("maximum session limit reached (%d)", MaxSessions)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	// Create placeholder session
	session := &Session{
		ID:             sessionID,
		CreatedAt:      time.Now(),
		State:          SessionStateNew,
		RedactionState: &RedactionSessionState{},
		ResponseState: &ResponseSessionState{
			PendingResponses:          make(map[string][]byte),
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
			PendingEncryptedResponses: make(map[uint64]*EncryptedResponseData),
		},
		Context: ctx,
		Cancel:  cancel,
	}

	sm.sessions[sessionID] = session
	return nil
}

// ActivateSession activates a registered session when client connects
func (sm *SessionManager) ActivateSession(sessionID string, clientConn Connection) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.ClientConn = clientConn
	session.LastActiveAt = time.Now()
	session.State = SessionStateActive
	sm.sessionsByConn[clientConn] = session

	return nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	return session, nil
}

// GetSessionByConnection retrieves a session by connection
func (sm *SessionManager) GetSessionByConnection(conn Connection) (*Session, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessionsByConn[conn]
	if !exists {
		return nil, fmt.Errorf("session not found for connection")
	}

	return session, nil
}

// CloseSession closes and removes a session
func (sm *SessionManager) CloseSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.IsClosed = true
	session.State = SessionStateClosed

	// Cancel context
	if session.Cancel != nil {
		session.Cancel()
	}

	if session.ClientConn != nil {
		session.ClientConn.Close()
		delete(sm.sessionsByConn, session.ClientConn)
	}

	delete(sm.sessions, sessionID)
	return nil
}

// StartCleanupRoutine starts the session cleanup routine
func (sm *SessionManager) StartCleanupRoutine() {
	sm.cleanupTicker = time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-sm.cleanupTicker.C:
				sm.cleanupExpiredSessions()
			case <-sm.cleanupDone:
				return
			}
		}
	}()
}

// Stop stops the session manager
func (sm *SessionManager) Stop() {
	if sm.cleanupTicker != nil {
		sm.cleanupTicker.Stop()
	}
	close(sm.cleanupDone)
}

// cleanupExpiredSessions removes expired sessions
func (sm *SessionManager) cleanupExpiredSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	for sessionID, session := range sm.sessions {
		if now.Sub(session.LastActiveAt) > sm.sessionTimeout {
			session.IsClosed = true
			if session.Cancel != nil {
				session.Cancel()
			}
			if session.ClientConn != nil {
				session.ClientConn.Close()
				delete(sm.sessionsByConn, session.ClientConn)
			}
			delete(sm.sessions, sessionID)
		}
	}
}

// Message routing methods
func (sm *SessionManager) RouteToSession(sessionID string, env *teeproto.Envelope) error {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return err
	}
	// Route to client connection
	if session.ClientConn != nil {
		if ws, ok := session.ClientConn.(*WSConnection); ok {
			// ensure session id is present
			if env.GetSessionId() == "" {
				env.SessionId = sessionID
			}
			data, err := proto.Marshal(env)
			if err != nil {
				return err
			}
			return ws.WriteMessage(websocket.BinaryMessage, data)
		}
	}

	return fmt.Errorf("no client connection in session %s", sessionID)
}

func (sm *SessionManager) RouteToTEEK(sessionID string, env *teeproto.Envelope) error {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return err
	}

	if session.TEEKConn == nil {
		return fmt.Errorf("no TEE_K connection in session %s", sessionID)
	}

	if ws, ok := session.TEEKConn.(*WSConnection); ok {
		if env.GetSessionId() == "" {
			env.SessionId = sessionID
		}
		data, err := proto.Marshal(env)
		if err != nil {
			return err
		}
		return ws.WriteMessage(websocket.BinaryMessage, data)
	}
	return fmt.Errorf("unsupported connection type for TEE_K")
}

func (sm *SessionManager) RouteToClient(sessionID string, env *teeproto.Envelope) error {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return err
	}

	if session.ClientConn == nil {
		return fmt.Errorf("no client connection in session %s", sessionID)
	}

	if ws, ok := session.ClientConn.(*WSConnection); ok {
		if env.GetSessionId() == "" {
			env.SessionId = sessionID
		}
		data, err := proto.Marshal(env)
		if err != nil {
			return err
		}
		return ws.WriteMessage(websocket.BinaryMessage, data)
	}
	return fmt.Errorf("unsupported client connection type")
}
