package main

import (
	"sync"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

// N concurrent cleanupSession calls -> exactly one activeSessions decrement.
func TestCleanupSession_ConcurrentIsIdempotent(t *testing.T) {
	logger := shared.NewNopLogger()
	teek := &TEEK{
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
	}

	// No SetTEEKSessionState: exercises the cleanup-before-state-set case.
	sid, err := teek.sessionManager.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	teek.activeSessions.Add(1)

	// Fire many concurrent cleanupSession calls for that one session.
	const N = 64
	var wg sync.WaitGroup
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			teek.cleanupSession(sid)
		}()
	}
	wg.Wait()

	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("activeSessions = %d, want 0 (counter leaked: %d cleanup calls double-decremented or skipped)", got, N)
	}
}

// TestCleanupSession_DifferentSessions_NoCrossEffect makes sure the
// CleanedUp flag is per-session, not per-process — cleaning session A
// must not block cleanup of session B.
func TestCleanupSession_DifferentSessions_NoCrossEffect(t *testing.T) {
	logger := shared.NewNopLogger()
	teek := &TEEK{
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
	}

	const N = 32
	sids := make([]string, N)
	for i := range N {
		sid, err := teek.sessionManager.CreateSession(nil)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		teek.activeSessions.Add(1)
		sids[i] = sid
	}

	// Each session gets several concurrent cleanup attempts.
	var wg sync.WaitGroup
	for _, sid := range sids {
		for range 3 {
			wg.Go(func() {
				teek.cleanupSession(sid)
			})
		}
	}
	wg.Wait()

	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("activeSessions = %d, want 0 after cleaning %d sessions", got, N)
	}
}

// Cleanup must decrement whether or not TEEKSessionState was ever set.
func TestCleanupSession_BeforeAndAfterStateSet(t *testing.T) {
	logger := shared.NewNopLogger()
	teek := &TEEK{
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
	}

	// Case 1: cleanup runs BEFORE any SetTEEKSessionState — must still
	// decrement (the original audit finding).
	sid1, err := teek.sessionManager.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	teek.activeSessions.Add(1)
	teek.cleanupSession(sid1)
	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("case 1 (before state set): activeSessions = %d, want 0", got)
	}

	// Case 2: state set then replaced (simulating performTLSHandshakeAndHTTP).
	sid2, err := teek.sessionManager.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	teek.activeSessions.Add(1)
	teek.sessionManager.SetTEEKSessionState(sid2, &TEEKSessionState{HandshakeComplete: false})
	teek.sessionManager.SetTEEKSessionState(sid2, &TEEKSessionState{HandshakeComplete: true})
	teek.cleanupSession(sid2)
	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("case 2 (after state replaced): activeSessions = %d, want 0", got)
	}
}
