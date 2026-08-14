package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestFinalSignatureFailuresTerminateExactSessionWithoutRetry(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*TEEK, *atomic.Int32)
	}{
		{
			name: "marshal",
			inject: func(teek *TEEK, attempts *atomic.Int32) {
				teek.finalSignatureMarshal = func(*teeproto.KOutputPayload) ([]byte, error) {
					attempts.Add(1)
					return nil, errors.New("injected final marshal failure")
				}
			},
		},
		{
			name: "sign",
			inject: func(teek *TEEK, attempts *atomic.Int32) {
				teek.finalSignatureSign = func(*shared.SigningKeyPair, []byte) ([]byte, error) {
					attempts.Add(1)
					return nil, errors.New("injected final sign failure")
				}
			},
		},
		{
			name: "client write",
			inject: func(teek *TEEK, attempts *atomic.Int32) {
				teek.finalSignatureWrite = func(*shared.Session, *teeproto.Envelope) error {
					attempts.Add(1)
					return errors.New("injected final client write failure")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			teek, identity := newReadyFinalSignatureSession(t)
			session := identity.session
			var attempts atomic.Int32
			test.inject(teek, &attempts)

			if err := teek.checkAndSendSignatureIfReadyForIdentity(identity); err == nil {
				t.Fatal("injected final signature failure returned nil")
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("final operation attempts = %d, want 1", got)
			}
			if got := session.FinalSignatureStatus(); got != shared.FinalSignatureInProgress {
				t.Fatalf("final signature state = %d, want InProgress", got)
			}
			if !session.CleanedUp.Load() {
				t.Fatal("final signature failure did not clean exact session")
			}
			if _, err := teek.sessionManager.GetSession(session.ID); err == nil {
				t.Fatal("final signature failure retained session manager entry")
			}
		})
	}
}

func TestConcurrentFinalSignatureReadinessHasOneWriter(t *testing.T) {
	teek, identity := newReadyFinalSignatureSession(t)
	enteredWrite := make(chan struct{})
	allowWrite := make(chan struct{})
	var releaseWrite sync.Once
	defer releaseWrite.Do(func() { close(allowWrite) })
	var writes atomic.Int32
	var once sync.Once
	teek.finalSignatureWrite = func(*shared.Session, *teeproto.Envelope) error {
		writes.Add(1)
		once.Do(func() { close(enteredWrite) })
		<-allowWrite
		return nil
	}

	start := make(chan struct{})
	results := make(chan error, 32)
	for range 32 {
		go func() {
			<-start
			results <- teek.checkAndSendSignatureIfReadyForIdentity(identity)
		}()
	}
	close(start)
	select {
	case <-enteredWrite:
	case <-time.After(time.Second):
		t.Fatal("final signature writer did not reach delivery")
	}
	releaseWrite.Do(func() { close(allowWrite) })
	for range 32 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent readiness caller: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent readiness caller did not finish after writer release")
		}
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("final signature writes = %d, want 1", got)
	}
	if got := identity.session.FinalSignatureStatus(); got != shared.FinalSignatureSent {
		t.Fatalf("final signature state = %d, want Sent", got)
	}
}

func newReadyFinalSignatureSession(t *testing.T) (*TEEK, *teekSessionIdentity) {
	t.Helper()
	teek, cm, session, sessionConn, _ := newTEEKPeerLossSession(t)
	keyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	teek.signingKeyPair = keyPair
	session.TranscriptData = [][]byte{{1}}
	session.RedactionProcessingComplete = true
	session.RedactedStreams = []shared.SignedRedactedDecryptionStream{{}}
	state, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	state.OPRFState.Store(int32(shared.OPRFStateNone))
	identity := &teekSessionIdentity{session: session, sessionConn: sessionConn, validate: func() error {
		return cm.validateSessionConnection(sessionConn)
	}}
	return teek, identity
}
