package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func TestTLS12CBCFinalSignatureUsesOnlyExplicitContractFields(t *testing.T) {
	teek, _, session, _, _ := newTEEKPeerLossSession(t)
	keyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	teek.signingKeyPair = keyPair
	state, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	state.CBCBinding = &teeproto.TLS12CBCSessionBinding{
		ContractVersion: 1, CipherSuite: minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		RecordMode:     teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_MAC_THEN_ENCRYPT,
		SessionBinding: make([]byte, 32),
	}
	state.CBCAuthenticatedRedactedRequest = []byte("redacted request")
	state.CBCRequestDigest = make([]byte, 32)
	state.CBCRequestRedactionRanges = []*teeproto.RequestRedactionRange{{Start: 1, Length: 2, Type: shared.RedactionTypeSensitive}}
	session.TranscriptData = [][]byte{[]byte("legacy request")}
	session.TranscriptDataTypes = []string{shared.TranscriptDataTypeHTTPRequestRedacted}
	session.ConsolidatedResponseKeystream = []byte("legacy keystream")
	session.ResponseState = &shared.ResponseSessionState{ResponseRedactionRanges: []shared.ResponseRedactionRange{{Start: 1, Length: 1}}}

	var delivered *teeproto.SignedMessage
	err = teek.generateComprehensiveSignatureForSession(session, state, func(env *teeproto.Envelope) error {
		delivered = env.GetSignedMessage()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivered == nil {
		t.Fatal("CBC signature was not delivered")
	}
	var payload teeproto.KOutputPayload
	if err := proto.Unmarshal(delivered.GetBody(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.GetTls12Cbc() == nil {
		t.Fatal("CBC signed payload is missing explicit contract")
	}
	if len(payload.GetTls12Cbc().GetRequestRedactionRanges()) != 1 {
		t.Fatal("CBC signed payload is missing request redaction ranges")
	}
	if len(payload.GetRedactedRequest()) != 0 || len(payload.GetRequestRedactionRanges()) != 0 ||
		len(payload.GetConsolidatedResponseKeystream()) != 0 || len(payload.GetResponseRedactionRanges()) != 0 {
		t.Fatal("CBC signed payload included legacy AEAD fields")
	}
	if len(delivered.GetResponsePackets()) != 0 || len(delivered.GetServerAppKey()) != 0 || delivered.GetCipherSuite() != 0 {
		t.Fatal("CBC signed message included legacy unsigned TLS metadata")
	}
}

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
