package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"google.golang.org/protobuf/proto"
)

func TestHandleOPRFRangesFromClientAcceptsSupportedCounts(t *testing.T) {
	for _, count := range []int{0, 1, shared.MaxOPRFRangesPerSession} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			teek, state, sessionID := newOPRFRangeLimitTEEK(t, nil)
			msg := &teeproto.OPRFRangesSubmission{Ranges: makeOPRFRangeSpecs(count)}

			if err := teek.handleOPRFRangesFromClient(sessionID, msg); err != nil {
				t.Fatalf("handle %d ranges: %v", count, err)
			}
			if !state.OPRFRangesSubmitted.Load() {
				t.Fatal("accepted submission did not claim the one-shot guard")
			}
			if count == 0 {
				if got := shared.OPRFSessionState(state.OPRFState.Load()); got != shared.OPRFStateNone {
					t.Fatalf("zero-range OPRF state = %v, want none", got)
				}
				return
			}
			if !state.ClientRangesReceived.Load() {
				t.Fatal("accepted non-empty submission was not published")
			}
			if got := state.OPRFExpectedCount; got != count {
				t.Fatalf("expected count = %d, want %d", got, count)
			}
			if got := len(state.OPRFRanges); got != count {
				t.Fatalf("stored ranges = %d, want %d", got, count)
			}
		})
	}
}

func TestHandleOPRFRangesFromClientRejectsTwentyOneAtomically(t *testing.T) {
	clientConn, messages := newAckTestWebSocketWithMessages(t)
	teek, state, sessionID := newOPRFRangeLimitTEEK(t, clientConn)

	err := teek.handleOPRFRangesFromClient(sessionID, &teeproto.OPRFRangesSubmission{
		Ranges: makeOPRFRangeSpecs(shared.MaxOPRFRangesPerSession + 1),
	})
	if err == nil || !strings.Contains(err.Error(), "too many OPRF ranges") {
		t.Fatalf("handle oversized ranges error = %v, want range-limit error", err)
	}
	if state.OPRFRangesSubmitted.Load() || state.ClientRangesReceived.Load() {
		t.Fatal("oversized submission published an OPRF state flag")
	}
	if state.OPRFRanges != nil || state.GarblerOnlineSessions != nil || state.OPRFResults != nil || state.OPRFExpectedCount != 0 {
		t.Fatal("oversized submission mutated queued or evaluator state")
	}

	select {
	case data := <-messages:
		var env teeproto.Envelope
		if unmarshalErr := proto.Unmarshal(data, &env); unmarshalErr != nil {
			t.Fatalf("unmarshal error envelope: %v", unmarshalErr)
		}
		payload, ok := env.Payload.(*teeproto.Envelope_Error)
		if !ok {
			t.Fatalf("payload = %T, want Envelope_Error", env.Payload)
		}
		if !strings.Contains(payload.Error.GetMessage(), "too many OPRF ranges") {
			t.Fatalf("error message = %q, want range-limit error", payload.Error.GetMessage())
		}
	case <-time.After(time.Second):
		t.Fatal("client did not receive existing Envelope_Error")
	}
}

func newOPRFRangeLimitTEEK(t *testing.T, clientConn *shared.WSConnection) (*TEEK, *TEEKSessionState, string) {
	t.Helper()
	logger := shared.NewNopLogger()
	manager := NewTEEKSessionManager()
	manager.SetLogger(logger)
	sessionID, err := manager.CreateSession(clientConn)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	state := &TEEKSessionState{}
	manager.SetTEEKSessionState(sessionID, state)
	teek := &TEEK{
		sessionManager:    manager,
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
		oprfKeyShare:      make([]byte, 16),
	}
	if clientConn != nil {
		teek.activeSessions.Add(1)
	}
	return teek, state, sessionID
}

func makeOPRFRangeSpecs(count int) []*teeproto.OPRFRangeSpec {
	ranges := make([]*teeproto.OPRFRangeSpec, count)
	for i := range ranges {
		ranges[i] = &teeproto.OPRFRangeSpec{TlsStart: int32(i), TlsLength: 1}
	}
	return ranges
}
