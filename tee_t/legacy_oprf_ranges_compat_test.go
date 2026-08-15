package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func TestLegacyOPRFRangesSubmissionKeepsOldClientConnectionAlive(t *testing.T) {
	const sessionID = "legacy-client-session"
	_, conn := newLegacyOPRFClientConnection(t, sessionID)

	writeLegacyOPRFRanges(t, conn, sessionID, &teeproto.OPRFRangesSubmission{
		SessionId: sessionID,
		Ranges:    []*teeproto.OPRFRangeSpec{{TlsStart: 7, TlsLength: 16}},
	})

	// A pong can only arrive if TEE_T consumed the legacy field-70 envelope and
	// remained in its read loop. Before the compatibility fix it sent ErrorData,
	// which old clients treat as terminal.
	pong := make(chan struct{}, 1)
	conn.SetPongHandler(func(string) error {
		select {
		case pong <- struct{}{}:
		default:
		}
		return nil
	})
	readDone := make(chan error, 1)
	go func() {
		_, data, err := conn.ReadMessage()
		if err == nil {
			var env teeproto.Envelope
			if unmarshalErr := proto.Unmarshal(data, &env); unmarshalErr != nil {
				err = unmarshalErr
			} else if env.GetError() != nil {
				err = fmt.Errorf("unexpected terminal response: %s", env.GetError().GetMessage())
			} else {
				err = fmt.Errorf("unexpected response type %T", env.Payload)
			}
		}
		readDone <- err
	}()
	if err := conn.WriteControl(websocket.PingMessage, []byte("still-open"), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("write ping after legacy submission: %v", err)
	}

	select {
	case <-pong:
	case err := <-readDone:
		t.Fatalf("legacy submission became terminal: %v", err)
	case <-time.After(time.Second):
		t.Fatal("TEE_T did not remain responsive after legacy submission")
	}
}

func TestLegacyOPRFRangesSubmissionRejectsInvalidCopies(t *testing.T) {
	const sessionID = "legacy-invalid-session"
	tests := []struct {
		name       string
		submission *teeproto.OPRFRangesSubmission
	}{
		{name: "missing nested session", submission: &teeproto.OPRFRangesSubmission{}},
		{name: "wrong nested session", submission: &teeproto.OPRFRangesSubmission{SessionId: "other-session"}},
		{
			name: "over shared range cap",
			submission: &teeproto.OPRFRangesSubmission{
				SessionId: sessionID,
				Ranges:    make([]*teeproto.OPRFRangeSpec, shared.MaxOPRFRangesPerSession+1),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, conn := newLegacyOPRFClientConnection(t, sessionID)
			writeLegacyOPRFRanges(t, conn, sessionID, test.submission)

			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			_, data, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("read terminal response: %v", err)
			}
			var env teeproto.Envelope
			if err := proto.Unmarshal(data, &env); err != nil {
				t.Fatalf("unmarshal terminal response: %v", err)
			}
			if env.GetError() == nil || !strings.Contains(env.GetError().GetMessage(), "Invalid legacy OPRF ranges submission") {
				t.Fatalf("terminal response = %T %q", env.Payload, env.GetError().GetMessage())
			}
		})
	}
}

func TestValidateLegacyOPRFRangesSubmissionRequiresCurrentExactSession(t *testing.T) {
	const sessionID = "current-session"
	identity := &teetSessionIdentity{
		session: &shared.Session{ID: sessionID},
		validate: func() error {
			return fmt.Errorf("superseded")
		},
	}
	err := validateLegacyOPRFRangesSubmission(identity, sessionID, &teeproto.OPRFRangesSubmission{SessionId: sessionID})
	if err == nil || !strings.Contains(err.Error(), "session is not current") {
		t.Fatalf("stale identity error = %v", err)
	}
}

func newLegacyOPRFClientConnection(t *testing.T, sessionID string) (*TEET, *websocket.Conn) {
	t.Helper()
	manager := NewTEETSessionManager()
	manager.SetLogger(shared.NewNopLogger())
	if err := manager.RegisterSession(sessionID); err != nil {
		t.Fatal(err)
	}
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetTEETSessionState(sessionID, &TEETSessionState{session: session})
	teet := &TEET{sessionManager: manager, logger: shared.NewNopLogger(), teekConnected: true}

	server := httptest.NewServer(http.HandlerFunc(teet.handleClientWebSocket))
	t.Cleanup(server.Close)
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial TEE_T: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return teet, conn
}

func writeLegacyOPRFRanges(t *testing.T, conn *websocket.Conn, sessionID string, submission *teeproto.OPRFRangesSubmission) {
	t.Helper()
	env := &teeproto.Envelope{
		SessionId: sessionID,
		Payload: &teeproto.Envelope_OprfRangesSubmission{
			OprfRangesSubmission: submission,
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.Fatalf("write legacy OPRF ranges: %v", err)
	}
}
