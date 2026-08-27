package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func TestValidateTLS12CBCRequestPlaintextRequiresSingleRecord(t *testing.T) {
	if err := validateTLS12CBCRequestPlaintext(bytes.Repeat([]byte{'a'}, maxTLS12CBCRequestPlaintext)); err != nil {
		t.Fatalf("maximum single-record request rejected: %v", err)
	}
	if err := validateTLS12CBCRequestPlaintext(bytes.Repeat([]byte{'a'}, maxTLS12CBCRequestPlaintext+1)); err == nil {
		t.Fatal("multi-record CBC request was accepted")
	}
}

func TestValidateHTTPRequestFormatRejectsAmbiguousFraming(t *testing.T) {
	teek := &TEEK{logger: shared.NewNopLogger()}
	connection := &shared.RequestConnectionData{Hostname: "example.com", Port: 443}
	valid := "POST /submit HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 4\r\n\r\ndata"

	tests := []struct {
		name    string
		request string
		ranges  []shared.RequestRedactionRange
	}{
		{name: "pipelined request", request: "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "trailing bytes", request: "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\ntrailing"},
		{name: "duplicate content length", request: "POST / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ndata"},
		{name: "transfer encoding", request: "POST / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\ndata"},
		{name: "redacted content length", request: valid, ranges: []shared.RequestRedactionRange{{Start: strings.Index(valid, "Content-Length"), Length: len("Content-Length"), Type: shared.RedactionTypeSensitive}}},
		{name: "redaction crosses request version", request: valid, ranges: []shared.RequestRedactionRange{{Start: strings.Index(valid, "submit"), Length: len("submit HTTP"), Type: shared.RedactionTypeSensitive}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := teek.validateRedactionPositions(test.ranges, len(test.request)); err != nil {
				t.Fatalf("test range invalid: %v", err)
			}
			if err := teek.validateTLS12CBCHTTPRequestFormat([]byte(test.request), test.ranges, connection); err == nil {
				t.Fatal("ambiguous request framing was accepted")
			}
		})
	}
}

func TestStrictCBCRequestChecksDoNotChangeLegacyValidator(t *testing.T) {
	teek := &TEEK{logger: shared.NewNopLogger()}
	connection := &shared.RequestConnectionData{Hostname: "example.com", Port: 443}
	legacyRequest := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

	if err := teek.validateHTTPRequestFormat(legacyRequest, nil, connection); err != nil {
		t.Fatalf("legacy split-AEAD request behavior changed: %v", err)
	}
	if err := teek.validateTLS12CBCHTTPRequestFormat(legacyRequest, nil, connection); err == nil {
		t.Fatal("CBC validator accepted request without explicit Content-Length")
	}
}

func TestValidateTLS12CBCRequestAcceptsProviderSecretHeaderRanges(t *testing.T) {
	params := providers.HTTPProviderParams{
		URL:     "https://example.com/orders",
		Method:  "GET",
		Headers: map[string]string{"User-Agent": "unit-test"},
	}
	secret := providers.HTTPProviderSecretParams{
		CookieStr:           "session=opaque-cookie",
		AuthorisationHeader: "Bearer opaque-auth",
		Headers: map[string]string{
			"X-API-Key":       "opaque-one",
			"X-Client-Secret": "opaque-two",
		},
	}
	request, err := providers.CreateRequest(&secret, &params)
	if err != nil {
		t.Fatalf("create provider request: %v", err)
	}

	teek := &TEEK{logger: shared.NewNopLogger()}
	connection := &shared.RequestConnectionData{Hostname: "example.com", Port: 443}
	if err := teek.validateRedactionPositions(request.Redactions, len(request.Data)); err != nil {
		t.Fatalf("provider emitted invalid redaction positions: %v", err)
	}
	if err := teek.validateTLS12CBCHTTPRequestFormat(request.Data, request.Redactions, connection); err != nil {
		t.Fatalf("CBC validator rejected provider request: %v", err)
	}
}

func TestValidateTLS12CBCRequestRejectsRedactionAcrossHeaderLines(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\nX-First: one\r\nX-Second: two\r\n\r\n"
	start := strings.Index(request, "X-First")
	ranges := []shared.RequestRedactionRange{{
		Start:  start,
		Length: len("X-First: one\r\nX-Second: two"),
		Type:   shared.RedactionTypeSensitive,
	}}
	teek := &TEEK{logger: shared.NewNopLogger()}
	connection := &shared.RequestConnectionData{Hostname: "example.com", Port: 443}

	if err := teek.validateRedactionPositions(ranges, len(request)); err != nil {
		t.Fatalf("test range invalid: %v", err)
	}
	if err := teek.validateTLS12CBCHTTPRequestFormat([]byte(request), ranges, connection); err == nil {
		t.Fatal("CBC validator accepted a redaction spanning header-line CRLF")
	}
}

func TestTLS12CBCRequestFailureTerminatesSession(t *testing.T) {
	testTLS12CBCRequestFailureTerminatesSession(t, true)
}

func TestTLS12CBCRequestFailureTerminatesSessionWithoutAttestation(t *testing.T) {
	testTLS12CBCRequestFailureTerminatesSession(t, false)
}

func testTLS12CBCRequestFailureTerminatesSession(t *testing.T, terminalAttestation bool) {
	t.Helper()
	logger := shared.NewNopLogger()
	manager := NewTEEKSessionManager()
	manager.SetLogger(logger)
	otState := NewOTPrecomputeState()
	if err := otState.pool.Add(accountingSenderOTs(0, mpc.OTsPerOPRF)); err != nil {
		t.Fatalf("seed OT pool: %v", err)
	}
	otState.ready = true
	teek := &TEEK{
		sessionManager:    manager,
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
		otPrecomputeState: otState,
	}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	control, controlMessages := newAckTestWebSocketWithMessages(t)
	_, generation := installAckTestControl(cm, control)
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()
	teetSession := newAckTestWebSocket(t)
	cm.dialSessionConnectionFn = func(string) (*shared.WSConnection, error) {
		return teetSession, nil
	}

	ackResult := make(chan error, 1)
	go func() {
		select {
		case data := <-controlMessages:
			var created teeproto.Envelope
			if err := proto.Unmarshal(data, &created); err != nil {
				ackResult <- fmt.Errorf("unmarshal SessionCreated: %w", err)
				return
			}
			if created.GetSessionCreated() == nil {
				ackResult <- fmt.Errorf("control payload = %T, want SessionCreated", created.Payload)
				return
			}
			ack, err := proto.Marshal(&teeproto.Envelope{
				SessionId: created.GetSessionId(),
				Payload: &teeproto.Envelope_SessionCreatedAck{
					SessionCreatedAck: &teeproto.SessionCreatedAck{SessionId: created.GetSessionId()},
				},
			})
			if err != nil {
				ackResult <- fmt.Errorf("marshal SessionCreatedAck: %w", err)
				return
			}
			cm.handleControlMessage(control, generation, ack)
			ackResult <- nil
		case <-time.After(time.Second):
			ackResult <- fmt.Errorf("timed out waiting for SessionCreated")
		}
	}()

	server := httptest.NewServer(http.HandlerFunc(teek.handleWebSocket))
	t.Cleanup(server.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial TEE_K websocket: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := <-ackResult; err != nil {
		t.Fatal(err)
	}

	ready := readCBCClientEnvelope(t, client)
	if ready.GetSessionReady() == nil {
		t.Fatalf("client payload = %T, want SessionReady", ready.Payload)
	}
	sessionID := ready.GetSessionId()
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get client session: %v", err)
	}
	manager.SetTEEKSessionState(sessionID, &TEEKSessionState{session: session})
	if !terminalAttestation {
		cm.attestationMutex.Lock()
		cm.attestationVerified = false
		cm.attestationMutex.Unlock()
	}

	requestBytes, err := proto.Marshal(&teeproto.Envelope{
		SessionId: sessionID,
		Payload: &teeproto.Envelope_Tls12CbcRequest{
			Tls12CbcRequest: &teeproto.TLS12CBCRequest{},
		},
	})
	if err != nil {
		t.Fatalf("marshal CBC request: %v", err)
	}
	if err := client.WriteMessage(websocket.BinaryMessage, requestBytes); err != nil {
		t.Fatalf("send CBC request: %v", err)
	}

	clientError := readCBCClientEnvelope(t, client).GetError()
	if clientError == nil || !strings.Contains(clientError.GetMessage(), "outside a completed CBC session") {
		t.Fatalf("client error = %q, want CBC message-order failure", clientError.GetMessage())
	}
	if terminalAttestation {
		teetError := readCBCEnvelopeFromChannel(t, controlMessages, "TEE_T").GetError()
		if teetError == nil || teetError.GetMessage() != clientError.GetMessage() {
			t.Fatalf("TEE_T error = %q, want client error %q", teetError.GetMessage(), clientError.GetMessage())
		}
		assertSessionClosedMessage(t, controlMessages, sessionID, "session_cleanup")
	}
	waitForCBCSessionCleanup(t, manager, teek, sessionID)
	if !terminalAttestation {
		assertNoControlMessage(t, controlMessages, "unattested terminal notification")
	}
	if !session.CleanedUp.Load() {
		t.Fatal("CBC handler failure did not clean the session")
	}
	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("active sessions = %d, want 0", got)
	}
}

func waitForCBCSessionCleanup(t *testing.T, manager *TEEKSessionManager, teek *TEEK, sessionID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		_, sessionErr := manager.GetSession(sessionID)
		activeSessions := teek.activeSessions.Load()
		if sessionErr != nil && activeSessions == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("CBC cleanup incomplete: session_error=%v active_sessions=%d", sessionErr, activeSessions)
		}
		time.Sleep(time.Millisecond)
	}
}

func readCBCClientEnvelope(t *testing.T, client *websocket.Conn) *teeproto.Envelope {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}
	_, data, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read client envelope: %v", err)
	}
	env := new(teeproto.Envelope)
	if err := proto.Unmarshal(data, env); err != nil {
		t.Fatalf("unmarshal client envelope: %v", err)
	}
	return env
}

func readCBCEnvelopeFromChannel(t *testing.T, messages <-chan []byte, peer string) *teeproto.Envelope {
	t.Helper()
	select {
	case data := <-messages:
		env := new(teeproto.Envelope)
		if err := proto.Unmarshal(data, env); err != nil {
			t.Fatalf("unmarshal %s envelope: %v", peer, err)
		}
		return env
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s envelope", peer)
		return nil
	}
}

func TestPreCBCClientCannotNegotiateCBC(t *testing.T) {
	legacyDefault := &minitls.Config{MinVersion: minitls.VersionTLS12, MaxVersion: minitls.VersionTLS12}
	if err := validateClientCipherCapabilities(legacyDefault, false); err != nil {
		t.Fatalf("legacy AEAD defaults rejected: %v", err)
	}

	forcedCBC := &minitls.Config{CipherSuites: []uint16{minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}
	if err := validateClientCipherCapabilities(forcedCBC, false); err == nil {
		t.Fatal("pre-CBC client was allowed to force a CBC cipher suite")
	}
	if err := validateClientCipherCapabilities(forcedCBC, true); err != nil {
		t.Fatalf("CBC-capable client was rejected: %v", err)
	}
}
