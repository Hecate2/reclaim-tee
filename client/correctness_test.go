package client

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func signedKMessage(t *testing.T, pair *shared.SigningKeyPair, session string) *teeproto.SignedMessage {
	t.Helper()
	body, err := proto.Marshal(&teeproto.KOutputPayload{SessionId: session, ConsolidatedResponseKeystream: []byte("k-stream")})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := pair.SignData(body)
	if err != nil {
		t.Fatal(err)
	}
	return &teeproto.SignedMessage{BodyType: teeproto.BodyType_BODY_TYPE_K_OUTPUT, Body: body, Signature: signature, EthAddress: []byte(pair.GetEthAddress().Hex())}
}

func signedTMessage(t *testing.T, pair *shared.SigningKeyPair, session string) *teeproto.SignedMessage {
	t.Helper()
	body, err := proto.Marshal(&teeproto.TOutputPayload{SessionId: session, ConsolidatedResponseCiphertext: []byte("t-stream")})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := pair.SignData(body)
	if err != nil {
		t.Fatal(err)
	}
	return &teeproto.SignedMessage{BodyType: teeproto.BodyType_BODY_TYPE_T_OUTPUT, Body: body, Signature: signature, EthAddress: []byte(pair.GetEthAddress().Hex())}
}

func clientWithSession(session string) *Client {
	c := NewClient("")
	c.SetMode(ModeStandalone)
	c.sessionID = session
	return c
}

func TestSignedMessagesAreVerifiedBeforePublication(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := clientWithSession("session-1")
	if err := c.acceptTEEKSignedMessage("session-1", signedKMessage(t, pair, "session-1")); err != nil {
		t.Fatalf("accept valid TEE_K message: %v", err)
	}
	if err := c.acceptTEETSignedMessage("session-1", signedTMessage(t, pair, "session-1")); err != nil {
		t.Fatalf("accept valid TEE_T message: %v", err)
	}
	transcripts, err := c.buildTranscriptResults()
	if err != nil {
		t.Fatal(err)
	}
	if !transcripts.BothReceived || !transcripts.BothSignaturesValid {
		t.Fatalf("valid messages reported invalid: %+v", transcripts)
	}
	validation, err := c.buildValidationResults()
	if err != nil {
		t.Fatal(err)
	}
	if !validation.AllValidationsPassed || !validation.TranscriptValidation.OverallValid {
		t.Fatalf("valid messages failed validation: %+v", validation)
	}
}

func TestSecureBootGenerationIsSignedWhileReportStaysLegacyCompatible(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	body, err := proto.Marshal(&teeproto.KOutputPayload{
		SessionId:                     "session-1",
		ConsolidatedResponseKeystream: []byte("k-stream"),
		AttestationType:               shared.AttestationTypeSecureBoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := pair.SignData(body)
	if err != nil {
		t.Fatal(err)
	}
	signed := &teeproto.SignedMessage{
		BodyType:  teeproto.BodyType_BODY_TYPE_K_OUTPUT,
		Body:      body,
		Signature: signature,
		AttestationReport: &teeproto.AttestationReport{
			Type:   shared.AttestationTypeSEVSNP,
			Report: []byte("legacy-tagged-secure-evidence"),
		},
	}

	c := NewClient("wss://tee-k.example/ws")
	c.SetTEETURL("wss://tee-t.example/ws")
	c.SetMode(ModeEnclave)
	c.sessionID = "session-1"
	c.verifySEVAttestation = func([]byte) ([]string, error) {
		return []string{"tee_k_public_key:" + pair.GetEthAddress().Hex()}, nil
	}
	if err := c.acceptTEEKSignedMessage("session-1", signed); err != nil {
		t.Fatalf("secure marker with legacy-compatible report rejected: %v", err)
	}
	if got := stripUnsignedFields(signed).GetBody(); !bytes.Equal(got, body) {
		t.Fatal("verification-bundle filtering changed the signed body marker")
	}

	var downgraded teeproto.KOutputPayload
	if err := proto.Unmarshal(body, &downgraded); err != nil {
		t.Fatal(err)
	}
	downgraded.AttestationType = shared.AttestationTypeSEVSNP
	downgradedBody, err := proto.Marshal(&downgraded)
	if err != nil {
		t.Fatal(err)
	}
	tampered := proto.Clone(signed).(*teeproto.SignedMessage)
	tampered.Body = downgradedBody
	c2 := NewClient("wss://tee-k.example/ws")
	c2.SetTEETURL("wss://tee-t.example/ws")
	c2.SetMode(ModeEnclave)
	c2.sessionID = "session-1"
	c2.verifySEVAttestation = c.verifySEVAttestation
	if err := c2.acceptTEEKSignedMessage("session-1", tampered); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("signed generation downgrade result = %v, want signature failure", err)
	}
}

func TestInvalidSignedMessagesNeverPublish(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		envelope   string
		message    func(*testing.T) *teeproto.SignedMessage
		wantErrSub string
	}{
		{
			name:     "empty signature",
			envelope: "session-1",
			message: func(t *testing.T) *teeproto.SignedMessage {
				msg := signedKMessage(t, pair, "session-1")
				msg.Signature = nil
				return msg
			},
			wantErrSub: "signature",
		},
		{
			name:     "altered signature",
			envelope: "session-1",
			message: func(t *testing.T) *teeproto.SignedMessage {
				msg := signedKMessage(t, pair, "session-1")
				msg.Signature[0] ^= 0xff
				return msg
			},
			wantErrSub: "signature",
		},
		{
			name:     "wrong body type",
			envelope: "session-1",
			message: func(t *testing.T) *teeproto.SignedMessage {
				msg := signedKMessage(t, pair, "session-1")
				msg.BodyType = teeproto.BodyType_BODY_TYPE_T_OUTPUT
				return msg
			},
			wantErrSub: "body type",
		},
		{
			name:     "wrong envelope session",
			envelope: "session-2",
			message: func(t *testing.T) *teeproto.SignedMessage {
				return signedKMessage(t, pair, "session-1")
			},
			wantErrSub: "envelope session mismatch",
		},
		{
			name:     "wrong signed body session",
			envelope: "session-1",
			message: func(t *testing.T) *teeproto.SignedMessage {
				return signedKMessage(t, pair, "session-2")
			},
			wantErrSub: "body session mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clientWithSession("session-1")
			err := c.acceptTEEKSignedMessage(tt.envelope, tt.message(t))
			if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("expected %q error, got %v", tt.wantErrSub, err)
			}
			if c.teekSignedMessage != nil || c.teeKSignatureValid {
				t.Fatal("invalid signed message was published")
			}
			transcripts, _ := c.buildTranscriptResults()
			if transcripts.BothSignaturesValid {
				t.Fatal("invalid message reported as a valid signature")
			}
		})
	}
}

func TestGetAttestorClientRetriesAfterConfigurationFailure(t *testing.T) {
	c := NewClient("")
	if got, err := c.getAttestorClient(); err == nil || got != nil {
		t.Fatalf("first call = (%v, %v), want nil configuration error", got, err)
	}
	c.attestorURL = "ws://attestor.example/ws"
	first, err := c.getAttestorClient()
	if err != nil || first == nil {
		t.Fatalf("retry failed: (%v, %v)", first, err)
	}
	second, err := c.getAttestorClient()
	if err != nil || second != first {
		t.Fatalf("successful client was not reused exactly: (%p, %p, %v)", first, second, err)
	}
}

func TestAttestorConnectionRetriesAfterDialFailure(t *testing.T) {
	server := newAttestorInitServer(t)
	defer server.Close()
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client := NewAttestorClient(wsURL(server.URL), pair.PrivateKey, nil, GetLogger("attestor-test", false))
	var dials atomic.Int32
	client.dial = func(rawURL string) (*websocket.Conn, error) {
		if dials.Add(1) == 1 {
			return nil, errors.New("injected dial failure")
		}
		conn, _, err := websocket.DefaultDialer.Dial(rawURL, nil)
		return conn, err
	}
	if err := client.ensureConnected(); err == nil || !strings.Contains(err.Error(), "injected dial failure") {
		t.Fatalf("first dial error = %v", err)
	}
	if err := client.ensureConnected(); err != nil {
		t.Fatalf("retry connect: %v", err)
	}
	if err := client.ensureConnected(); err != nil {
		t.Fatalf("reuse connect: %v", err)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dial count = %d, want 2", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOPRFRangeProcessingPublishesAtomicallyAndRetries(t *testing.T) {
	c := NewClient("")
	c.oprfRedactionRanges = map[int]int{20: 2, 10: 1}
	failSecond := true
	var order []int
	c.processOPRFRange = func(start, length int) (*OPRFRangeData, error) {
		order = append(order, start)
		if start == 20 && failSecond {
			return nil, errors.New("injected range-2 failure")
		}
		return &OPRFRangeData{Start: start, Length: length, FinalOutput: []byte{byte(start)}}, nil
	}
	if err := c.ProcessOPRFForHashedRanges(nil); err == nil || !strings.Contains(err.Error(), "range-2 failure") {
		t.Fatalf("first processing error = %v", err)
	}
	if got := c.GetOPRFRanges(); len(got) != 0 {
		t.Fatalf("partial OPRF map published: %+v", got)
	}
	if c.oprfLegacyComplete {
		t.Fatal("failed OPRF attempt marked complete")
	}
	failSecond = false
	if err := c.ProcessOPRFForHashedRanges(nil); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if got := c.GetOPRFRanges(); len(got) != 2 {
		t.Fatalf("retry published %d ranges, want 2", len(got))
	}
	wantOrder := []int{10, 20, 10, 20}
	if fmt.Sprint(order) != fmt.Sprint(wantOrder) {
		t.Fatalf("processing order = %v, want %v", order, wantOrder)
	}
}

func TestConcurrentHTTPRequestStartHasOneWinner(t *testing.T) {
	c := NewClient("")
	defer c.Close()
	c.providerParams = &providers.HTTPProviderParams{URL: "https://example.com/", Method: "GET"}
	c.providerSecretParams = &providers.HTTPProviderSecretParams{AuthorisationHeader: "Bearer test"}
	const callers = 16
	results := make(chan error, callers)
	for range callers {
		go func() { results <- c.RequestHTTP() }()
	}
	var successes int
	for range callers {
		err := <-results
		if err == nil {
			successes++
			continue
		}
		if !strings.Contains(err.Error(), "protocol request already started") {
			t.Fatalf("unexpected losing start error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful protocol starts = %d, want 1", successes)
	}
}

func TestTEEConnectFailureClosesPartialPairAndCanRetry(t *testing.T) {
	kServer, kAccepted, kClosed := newPassiveWSServer(t)
	defer kServer.Close()
	tServer, _, _ := newPassiveWSServer(t)
	defer tServer.Close()
	c := NewClient(wsURL(kServer.URL))
	c.SetTEETURL(wsURL(tServer.URL))
	var kDials, tDials atomic.Int32
	c.teeDial = func(role, rawURL string) (*websocket.Conn, error) {
		if role == "tee_k" {
			kDials.Add(1)
		} else if tDials.Add(1) == 1 {
			return nil, errors.New("injected TEE_T dial failure")
		}
		conn, _, err := websocket.DefaultDialer.Dial(rawURL, nil)
		return conn, err
	}
	r := &ReclaimClient{Client: c, logger: c.logger}
	if err := r.Connect(); err == nil {
		t.Fatal("expected first pair connection to fail")
	}
	select {
	case <-kAccepted:
	case <-time.After(time.Second):
		t.Fatal("TEE_K did not accept first connection")
	}
	select {
	case <-kClosed:
	case <-time.After(time.Second):
		t.Fatal("partial TEE_K connection was not closed")
	}
	if c.hasTEEConnection("TEE_K") || c.hasTEEConnection("TEE_T") {
		t.Fatal("partial pair remained published")
	}
	if err := r.Connect(); err != nil {
		t.Fatalf("pair retry failed: %v", err)
	}
	if got := kDials.Load(); got != 2 {
		t.Fatalf("TEE_K dials = %d, want 2", got)
	}
	if got := tDials.Load(); got != 2 {
		t.Fatalf("TEE_T dials = %d, want 2", got)
	}
	c.Close()
}

func TestUnexpectedTEEReadFailureFailsImmediatelyAndClosesPair(t *testing.T) {
	for _, failedRole := range []string{"TEE_K", "TEE_T"} {
		t.Run(failedRole, func(t *testing.T) {
			kServer, kAccepted, _ := newPassiveWSServer(t)
			defer kServer.Close()
			tServer, tAccepted, _ := newPassiveWSServer(t)
			defer tServer.Close()
			c := NewClient(wsURL(kServer.URL))
			c.SetTEETURL(wsURL(tServer.URL))
			if err := c.connectToTEEs(); err != nil {
				t.Fatal(err)
			}
			kPeer := <-kAccepted
			tPeer := <-tAccepted
			if failedRole == "TEE_K" {
				_ = kPeer.Close()
			} else {
				_ = tPeer.Close()
			}
			select {
			case err := <-c.WaitForCompletion():
				if err == nil || !strings.Contains(err.Error(), failedRole+" connection closed unexpectedly") {
					t.Fatalf("unexpected completion error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("disconnect fell through to a generic timeout")
			}
			if c.hasTEEConnection("TEE_K") || c.hasTEEConnection("TEE_T") {
				t.Fatal("disconnect did not close both TEE sockets")
			}
		})
	}
}

func TestTEEReadFailureIsNotBlockedByPeerDial(t *testing.T) {
	kServer, kAccepted, _ := newPassiveWSServer(t)
	defer kServer.Close()
	c := NewClient(wsURL(kServer.URL))
	c.SetTEETURL("ws://tee-t.test/ws")
	tDialStarted := make(chan struct{})
	releaseTDial := make(chan struct{})
	c.teeDial = func(role, rawURL string) (*websocket.Conn, error) {
		if role == "tee_t" {
			close(tDialStarted)
			<-releaseTDial
			return nil, errors.New("released TEE_T dial")
		}
		conn, _, err := websocket.DefaultDialer.Dial(rawURL, nil)
		return conn, err
	}
	if err := c.ConnectToTEEK(); err != nil {
		t.Fatal(err)
	}
	kPeer := <-kAccepted
	tDialDone := make(chan error, 1)
	go func() { tDialDone <- c.ConnectToTEET() }()
	<-tDialStarted
	_ = kPeer.Close()
	select {
	case err := <-c.WaitForCompletion():
		if err == nil || !strings.Contains(err.Error(), "TEE_K connection closed unexpectedly") {
			t.Fatalf("unexpected completion error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TEE_K read failure was blocked by the in-progress TEE_T dial")
	}
	close(releaseTDial)
	if err := <-tDialDone; err == nil {
		t.Fatal("TEE_T dial unexpectedly succeeded")
	}
}

func TestCoreProtocolTimeoutClosesBothTEESockets(t *testing.T) {
	kServer, kAccepted, _ := newPassiveWSServer(t)
	defer kServer.Close()
	tServer, tAccepted, _ := newPassiveWSServer(t)
	defer tServer.Close()
	c := NewClient(wsURL(kServer.URL))
	c.SetTEETURL(wsURL(tServer.URL))
	if err := c.connectToTEEs(); err != nil {
		t.Fatal(err)
	}
	<-kAccepted
	<-tAccepted
	c.coreProtocolTimeout = 5 * time.Millisecond
	c.startCoreProtocolWatchdog()
	if err := c.waitForCoreProtocol(); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
	if c.hasTEEConnection("TEE_K") || c.hasTEEConnection("TEE_T") {
		t.Fatal("timeout did not close both TEE sockets")
	}
}

func TestStaleTEEReaderCannotCloseReplacement(t *testing.T) {
	server, accepted, _ := newPassiveWSServer(t)
	defer server.Close()
	c := NewClient(wsURL(server.URL))
	if err := c.ConnectToTEEK(); err != nil {
		t.Fatal(err)
	}
	<-accepted
	c.connectionMutex.Lock()
	oldConn, oldGeneration := c.wsConn, c.teekGeneration
	c.connectionMutex.Unlock()
	c.closeTEEConnections()
	if err := c.ConnectToTEEK(); err != nil {
		t.Fatal(err)
	}
	<-accepted
	c.handleTEEReadFailure("TEE_K", oldConn, oldGeneration, errors.New("stale reader failure"))
	if !c.hasTEEConnection("TEE_K") || c.isClosing.Load() {
		t.Fatal("stale reader terminated the replacement generation")
	}
	select {
	case err := <-c.WaitForCompletion():
		t.Fatalf("stale reader signaled completion: %v", err)
	default:
	}
	c.Close()
}

func newPassiveWSServer(t *testing.T) (*httptest.Server, <-chan *websocket.Conn, <-chan struct{}) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 4)
	closed := make(chan struct{}, 4)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		accepted <- conn
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				closed <- struct{}{}
				return
			}
		}
	}))
	return server, accepted, closed
}

func newAttestorInitServer(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var requests teeproto.RPCMessages
		if err := proto.Unmarshal(raw, &requests); err != nil || len(requests.GetMessages()) != 1 {
			return
		}
		response := &teeproto.RPCMessages{Messages: []*teeproto.RPCMessage{{
			Id:      requests.GetMessages()[0].GetId(),
			Message: &teeproto.RPCMessage_InitResponse{InitResponse: &teeproto.InitResponse{}},
		}}}
		encoded, err := proto.Marshal(response)
		if err == nil {
			_ = conn.WriteMessage(websocket.BinaryMessage, encoded)
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
}

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}
