package client

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/gorilla/websocket"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	prover "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/utils"
	"google.golang.org/protobuf/proto"
)

func TestOverlappingPairConnectFailureCannotPublishPartialSuccess(t *testing.T) {
	c := NewClient("ws://tee-k.test/ws")
	c.SetTEETURL("ws://tee-t.test/ws")
	defer c.Close()

	firstTDialStarted := make(chan struct{})
	releaseFirstTDial := make(chan struct{})
	var kDials, tDials atomic.Int32
	var orderMutex sync.Mutex
	var order []string
	c.teeDial = func(role, rawURL string) (*websocket.Conn, error) {
		orderMutex.Lock()
		order = append(order, role)
		orderMutex.Unlock()
		if role == "tee_k" {
			kDials.Add(1)
		} else if tDials.Add(1) == 1 {
			close(firstTDialStarted)
			select {
			case <-releaseFirstTDial:
			case <-time.After(time.Second):
				return nil, fmt.Errorf("timed out waiting to release first TEE_T dial")
			}
			return nil, fmt.Errorf("injected first TEE_T failure")
		}
		return newPassivePipeWebSocket(t, rawURL)
	}

	aDone := make(chan error, 1)
	bDone := make(chan error, 1)
	go func() { aDone <- c.connectToTEEs() }()
	select {
	case <-firstTDialStarted:
	case <-time.After(time.Second):
		t.Fatal("first TEE_T dial did not start")
	}
	go func() { bDone <- c.connectToTEEs() }()

	select {
	case err := <-bDone:
		t.Fatalf("overlapping pair returned before first transaction reset: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseFirstTDial)
	select {
	case err := <-aDone:
		if err == nil || !strings.Contains(err.Error(), "injected first TEE_T failure") {
			t.Fatalf("first pair result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first pair transaction did not finish")
	}
	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("second pair result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second pair transaction did not finish")
	}
	if !c.hasTEEConnection("TEE_K") || !c.hasTEEConnection("TEE_T") {
		t.Fatal("successful second transaction did not publish a complete pair")
	}
	if kDials.Load() != 2 || tDials.Load() != 2 {
		t.Fatalf("dial counts K=%d T=%d, want 2/2", kDials.Load(), tDials.Load())
	}
	orderMutex.Lock()
	gotOrder := append([]string(nil), order...)
	orderMutex.Unlock()
	wantOrder := []string{"tee_k", "tee_t", "tee_k", "tee_t"}
	if fmt.Sprint(gotOrder) != fmt.Sprint(wantOrder) {
		t.Fatalf("dial order = %v, want %v", gotOrder, wantOrder)
	}
}

func TestAddressOnlySignedMessagesRequireStandaloneModeForBothRoles(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []ClientMode{ModeAuto, ModeEnclave} {
		for _, role := range []string{"TEE_K", "TEE_T"} {
			t.Run(fmt.Sprintf("mode_%d/%s", mode, role), func(t *testing.T) {
				c := clientWithSession("session-1")
				c.SetMode(mode)
				var acceptErr error
				if role == "TEE_K" {
					acceptErr = c.acceptTEEKSignedMessage("session-1", signedKMessage(t, pair, "session-1"))
				} else {
					acceptErr = c.acceptTEETSignedMessage("session-1", signedTMessage(t, pair, "session-1"))
				}
				if acceptErr == nil || !strings.Contains(acceptErr.Error(), "requires verified attestation") {
					t.Fatalf("production address-only result = %v", acceptErr)
				}
				c.protocolStateMutex.RLock()
				published := c.teekSignedMessage != nil || c.teetSignedMessage != nil || c.teeKTranscriptReceived || c.teeTTranscriptReceived || c.teeKSignatureValid || c.teeTSignatureValid
				c.protocolStateMutex.RUnlock()
				if published {
					t.Fatal("unattested production message was published")
				}
			})
		}
	}
}

func TestLegacyDirectAutoClientResolvesStandaloneFromFinalURLs(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient("ws://tee-k.local/ws")
	c.SetTEETURL("ws://tee-t.local/ws")
	c.sessionID = "session-1"
	if err := c.acceptTEEKSignedMessage("session-1", signedKMessage(t, pair, "session-1")); err != nil {
		t.Fatalf("legacy direct TEE_K: %v", err)
	}
	if err := c.acceptTEETSignedMessage("session-1", signedTMessage(t, pair, "session-1")); err != nil {
		t.Fatalf("legacy direct TEE_T: %v", err)
	}
	if mode := c.resolveClientMode(); mode != ModeStandalone {
		t.Fatalf("resolved mode = %v, want standalone", mode)
	}
}

func TestUnresolvedRouterAutoClientRequiresAttestation(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient("ws://tee-k.router/ws")
	c.SetTEETURL("ws://tee-t.router/ws")
	c.SetRouterJWT("allocation-jwt")
	c.sessionID = "session-1"
	err = c.acceptTEEKSignedMessage("session-1", signedKMessage(t, pair, "session-1"))
	if err == nil || !strings.Contains(err.Error(), "requires verified attestation") {
		t.Fatalf("router Auto address-only result = %v", err)
	}
	if mode := c.resolveClientMode(); mode != ModeEnclave {
		t.Fatalf("resolved router mode = %v, want enclave", mode)
	}
}

func TestStandaloneSignedMessagesPublishReceiptAndValidityAtomically(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := clientWithSession("session-1")
	if err := c.acceptTEEKSignedMessage("session-1", signedKMessage(t, pair, "session-1")); err != nil {
		t.Fatal(err)
	}
	c.protocolStateMutex.RLock()
	kAtomic := c.teekSignedMessage != nil && c.teeKTranscriptReceived && c.teeKSignatureValid
	c.protocolStateMutex.RUnlock()
	if !kAtomic {
		t.Fatal("TEE_K accept returned before message, receipt, and validity were atomically published")
	}
	if err := c.acceptTEETSignedMessage("session-1", signedTMessage(t, pair, "session-1")); err != nil {
		t.Fatal(err)
	}
	results, err := c.buildTranscriptResults()
	if err != nil {
		t.Fatal(err)
	}
	if !results.BothReceived || !results.BothSignaturesValid {
		t.Fatalf("atomic transcript snapshot = %+v", results)
	}
}

func TestSignedMessageAttestationEnvelopeRejectsAmbiguousAndMalformedIdentity(t *testing.T) {
	c := clientWithSession("session-1")
	for _, tc := range []struct {
		name   string
		signed *teeproto.SignedMessage
		want   string
	}{
		{"report and address", &teeproto.SignedMessage{EthAddress: []byte("0x0000000000000000000000000000000000000000"), AttestationReport: &teeproto.AttestationReport{Type: "gcp", Report: []byte{1}}}, "both attestation and standalone address"},
		{"unknown report", &teeproto.SignedMessage{AttestationReport: &teeproto.AttestationReport{Type: "unknown", Report: []byte{1}}}, "unsupported"},
		{"empty report", &teeproto.SignedMessage{AttestationReport: &teeproto.AttestationReport{Type: "gcp"}}, "attestation is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.signedMessageAddress("tee_k", tc.signed); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("identity result = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifiedAttestationIdentityPlumbingBindsBothRoles(t *testing.T) {
	want := "0x0123456789abcdef0123456789abcdef01234567"
	for _, role := range []string{"tee_k", "tee_t"} {
		t.Run(role, func(t *testing.T) {
			address, err := verifiedSigningAddress(role, func(prefix string) (string, error) {
				if prefix != role+"_public_key:" {
					t.Fatalf("nonce prefix = %q", prefix)
				}
				return want, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if address != shared.HexToAddress(want) {
				t.Fatalf("address = %s, want %s", address.Hex(), want)
			}
		})
	}
	if _, err := verifiedSigningAddress("tee_k", func(string) (string, error) { return "malformed", nil }); err == nil || !strings.Contains(err.Error(), "invalid signing address") {
		t.Fatalf("malformed verified nonce result = %v", err)
	}
}

func TestVerifiedCloudSignedMessagesPassBothProviderBranches(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fixture := []byte("verified-provider-fixture")
	for _, provider := range []string{"gcp", "sev-snp"} {
		for _, role := range []string{"tee_k", "tee_t"} {
			t.Run(provider+"/"+role, func(t *testing.T) {
				c := NewClient("wss://tee-k.example/ws")
				c.SetTEETURL("wss://tee-t.example/ws")
				c.SetMode(ModeEnclave)
				c.sessionID = "session-1"
				c.verifyGCPAttestation = func(raw []byte) error {
					if string(raw) != string(fixture) {
						return fmt.Errorf("unexpected GCP fixture")
					}
					return nil
				}
				c.findGCPNonce = func(raw []byte, prefix string) (string, error) {
					if string(raw) != string(fixture) || prefix != role+"_public_key:" {
						return "", fmt.Errorf("unexpected GCP identity lookup %q", prefix)
					}
					return pair.GetEthAddress().Hex(), nil
				}
				c.verifySEVAttestation = func(raw []byte) ([]string, error) {
					if string(raw) != string(fixture) {
						return nil, fmt.Errorf("unexpected SEV fixture")
					}
					return []string{role + "_public_key:" + pair.GetEthAddress().Hex()}, nil
				}

				var signed *teeproto.SignedMessage
				if role == "tee_k" {
					signed = signedKMessage(t, pair, "session-1")
				} else {
					signed = signedTMessage(t, pair, "session-1")
				}
				signed.EthAddress = nil
				signed.AttestationReport = &teeproto.AttestationReport{Type: provider, Report: append([]byte(nil), fixture...)}
				var acceptErr error
				if role == "tee_k" {
					acceptErr = c.acceptTEEKSignedMessage("session-1", signed)
				} else {
					acceptErr = c.acceptTEETSignedMessage("session-1", signed)
				}
				if acceptErr != nil {
					t.Fatalf("verified %s %s message: %v", provider, role, acceptErr)
				}
			})
		}
	}
}

func TestProtocolPhaseCannotRegressUnderConcurrentCallbacks(t *testing.T) {
	c := NewClient("")
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c.advanceToPhase(PhaseComplete)
		}()
		go func() {
			defer wg.Done()
			c.advanceToPhase(PhaseReceivingDecryption)
		}()
	}
	wg.Wait()
	c.protocolStateMutex.RLock()
	phase := c.protocolPhase
	c.protocolStateMutex.RUnlock()
	if phase != PhaseComplete {
		t.Fatalf("phase regressed to %s", phase)
	}
	select {
	case err := <-c.WaitForCompletion():
		if err != nil {
			t.Fatalf("monotonic completion result = %v", err)
		}
	default:
		t.Fatal("crossing the validation phase did not signal completion")
	}
	select {
	case err := <-c.WaitForCompletion():
		t.Fatalf("completion was published more than once: %v", err)
	default:
	}
}

func TestSuccessfulPhaseClaimsCompletionBeforeWatchdog(t *testing.T) {
	c := NewClient("")
	c.coreProtocolTimeout = 5 * time.Millisecond
	claimed := make(chan struct{})
	release := make(chan struct{})
	c.phaseCompletionHook = func() {
		close(claimed)
		select {
		case <-release:
		case <-time.After(time.Second):
		}
	}
	phaseDone := make(chan struct{})
	go func() {
		c.advanceToPhase(PhaseValidating)
		close(phaseDone)
	}()
	select {
	case <-claimed:
	case <-time.After(time.Second):
		t.Fatal("successful phase did not claim completion")
	}
	c.startCoreProtocolWatchdog()
	time.Sleep(15 * time.Millisecond)
	close(release)
	select {
	case <-phaseDone:
	case <-time.After(time.Second):
		t.Fatal("successful phase did not finish after release")
	}
	select {
	case err := <-c.WaitForCompletion():
		if err != nil {
			t.Fatalf("success lost completion race: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("success completion was not published")
	}
	if c.isClosing.Load() {
		t.Fatal("watchdog tore down a successfully completed protocol")
	}
}

func TestOPRFAndTranscriptSnapshotsAreDeepCopies(t *testing.T) {
	boundary := uint32(7)
	point := &twistededwards.PointAffine{}
	c := NewClient("")
	c.oprfRanges = map[int]*OPRFRangeData{3: {
		Start: 3, Length: 2, Data: []byte{1}, Mask: []byte{2}, FinalOutput: []byte{3}, ZKProof: []byte{4},
		Request:  &utils.OPRFRequest{Mask: big.NewInt(5), MaskedData: point, SecretElements: [2]*big.Int{big.NewInt(6), big.NewInt(7)}},
		Response: &teeproto.TOPRFResponse{PublicKeyShare: []byte{8}, Evaluated: []byte{9}, C: []byte{10}, R: []byte{11}},
		ZKProofParams: &prover.InputParams{
			Cipher: "test", Key: []byte{12}, Input: []byte{13},
			Blocks: []prover.Block{{Nonce: []byte{14}, Counter: 15, Boundary: &boundary}},
			TOPRF: &prover.TOPRFParams{
				Locations: []prover.Location{{Pos: 16, Len: 17}}, Mask: []byte{18}, DomainSeparator: []byte{19}, Output: []byte{20},
				Responses: []*prover.TOPRFResponse{{Index: 1, PublicKeyShare: []byte{21}, Evaluated: []byte{22}, C: []byte{23}, R: []byte{24}}},
			},
		},
	}}

	first := c.GetOPRFRanges()[3]
	first.Data[0] = 101
	first.Mask[0] = 102
	first.FinalOutput[0] = 103
	first.ZKProof[0] = 104
	first.Request.Mask.SetInt64(105)
	first.Request.SecretElements[0].SetInt64(106)
	if first.Request.MaskedData == point {
		t.Fatal("returned OPRF curve point aliases internal state")
	}
	first.Response.PublicKeyShare[0] = 107
	first.ZKProofParams.Key[0] = 108
	first.ZKProofParams.Input[0] = 109
	first.ZKProofParams.Blocks[0].Nonce[0] = 110
	*first.ZKProofParams.Blocks[0].Boundary = 111
	first.ZKProofParams.TOPRF.Locations[0].Pos = 112
	first.ZKProofParams.TOPRF.Mask[0] = 113
	first.ZKProofParams.TOPRF.Responses[0].R[0] = 114

	second := c.GetOPRFRanges()[3]
	if second.Data[0] != 1 || second.Mask[0] != 2 || second.FinalOutput[0] != 3 || second.ZKProof[0] != 4 || second.Request.Mask.Int64() != 5 || second.Request.SecretElements[0].Int64() != 6 || second.Response.PublicKeyShare[0] != 8 || second.ZKProofParams.Key[0] != 12 || second.ZKProofParams.Input[0] != 13 || second.ZKProofParams.Blocks[0].Nonce[0] != 14 || *second.ZKProofParams.Blocks[0].Boundary != 7 || second.ZKProofParams.TOPRF.Locations[0].Pos != 16 || second.ZKProofParams.TOPRF.Mask[0] != 18 || second.ZKProofParams.TOPRF.Responses[0].R[0] != 24 {
		t.Fatalf("returned OPRF mutation reached internal state: %+v", second)
	}

	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c = clientWithSession("session-1")
	kSigned := signedKMessage(t, pair, "session-1")
	tSigned := signedTMessage(t, pair, "session-1")
	if err := c.acceptTEEKSignedMessage("session-1", kSigned); err != nil {
		t.Fatal(err)
	}
	if err := c.acceptTEETSignedMessage("session-1", tSigned); err != nil {
		t.Fatal(err)
	}
	kSigned.Body[0] ^= 0xff
	kSigned.Signature[0] ^= 0xff
	kSigned.EthAddress[0] ^= 0xff
	firstTranscripts, _ := c.buildTranscriptResults()
	firstTranscripts.TEEK.Data[0][0] ^= 0xff
	firstTranscripts.TEEK.Signature[0] ^= 0xff
	firstTranscripts.TEEK.EthAddress[0] ^= 0xff
	secondTranscripts, _ := c.buildTranscriptResults()
	if string(secondTranscripts.TEEK.Data[0]) != "k-stream" || secondTranscripts.TEEK.Signature[0] == firstTranscripts.TEEK.Signature[0] || secondTranscripts.TEEK.EthAddress[0] == firstTranscripts.TEEK.EthAddress[0] {
		t.Fatal("returned transcript mutation reached internal signed message")
	}

	source := &teeproto.SignedMessage{Body: []byte{1}, Signature: []byte{2}, EthAddress: []byte{3}, AttestationReport: &teeproto.AttestationReport{Type: "gcp", Report: []byte{4}}}
	stripped := stripUnsignedFields(source)
	stripped.Body[0] = 9
	stripped.Signature[0] = 9
	stripped.EthAddress[0] = 9
	stripped.AttestationReport.Report[0] = 9
	if source.Body[0] != 1 || source.Signature[0] != 2 || source.EthAddress[0] != 3 || source.AttestationReport.Report[0] != 4 {
		t.Fatal("bundle signed-message snapshot aliases its source")
	}
}

func TestFreshOPRFRangesPreserveNilSemantics(t *testing.T) {
	if got := NewClient("").GetOPRFRanges(); got != nil {
		t.Fatalf("fresh OPRF ranges = %#v, want nil", got)
	}
}

func TestClientWebSocketReadLimitBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		wantLimit bool
	}{{"at limit", shared.MaxWebSocketMessageSize, false}, {"one byte over", shared.MaxWebSocketMessageSize + 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			clientNet, peerNet := net.Pipe()
			t.Cleanup(func() { _ = clientNet.Close(); _ = peerNet.Close() })
			go serveClientReadLimitWebSocket(peerNet, tc.size)
			dialer := &websocket.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return clientNet, nil }}
			conn, _, err := dialer.Dial("ws://in-memory/client", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			installWebSocketReadLimit(conn)
			_, payload, err := conn.ReadMessage()
			if tc.wantLimit {
				if err != websocket.ErrReadLimit {
					t.Fatalf("over-limit read error = %v", err)
				}
				return
			}
			if err != nil || len(payload) != tc.size {
				t.Fatalf("at-limit read = (%d, %v), want (%d, nil)", len(payload), err, tc.size)
			}
		})
	}
}

func TestClientConfigTimeoutControlsCoreProtocol(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "http://router.test/allocate" {
			return nil, fmt.Errorf("unexpected allocation URL %s", request.URL)
		}
		body, err := json.Marshal(&AllocationResponse{PairID: "pair", TEEKAddr: "k.example", TEETAddr: "t.example", JWT: "jwt"})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	want := 17 * time.Millisecond
	defaultClient, err := NewReclaimClient(ClientConfig{RouterURL: "http://router.test", Mode: ModeStandalone})
	if err != nil {
		t.Fatal(err)
	}
	if defaultClient.Client.coreProtocolTimeout != time.Minute {
		t.Fatalf("default core timeout = %s, want %s", defaultClient.Client.coreProtocolTimeout, time.Minute)
	}

	r, err := NewReclaimClient(ClientConfig{RouterURL: "http://router.test", Timeout: want, Mode: ModeStandalone})
	if err != nil {
		t.Fatal(err)
	}
	if r.Client.coreProtocolTimeout != want {
		t.Fatalf("core timeout = %s, want %s", r.Client.coreProtocolTimeout, want)
	}

	providerJSON, err := json.Marshal(&ProviderRequestData{
		Name: "http",
		Params: &providers.HTTPProviderParams{
			URL: "https://example.com/", Method: "GET",
			ResponseMatches: []providers.ResponseMatch{{Value: "ok", Type: "contains"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonClient, err := NewReclaimClientFromJSON(string(providerJSON), `{"routerUrl":"http://router.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	if jsonClient.Client.coreProtocolTimeout != time.Minute {
		t.Fatalf("JSON/C default core timeout = %s, want %s", jsonClient.Client.coreProtocolTimeout, time.Minute)
	}
}

func serveClientReadLimitWebSocket(peer net.Conn, payloadSize int) {
	reader := bufio.NewReader(peer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if _, err := fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		return
	}
	header := []byte{0x80 | websocket.BinaryMessage, 127}
	var extended [8]byte
	binary.BigEndian.PutUint64(extended[:], uint64(payloadSize))
	if _, err := peer.Write(append(header, extended[:]...)); err != nil {
		return
	}
	_, _ = io.CopyN(peer, clientZeroReader{}, int64(payloadSize))
}

type clientZeroReader struct{}

func (clientZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestSplitStartUsesOneShotTimeoutAndJoinsReaders(t *testing.T) {
	c := NewClient("ws://tee-k.test/ws")
	c.SetTEETURL("ws://tee-t.test/ws")
	c.teeDial = func(_ string, rawURL string) (*websocket.Conn, error) {
		return newPassivePipeWebSocket(t, rawURL)
	}
	c.coreProtocolTimeout = 10 * time.Millisecond
	r := &ReclaimClient{Client: c, logger: c.logger}
	providerJSON, err := json.Marshal(&ProviderRequestData{
		Name: "http",
		Params: &providers.HTTPProviderParams{
			URL: "https://example.com/", Method: "GET",
			ResponseMatches: []providers.ResponseMatch{{Value: "ok", Type: "contains"}},
		},
		SecretParams: &providers.HTTPProviderSecretParams{AuthorisationHeader: "Bearer test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.StartProtocol(string(providerJSON)); err != nil {
		t.Fatal(err)
	}
	c.connectionMutex.Lock()
	kDone, tDone := c.teekReaderDone, c.teetReaderDone
	c.connectionMutex.Unlock()
	select {
	case err := <-r.WaitForCompletion():
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("split timeout result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("split protocol did not start its watchdog")
	}
	if c.hasTEEConnection("TEE_K") || c.hasTEEConnection("TEE_T") {
		t.Fatal("split timeout did not close both TEE sockets")
	}
	select {
	case <-kDone:
	default:
		t.Fatal("TEE_K exact reader was not joined before timeout publication")
	}
	select {
	case <-tDone:
	default:
		t.Fatal("TEE_T exact reader was not joined before timeout publication")
	}
}

func TestSplitStartClosePublishesCancellation(t *testing.T) {
	c := NewClient("ws://tee-k.test/ws")
	c.SetTEETURL("ws://tee-t.test/ws")
	c.teeDial = func(_ string, rawURL string) (*websocket.Conn, error) {
		return newPassivePipeWebSocket(t, rawURL)
	}
	c.coreProtocolTimeout = time.Second
	r := &ReclaimClient{Client: c, logger: c.logger}
	providerJSON, err := json.Marshal(&ProviderRequestData{
		Name: "http",
		Params: &providers.HTTPProviderParams{
			URL: "https://example.com/", Method: "GET",
			ResponseMatches: []providers.ResponseMatch{{Value: "ok", Type: "contains"}},
		},
		SecretParams: &providers.HTTPProviderSecretParams{AuthorisationHeader: "Bearer test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.StartProtocol(string(providerJSON)); err != nil {
		t.Fatal(err)
	}
	c.connectionMutex.Lock()
	kDone, tDone := c.teekReaderDone, c.teetReaderDone
	c.connectionMutex.Unlock()
	barrier := make(chan struct{})
	release := make(chan struct{})
	c.closeBeforePublishHook = func() {
		close(barrier)
		select {
		case <-release:
		case <-time.After(time.Second):
		}
	}
	closeDone := make(chan struct{})
	go func() {
		c.Close()
		close(closeDone)
	}()
	select {
	case <-barrier:
	case <-time.After(time.Second):
		t.Fatal("Close did not reach cleanup publication barrier")
	}
	if c.hasTEEConnection("TEE_K") || c.hasTEEConnection("TEE_T") {
		t.Fatal("Close reached publication barrier with live TEE sockets")
	}
	select {
	case <-kDone:
	default:
		t.Fatal("Close reached publication barrier before joining TEE_K reader")
	}
	select {
	case <-tDone:
	default:
		t.Fatal("Close reached publication barrier before joining TEE_T reader")
	}
	select {
	case err := <-r.WaitForCompletion():
		t.Fatalf("completion published before resource cleanup barrier: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-r.WaitForCompletion():
		if err == nil || !strings.Contains(err.Error(), "client closed") {
			t.Fatalf("Close completion = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("split WaitForCompletion hung after Close")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after completion publication")
	}
}

func TestTEEClosureSendsNormalCloseControl(t *testing.T) {
	closeCodes := make(chan int, 2)
	c := NewClient("ws://tee-k.test/ws")
	c.SetTEETURL("ws://tee-t.test/ws")
	c.teeDial = func(_ string, rawURL string) (*websocket.Conn, error) {
		return newCloseObservingPipeWebSocket(t, rawURL, closeCodes)
	}
	if err := c.connectToTEEs(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	for range 2 {
		select {
		case code := <-closeCodes:
			if code != websocket.CloseNormalClosure {
				t.Fatalf("peer close code = %d, want %d", code, websocket.CloseNormalClosure)
			}
		case <-time.After(time.Second):
			t.Fatal("peer did not observe normal close control")
		}
	}
}

func TestTEEClosureDoesNotWaitForBlockedWriters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		watchdog bool
	}{{"Close", false}, {"watchdog", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient("ws://tee-k.test/ws")
			c.SetTEETURL("ws://tee-t.test/ws")
			c.teeDial = func(_ string, rawURL string) (*websocket.Conn, error) {
				return newPassivePipeWebSocket(t, rawURL)
			}
			if err := c.connectToTEEs(); err != nil {
				t.Fatal(err)
			}
			c.wsWriteMutex.Lock()
			c.teetWriteMutex.Lock()
			defer c.wsWriteMutex.Unlock()
			defer c.teetWriteMutex.Unlock()

			if tc.watchdog {
				c.coreProtocolTimeout = 5 * time.Millisecond
				c.startCoreProtocolWatchdog()
				select {
				case err := <-c.WaitForCompletion():
					if err == nil || !strings.Contains(err.Error(), "timed out") {
						t.Fatalf("watchdog completion = %v", err)
					}
				case <-time.After(250 * time.Millisecond):
					t.Fatal("watchdog cleanup waited for a blocked writer")
				}
				return
			}

			closed := make(chan struct{})
			go func() {
				c.Close()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(250 * time.Millisecond):
				t.Fatal("Close waited for a blocked writer")
			}
		})
	}
}

func TestClientFailureInterruptsBlockedAttestorRPC(t *testing.T) {
	dial, rpcReceived, peerClosed := newBlockingAttestorRPCPipe(t)
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attestor := NewAttestorClient("ws://attestor.test/ws", pair.PrivateKey, nil, GetLogger("attestor-close-test", false))
	attestor.dial = dial
	if err := attestor.ensureConnected(); err != nil {
		t.Fatal(err)
	}
	c := NewClient("")
	c.attestorClient = attestor
	rpcDone := make(chan error, 1)
	go func() {
		_, err := attestor.sendRPCMessage(&teeproto.RPCMessage_ToprfRequest{ToprfRequest: &teeproto.TOPRFRequest{MaskedData: []byte{1}}})
		rpcDone <- err
	}()
	select {
	case <-rpcReceived:
	case <-time.After(time.Second):
		t.Fatal("blocked attestor RPC was not received")
	}

	failureDone := make(chan struct{})
	go func() {
		c.terminateConnectionWithErrorAndWait("injected post-attestor failure", errors.New("injected failure"))
		close(failureDone)
	}()
	select {
	case <-failureDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("client failure waited for blocked attestor RPC")
	}
	select {
	case err := <-rpcDone:
		if err == nil {
			t.Fatal("blocked attestor RPC unexpectedly succeeded")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("attestor RPC was not interrupted")
	}
	select {
	case <-peerClosed:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("attestor peer did not observe socket closure")
	}
	if err := attestor.ensureConnected(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed attestor reconnected: %v", err)
	}
	c.attestorMutex.Lock()
	published := c.attestorClient
	c.attestorMutex.Unlock()
	if published != nil {
		t.Fatal("closed attestor remained published on client")
	}
}

func TestConcurrentAttestorRPCReconnectsOnlyFollowingCall(t *testing.T) {
	dial, firstRPCReceived, releaseFirst, dials := newConcurrentAttestorRPCPipe(t)
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attestor := NewAttestorClient("ws://attestor.test/ws", pair.PrivateKey, nil, GetLogger("attestor-concurrent-test", false))
	attestor.dial = dial
	if err := attestor.ensureConnected(); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := attestor.sendRPCMessage(&teeproto.RPCMessage_ToprfRequest{ToprfRequest: &teeproto.TOPRFRequest{MaskedData: []byte{1}}})
		firstDone <- err
	}()
	select {
	case <-firstRPCReceived:
	case <-time.After(time.Second):
		t.Fatal("first attestor RPC was not received")
	}
	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, err := attestor.sendRPCMessage(&teeproto.RPCMessage_ToprfRequest{ToprfRequest: &teeproto.TOPRFRequest{MaskedData: []byte{2}}})
		secondDone <- err
	}()
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("following attestor RPC did not start")
	}
	close(releaseFirst)
	select {
	case err := <-firstDone:
		if err == nil {
			t.Fatal("ambiguous first RPC unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("ambiguous first RPC did not finish")
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("following RPC did not reconnect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("following RPC did not finish")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("attestor dial count = %d, want exactly 2", got)
	}
	if err := attestor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitToAttestorPreSendFailureRemainsRetryable(t *testing.T) {
	dial, submitReceived, releaseSubmit, dials := newSubmitAttestorPipe(t, false)
	close(releaseSubmit)
	c, attestor := newSubmitReadyClient(t, dial)
	defer c.Close()

	c.protocolStateMutex.Lock()
	c.teeTSignatureValid = false
	c.protocolStateMutex.Unlock()
	if _, err := c.SubmitToAttestorCore(ClaimTeeBundleParams{Provider: "http"}); err == nil || !strings.Contains(err.Error(), "validation was not completed") {
		t.Fatalf("pre-send failure = %v", err)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("pre-send failure dialed attestor %d times", got)
	}
	attestor.connMutex.Lock()
	closed := attestor.closed
	attestor.connMutex.Unlock()
	if closed {
		t.Fatal("pre-send failure permanently closed the client-owned attestor")
	}

	c.protocolStateMutex.Lock()
	c.teeTSignatureValid = true
	c.protocolStateMutex.Unlock()
	result, err := c.SubmitToAttestorCore(ClaimTeeBundleParams{Provider: "http"})
	if err != nil {
		t.Fatalf("retry after pre-send failure: %v", err)
	}
	if result.Claim.GetIdentifier() != "claim-test" {
		t.Fatalf("retry claim identifier = %q", result.Claim.GetIdentifier())
	}
	select {
	case <-submitReceived:
	case <-time.After(time.Second):
		t.Fatal("retry did not submit")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("retry dial count = %d, want 1 fresh connection", got)
	}
}

func TestConcurrentSubmitToAttestorDoesNotCloseSharedConnection(t *testing.T) {
	dial, firstSubmitReceived, releaseFirst, dials := newSubmitAttestorPipe(t, true)
	c, _ := newSubmitReadyClient(t, dial)
	defer c.Close()

	firstDone := make(chan error, 1)
	go func() {
		_, err := c.SubmitToAttestorCore(ClaimTeeBundleParams{Provider: "http"})
		firstDone <- err
	}()
	select {
	case <-firstSubmitReceived:
	case <-time.After(time.Second):
		t.Fatal("first concurrent submit was not received")
	}
	secondDone := make(chan error, 1)
	go func() {
		_, err := c.SubmitToAttestorCore(ClaimTeeBundleParams{Provider: "http"})
		secondDone <- err
	}()
	close(releaseFirst)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first concurrent submit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first concurrent submit did not finish")
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second concurrent submit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second concurrent submit did not finish")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("concurrent submit dial count = %d, want one shared connection", got)
	}
}

func TestConcurrentCiphertextInsertionAndDecryptionSnapshot(t *testing.T) {
	c := NewClient("")
	c.responseContentMutex.Lock()
	c.ciphertextBySeq[0] = []byte{1, 2, 3, 4}
	c.responseContentMutex.Unlock()

	start := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		<-start
		for i := uint64(1); i <= 10_000; i++ {
			c.responseContentMutex.Lock()
			c.ciphertextBySeq[i] = []byte{byte(i)}
			c.responseContentMutex.Unlock()
		}
	}()
	close(start)
	for range 10_000 {
		ciphertext, exists := c.storeDecryptionStreamAndSnapshotCiphertext(0, []byte{4, 3, 2, 1})
		if !exists || !bytes.Equal(ciphertext, []byte{1, 2, 3, 4}) {
			t.Fatalf("ciphertext snapshot = %v, exists=%v", ciphertext, exists)
		}
		ciphertext[0] = 0xff
	}
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("concurrent TLS ciphertext publication did not finish")
	}
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()
	if got := c.ciphertextBySeq[0][0]; got != 1 {
		t.Fatalf("snapshot mutation changed stored ciphertext: %d", got)
	}
	if got := c.decryptionStreamBySeq[0][0]; got != 4 {
		t.Fatalf("decryption stream was not stored: %d", got)
	}
}

func newSubmitReadyClient(t *testing.T, dial func(string) (*websocket.Conn, error)) (*Client, *AttestorClient) {
	t.Helper()
	signingPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := clientWithSession("submit-session")
	c.SetMode(ModeStandalone)
	if err := c.acceptTEEKSignedMessage("submit-session", signedKMessage(t, signingPair, "submit-session")); err != nil {
		t.Fatal(err)
	}
	if err := c.acceptTEETSignedMessage("submit-session", signedTMessage(t, signingPair, "submit-session")); err != nil {
		t.Fatal(err)
	}
	attestorPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attestor := NewAttestorClient("ws://attestor.test/ws", attestorPair.PrivateKey, nil, GetLogger("attestor-submit-test", false))
	attestor.dial = dial
	c.attestorMutex.Lock()
	c.attestorClient = attestor
	c.attestorMutex.Unlock()
	return c, attestor
}

func TestResponseResultsAreDeepSnapshots(t *testing.T) {
	c := NewClient("")
	c.responseContentMutex.Lock()
	c.responseProcessingSuccessful = true
	c.reconstructedResponseSize = 4
	c.lastRedactionRanges = []shared.ResponseRedactionRange{{Start: 1, Length: 2}}
	c.lastResponseData = &HTTPResponse{StatusCode: 200, Headers: map[string]string{"x-test": "original"}, Body: []byte("body"), FullResponse: []byte("full")}
	c.responseContentMutex.Unlock()
	r := &ReclaimClient{Client: c}

	first, err := r.GetResponseResults()
	if err != nil {
		t.Fatal(err)
	}
	first.HTTPResponse.Headers["x-test"] = "mutated"
	first.HTTPResponse.Body[0] = 'X'
	first.HTTPResponse.FullResponse[0] = 'Y'
	second, _ := r.GetResponseResults()
	if second.HTTPResponse.Headers["x-test"] != "original" || string(second.HTTPResponse.Body) != "body" || string(second.HTTPResponse.FullResponse) != "full" {
		t.Fatalf("GetResponseResults mutation reached client state: %+v", second.HTTPResponse)
	}

	protocol, err := r.GetProtocolResult()
	if err != nil {
		t.Fatal(err)
	}
	protocol.Response.HTTPResponse.Headers["x-test"] = "protocol-mutated"
	protocol.Response.HTTPResponse.Body[0] = 'Z'
	again, _ := r.GetProtocolResult()
	if again.Response.HTTPResponse.Headers["x-test"] != "original" || string(again.Response.HTTPResponse.Body) != "body" {
		t.Fatalf("GetProtocolResult mutation reached client state: %+v", again.Response.HTTPResponse)
	}
}

func TestHTTPResponseSnapshotPreservesEmptyAndNilSlices(t *testing.T) {
	nonNilEmpty := cloneHTTPResponse(&HTTPResponse{Body: []byte{}, FullResponse: []byte{}})
	if nonNilEmpty.Body == nil || nonNilEmpty.FullResponse == nil {
		t.Fatalf("non-nil empty slices collapsed to nil: body=%v full=%v", nonNilEmpty.Body, nonNilEmpty.FullResponse)
	}
	nilSlices := cloneHTTPResponse(&HTTPResponse{})
	if nilSlices.Body != nil || nilSlices.FullResponse != nil {
		t.Fatalf("nil slices changed to non-nil: body=%v full=%v", nilSlices.Body, nilSlices.FullResponse)
	}
}

func TestResponseSnapshotConcurrentPublication(t *testing.T) {
	c := NewClient("")
	c.responseContentMutex.Lock()
	c.lastResponseData = &HTTPResponse{Headers: map[string]string{"generation": "0"}, Body: []byte{0}, FullResponse: []byte{0}}
	c.responseContentMutex.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			c.responseContentMutex.Lock()
			c.responseProcessingSuccessful = i%2 == 0
			c.reconstructedResponseSize = i
			c.lastResponseData = &HTTPResponse{Headers: map[string]string{"generation": fmt.Sprint(i)}, Body: []byte{byte(i)}, FullResponse: []byte{byte(i)}}
			c.responseContentMutex.Unlock()
		}
	}()
	for range 1000 {
		result, err := c.buildResponseResults()
		if err != nil {
			t.Fatal(err)
		}
		if result.HTTPResponse != nil {
			result.HTTPResponse.Headers["generation"] = "caller"
			result.HTTPResponse.Body[0] = 0xff
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent response publication did not finish")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func newPassivePipeWebSocket(t *testing.T, rawURL string) (*websocket.Conn, error) {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	t.Cleanup(func() {
		_ = clientNet.Close()
		_ = peerNet.Close()
	})
	go func() {
		reader := bufio.NewReader(peerNet)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		if _, err := fmt.Fprintf(peerNet, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, reader)
	}()
	dialer := &websocket.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return clientNet, nil }}
	conn, _, err := dialer.Dial(rawURL, nil)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		return nil, err
	}
	return conn, nil
}

func newCloseObservingPipeWebSocket(t *testing.T, rawURL string, closeCodes chan<- int) (*websocket.Conn, error) {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	t.Cleanup(func() {
		_ = clientNet.Close()
		_ = peerNet.Close()
	})
	go func() {
		reader := bufio.NewReader(peerNet)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		if _, err := fmt.Fprintf(peerNet, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
			return
		}
		for {
			opcode, payload, err := readMaskedClientFrameWithOpcode(reader)
			if err != nil {
				return
			}
			if opcode != websocket.CloseMessage {
				continue
			}
			if len(payload) < 2 {
				closeCodes <- websocket.CloseNoStatusReceived
				return
			}
			closeCodes <- int(binary.BigEndian.Uint16(payload[:2]))
			return
		}
	}()
	dialer := &websocket.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return clientNet, nil }}
	conn, _, err := dialer.Dial(rawURL, nil)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		return nil, err
	}
	return conn, nil
}

func newBlockingAttestorRPCPipe(t *testing.T) (func(string) (*websocket.Conn, error), <-chan struct{}, <-chan struct{}) {
	t.Helper()
	rpcReceived := make(chan struct{})
	peerClosed := make(chan struct{})
	dial := func(rawURL string) (*websocket.Conn, error) {
		clientNet, peerNet := net.Pipe()
		t.Cleanup(func() {
			_ = clientNet.Close()
			_ = peerNet.Close()
		})
		go func() {
			reader := bufio.NewReader(peerNet)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			if _, err := fmt.Fprintf(peerNet, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
				return
			}
			raw, err := readMaskedClientFrame(reader)
			if err != nil {
				return
			}
			var requests teeproto.RPCMessages
			if err := proto.Unmarshal(raw, &requests); err != nil || len(requests.GetMessages()) != 1 {
				return
			}
			response := &teeproto.RPCMessages{Messages: []*teeproto.RPCMessage{{
				Id: requests.GetMessages()[0].GetId(), Message: &teeproto.RPCMessage_InitResponse{InitResponse: &teeproto.InitResponse{}},
			}}}
			encoded, err := proto.Marshal(response)
			if err != nil {
				return
			}
			if err := writeServerBinaryFrame(peerNet, encoded); err != nil {
				return
			}
			if _, err := readMaskedClientFrame(reader); err != nil {
				return
			}
			close(rpcReceived)
			if _, err := reader.ReadByte(); err != nil {
				close(peerClosed)
			}
		}()
		dialer := &websocket.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return clientNet, nil }}
		conn, _, err := dialer.Dial(rawURL, nil)
		return conn, err
	}
	return dial, rpcReceived, peerClosed
}

func newConcurrentAttestorRPCPipe(t *testing.T) (func(string) (*websocket.Conn, error), <-chan struct{}, chan<- struct{}, *atomic.Int32) {
	t.Helper()
	firstRPCReceived := make(chan struct{})
	releaseFirst := make(chan struct{})
	var dials atomic.Int32
	dial := func(rawURL string) (*websocket.Conn, error) {
		generation := dials.Add(1)
		clientNet, peerNet := net.Pipe()
		t.Cleanup(func() {
			_ = clientNet.Close()
			_ = peerNet.Close()
		})
		go func() {
			reader := bufio.NewReader(peerNet)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			if _, err := fmt.Fprintf(peerNet, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
				return
			}
			respond := func(raw []byte) error {
				var requests teeproto.RPCMessages
				if err := proto.Unmarshal(raw, &requests); err != nil || len(requests.GetMessages()) != 1 {
					return fmt.Errorf("invalid RPC request: %w", err)
				}
				response := &teeproto.RPCMessages{Messages: []*teeproto.RPCMessage{{
					Id: requests.GetMessages()[0].GetId(), Message: &teeproto.RPCMessage_InitResponse{InitResponse: &teeproto.InitResponse{}},
				}}}
				encoded, err := proto.Marshal(response)
				if err != nil {
					return err
				}
				return writeServerBinaryFrame(peerNet, encoded)
			}

			initRaw, err := readMaskedClientFrame(reader)
			if err != nil || respond(initRaw) != nil {
				return
			}
			rpcRaw, err := readMaskedClientFrame(reader)
			if err != nil {
				return
			}
			if generation == 1 {
				close(firstRPCReceived)
				select {
				case <-releaseFirst:
				case <-time.After(time.Second):
				}
				_ = peerNet.Close()
				return
			}
			if err := respond(rpcRaw); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, reader)
		}()
		dialer := &websocket.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return clientNet, nil }}
		conn, _, err := dialer.Dial(rawURL, nil)
		return conn, err
	}
	return dial, firstRPCReceived, releaseFirst, &dials
}

func newSubmitAttestorPipe(t *testing.T, delaySecond bool) (func(string) (*websocket.Conn, error), <-chan struct{}, chan<- struct{}, *atomic.Int32) {
	t.Helper()
	firstSubmitReceived := make(chan struct{})
	releaseFirst := make(chan struct{})
	var dials atomic.Int32
	dial := func(rawURL string) (*websocket.Conn, error) {
		dials.Add(1)
		clientNet, peerNet := net.Pipe()
		t.Cleanup(func() {
			_ = clientNet.Close()
			_ = peerNet.Close()
		})
		go func() {
			reader := bufio.NewReader(peerNet)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			if _, err := fmt.Fprintf(peerNet, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
				return
			}
			requestNumber := 0
			for {
				raw, err := readMaskedClientFrame(reader)
				if err != nil {
					return
				}
				var requests teeproto.RPCMessages
				if err := proto.Unmarshal(raw, &requests); err != nil || len(requests.GetMessages()) != 1 {
					return
				}
				request := requests.GetMessages()[0]
				var responseMessage teeproto.IsRPCMessage
				if request.GetInitRequest() != nil {
					responseMessage = &teeproto.RPCMessage_InitResponse{InitResponse: &teeproto.InitResponse{}}
				} else if request.GetClaimTeeBundleRequest() != nil {
					requestNumber++
					if requestNumber == 1 {
						close(firstSubmitReceived)
						select {
						case <-releaseFirst:
						case <-time.After(time.Second):
							return
						}
					} else if delaySecond {
						time.Sleep(20 * time.Millisecond)
					}
					responseMessage = &teeproto.RPCMessage_ClaimTeeBundleResponse{ClaimTeeBundleResponse: &teeproto.ClaimTeeBundleResponse{
						Result:     &teeproto.ClaimTeeBundleResponse_Claim{Claim: &teeproto.ProviderClaimData{Identifier: "claim-test", Provider: "http"}},
						Signatures: &teeproto.ClaimTeeBundleResponse_Signature{ClaimSignature: []byte{1}},
					}}
				} else {
					return
				}
				response := &teeproto.RPCMessages{Messages: []*teeproto.RPCMessage{{Id: request.GetId(), Message: responseMessage}}}
				encoded, err := proto.Marshal(response)
				if err != nil || writeServerBinaryFrame(peerNet, encoded) != nil {
					return
				}
			}
		}()
		dialer := &websocket.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return clientNet, nil }}
		conn, _, err := dialer.Dial(rawURL, nil)
		return conn, err
	}
	return dial, firstSubmitReceived, releaseFirst, &dials
}

func readMaskedClientFrame(reader io.Reader) ([]byte, error) {
	_, payload, err := readMaskedClientFrameWithOpcode(reader)
	return payload, err
}

func readMaskedClientFrameWithOpcode(reader io.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 0x0f
	payloadLength := uint64(header[1] & 0x7f)
	switch payloadLength {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		payloadLength = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		payloadLength = binary.BigEndian.Uint64(extended[:])
	}
	var mask [4]byte
	if header[1]&0x80 != 0 {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(payloadLength))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if header[1]&0x80 != 0 {
		for i := range payload {
			payload[i] ^= mask[i%len(mask)]
		}
	}
	return opcode, payload, nil
}

func writeServerBinaryFrame(writer io.Writer, payload []byte) error {
	header := []byte{0x80 | websocket.BinaryMessage}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127)
		var extended [8]byte
		binary.BigEndian.PutUint64(extended[:], uint64(len(payload)))
		header = append(header, extended[:]...)
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
