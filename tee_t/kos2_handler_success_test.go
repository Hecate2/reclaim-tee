package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func TestKOS2ReceiverProductionHandlerSevenFrameSuccess(t *testing.T) {
	const count = mpc.InputBits
	logger := shared.NewNopLogger()
	teet := &TEET{logger: logger}
	cm := NewTEEKConnectionManager(teet, logger)
	teet.connManager = cm
	control, inbound, outbound := newKOS2ReceiverControlWebSocket(t)
	generation, superseded, sessions, owners := cm.activateControlConnection(control)
	if superseded != nil || len(sessions) != 0 || len(owners) != 0 {
		t.Fatal("fresh production receiver control unexpectedly superseded state")
	}
	if err := cm.completeControlAttestation(control, generation, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !cm.isCurrentControlConnection(control, generation) || !cm.IsAttestationVerified() {
		t.Fatal("production receiver control owner was not installed and attested")
	}
	go cm.handleControlMessages(control, generation)

	session, err := mpc.NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := mpc.InitialExtensionEpoch("00000000-0000-4000-8000-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	begin := mpc.PrecomputeBegin{SessionID: session, Count: count, Epoch: epoch}
	beginFrame, err := mpc.MarshalPrecomputeBegin(begin)
	if err != nil {
		t.Fatal(err)
	}

	var phases []string
	sendKOS2ReceiverRequest(t, inbound, count, true, epoch, beginFrame, &phases)
	setupEnvelope := receiveKOS2ReceiverEnvelope(t, outbound)
	setupResponse := requireKOS2ReceiverResponse(t, setupEnvelope, count)
	phases = append(phases, string(setupResponse.GetOtReceiverData()[:4]))
	setup, err := mpc.UnmarshalPrecomputeBaseSetup(setupResponse.GetOtReceiverData(), session)
	if err != nil {
		t.Fatal(err)
	}
	assertKOS2ReceiverPending(t, teet, generation, receiverPrecomputeAwaitBaseChoices, 0, false)

	baseReceiver, choices, err := mpc.StartBaseOTReceiver(rand.Reader, session, setup)
	if err != nil {
		t.Fatal(err)
	}
	choiceFrame, err := mpc.MarshalPrecomputeBaseChoices(session, choices)
	if err != nil {
		t.Fatal(err)
	}
	sendKOS2ReceiverRequest(t, inbound, count, true, epoch, choiceFrame, &phases)
	commitmentEnvelope := receiveKOS2ReceiverEnvelope(t, outbound)
	commitmentResponse := requireKOS2ReceiverResponse(t, commitmentEnvelope, count)
	phases = append(phases, string(commitmentResponse.GetOtReceiverData()[:4]))
	ciphertext, commitment, err := mpc.UnmarshalPrecomputeCommitment(commitmentResponse.GetOtReceiverData())
	if err != nil {
		t.Fatal(err)
	}
	assertKOS2ReceiverPending(t, teet, generation, receiverPrecomputeAwaitChallenge, 0, false)

	selected, delta, err := mpc.FinishBaseOTReceiver(baseReceiver, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	senderState, challenge, err := mpc.StartExtensionSender(rand.Reader, selected, delta, epoch, ciphertext, commitment)
	if err != nil {
		t.Fatal(err)
	}
	challengeFrame, err := mpc.MarshalExtensionChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	sendKOS2ReceiverRequest(t, inbound, count, true, epoch, challengeFrame, &phases)
	proofEnvelope := receiveKOS2ReceiverEnvelope(t, outbound)
	proofResponse := requireKOS2ReceiverResponse(t, proofEnvelope, count)
	phases = append(phases, string(proofResponse.GetOtReceiverData()[:4]))
	proof, err := mpc.UnmarshalExtensionProof(proofResponse.GetOtReceiverData())
	if err != nil {
		t.Fatal(err)
	}
	pending := assertKOS2ReceiverPending(t, teet, generation, receiverPrecomputeAwaitComplete, 0, false)

	senderEntries, err := mpc.FinishExtensionSender(senderState, proof)
	if err != nil {
		t.Fatal(err)
	}
	complete := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeComplete{OtPrecomputeComplete: &teeproto.OTPrecomputeComplete{PoolSize: count}},
	}
	sendKOS2ReceiverEnvelope(t, inbound, complete)
	phases = append(phases, "Complete")
	select {
	case <-pending.done:
	case <-time.After(5 * time.Second):
		t.Fatal("production receiver did not handle Complete")
	}
	if pending.outcome != receiverPrecomputeCommitted {
		t.Fatalf("receiver pending outcome=%d, want committed", pending.outcome)
	}

	wantPhases := []string{"KOB2", "KBS2", "KBC2", "KOF2", "KCH2", "KPR2", "Complete"}
	if !slices.Equal(phases, wantPhases) {
		t.Fatalf("production receiver phases=%v, want %v", phases, wantPhases)
	}
	teet.otReceiverStateMu.Lock()
	state := teet.otReceiverState
	if state == nil || state.pending != nil || !state.ready || state.epoch != mpc.ExtensionEpoch(session) {
		teet.otReceiverStateMu.Unlock()
		t.Fatalf("committed receiver state=%+v", state)
	}
	if state.pool.TotalCount() != count || state.pool.Available() != count {
		teet.otReceiverStateMu.Unlock()
		t.Fatalf("committed receiver pool total=%d available=%d", state.pool.TotalCount(), state.pool.Available())
	}
	teet.otReceiverStateMu.Unlock()
	if !teet.isOTReceiverPoolReady() || !teet.otReady.Load() {
		t.Fatal("production receiver readiness was not published")
	}

	receiverEntries, err := state.pool.Consume(0, count)
	if err != nil {
		t.Fatal(err)
	}
	for i := range senderEntries {
		want := senderEntries[i].R0
		if receiverEntries[i].Choice {
			want = senderEntries[i].R1
		}
		if senderEntries[i].Index != receiverEntries[i].Index || receiverEntries[i].R != want {
			t.Fatalf("production receiver OT %d does not match peer sender entry", i)
		}
	}
}

func newKOS2ReceiverControlWebSocket(t *testing.T) (*shared.WSConnection, chan<- []byte, <-chan []byte) {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	handshake := make(chan error, 1)
	inbound := make(chan []byte, 8)
	outbound := make(chan []byte, 8)
	go serveKOS2ReceiverControlWebSocket(peerNet, handshake, inbound, outbound)
	conn, _, err := websocket.NewClient(clientNet, &url.URL{Scheme: "ws", Host: "in-memory", Path: "/"}, nil, 64*1024, 64*1024)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		t.Fatalf("dial KOS2 receiver websocket: %v", err)
	}
	if err := <-handshake; err != nil {
		_ = conn.Close()
		_ = peerNet.Close()
		t.Fatalf("serve KOS2 receiver websocket handshake: %v", err)
	}
	t.Cleanup(func() {
		close(inbound)
		_ = conn.Close()
		_ = peerNet.Close()
	})
	return shared.NewWSConnection(conn), inbound, outbound
}

func serveKOS2ReceiverControlWebSocket(peer net.Conn, handshake chan<- error, inbound <-chan []byte, outbound chan<- []byte) {
	reader := bufio.NewReader(peer)
	request, err := http.ReadRequest(reader)
	if err != nil {
		handshake <- err
		return
	}
	sum := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, err = fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	handshake <- err
	if err != nil {
		return
	}
	go func() {
		for payload := range inbound {
			if writeServerBinaryFrame(peer, payload) != nil {
				return
			}
		}
	}()
	for {
		opcode, payload, readErr := readKOS2ReceiverClientFrame(reader)
		if readErr != nil || opcode == websocket.CloseMessage {
			return
		}
		if opcode == websocket.BinaryMessage {
			outbound <- payload
		}
	}
}

func readKOS2ReceiverClientFrame(reader *bufio.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
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
	if payloadLength > MaxWebSocketMessageSize {
		return 0, nil, fmt.Errorf("test websocket frame is too large: %d", payloadLength)
	}
	var mask [4]byte
	masked := header[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(payloadLength))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%len(mask)]
		}
	}
	return header[0] & 0x0f, payload, nil
}

func sendKOS2ReceiverRequest(t *testing.T, inbound chan<- []byte, count uint32, initial bool, epoch string, payload []byte, phases *[]string) {
	t.Helper()
	if len(payload) < 4 {
		t.Fatal("short peer request payload")
	}
	envelope := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeRequest{OtPrecomputeRequest: &teeproto.OTPrecomputeRequest{
			Count: count, OtSenderSetup: payload, IsInitial: initial, Epoch: epoch,
		}},
	}
	request := envelope.GetOtPrecomputeRequest()
	if envelope.GetTimestampMs() <= 0 || request.GetCount() != count || request.GetIsInitial() != initial || request.GetEpoch() != epoch {
		t.Fatalf("invalid peer request metadata: %+v", request)
	}
	*phases = append(*phases, string(payload[:4]))
	sendKOS2ReceiverEnvelope(t, inbound, envelope)
}

func sendKOS2ReceiverEnvelope(t *testing.T, inbound chan<- []byte, envelope *teeproto.Envelope) {
	t.Helper()
	if envelope.GetSessionId() != "ot_precompute" || envelope.GetTimestampMs() <= 0 {
		t.Fatalf("invalid peer control envelope: %+v", envelope)
	}
	data, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case inbound <- data:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out sending peer frame to production receiver")
	}
}

func receiveKOS2ReceiverEnvelope(t *testing.T, outbound <-chan []byte) *teeproto.Envelope {
	t.Helper()
	select {
	case data := <-outbound:
		envelope := new(teeproto.Envelope)
		if err := proto.Unmarshal(data, envelope); err != nil {
			t.Fatal(err)
		}
		return envelope
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for production receiver frame")
		return nil
	}
}

func requireKOS2ReceiverResponse(t *testing.T, envelope *teeproto.Envelope, count uint32) *teeproto.OTPrecomputeResponse {
	t.Helper()
	response := envelope.GetOtPrecomputeResponse()
	if envelope.GetSessionId() != "ot_precompute" || envelope.GetTimestampMs() <= 0 || response == nil || response.GetCount() != count || len(response.GetOtReceiverData()) < 4 {
		t.Fatalf("invalid production receiver response: %+v", envelope)
	}
	return response
}

func assertKOS2ReceiverPending(
	t *testing.T,
	teet *TEET,
	generation uint64,
	wantPhase receiverPrecomputePhase,
	wantPool int,
	wantReady bool,
) *receiverPrecompute {
	t.Helper()
	teet.otReceiverStateMu.Lock()
	defer teet.otReceiverStateMu.Unlock()
	state := teet.otReceiverState
	if state == nil || state.pending == nil || state.pending.phase != wantPhase {
		t.Fatalf("receiver state/pending phase=%+v, want %d", state, wantPhase)
	}
	if state.pending.controlGeneration != generation {
		t.Fatalf("receiver pending generation=%d, want owner generation %d", state.pending.controlGeneration, generation)
	}
	if state.pool.TotalCount() != wantPool || state.pool.Available() != wantPool || state.ready != wantReady {
		t.Fatalf("receiver pre-proof pool total=%d available=%d ready=%t", state.pool.TotalCount(), state.pool.Available(), state.ready)
	}
	return state.pending
}
