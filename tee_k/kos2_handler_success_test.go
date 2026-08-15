package main

import (
	"crypto/rand"
	"net"
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

func TestKOS2SenderProductionHandlerSevenFrameSuccess(t *testing.T) {
	const count = mpc.InputBits
	logger := shared.NewNopLogger()
	teek := &TEEK{logger: logger}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	control, outbound := newKOS2SenderCaptureWebSocket(t)
	_, generation := installAckTestControl(cm, control)
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()

	result := make(chan error, 1)
	go func() {
		result <- teek.performOTPrecomputation(count, true)
	}()

	var phases []string
	beginEnvelope := receiveKOS2SenderEnvelope(t, outbound)
	beginRequest := requireKOS2SenderRequest(t, beginEnvelope, count, true, "")
	phases = append(phases, string(beginRequest.GetOtSenderSetup()[:4]))
	begin, err := mpc.UnmarshalPrecomputeBegin(beginRequest.GetOtSenderSetup())
	if err != nil {
		t.Fatal(err)
	}
	if begin.StartIndex != 0 || begin.Count != count || begin.Epoch != beginRequest.GetEpoch() {
		t.Fatalf("begin metadata start=%d count=%d epoch=%q", begin.StartIndex, begin.Count, begin.Epoch)
	}
	assertKOS2SenderPending(t, teek, control, generation, senderPrecomputeAwaitBaseSetup, 0, false)

	// The peer produces a valid KBS2 response. Dispatch through the production
	// control-message router, not directly into the cryptographic primitive.
	baseSender, setup, err := mpc.StartBaseOTSender(rand.Reader, begin.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	setupFrame, err := mpc.MarshalPrecomputeBaseSetup(begin.SessionID, setup)
	if err != nil {
		t.Fatal(err)
	}
	dispatchKOS2SenderResponse(t, cm, control, generation, count, setupFrame, &phases)

	choiceEnvelope := receiveKOS2SenderEnvelope(t, outbound)
	choiceRequest := requireKOS2SenderRequest(t, choiceEnvelope, count, true, begin.Epoch)
	phases = append(phases, string(choiceRequest.GetOtSenderSetup()[:4]))
	choices, err := mpc.UnmarshalPrecomputeBaseChoices(choiceRequest.GetOtSenderSetup(), begin.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	assertKOS2SenderPending(t, teek, control, generation, senderPrecomputeAwaitCommitment, 0, false)

	// The peer fixes BOT+U and returns KOF2. The production handler must move
	// to AwaitProof and emit KCH2 without publishing any sender entries.
	ciphertext, pairs, err := mpc.FinishBaseOTSender(baseSender, choices)
	if err != nil {
		t.Fatal(err)
	}
	receiverState, commitment, receiverEntries, err := mpc.StartExtensionReceiver(
		rand.Reader, pairs, begin.Epoch, ciphertext, begin.SessionID, begin.StartIndex, count,
	)
	if err != nil {
		t.Fatal(err)
	}
	commitmentFrame, err := mpc.MarshalPrecomputeCommitment(ciphertext, commitment)
	if err != nil {
		t.Fatal(err)
	}
	dispatchKOS2SenderResponse(t, cm, control, generation, count, commitmentFrame, &phases)

	challengeEnvelope := receiveKOS2SenderEnvelope(t, outbound)
	challengeRequest := requireKOS2SenderRequest(t, challengeEnvelope, count, true, begin.Epoch)
	phases = append(phases, string(challengeRequest.GetOtSenderSetup()[:4]))
	challenge, err := mpc.UnmarshalExtensionChallenge(challengeRequest.GetOtSenderSetup())
	if err != nil {
		t.Fatal(err)
	}
	assertKOS2SenderPending(t, teek, control, generation, senderPrecomputeAwaitProof, 0, false)

	proof, err := mpc.FinishExtensionReceiver(receiverState, challenge)
	if err != nil {
		t.Fatal(err)
	}
	proofFrame, err := mpc.MarshalExtensionProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	dispatchKOS2SenderResponse(t, cm, control, generation, count, proofFrame, &phases)

	completeEnvelope := receiveKOS2SenderEnvelope(t, outbound)
	complete := completeEnvelope.GetOtPrecomputeComplete()
	if completeEnvelope.GetSessionId() != "ot_precompute" || completeEnvelope.GetTimestampMs() <= 0 || complete == nil {
		t.Fatalf("invalid production Complete envelope: %+v", completeEnvelope)
	}
	phases = append(phases, "Complete")
	if complete.GetPoolSize() != count {
		t.Fatalf("Complete pool size=%d, want %d", complete.GetPoolSize(), count)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("performOTPrecomputation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("production sender precomputation did not complete")
	}

	wantPhases := []string{"KOB2", "KBS2", "KBC2", "KOF2", "KCH2", "KPR2", "Complete"}
	if !slices.Equal(phases, wantPhases) {
		t.Fatalf("production sender phases=%v, want %v", phases, wantPhases)
	}
	state := teek.otPrecomputeState
	if state == nil {
		t.Fatal("production sender state was not retained")
	}
	state.mu.Lock()
	if state.pending != nil || !state.ready || state.inconsistent || state.epoch != mpc.ExtensionEpoch(begin.SessionID) {
		state.mu.Unlock()
		t.Fatalf("committed sender state pending=%t ready=%t inconsistent=%t epoch=%q", state.pending != nil, state.ready, state.inconsistent, state.epoch)
	}
	if state.pool.TotalCount() != count || state.pool.Available() != count {
		state.mu.Unlock()
		t.Fatalf("committed sender pool total=%d available=%d", state.pool.TotalCount(), state.pool.Available())
	}
	state.mu.Unlock()
	if !teek.isOTPoolReady() {
		t.Fatal("production sender readiness was not published")
	}

	_, senderEntries, err := state.pool.Reserve(count)
	if err != nil {
		t.Fatal(err)
	}
	for i := range senderEntries {
		want := senderEntries[i].R0
		if receiverEntries[i].Choice {
			want = senderEntries[i].R1
		}
		if senderEntries[i].Index != receiverEntries[i].Index || receiverEntries[i].R != want {
			t.Fatalf("production sender OT %d does not match peer receiver entry", i)
		}
	}
}

func newKOS2SenderCaptureWebSocket(t *testing.T) (*shared.WSConnection, <-chan []byte) {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	handshake := make(chan error, 1)
	messages := make(chan []byte, 8)
	go serveAckTestCapturingWebSocket(peerNet, handshake, messages)
	// The package-wide capture helper uses a 1 KiB buffer and its deliberately
	// small raw-frame reader does not reassemble continuation frames. KBC2 is
	// 4,296 bytes, so keep every frame whole in this handler-level test.
	conn, _, err := websocket.NewClient(clientNet, &url.URL{Scheme: "ws", Host: "in-memory", Path: "/"}, nil, 64*1024, 64*1024)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		t.Fatalf("dial KOS2 capture websocket: %v", err)
	}
	if err := <-handshake; err != nil {
		_ = conn.Close()
		_ = peerNet.Close()
		t.Fatalf("serve KOS2 capture websocket handshake: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peerNet.Close()
	})
	return shared.NewWSConnection(conn), messages
}

func receiveKOS2SenderEnvelope(t *testing.T, messages <-chan []byte) *teeproto.Envelope {
	t.Helper()
	select {
	case data := <-messages:
		envelope := new(teeproto.Envelope)
		if err := proto.Unmarshal(data, envelope); err != nil {
			t.Fatal(err)
		}
		return envelope
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for production sender frame")
		return nil
	}
}

func requireKOS2SenderRequest(t *testing.T, envelope *teeproto.Envelope, count uint32, initial bool, epoch string) *teeproto.OTPrecomputeRequest {
	t.Helper()
	request := envelope.GetOtPrecomputeRequest()
	if envelope.GetSessionId() != "ot_precompute" || envelope.GetTimestampMs() <= 0 || request == nil {
		t.Fatalf("invalid production request envelope: %+v", envelope)
	}
	if request.GetCount() != count || request.GetIsInitial() != initial {
		t.Fatalf("request metadata count=%d initial=%t, want %d %t", request.GetCount(), request.GetIsInitial(), count, initial)
	}
	if epoch != "" && request.GetEpoch() != epoch {
		t.Fatalf("request epoch=%q, want %q", request.GetEpoch(), epoch)
	}
	if len(request.GetOtSenderSetup()) < 4 {
		t.Fatal("short production sender request phase")
	}
	return request
}

func dispatchKOS2SenderResponse(
	t *testing.T,
	cm *TEETConnectionManager,
	control *shared.WSConnection,
	generation uint64,
	count uint32,
	payload []byte,
	phases *[]string,
) {
	t.Helper()
	envelope := &teeproto.Envelope{
		SessionId: "ot_precompute", TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_OtPrecomputeResponse{OtPrecomputeResponse: &teeproto.OTPrecomputeResponse{
			Count: count, OtReceiverData: payload,
		}},
	}
	data, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(teeproto.Envelope)
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	response := decoded.GetOtPrecomputeResponse()
	if decoded.GetSessionId() != "ot_precompute" || decoded.GetTimestampMs() <= 0 || response == nil || response.GetCount() != count || len(response.GetOtReceiverData()) < 4 {
		t.Fatalf("invalid peer response envelope: %+v", decoded)
	}
	*phases = append(*phases, string(response.GetOtReceiverData()[:4]))
	cm.handleControlMessage(control, generation, data)
}

func assertKOS2SenderPending(
	t *testing.T,
	teek *TEEK,
	control *shared.WSConnection,
	generation uint64,
	wantPhase senderPrecomputePhase,
	wantPool int,
	wantReady bool,
) {
	t.Helper()
	state := teek.otPrecomputeState
	if state == nil {
		t.Fatal("production sender state is nil")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	pending := state.pending
	if pending == nil || pending.phase != wantPhase {
		t.Fatalf("sender pending phase=%v, want %v", pending, wantPhase)
	}
	if pending.controlConn != control || pending.controlGeneration != generation {
		t.Fatal("sender pending control owner does not match current generation")
	}
	if state.pool.TotalCount() != wantPool || state.pool.Available() != wantPool || state.ready != wantReady {
		t.Fatalf("sender pre-proof pool total=%d available=%d ready=%t", state.pool.TotalCount(), state.pool.Available(), state.ready)
	}
}
