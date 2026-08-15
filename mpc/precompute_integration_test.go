package mpc

import (
	"crypto/rand"
	"slices"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"google.golang.org/protobuf/proto"
)

func TestKOS2SevenFramePrimitiveAndProtobufExchange(t *testing.T) {
	const (
		controlSession = "ot_precompute"
		count          = InputBits
		isInitial      = true
	)

	session, err := NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := InitialExtensionEpoch("00000000-0000-4000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	begin := PrecomputeBegin{SessionID: session, Count: count, Epoch: epoch}

	kPool := NewSenderPool(count)
	tPool := NewReceiverPool(count)
	kEpoch, tEpoch := epoch, epoch
	kReady, tReady := false, false
	var phases []string

	// K handler: create and send KOB2.
	beginData, err := MarshalPrecomputeBegin(begin)
	if err != nil {
		t.Fatal(err)
	}
	beginEnvelope := roundTripKOS2Envelope(t, &teeproto.Envelope{
		SessionId: controlSession,
		Payload: &teeproto.Envelope_OtPrecomputeRequest{OtPrecomputeRequest: &teeproto.OTPrecomputeRequest{
			Count: count, OtSenderSetup: beginData, IsInitial: isInitial, Epoch: epoch,
		}},
	}, &phases)

	// T handler: validate KOB2 and return KBS2.
	beginRequest := requireKOS2RequestMetadata(t, beginEnvelope, count, isInitial, tEpoch)
	decodedBegin, err := UnmarshalPrecomputeBegin(beginRequest.GetOtSenderSetup())
	if err != nil {
		t.Fatal(err)
	}
	if decodedBegin != begin || decodedBegin.StartIndex != uint64(tPool.TotalCount()) {
		t.Fatalf("begin metadata=%+v, want %+v at pool total %d", decodedBegin, begin, tPool.TotalCount())
	}
	if err := ValidatePrecomputeCount(int(decodedBegin.Count)); err != nil {
		t.Fatal(err)
	}
	baseSender, setup, err := StartBaseOTSender(rand.Reader, decodedBegin.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	setupData, err := MarshalPrecomputeBaseSetup(decodedBegin.SessionID, setup)
	if err != nil {
		t.Fatal(err)
	}
	setupEnvelope := roundTripKOS2Envelope(t, &teeproto.Envelope{
		SessionId: controlSession,
		Payload: &teeproto.Envelope_OtPrecomputeResponse{OtPrecomputeResponse: &teeproto.OTPrecomputeResponse{
			Count: count, OtReceiverData: setupData,
		}},
	}, &phases)

	// K handler: validate KBS2 and return KBC2.
	setupResponse := requireKOS2ResponseMetadata(t, setupEnvelope, count)
	decodedSetup, err := UnmarshalPrecomputeBaseSetup(setupResponse.GetOtReceiverData(), session)
	if err != nil {
		t.Fatal(err)
	}
	baseReceiver, choices, err := StartBaseOTReceiver(rand.Reader, session, decodedSetup)
	if err != nil {
		t.Fatal(err)
	}
	choiceData, err := MarshalPrecomputeBaseChoices(session, choices)
	if err != nil {
		t.Fatal(err)
	}
	choiceEnvelope := roundTripKOS2Envelope(t, &teeproto.Envelope{
		SessionId: controlSession,
		Payload: &teeproto.Envelope_OtPrecomputeRequest{OtPrecomputeRequest: &teeproto.OTPrecomputeRequest{
			Count: count, OtSenderSetup: choiceData, IsInitial: isInitial, Epoch: kEpoch,
		}},
	}, &phases)

	// T handler: validate KBC2, fix BOT+U, and return KOF2. The receiver
	// entries remain pending and the pool remains unready.
	choiceRequest := requireKOS2RequestMetadata(t, choiceEnvelope, count, isInitial, tEpoch)
	decodedChoices, err := UnmarshalPrecomputeBaseChoices(choiceRequest.GetOtSenderSetup(), session)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, basePairs, err := FinishBaseOTSender(baseSender, decodedChoices)
	if err != nil {
		t.Fatal(err)
	}
	receiverState, commitment, pendingReceiver, err := StartExtensionReceiver(
		rand.Reader, basePairs, tEpoch, ciphertext, session, begin.StartIndex, count,
	)
	if err != nil {
		t.Fatal(err)
	}
	commitmentData, err := MarshalPrecomputeCommitment(ciphertext, commitment)
	if err != nil {
		t.Fatal(err)
	}
	commitmentEnvelope := roundTripKOS2Envelope(t, &teeproto.Envelope{
		SessionId: controlSession,
		Payload: &teeproto.Envelope_OtPrecomputeResponse{OtPrecomputeResponse: &teeproto.OTPrecomputeResponse{
			Count: count, OtReceiverData: commitmentData,
		}},
	}, &phases)
	assertKOS2Pools(t, kPool, tPool, kReady, tReady, 0)

	// K handler: parse and validate the complete KOF2 commitment before it
	// samples the full independent challenge and returns KCH2.
	commitmentResponse := requireKOS2ResponseMetadata(t, commitmentEnvelope, count)
	decodedCiphertext, decodedCommitment, err := UnmarshalPrecomputeCommitment(commitmentResponse.GetOtReceiverData())
	if err != nil {
		t.Fatal(err)
	}
	if decodedCommitment.SessionID != session || decodedCommitment.StartIndex != begin.StartIndex || decodedCommitment.Count != count {
		t.Fatalf("commitment metadata session=%x start=%d count=%d", decodedCommitment.SessionID, decodedCommitment.StartIndex, decodedCommitment.Count)
	}
	selected, delta, err := FinishBaseOTReceiver(baseReceiver, decodedCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	senderState, challenge, err := StartExtensionSender(rand.Reader, selected, delta, kEpoch, decodedCiphertext, decodedCommitment)
	if err != nil {
		t.Fatal(err)
	}
	challengeData, err := MarshalExtensionChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	challengeEnvelope := roundTripKOS2Envelope(t, &teeproto.Envelope{
		SessionId: controlSession,
		Payload: &teeproto.Envelope_OtPrecomputeRequest{OtPrecomputeRequest: &teeproto.OTPrecomputeRequest{
			Count: count, OtSenderSetup: challengeData, IsInitial: isInitial, Epoch: kEpoch,
		}},
	}, &phases)

	// T handler: validate KCH2 and return KPR2. Proof generation still does
	// not publish the pending receiver entries.
	challengeRequest := requireKOS2RequestMetadata(t, challengeEnvelope, count, isInitial, tEpoch)
	decodedChallenge, err := UnmarshalExtensionChallenge(challengeRequest.GetOtSenderSetup())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := FinishExtensionReceiver(receiverState, decodedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	proofData, err := MarshalExtensionProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	proofEnvelope := roundTripKOS2Envelope(t, &teeproto.Envelope{
		SessionId: controlSession,
		Payload: &teeproto.Envelope_OtPrecomputeResponse{OtPrecomputeResponse: &teeproto.OTPrecomputeResponse{
			Count: count, OtReceiverData: proofData,
		}},
	}, &phases)
	assertKOS2Pools(t, kPool, tPool, kReady, tReady, 0)

	// K handler: verify all 128 equations before creating Complete. Neither
	// pool has committed anything at the point FinishExtensionSender returns.
	proofResponse := requireKOS2ResponseMetadata(t, proofEnvelope, count)
	decodedProof, err := UnmarshalExtensionProof(proofResponse.GetOtReceiverData())
	if err != nil {
		t.Fatal(err)
	}
	pendingSender, err := FinishExtensionSender(senderState, decodedProof)
	if err != nil {
		t.Fatal(err)
	}
	assertKOS2Pools(t, kPool, tPool, kReady, tReady, 0)
	completeEnvelope := roundTripKOS2Envelope(t, &teeproto.Envelope{
		SessionId: controlSession,
		Payload: &teeproto.Envelope_OtPrecomputeComplete{OtPrecomputeComplete: &teeproto.OTPrecomputeComplete{
			PoolSize: uint32(kPool.TotalCount() + len(pendingSender)),
		}},
	}, &phases)

	// The successful Complete write lets K commit locally. T commits the
	// matching pending entries only after it handles that same message.
	if err := kPool.Add(pendingSender); err != nil {
		t.Fatal(err)
	}
	kEpoch = ExtensionEpoch(session)
	kReady = true
	if completeEnvelope.GetSessionId() != controlSession || completeEnvelope.GetOtPrecomputeComplete() == nil {
		t.Fatal("invalid OTPrecomputeComplete envelope")
	}
	if got := completeEnvelope.GetOtPrecomputeComplete().GetPoolSize(); got != uint32(tPool.TotalCount()+len(pendingReceiver)) {
		t.Fatalf("complete pool size=%d, want %d", got, tPool.TotalCount()+len(pendingReceiver))
	}
	if err := tPool.Add(pendingReceiver); err != nil {
		t.Fatal(err)
	}
	tEpoch = ExtensionEpoch(session)
	tReady = true

	wantPhases := []string{"KOB2", "KBS2", "KBC2", "KOF2", "KCH2", "KPR2", "Complete"}
	if !slices.Equal(phases, wantPhases) {
		t.Fatalf("frame phases=%v, want %v", phases, wantPhases)
	}
	if kEpoch != tEpoch || kEpoch != ExtensionEpoch(session) {
		t.Fatalf("committed epochs K=%q T=%q want=%q", kEpoch, tEpoch, ExtensionEpoch(session))
	}
	assertKOS2Pools(t, kPool, tPool, kReady, tReady, count)
	if err := ValidatePoolAgreement(kPool, tPool); err != nil {
		t.Fatal(err)
	}

	_, senderEntries, err := kPool.Reserve(count)
	if err != nil {
		t.Fatal(err)
	}
	receiverEntries, err := tPool.Consume(0, count)
	if err != nil {
		t.Fatal(err)
	}
	for i := range senderEntries {
		want := senderEntries[i].R0
		if receiverEntries[i].Choice {
			want = senderEntries[i].R1
		}
		if receiverEntries[i].Index != senderEntries[i].Index || receiverEntries[i].R != want {
			t.Fatalf("committed OT %d does not match", i)
		}
	}
}

func roundTripKOS2Envelope(t *testing.T, envelope *teeproto.Envelope, phases *[]string) *teeproto.Envelope {
	t.Helper()
	encoded, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(teeproto.Envelope)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetSessionId() != "ot_precompute" {
		t.Fatalf("control session=%q, want ot_precompute", decoded.GetSessionId())
	}
	var phase string
	switch payload := decoded.GetPayload().(type) {
	case *teeproto.Envelope_OtPrecomputeRequest:
		if len(payload.OtPrecomputeRequest.GetOtSenderSetup()) < 4 {
			t.Fatal("short OTPrecomputeRequest phase frame")
		}
		phase = string(payload.OtPrecomputeRequest.GetOtSenderSetup()[:4])
	case *teeproto.Envelope_OtPrecomputeResponse:
		if len(payload.OtPrecomputeResponse.GetOtReceiverData()) < 4 {
			t.Fatal("short OTPrecomputeResponse phase frame")
		}
		phase = string(payload.OtPrecomputeResponse.GetOtReceiverData()[:4])
	case *teeproto.Envelope_OtPrecomputeComplete:
		phase = "Complete"
	default:
		t.Fatalf("unexpected precompute envelope payload %T", payload)
	}
	*phases = append(*phases, phase)
	return decoded
}

func requireKOS2RequestMetadata(t *testing.T, envelope *teeproto.Envelope, count uint32, initial bool, epoch string) *teeproto.OTPrecomputeRequest {
	t.Helper()
	request := envelope.GetOtPrecomputeRequest()
	if request == nil {
		t.Fatal("expected OTPrecomputeRequest")
	}
	if request.GetCount() != count || request.GetIsInitial() != initial || request.GetEpoch() != epoch {
		t.Fatalf("request metadata count=%d initial=%t epoch=%q, want %d %t %q", request.GetCount(), request.GetIsInitial(), request.GetEpoch(), count, initial, epoch)
	}
	return request
}

func requireKOS2ResponseMetadata(t *testing.T, envelope *teeproto.Envelope, count uint32) *teeproto.OTPrecomputeResponse {
	t.Helper()
	response := envelope.GetOtPrecomputeResponse()
	if response == nil {
		t.Fatal("expected OTPrecomputeResponse")
	}
	if response.GetCount() != count {
		t.Fatalf("response count=%d, want %d", response.GetCount(), count)
	}
	return response
}

func assertKOS2Pools(t *testing.T, kPool *SenderPool, tPool *ReceiverPool, kReady, tReady bool, want int) {
	t.Helper()
	if kPool.TotalCount() != want || kPool.Available() != want || tPool.TotalCount() != want || tPool.Available() != want {
		t.Fatalf("pool counts K=(%d,%d) T=(%d,%d), want totals and available %d", kPool.TotalCount(), kPool.Available(), tPool.TotalCount(), tPool.Available(), want)
	}
	if kReady != (want > 0) || tReady != (want > 0) {
		t.Fatalf("readiness K=%t T=%t, want %t", kReady, tReady, want > 0)
	}
}
