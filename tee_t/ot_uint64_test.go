package main

import (
	"crypto/rand"
	"math"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestHandleOPRFOnlineFullPreservesHighDuplicatedOTStart(t *testing.T) {
	const sessionID = "high-ot-start"
	manager := NewTEETSessionManager()
	if err := manager.RegisterSession(sessionID); err != nil {
		t.Fatal(err)
	}
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	state := &TEETSessionState{session: session, ConsolidatedResponseCiphertext: []byte{1}}
	manager.SetTEETSessionState(sessionID, state)
	receiverState := NewOTReceiverState()
	receiverState.ready = true
	teet := &TEET{
		sessionManager: manager, logger: shared.NewNopLogger(), oprfKeyShare: make([]byte, 16),
		otReceiverState: receiverState,
	}

	payload := highStartOnlinePayloadForTest(t, math.MaxUint32+1)
	encoded, err := mpc.MarshalOnlinePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	oprfSessionID := payload.SessionID
	otStartIndex := payload.OTStartIndex
	payload.Release()
	reachedConsume := false
	identity := &teetSessionIdentity{session: session, beforeOTReceiverConsume: func() { reachedConsume = true }}
	err = teet.handleOPRFOnlineFull(identity, &teeproto.OPRFOnlineFull{
		SessionId: sessionID, OprfSessionId: oprfSessionID, RangeIndex: 0,
		TlsStart: 0, TlsLength: 1, TlsSessionHash: []byte{1}, GarbledTables: encoded,
		OtStartIndex: otStartIndex, TotalRanges: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "connection manager is not initialized") {
		t.Fatalf("handler error=%v", err)
	}
	if !reachedConsume {
		t.Fatal("high uint64 OT start was rejected before exact duplicated-index validation")
	}
}

func TestHandleOTPrecomputeCompleteDoesNotTruncateHighPoolSize(t *testing.T) {
	pending := &receiverPrecompute{
		begin: mpc.PrecomputeBegin{StartIndex: 0, Count: 1}, entries: []mpc.ReceiverOT{{Index: 0}},
		phase: receiverPrecomputeAwaitComplete, done: make(chan struct{}),
	}
	state := &OTReceiverState{pool: mpc.NewReceiverPool(1), pending: pending}
	teet := &TEET{otReceiverState: state, logger: shared.NewNopLogger()}

	err := teet.handleOTPrecomputeComplete(0, directControlStateLease, &teeproto.OTPrecomputeComplete{PoolSize: math.MaxUint32 + 2})
	if err == nil || !strings.Contains(err.Error(), "pool total mismatch") {
		t.Fatalf("completion error=%v", err)
	}
	if state.pool.TotalCount() != 0 || state.pending != pending || state.ready {
		t.Fatal("mismatched high completion mutated receiver state")
	}
}

func TestHandleOTResumeRequestDoesNotTruncateHighNextIndex(t *testing.T) {
	epoch := mpc.ExtensionEpoch([32]byte{1})
	state := &OTReceiverState{pool: mpc.NewReceiverPool(1), ready: true, epoch: epoch}
	teet := &TEET{otReceiverState: state, logger: shared.NewNopLogger()}
	control, _, outbound := newKOS2ReceiverControlWebSocket(t)

	if err := teet.handleOTResumeRequest(control, directControlStateLease, &teeproto.OTResumeRequest{
		Epoch: epoch, NextIndex: math.MaxUint32 + 1,
	}); err != nil {
		t.Fatal(err)
	}
	response := receiveKOS2ReceiverEnvelope(t, outbound).GetOtResumeResponse()
	if response == nil || response.GetAccepted() {
		t.Fatalf("high resume response=%+v, want rejected", response)
	}
	if state.pool.NextIndex() != 0 || state.pool.TotalCount() != 0 {
		t.Fatal("rejected high resume mutated receiver pool")
	}
}

func highStartOnlinePayloadForTest(t *testing.T, start uint64) *mpc.OnlinePayload {
	t.Helper()
	// Create a structurally valid opaque MPC1 payload, then replace only its
	// already-uint64 start field through a round trip.
	sender := make([]mpc.SenderOT, mpc.InputBits)
	for i := range sender {
		sender[i].Index = uint64(i)
	}
	payload, _, err := mpc.GarblerOnline(rand.Reader, [80]byte{}, sender, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload.OTStartIndex = start
	return payload
}
