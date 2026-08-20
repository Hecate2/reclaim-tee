package main

import (
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"google.golang.org/protobuf/proto"
)

func TestOTPrecomputeCountPreflightBeforeStateAndRandomness(t *testing.T) {
	rng := &failAfterReader{remaining: 64}
	teek := &TEEK{logger: shared.NewNopLogger(), otPrecomputeRandom: rng}
	err := teek.performOTPrecomputation(mpc.MaxPrecomputeOTs+1, true)
	if err == nil || !strings.Contains(err.Error(), "unsupported OT precompute count") {
		t.Fatalf("max+1 error=%v, want count rejection", err)
	}
	if rng.read != 0 || teek.otPrecomputeState != nil {
		t.Fatalf("rejected count read %d random bytes or created state=%t", rng.read, teek.otPrecomputeState != nil)
	}

	err = teek.performOTPrecomputation(mpc.MaxPrecomputeOTs, true)
	if err == nil || !strings.Contains(err.Error(), "connection manager not initialized") {
		t.Fatalf("maximum accepted count error=%v, want post-preflight connection error", err)
	}
	if rng.read != 0 || teek.otPrecomputeState != nil {
		t.Fatal("maximum-count preflight mutated state before connection validation")
	}
}

func TestInitialOTEpochRandomFailureReturnsWithoutStateMutation(t *testing.T) {
	logger := shared.NewNopLogger()
	rng := &failAfterReader{remaining: 32}
	teek := &TEEK{logger: logger, otPrecomputeRandom: rng}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	installAckTestControl(cm, shared.NewWSConnection(nil))
	cm.attestationMutex.Lock()
	cm.attestationVerified = true
	cm.attestationMutex.Unlock()

	err := teek.performOTPrecomputation(1, true)
	if err == nil || !strings.Contains(err.Error(), "sample initial OT extension epoch") || !errors.Is(err, errInjectedRandom) {
		t.Fatalf("epoch randomness error=%v", err)
	}
	if rng.read != 32 {
		t.Fatalf("random bytes read=%d, want exactly the 32-byte session before epoch failure", rng.read)
	}
	if teek.otPrecomputeState != nil {
		t.Fatal("epoch randomness failure created or mutated OT state")
	}
}

func TestPrecomputeIdentityRejectsFrontierOverflowBeforeRandomness(t *testing.T) {
	rng := &failAfterReader{remaining: 64}
	_, _, err := newSenderPrecomputeIdentity(rng, math.MaxUint64, 1, false)
	if err == nil || !strings.Contains(err.Error(), "overflows uint64") {
		t.Fatalf("frontier overflow error=%v", err)
	}
	if rng.calls != 0 || rng.read != 0 {
		t.Fatalf("overflowing frontier made %d RNG calls and read %d bytes", rng.calls, rng.read)
	}
}

func TestMaximumKOS2CommitmentFitsWebSocketLimit(t *testing.T) {
	payloadSize, err := mpc.PrecomputeCommitmentWireSize(mpc.MaxPrecomputeOTs)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(&teeproto.Envelope{
		SessionId: "ot_precompute",
		Payload: &teeproto.Envelope_OtPrecomputeResponse{OtPrecomputeResponse: &teeproto.OTPrecomputeResponse{
			Count: mpc.MaxPrecomputeOTs, OtReceiverData: make([]byte, payloadSize),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= MaxWebSocketMessageSize {
		t.Fatalf("maximum KOS2 commitment envelope=%d bytes, limit=%d", len(encoded), MaxWebSocketMessageSize)
	}
}

var errInjectedRandom = errors.New("injected random failure")

type failAfterReader struct {
	remaining int
	read      int
	calls     int
}

func (r *failAfterReader) Read(dst []byte) (int, error) {
	r.calls++
	if r.remaining == 0 {
		return 0, errInjectedRandom
	}
	n := min(len(dst), r.remaining)
	clear(dst[:n])
	r.remaining -= n
	r.read += n
	if n < len(dst) {
		return n, errInjectedRandom
	}
	return n, nil
}

var _ io.Reader = (*failAfterReader)(nil)
