package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestKOS2ProofFailureCommitsNoSenderEntries(t *testing.T) {
	session, err := mpc.NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := mpc.ExtensionEpoch([32]byte{4})
	baseSender, setup, err := mpc.StartBaseOTSender(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	baseReceiver, choices, err := mpc.StartBaseOTReceiver(rand.Reader, session, setup)
	if err != nil {
		t.Fatal(err)
	}
	cipher, pairs, err := mpc.FinishBaseOTSender(baseSender, choices)
	if err != nil {
		t.Fatal(err)
	}
	receiverState, commitment, _, err := mpc.StartExtensionReceiver(rand.Reader, pairs, epoch, cipher, session, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	selected, delta, err := mpc.FinishBaseOTReceiver(baseReceiver, cipher)
	if err != nil {
		t.Fatal(err)
	}
	extension, challenge, err := mpc.StartExtensionSender(rand.Reader, selected, delta, epoch, cipher, commitment)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := mpc.FinishExtensionReceiver(receiverState, challenge)
	if err != nil {
		t.Fatal(err)
	}
	proof.T[127].D0 ^= 1
	proofFrame, err := mpc.MarshalExtensionProof(proof)
	if err != nil {
		t.Fatal(err)
	}

	logger := shared.NewNopLogger()
	state := NewOTPrecomputeState()
	teek := &TEEK{logger: logger, otPrecomputeState: state}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	control, generation := installAckTestControl(cm, shared.NewWSConnection(nil))
	pending := &senderPrecompute{
		session: session, count: 1, isInitial: true, extension: extension,
		phase: senderPrecomputeAwaitProof, done: make(chan error, 1),
		controlConn: control, controlGeneration: generation,
	}
	state.mu.Lock()
	state.epoch = epoch
	state.pending = pending
	state.mu.Unlock()

	err = teek.handleOTPrecomputeResponse(control, generation, &teeproto.OTPrecomputeResponse{Count: 1, OtReceiverData: proofFrame})
	if err == nil {
		t.Fatal("accepted tampered KOS2 proof")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pool.TotalCount() != 0 || state.pool.Available() != 0 {
		t.Fatalf("proof failure changed sender pool: total=%d available=%d", state.pool.TotalCount(), state.pool.Available())
	}
	if state.pending != nil {
		t.Fatal("proof failure retained pending sender batch")
	}
}

func TestKOS2CommitmentOversizeCountFailsBeforeSenderPoolMutation(t *testing.T) {
	const count = 1
	session, err := mpc.NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := mpc.ExtensionEpoch([32]byte{6})
	baseSender, setup, err := mpc.StartBaseOTSender(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	_, choices, err := mpc.StartBaseOTReceiver(rand.Reader, session, setup)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, pairs, err := mpc.FinishBaseOTSender(baseSender, choices)
	if err != nil {
		t.Fatal(err)
	}
	_, commitment, _, err := mpc.StartExtensionReceiver(rand.Reader, pairs, epoch, ciphertext, session, 0, count)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := mpc.MarshalPrecomputeCommitment(ciphertext, commitment)
	if err != nil {
		t.Fatal(err)
	}
	nested := bytes.Index(frame, []byte("KOC2"))
	if nested < 0 {
		t.Fatal("valid commitment frame lacks KOC2")
	}
	binary.BigEndian.PutUint32(frame[nested+44:nested+48], mpc.MaxPrecomputeOTs+1)

	teek, state, control, generation := newKOS2MalformedSenderState(t, session, epoch, senderPrecomputeAwaitCommitment)
	baseReceiver := state.pending.baseReceiver
	err = teek.handleOTPrecomputeResponse(control, generation, &teeproto.OTPrecomputeResponse{Count: count, OtReceiverData: frame})
	if err == nil {
		t.Fatal("accepted commitment with attacker-controlled oversize nested count")
	}
	assertKOS2MalformedSenderPoolUnchanged(t, state)
	if _, _, err := mpc.FinishBaseOTReceiver(baseReceiver, nil); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("malformed commitment retained base OT state: %v", err)
	}
}

func TestKOS2TinyProofFailsBeforeSenderPoolMutation(t *testing.T) {
	session, err := mpc.NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	teek, state, control, generation := newKOS2MalformedSenderState(t, session, mpc.ExtensionEpoch([32]byte{7}), senderPrecomputeAwaitProof)
	extension := state.pending.extension
	err = teek.handleOTPrecomputeResponse(control, generation, &teeproto.OTPrecomputeResponse{Count: 1, OtReceiverData: []byte("KPR2")})
	if err == nil {
		t.Fatal("accepted tiny KOS2 proof")
	}
	assertKOS2MalformedSenderPoolUnchanged(t, state)
	if _, err := mpc.FinishExtensionSender(extension, nil); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("malformed proof retained extension state: %v", err)
	}
}

func newKOS2MalformedSenderState(
	t *testing.T,
	session [32]byte,
	epoch string,
	phase senderPrecomputePhase,
) (*TEEK, *OTPrecomputeState, *shared.WSConnection, uint64) {
	t.Helper()
	logger := shared.NewNopLogger()
	state := NewOTPrecomputeState()
	teek := &TEEK{logger: logger, otPrecomputeState: state}
	cm := NewTEETConnectionManager(teek, "ws://example.invalid", logger)
	teek.connManager = cm
	control, generation := installAckTestControl(cm, shared.NewWSConnection(nil))
	pending := &senderPrecompute{
		session: session, count: 1, isInitial: true, phase: phase, done: make(chan error, 1),
		controlConn: control, controlGeneration: generation,
	}
	switch phase {
	case senderPrecomputeAwaitCommitment:
		pending.baseReceiver = new(mpc.BaseOTReceiverState)
	case senderPrecomputeAwaitProof:
		pending.extension = new(mpc.ExtensionSenderState)
	}
	state.mu.Lock()
	state.epoch = epoch
	state.pending = pending
	state.mu.Unlock()
	return teek, state, control, generation
}

func assertKOS2MalformedSenderPoolUnchanged(t *testing.T, state *OTPrecomputeState) {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pool.TotalCount() != 0 || state.pool.Available() != 0 || state.ready {
		t.Fatalf("malformed frame changed sender pool total=%d available=%d ready=%t", state.pool.TotalCount(), state.pool.Available(), state.ready)
	}
	if state.pending != nil {
		t.Fatal("malformed frame retained failed sender pending state")
	}
}
