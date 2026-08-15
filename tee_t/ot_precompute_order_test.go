package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

type receiverConsumeResult struct {
	entries []mpc.ReceiverOT
	err     error
}

func TestKOS2ReceiverCannotCommitBeforeProof(t *testing.T) {
	state := &OTReceiverState{pool: receiverPoolWith(t, 3), ready: true}
	pending := &receiverPrecompute{
		begin: mpc.PrecomputeBegin{StartIndex: 3, Count: 2}, entries: receiverEntries(3, 2),
		phase: receiverPrecomputeAwaitChallenge, done: make(chan struct{}),
	}
	state.pending = pending
	teet := &TEET{otReceiverState: state, logger: shared.NewNopLogger()}
	err := teet.handleOTPrecomputeComplete(0, directControlStateLease, &teeproto.OTPrecomputeComplete{PoolSize: 5})
	if err == nil {
		t.Fatal("committed receiver entries before KOS2 proof")
	}
	if state.pool.TotalCount() != 3 || state.pool.Available() != 3 || state.pending != pending {
		t.Fatal("early completion changed receiver pool or pending ownership")
	}
}

func TestKOS2ChallengeOversizeCountFailsBeforeReceiverPoolMutation(t *testing.T) {
	const count = 1
	session, err := mpc.NewExtensionSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := mpc.ExtensionEpoch([32]byte{8})
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
	extension, _, entries, err := mpc.StartExtensionReceiver(rand.Reader, pairs, epoch, ciphertext, session, 0, count)
	if err != nil {
		t.Fatal(err)
	}
	challengeSize, err := mpc.PrecomputeChallengeWireSize(count)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, challengeSize)
	copy(challenge[:4], "KCH2")
	copy(challenge[4:36], session[:])
	binary.BigEndian.PutUint32(challenge[100:104], math.MaxUint32)

	pending := &receiverPrecompute{
		begin:     mpc.PrecomputeBegin{SessionID: session, Count: count, Epoch: epoch},
		isInitial: true, controlGeneration: 11, extension: extension, entries: entries,
		phase: receiverPrecomputeAwaitChallenge, done: make(chan struct{}),
	}
	state := &OTReceiverState{pool: mpc.NewReceiverPool(count), epoch: epoch, pending: pending}
	teet := &TEET{logger: shared.NewNopLogger(), otReceiverState: state}
	err = teet.handleOTPrecomputeChallenge(newReceiverTestWebSocket(t), 11, directControlStateLease, &teeproto.OTPrecomputeRequest{
		Count: count, OtSenderSetup: challenge, IsInitial: true, Epoch: epoch,
	})
	if err == nil {
		t.Fatal("accepted challenge with attacker-controlled oversize coefficient count")
	}
	if state.pool.TotalCount() != 0 || state.pool.Available() != 0 || state.ready {
		t.Fatalf("malformed challenge changed receiver pool total=%d available=%d ready=%t", state.pool.TotalCount(), state.pool.Available(), state.ready)
	}
	if state.pending != nil || pending.outcome != receiverPrecomputeAborted {
		t.Fatal("malformed challenge did not abort only its pending receiver batch")
	}
}

func TestConsumeOTReceiverEntriesWaitsForReorderedCompletion(t *testing.T) {
	teet, pending := teetWithPendingReceiverBatch(t, 10, 10)
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 8, 5, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()

	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("online OT consume did not wait for pending completion")
	}
	select {
	case got := <-result:
		t.Fatalf("consume returned before completion: %v", got.err)
	default:
	}

	if err := teet.handleOTPrecomputeComplete(0, directControlStateLease, &teeproto.OTPrecomputeComplete{PoolSize: 20}); err != nil {
		t.Fatalf("handleOTPrecomputeComplete: %v", err)
	}
	got := receiveConsumeResult(t, result)
	if got.err != nil {
		t.Fatalf("consume after completion: %v", got.err)
	}
	if len(got.entries) != 5 {
		t.Fatalf("consumed %d entries, want 5", len(got.entries))
	}
	for i, entry := range got.entries {
		if entry.Index != uint64(8+i) {
			t.Fatalf("entry[%d].Index = %d, want %d", i, entry.Index, 8+i)
		}
	}
	if pending.outcome != receiverPrecomputeCommitted {
		t.Fatalf("pending outcome = %d, want committed", pending.outcome)
	}
	select {
	case <-pending.done:
	default:
		t.Fatal("completed pending batch did not close its terminal signal")
	}
}

func TestConsumeOTReceiverEntriesWaitsForInitialCompletion(t *testing.T) {
	teet, _ := teetWithPendingReceiverBatch(t, 0, 10)
	teet.otReceiverState.ready = false
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 0, 2, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)

	if err := teet.handleOTPrecomputeComplete(0, directControlStateLease, &teeproto.OTPrecomputeComplete{PoolSize: 10}); err != nil {
		t.Fatalf("handle initial OTPrecomputeComplete: %v", err)
	}
	got := receiveConsumeResult(t, result)
	if got.err != nil {
		t.Fatalf("consume after initial completion: %v", got.err)
	}
	if len(got.entries) != 2 || got.entries[0].Index != 0 || got.entries[1].Index != 1 {
		t.Fatalf("initial consumed entries = %+v, want indices 0 and 1", got.entries)
	}
}

func TestConsumeOTReceiverEntriesPendingAbortWakesWaiter(t *testing.T) {
	teet, _ := teetWithPendingReceiverBatch(t, 10, 10)
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)
	state := teet.otReceiverState

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 10, 2, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)
	teet.clearPendingReceiverPrecompute(state, state.pending)

	got := receiveConsumeResult(t, result)
	if got.err == nil || !strings.Contains(got.err.Error(), "did not commit") {
		t.Fatalf("error after pending abort = %v, want fail-closed commit error", got.err)
	}
}

func TestConsumeOTReceiverEntriesDisconnectWakesWaiter(t *testing.T) {
	teet, _ := teetWithPendingReceiverBatch(t, 10, 10)
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 10, 2, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)
	teet.suspendOTReceiverPoolForReconnect()

	got := receiveConsumeResult(t, result)
	if got.err == nil || !strings.Contains(got.err.Error(), "did not commit") {
		t.Fatalf("error after disconnect = %v, want fail-closed commit error", got.err)
	}
}

func TestClearOTReceiverPoolWakesPendingWaiter(t *testing.T) {
	teet, pending := teetWithPendingReceiverBatch(t, 10, 10)
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 10, 2, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)
	teet.clearOTReceiverPool()

	got := receiveConsumeResult(t, result)
	if got.err == nil || !strings.Contains(got.err.Error(), "did not commit") {
		t.Fatalf("error after pool clear = %v, want fail-closed commit error", got.err)
	}
	if pending.outcome != receiverPrecomputeAborted {
		t.Fatalf("pending outcome after pool clear = %d, want aborted", pending.outcome)
	}
}

func TestInitialPrecomputeResetWakesPendingWaiter(t *testing.T) {
	teet, pending := teetWithPendingReceiverBatch(t, 10, 10)
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)
	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 10, 2, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)

	epoch := mpc.ExtensionEpoch([32]byte{9})
	begin := mpc.PrecomputeBegin{Count: 1, Epoch: epoch}
	begin.SessionID[0] = 1
	payload, err := mpc.MarshalPrecomputeBegin(begin)
	if err != nil {
		t.Fatalf("marshal initial begin: %v", err)
	}
	conn := newReceiverTestWebSocket(t)
	err = teet.handleOTPrecomputeBegin(conn, 1, directControlStateLease, &teeproto.OTPrecomputeRequest{
		Count: 1, OtSenderSetup: payload, IsInitial: true, Epoch: epoch,
	})
	if err != nil {
		t.Fatalf("handle replacement initial begin: %v", err)
	}

	got := receiveConsumeResult(t, result)
	if got.err == nil || !strings.Contains(got.err.Error(), "state changed") {
		t.Fatalf("error after initial reset = %v, want state-changed error", got.err)
	}
	if pending.outcome != receiverPrecomputeAborted {
		t.Fatalf("replaced pending outcome = %d, want aborted", pending.outcome)
	}
	teet.clearOTReceiverPool()
}

func TestConsumeOTReceiverEntriesDoesNotConsumeReplacementState(t *testing.T) {
	teet, pending := teetWithPendingReceiverBatch(t, 10, 10)
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 10, 2, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)

	replacement := &OTReceiverState{
		pool:  receiverPoolWith(t, 20),
		ready: true,
		epoch: "replacement-epoch",
	}
	teet.otReceiverStateMu.Lock()
	finishReceiverPrecompute(pending, receiverPrecomputeAborted)
	teet.otReceiverState = replacement
	teet.otReceiverStateMu.Unlock()

	got := receiveConsumeResult(t, result)
	if got.err == nil || !strings.Contains(got.err.Error(), "state changed") {
		t.Fatalf("error after receiver-state replacement = %v, want state-changed error", got.err)
	}
	if available := replacement.pool.Available(); available != 20 {
		t.Fatalf("replacement pool available = %d, want 20", available)
	}
}

func TestConsumeOTReceiverEntriesDoesNotConsumeReplacementBatch(t *testing.T) {
	teet, pending := teetWithPendingReceiverBatch(t, 10, 10)
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 10, 2, func(_ context.Context, done <-chan struct{}) error {
			close(waiting)
			<-done
			return nil
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)

	replacement := &receiverPrecompute{
		begin:   mpc.PrecomputeBegin{StartIndex: 10, Count: 10},
		entries: receiverEntries(10, 10),
		done:    make(chan struct{}),
	}
	state := teet.otReceiverState
	teet.otReceiverStateMu.Lock()
	finishReceiverPrecompute(pending, receiverPrecomputeAborted)
	state.pending = replacement
	err := state.pool.Add(replacement.entries)
	if err == nil {
		state.pending = nil
		finishReceiverPrecompute(replacement, receiverPrecomputeCommitted)
	}
	teet.otReceiverStateMu.Unlock()
	if err != nil {
		t.Fatalf("commit replacement batch: %v", err)
	}

	got := receiveConsumeResult(t, result)
	if got.err == nil || !strings.Contains(got.err.Error(), "did not commit") {
		t.Fatalf("error after pending-batch replacement = %v, want fail-closed commit error", got.err)
	}
	if available := state.pool.Available(); available != 20 {
		t.Fatalf("pool available after replacement commit = %d, want 20", available)
	}
}

func TestClearPendingReceiverPrecomputeDoesNotClearReplacementBatch(t *testing.T) {
	teet, stale := teetWithPendingReceiverBatch(t, 10, 10)
	state := teet.otReceiverState
	replacement := &receiverPrecompute{
		begin:   mpc.PrecomputeBegin{StartIndex: 10, Count: 10},
		entries: receiverEntries(10, 10),
		done:    make(chan struct{}),
	}
	teet.otReceiverStateMu.Lock()
	state.pending = replacement
	teet.otReceiverStateMu.Unlock()

	teet.clearPendingReceiverPrecompute(state, stale)

	if state.pending != replacement {
		t.Fatal("stale failure cleared replacement pending batch")
	}
	if replacement.outcome != receiverPrecomputeInProgress {
		t.Fatalf("replacement outcome = %d, want in-progress", replacement.outcome)
	}
	select {
	case <-replacement.done:
		t.Fatal("stale failure woke replacement pending batch")
	default:
	}
}

func TestConsumeOTReceiverEntriesSessionCancellationStopsWait(t *testing.T) {
	teet, pending := teetWithPendingReceiverBatch(t, 10, 10)
	ctx, cancel := context.WithCancel(t.Context())
	waiting := make(chan struct{})
	result := make(chan receiverConsumeResult, 1)

	go func() {
		entries, err := teet.consumeOTReceiverEntriesWithWait(ctx, 10, 2, func(ctx context.Context, done <-chan struct{}) error {
			close(waiting)
			return waitForReceiverPrecompute(ctx, done)
		})
		result <- receiverConsumeResult{entries: entries, err: err}
	}()
	awaitReceiverWait(t, waiting)
	cancel()

	got := receiveConsumeResult(t, result)
	if got.err == nil || !strings.Contains(got.err.Error(), context.Canceled.Error()) {
		t.Fatalf("error after session cancellation = %v, want context canceled", got.err)
	}
	if pending.outcome != receiverPrecomputeInProgress {
		t.Fatalf("pending outcome after waiter cancellation = %d, want in-progress", pending.outcome)
	}
	if available := teet.otReceiverState.pool.Available(); available != 10 {
		t.Fatalf("pool available after waiter cancellation = %d, want 10", available)
	}
}

func TestConsumeOTReceiverEntriesSessionDeadlineStopsWait(t *testing.T) {
	teet, _ := teetWithPendingReceiverBatch(t, 10, 10)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now())
	defer cancel()

	_, err := teet.consumeOTReceiverEntries(ctx, 10, 2)
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("error after session deadline = %v, want context deadline exceeded", err)
	}
	if available := teet.otReceiverState.pool.Available(); available != 10 {
		t.Fatalf("pool available after waiter deadline = %d, want 10", available)
	}
}

func TestConsumeOTReceiverEntriesDoesNotWaitForUnrelatedRange(t *testing.T) {
	teet, _ := teetWithPendingReceiverBatch(t, 10, 10)

	_, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 20, 1, func(context.Context, <-chan struct{}) error {
		t.Fatal("unrelated out-of-range request waited for pending completion")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "insufficient receiver OTs") {
		t.Fatalf("error = %v, want insufficient receiver OTs", err)
	}
}

func TestConsumeOTReceiverEntriesRejectsUsedBoundaryPrefix(t *testing.T) {
	teet, _ := teetWithPendingReceiverBatch(t, 10, 10)
	if _, err := teet.otReceiverState.pool.Consume(8, 1); err != nil {
		t.Fatalf("consume setup entry: %v", err)
	}

	_, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 8, 5, func(context.Context, <-chan struct{}) error {
		t.Fatal("request with a used committed prefix waited for pending completion")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("error = %v, want already used", err)
	}
}

func TestConsumeOTReceiverEntriesRejectsInvalidCountsWithoutWaiting(t *testing.T) {
	for _, count := range []int{0, -1} {
		t.Run(fmt.Sprintf("count_%d", count), func(t *testing.T) {
			teet, _ := teetWithPendingReceiverBatch(t, 10, 10)
			_, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), 10, count, func(context.Context, <-chan struct{}) error {
				t.Fatal("invalid count entered pending barrier")
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "invalid OT consume count") {
				t.Fatalf("error = %v, want invalid consume count", err)
			}
		})
	}
}

func TestConsumeOTReceiverEntriesRejectsRangeOverflowWithoutWaiting(t *testing.T) {
	teet, _ := teetWithPendingReceiverBatch(t, 10, 10)
	_, err := teet.consumeOTReceiverEntriesWithWait(t.Context(), math.MaxUint64-1, 4, func(context.Context, <-chan struct{}) error {
		t.Fatal("overflowing range entered pending barrier")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "insufficient receiver OTs") {
		t.Fatalf("error = %v, want insufficient receiver OTs", err)
	}
}

func teetWithPendingReceiverBatch(t *testing.T, committed, pendingCount int) (*TEET, *receiverPrecompute) {
	t.Helper()
	pending := &receiverPrecompute{
		begin:   mpc.PrecomputeBegin{StartIndex: uint64(committed), Count: uint32(pendingCount)},
		entries: receiverEntries(uint64(committed), pendingCount),
		phase:   receiverPrecomputeAwaitComplete,
		done:    make(chan struct{}),
	}
	state := &OTReceiverState{
		pool:    receiverPoolWith(t, committed),
		ready:   true,
		epoch:   "old-epoch",
		pending: pending,
	}
	return &TEET{otReceiverState: state, logger: shared.NewNopLogger()}, pending
}

func receiverPoolWith(t *testing.T, count int) *mpc.ReceiverPool {
	t.Helper()
	pool := mpc.NewReceiverPool(count)
	if err := pool.Add(receiverEntries(0, count)); err != nil {
		t.Fatalf("add receiver entries: %v", err)
	}
	return pool
}

func receiverEntries(start uint64, count int) []mpc.ReceiverOT {
	entries := make([]mpc.ReceiverOT, count)
	for i := range entries {
		entries[i].Index = start + uint64(i)
	}
	return entries
}

func awaitReceiverWait(t *testing.T, waiting <-chan struct{}) {
	t.Helper()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("online OT consume did not enter pending wait")
	}
}

func receiveConsumeResult(t *testing.T, result <-chan receiverConsumeResult) receiverConsumeResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(time.Second):
		t.Fatal("online OT consume did not return after pending batch terminated")
		return receiverConsumeResult{}
	}
}

func directControlStateLease(mutate func() error) error {
	return mutate()
}

func newReceiverTestWebSocket(t *testing.T) *shared.WSConnection {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	handshake := make(chan error, 1)
	go serveReceiverTestWebSocket(peerNet, handshake)
	conn, _, err := websocket.NewClient(clientNet, &url.URL{Scheme: "ws", Host: "in-memory", Path: "/"}, nil, 1024, 1024)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		t.Fatalf("dial test websocket: %v", err)
	}
	if err := <-handshake; err != nil {
		_ = conn.Close()
		_ = peerNet.Close()
		t.Fatalf("serve test websocket handshake: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peerNet.Close()
	})
	return shared.NewWSConnection(conn)
}

func newInboundReceiverTestWebSocket(t *testing.T) (*shared.WSConnection, chan<- []byte) {
	t.Helper()
	clientNet, peerNet := net.Pipe()
	handshake := make(chan error, 1)
	messages := make(chan []byte, 4)
	go serveInboundReceiverTestWebSocket(peerNet, handshake, messages)
	conn, _, err := websocket.NewClient(clientNet, &url.URL{Scheme: "ws", Host: "in-memory", Path: "/"}, nil, 1024, 1024)
	if err != nil {
		_ = clientNet.Close()
		_ = peerNet.Close()
		t.Fatalf("dial inbound test websocket: %v", err)
	}
	if err := <-handshake; err != nil {
		_ = conn.Close()
		_ = peerNet.Close()
		t.Fatalf("serve inbound test websocket handshake: %v", err)
	}
	t.Cleanup(func() {
		close(messages)
		_ = conn.Close()
		_ = peerNet.Close()
	})
	return shared.NewWSConnection(conn), messages
}

func serveReceiverTestWebSocket(peer net.Conn, handshake chan<- error) {
	reader := bufio.NewReader(peer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		handshake <- err
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, err = fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	handshake <- err
	if err == nil {
		_, _ = io.Copy(io.Discard, reader)
	}
}

func serveInboundReceiverTestWebSocket(peer net.Conn, handshake chan<- error, messages <-chan []byte) {
	reader := bufio.NewReader(peer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		handshake <- err
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, err = fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	handshake <- err
	if err != nil {
		return
	}
	for payload := range messages {
		if err := writeServerBinaryFrame(peer, payload); err != nil {
			return
		}
	}
}

func writeServerBinaryFrame(conn net.Conn, payload []byte) error {
	frame := make([]byte, 0, len(payload)+10)
	frame = append(frame, 0x80|websocket.BinaryMessage)
	switch {
	case len(payload) < 126:
		frame = append(frame, byte(len(payload)))
	case uint64(len(payload)) <= math.MaxUint16:
		frame = append(frame, 126, 0, 0)
		binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(len(payload)))
	default:
		frame = append(frame, 127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(frame[len(frame)-8:], uint64(len(payload)))
	}
	frame = append(frame, payload...)
	_, err := conn.Write(frame)
	return err
}
