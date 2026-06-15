//go:build !mobile

package shared

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHeartbeatTarget is a minimal HeartbeatTarget for unit tests. The
// heartbeat goroutine only reads through the interface, so we don't need
// to construct a full TEEK/TEET.
type fakeHeartbeatTarget struct {
	pairID         string
	router         *RouterClient
	controlHealthy bool
	otReady        bool
	activeSessions int
}

func (f *fakeHeartbeatTarget) PairID() string         { return f.pairID }
func (f *fakeHeartbeatTarget) Router() *RouterClient  { return f.router }
func (f *fakeHeartbeatTarget) ControlHealthy() bool   { return f.controlHealthy }
func (f *fakeHeartbeatTarget) OTReady() bool          { return f.otReady }
func (f *fakeHeartbeatTarget) ActiveSessions() int    { return f.activeSessions }

// fakeRouter answers /register and /heartbeat. heartbeat404Until lets a
// test 404 the first N heartbeats to exercise the re-register path.
type fakeRouter struct {
	mu                sync.Mutex
	heartbeats        int
	registers         int
	heartbeat404Until int
}

func (f *fakeRouter) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/register":
			f.registers++
			_ = json.NewEncoder(w).Encode(RegisterResponse{
				PairID: "test-pair", Status: "registering",
			})
		case "/heartbeat":
			f.heartbeats++
			if f.heartbeats <= f.heartbeat404Until {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(HeartbeatResponse{
				PairID: "test-pair", Status: "degraded",
			})
		default:
			http.Error(w, "unknown path", http.StatusNotFound)
		}
	}
}

func (f *fakeRouter) snapshot() (heartbeats, registers int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats, f.registers
}

func newFakeRouter() (*fakeRouter, *httptest.Server) {
	f := &fakeRouter{}
	return f, httptest.NewServer(f.handler())
}

func TestRunHeartbeats_SendsPeriodically(t *testing.T) {
	f, srv := newFakeRouter()
	t.Cleanup(srv.Close)

	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := NewRouterClient(srv.URL, tokens)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	target := &fakeHeartbeatTarget{pairID: "test-pair", router: router}
	done := make(chan struct{})
	go func() {
		RunHeartbeats(ctx, target, "K", GetTEEKLogger(),
			func(_ context.Context) error { return nil },
			5*time.Millisecond)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	hb, regs := f.snapshot()
	if hb < 3 {
		t.Fatalf("expected at least 3 heartbeats in 30ms@5ms, got %d", hb)
	}
	if regs != 0 {
		t.Fatalf("expected no re-registers when heartbeats succeed, got %d", regs)
	}
}

func TestRunHeartbeats_ReregistersOn404(t *testing.T) {
	f, srv := newFakeRouter()
	f.heartbeat404Until = 1
	t.Cleanup(srv.Close)

	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := NewRouterClient(srv.URL, tokens)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	var reregisterCalls atomic.Int32
	onLost := func(_ context.Context) error {
		reregisterCalls.Add(1)
		return nil
	}

	target := &fakeHeartbeatTarget{pairID: "test-pair", router: router}
	done := make(chan struct{})
	go func() {
		RunHeartbeats(ctx, target, "K", GetTEEKLogger(), onLost, 5*time.Millisecond)
		close(done)
	}()

	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done

	if got := reregisterCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 re-register triggered by 404, got %d", got)
	}
	hb, _ := f.snapshot()
	if hb < 3 {
		t.Fatalf("expected heartbeats to keep firing after 404, got %d", hb)
	}
}

func TestRunHeartbeats_SkipsUntilPairIDKnown(t *testing.T) {
	f, srv := newFakeRouter()
	t.Cleanup(srv.Close)

	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := NewRouterClient(srv.URL, tokens)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	target := &fakeHeartbeatTarget{pairID: "", router: router} // unknown
	done := make(chan struct{})
	go func() {
		RunHeartbeats(ctx, target, "T", GetTEETLogger(),
			func(_ context.Context) error { return nil },
			5*time.Millisecond)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	hb, _ := f.snapshot()
	if hb != 0 {
		t.Fatalf("expected zero heartbeats when pair_id empty, got %d", hb)
	}
}

func TestRunHeartbeats_ContextCancelStops(t *testing.T) {
	_, srv := newFakeRouter()
	t.Cleanup(srv.Close)

	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := NewRouterClient(srv.URL, tokens)

	ctx, cancel := context.WithCancel(t.Context())
	target := &fakeHeartbeatTarget{pairID: "p", router: router}
	done := make(chan struct{})
	go func() {
		RunHeartbeats(ctx, target, "K", GetTEEKLogger(),
			func(_ context.Context) error { return nil },
			50*time.Millisecond)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// expected
	case <-time.After(time.Second):
		t.Fatal("RunHeartbeats did not return within 1s of context cancel")
	}
}

func TestExtractIdentityFromRATLS_StandaloneMode(t *testing.T) {
	// Local dev: no launcher socket → RATLSManager produces a cert without
	// the attestation extension. ExtractIdentityFromRATLS must fail clearly,
	// not silently return empty strings.
	ratls, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new ratls: %v", err)
	}
	logger := GetTEEKLogger()
	defer logger.Sync()

	_, _, err = ExtractIdentityFromRATLS(ratls, logger)
	if err == nil {
		t.Fatal("expected error in standalone mode (no attestation extension)")
	}
}
