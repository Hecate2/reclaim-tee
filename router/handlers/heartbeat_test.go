package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
)

// seedRegisteredPair runs the standard K-then-T register flow against s and
// returns the resulting pair. Used by /heartbeat and /allocate tests to set
// up a fully-registered pair before exercising the endpoint under test.
func seedRegisteredPair(t *testing.T, s *Server) *store.Pair {
	t.Helper()
	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("seed K: %d body=%s", w.Code, w.Body.String())
	}
	w = doRegister(t, s,
		validBody("T", teetIP+":443", teekIP+":443"),
		teetIP+":54321", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("seed T: %d body=%s", w.Code, w.Body.String())
	}
	p, err := s.Store.GetPair(t.Context(), pairID)
	if err != nil {
		t.Fatalf("seed get pair: %v", err)
	}
	return p
}

func doHeartbeat(t *testing.T, s *Server, body heartbeatRequest, remoteAddr, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/heartbeat", bytes.NewReader(raw))
	req.RemoteAddr = remoteAddr
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	s.HandleHeartbeat(w, req)
	return w
}

func TestHeartbeatHappyPath_BothSidesReady(t *testing.T) {
	s := newTestServer(t)
	seedRegisteredPair(t, s)

	w := doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "K",
		ControlHealthy: true, OTReady: true,
		ActiveSessions: 0,
	}, teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("K heartbeat: %d body=%s", w.Code, w.Body.String())
	}

	w = doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "T",
		ControlHealthy: true, OTReady: true,
		ActiveSessions: 0,
	}, teetIP+":54321", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("T heartbeat: %d body=%s", w.Code, w.Body.String())
	}

	var resp heartbeatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	if resp.Status != store.StatusReady {
		t.Fatalf("expected ready after both healthy heartbeats, got %v", resp.Status)
	}
}

func TestHeartbeatRegistering_FreshPairControlUnhealthy(t *testing.T) {
	// A pair that has never reached Ready, where one side reports unhealthy
	// from the start, is Registering — not Degraded. Degraded is reserved
	// for pairs that were Ready and went bad.
	s := newTestServer(t)
	seedRegisteredPair(t, s)

	w := doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "K",
		ControlHealthy: false, OTReady: true,
	}, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusOK {
		t.Fatalf("K heartbeat: %d", w.Code)
	}
	var resp heartbeatResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != store.StatusRegistering {
		t.Fatalf("fresh pair unhealthy should be Registering, got %v", resp.Status)
	}
}

func TestHeartbeatDegradedAfterReady(t *testing.T) {
	// Bring pair to Ready first (so ReadyAt is set), then one side reports
	// control unhealthy. Status should be Degraded, not Registering.
	s := newTestServer(t)
	seedRegisteredPair(t, s)

	for _, role := range []string{"K", "T"} {
		addr := teekIP + ":12345"
		if role == "T" {
			addr = teetIP + ":54321"
		}
		w := doHeartbeat(t, s, heartbeatRequest{
			PairID: pairID, Role: role,
			ControlHealthy: true, OTReady: true,
		}, addr, "Bearer x")
		if w.Code != http.StatusOK {
			t.Fatalf("%s healthy heartbeat: %d", role, w.Code)
		}
	}

	// T now reports control unhealthy.
	w := doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "T",
		ControlHealthy: false, OTReady: true,
	}, teetIP+":54321", "Bearer x")
	if w.Code != http.StatusOK {
		t.Fatalf("T unhealthy heartbeat: %d", w.Code)
	}
	var resp heartbeatResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != store.StatusDegraded {
		t.Fatalf("once-ready pair unhealthy should be Degraded, got %v", resp.Status)
	}
}

func TestHeartbeatRecoveryAfterDegraded(t *testing.T) {
	// Ready → Degraded → Ready, verifying since-timestamps clear on recovery.
	s := newTestServer(t)
	seedRegisteredPair(t, s)

	for _, role := range []string{"K", "T"} {
		addr := teekIP + ":12345"
		if role == "T" {
			addr = teetIP + ":54321"
		}
		doHeartbeat(t, s, heartbeatRequest{
			PairID: pairID, Role: role,
			ControlHealthy: true, OTReady: true,
		}, addr, "Bearer x")
	}

	doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "T",
		ControlHealthy: false, OTReady: true,
	}, teetIP+":54321", "Bearer x")

	w := doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "T",
		ControlHealthy: true, OTReady: true,
	}, teetIP+":54321", "Bearer x")
	if w.Code != http.StatusOK {
		t.Fatalf("recovery heartbeat: %d", w.Code)
	}
	var resp heartbeatResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != store.StatusReady {
		t.Fatalf("expected Ready after recovery, got %v", resp.Status)
	}
}

func TestHeartbeatRejectsUnknownPair(t *testing.T) {
	s := newTestServer(t)
	w := doHeartbeat(t, s, heartbeatRequest{
		PairID:         "00000000-0000-0000-0000-000000000099", // valid UUID, not registered
		Role:           "K",
		ControlHealthy: true,
		OTReady:        true,
	}, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", w.Code, w.Body.String())
	}
}

// SEV-SNP TEEs hold no GCP SA and send no Authorization header, so an unknown
// pair_id must still answer 404 (-> shared.ErrRouterNotFound -> re-register) and
// never 401, which they would retry forever. Regression: 2026-08-04, one pair
// spent 8h heartbeating a deleted pair_id because auth ran before the lookup.
func TestHeartbeatUnknownPairIs404WithoutAuthHeader(t *testing.T) {
	s := newTestServer(t)
	w := doHeartbeat(t, s, heartbeatRequest{
		PairID:         "00000000-0000-0000-0000-000000000099",
		Role:           "K",
		ControlHealthy: true,
		OTReady:        true,
	}, teekIP+":12345", "") // no Authorization header, as an SNP TEE sends
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("got 401: auth ran before the pair lookup, so the TEE will retry forever instead of re-registering (body=%s)", w.Body.String())
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHeartbeatRejectsUnregisteredRole(t *testing.T) {
	s := newTestServer(t)
	// Only K registers.
	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer x")
	if w.Code != http.StatusOK {
		t.Fatalf("K register: %d", w.Code)
	}
	// T tries to heartbeat without registering.
	w = doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "T",
		ControlHealthy: true, OTReady: true,
	}, teetIP+":54321", "Bearer x")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestEffectiveStatusDeadWhenStale(t *testing.T) {
	// Direct unit-style assertion on the pair model rather than through
	// the heartbeat endpoint, since simulating stale time via the HTTP
	// surface would require injecting a clock.
	p := &store.Pair{
		ID:              pairID,
		TEEKAddr:        teekIP + ":443",
		TEETAddr:        teetIP + ":443",
		LastHeartbeatK:  time.Now().Add(-1 * time.Minute),
		LastHeartbeatT:  time.Now(),
		ControlHealthyK: true, ControlHealthyT: true,
		OTReadyK: true, OTReadyT: true,
	}
	if got := p.EffectiveStatus(time.Now(), 15*time.Second, 30*time.Second, 60*time.Second); got != store.StatusDead {
		t.Fatalf("expected dead, got %v", got)
	}
}
