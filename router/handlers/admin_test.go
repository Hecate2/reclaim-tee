package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"
)

const adminToken = "test-admin-token"

// sha256Hex matches how the router stores the admin token (hex SHA-256).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var adminTokenHash = sha256Hex(adminToken)

func adminServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t)
	s.Config.AdminTokenHash = adminTokenHash
	return s
}

func adminGet(t *testing.T, s *Server, path, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)
	return w
}

func adminPost(t *testing.T, s *Server, path, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)
	return w
}

func TestAdmin_DisabledWithoutToken(t *testing.T) {
	s := newTestServer(t) // AdminToken left empty
	w := adminGet(t, s, "/pairs", "Bearer anything")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (admin disabled), got %d", w.Code)
	}
}

func TestAdmin_RejectsMissingAuth(t *testing.T) {
	s := adminServer(t)
	w := adminGet(t, s, "/pairs", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAdmin_RejectsBadToken(t *testing.T) {
	s := adminServer(t)
	w := adminGet(t, s, "/pairs", "Bearer wrong-token")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAdmin_ListPairs_Empty(t *testing.T) {
	s := adminServer(t)
	w := adminGet(t, s, "/pairs", "Bearer "+adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp listPairsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Pairs) != 0 {
		t.Fatalf("expected empty pairs, got %d", len(resp.Pairs))
	}
}

func TestAdmin_ListPairs_WithPair(t *testing.T) {
	s := adminServer(t)
	seedRegisteredPair(t, s)

	w := adminGet(t, s, "/pairs", "Bearer "+adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp listPairsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(resp.Pairs))
	}
	p := resp.Pairs[0]
	if p.ID != pairID {
		t.Fatalf("id: %q", p.ID)
	}
	if p.TEEKAddr != teekIP+":443" || p.TEETAddr != teetIP+":443" {
		t.Fatalf("addrs: %+v", p)
	}
	// Both sides registered, but neither has reported control_healthy=true
	// yet, so status should be Registering (or Degraded under zero thresholds,
	// but ReadyAt is zero so it's Registering).
	if p.Status != "registering" {
		t.Fatalf("expected status=registering, got %q", p.Status)
	}
}

func TestAdmin_Drain_Happy(t *testing.T) {
	s := adminServer(t)
	seedRegisteredPair(t, s)

	w := adminPost(t, s, "/pairs/"+pairID+"/drain", "Bearer "+adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var view pairView
	_ = json.Unmarshal(w.Body.Bytes(), &view)
	if !view.Draining {
		t.Fatal("expected Draining=true in response")
	}
	if view.Status != "draining" {
		t.Fatalf("expected status=draining, got %q", view.Status)
	}

	// Reading back through /pairs should also show draining.
	w = adminGet(t, s, "/pairs", "Bearer "+adminToken)
	var listResp listPairsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &listResp)
	if !listResp.Pairs[0].Draining {
		t.Fatal("expected drained pair to show Draining=true in /pairs")
	}
}

func TestAdmin_Drain_Idempotent(t *testing.T) {
	s := adminServer(t)
	seedRegisteredPair(t, s)

	for range 3 {
		w := adminPost(t, s, "/pairs/"+pairID+"/drain", "Bearer "+adminToken)
		if w.Code != http.StatusOK {
			t.Fatalf("drain returned %d", w.Code)
		}
	}
}

func TestAdmin_Drain_UnknownPair(t *testing.T) {
	s := adminServer(t)
	w := adminPost(t, s,
		"/pairs/00000000-0000-0000-0000-000000000099/drain",
		"Bearer "+adminToken)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestAdmin_Drain_InvalidUUID(t *testing.T) {
	s := adminServer(t)
	w := adminPost(t, s, "/pairs/not-a-uuid/drain", "Bearer "+adminToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAdmin_Kill_Happy(t *testing.T) {
	s := adminServer(t)
	seedRegisteredPair(t, s)

	// /dead now requires the pair to be drained (ActiveSessions==0 + Draining)
	// OR have stale heartbeats. Drain first.
	w := adminPost(t, s, "/pairs/"+pairID+"/drain", "Bearer "+adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("drain: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	w = adminPost(t, s, "/pairs/"+pairID+"/dead", "Bearer "+adminToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%s", w.Code, w.Body.String())
	}

	w = adminGet(t, s, "/pairs", "Bearer "+adminToken)
	var listResp listPairsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &listResp)
	if len(listResp.Pairs) != 0 {
		t.Fatalf("expected 0 pairs after kill, got %d", len(listResp.Pairs))
	}
}

// /dead must refuse a fresh pair that hasn't been drained.
func TestAdmin_Kill_RejectsUnDrained(t *testing.T) {
	s := adminServer(t)
	seedRegisteredPair(t, s)

	w := adminPost(t, s, "/pairs/"+pairID+"/dead", "Bearer "+adminToken)
	if w.Code != http.StatusConflict {
		t.Fatalf("kill on un-drained pair: expected 409, got %d body=%s", w.Code, w.Body.String())
	}

	w = adminGet(t, s, "/pairs", "Bearer "+adminToken)
	var listResp listPairsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &listResp)
	if len(listResp.Pairs) != 1 {
		t.Fatalf("expected pair to still be present after rejected kill, got %d", len(listResp.Pairs))
	}
}

func TestAdmin_Kill_UnknownPair(t *testing.T) {
	s := adminServer(t)
	w := adminPost(t, s,
		"/pairs/00000000-0000-0000-0000-000000000099/dead",
		"Bearer "+adminToken)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestAdmin_DrainBlocksFutureAllocations(t *testing.T) {
	s, _ := newTestServerWithSigner(t)
	s.Config.AdminTokenHash = adminTokenHash
	bothSidesReady(t, s)

	// Confirm allocation works before drain.
	w := doAllocate(t, s, "nonce-pre-drain")
	if w.Code != http.StatusOK {
		t.Fatalf("pre-drain allocation should succeed, got %d", w.Code)
	}

	w = adminPost(t, s, "/pairs/"+pairID+"/drain", "Bearer "+adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("drain: %d", w.Code)
	}

	// After drain, no ready pairs → allocate returns 503.
	w = doAllocate(t, s, "nonce-post-drain")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-drain allocation should fail with 503, got %d body=%s",
			w.Code, w.Body.String())
	}
}
