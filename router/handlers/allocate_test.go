package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/router/signer"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func newTestServerWithSigner(t *testing.T) (*Server, *signer.LocalSigner) {
	t.Helper()
	s := newTestServer(t)
	sgnr, err := signer.NewLocalSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.Signer = sgnr
	return s, sgnr
}

func bothSidesReady(t *testing.T, s *Server) {
	t.Helper()
	seedRegisteredPair(t, s)
	w := doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "K",
		ControlHealthy: true, OTReady: true,
	}, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusOK {
		t.Fatalf("K heartbeat: %d", w.Code)
	}
	w = doHeartbeat(t, s, heartbeatRequest{
		PairID: pairID, Role: "T",
		ControlHealthy: true, OTReady: true,
	}, teetIP+":54321", "Bearer x")
	if w.Code != http.StatusOK {
		t.Fatalf("T heartbeat: %d", w.Code)
	}
}

func doAllocate(t *testing.T, s *Server, clientNonce string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(allocateRequest{ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/allocate", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	s.HandleAllocate(w, req)
	return w
}

func TestAllocateNoReadyPairs(t *testing.T) {
	s, _ := newTestServerWithSigner(t)
	w := doAllocate(t, s, "nonce-1")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestAllocateHappyPath(t *testing.T) {
	s, sgnr := newTestServerWithSigner(t)
	bothSidesReady(t, s)

	w := doAllocate(t, s, "nonce-abc")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp allocateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.PairID != pairID {
		t.Fatalf("pair_id: got %q", resp.PairID)
	}
	if resp.TEEKAddr != teekIP+":443" || resp.TEETAddr != teetIP+":443" {
		t.Fatalf("addrs: %+v", resp)
	}
	if resp.JWT == "" {
		t.Fatal("empty jwt")
	}

	// Verify the JWT round-trips against the signer's public key and carries
	// the right claims.
	pemBytes, err := sgnr.PublicKeyPEM()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	claims := &signer.AllocClaims{}
	parsed, err := jwt.ParseWithClaims(resp.JWT, claims, func(_ *jwt.Token) (any, error) {
		return mustParsePubKey(t, pemBytes), nil
	})
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("jwt not valid")
	}
	if claims.ClientNonce != "nonce-abc" {
		t.Fatalf("client_nonce: %q", claims.ClientNonce)
	}
	aud, _ := claims.GetAudience()
	if len(aud) != 1 || aud[0] != pairID {
		t.Fatalf("aud: %v", aud)
	}
	if claims.TEEKAddr != teekIP+":443" || claims.TEETAddr != teetIP+":443" {
		t.Fatalf("addrs in claims: %+v", claims)
	}
	if claims.ID == "" {
		t.Fatal("missing jti")
	}
}

func TestAllocateLogsStablePairDimensions(t *testing.T) {
	s, _ := newTestServerWithSigner(t)
	bothSidesReady(t, s)

	p, err := s.Store.GetPair(t.Context(), pairID)
	if err != nil {
		t.Fatalf("get pair: %v", err)
	}
	p.TEEKRegion = "asia-south2"
	p.TEETRegion = "ap-south-1"
	if err := s.Store.UpsertPair(t.Context(), p); err != nil {
		t.Fatalf("update pair regions: %v", err)
	}

	core, logs := observer.New(zap.InfoLevel)
	s.Logger = zap.New(core)
	if w := doAllocate(t, s, "nonce-stable-dimensions"); w.Code != http.StatusOK {
		t.Fatalf("allocate: got %d body=%s", w.Code, w.Body.String())
	}

	entries := logs.FilterMessage("pair allocated").All()
	if len(entries) != 1 {
		t.Fatalf("allocation logs: got %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	want := map[string]string{
		"teek_ip":     teekIP,
		"teet_ip":     teetIP,
		"teek_region": "asia-south2",
		"teet_region": "ap-south-1",
	}
	for key, value := range want {
		if fields[key] != value {
			t.Errorf("%s: got %#v, want %q", key, fields[key], value)
		}
	}
}

func TestAllocateRequiresClientNonce(t *testing.T) {
	s, _ := newTestServerWithSigner(t)
	w := doAllocate(t, s, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAllocateRateLimitedAfterBurst(t *testing.T) {
	s, _ := newTestServerWithSigner(t)
	bothSidesReady(t, s)

	// First `allocateBurst` calls should pass; the one after must 429.
	// httptest.NewRequest assigns the same RemoteAddr to every call so
	// they all hit the same bucket. Reading the constant rather than
	// hardcoding keeps the test honest under any tuning.
	for i := range allocateBurst {
		w := doAllocate(t, s, fmt.Sprintf("nonce-%d", i))
		if w.Code != http.StatusOK {
			t.Fatalf("burst call %d: expected 200, got %d body=%s", i, w.Code, w.Body.String())
		}
	}
	w := doAllocate(t, s, "post-burst")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("post-burst call: expected 429, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestAllocateSkipsDrainingPair(t *testing.T) {
	s, _ := newTestServerWithSigner(t)
	bothSidesReady(t, s)
	p, err := s.Store.GetPair(t.Context(), pairID)
	if err != nil {
		t.Fatalf("get pair: %v", err)
	}
	p.Draining = true
	if err := s.Store.UpsertPair(t.Context(), p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	w := doAllocate(t, s, "nonce")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (no ready pairs), got %d", w.Code)
	}
}
