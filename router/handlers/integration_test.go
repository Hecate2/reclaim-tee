package handlers

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/signer"
	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// integrationServer wires a Server with in-memory store, fake SA + attestation
// validators, a real LocalSigner, and admin-token enabled. Returned alongside
// an in-memory httptest server so the test can drive real HTTP requests.
type integrationServer struct {
	srv     *Server
	signer  *signer.LocalSigner
	http    *httptest.Server
	client  *http.Client
	baseURL string
}

const (
	intAdminToken = "integration-admin-token"
	intPairID     = "11111111-1111-1111-1111-111111111111"
)

func newIntegrationServer(t *testing.T) *integrationServer {
	t.Helper()
	ls, err := signer.NewLocalSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	st := store.NewMemoryStore()
	allowlist, err := auth.NewAllowlist(t.Context(), st, []string{approvedDigest}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	t.Cleanup(allowlist.Stop)
	srv := &Server{
		Store: st,
		SAValidator: &fakeSAValidator{
			claims: &auth.SAClaims{
				Email:            "tee-vm-1@new-reclaim-architecture.iam.gserviceaccount.com",
				RegisteredClaims: jwt.RegisteredClaims{},
			},
		},
		AttestValidator: &fakeAttestValidator{digest: approvedDigest, spkiHash: testRegSPKIHash},
		Allowlist:       allowlist,
		Signer:          ls,
		Logger:          zap.NewNop(),
		Config: &config.Config{
			HeartbeatStaleness: 15 * time.Second,
			ControlUnhealthy:   0, // immediate flip for deterministic testing
			OTNotReady:         0,
			JWTExpiry:          60 * time.Second,
			JWTIssuer:          "router.integration.test",
			AdminTokenHash:     sha256Hex(intAdminToken),
		},
	}
	hs := httptest.NewTestServer(t, srv.Routes())
	client := hs.Client()
	return &integrationServer{srv: srv, signer: ls, http: hs, client: client, baseURL: hs.URL}
}

// post sends a JSON-encoded body to path with optional headers; returns
// status code and decoded body. RemoteAddr is set automatically by net/http
// based on the test client's local IP.
func (i *integrationServer) post(t *testing.T, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, i.baseURL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := i.client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

func (i *integrationServer) get(t *testing.T, path string, headers map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, i.baseURL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := i.client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// loopbackAddr returns a stable valid TEE address for registration requests.
// Router registration no longer derives identity from the HTTP source address.
func (i *integrationServer) loopbackAddr() string {
	return "127.0.0.1:443"
}

// TestIntegration_FullLifecycle exercises the whole router API end-to-end
// through real HTTP: register both sides, heartbeat to Ready, allocate +
// verify JWT, drain, fail allocation, kill, list empty.
//
// Source IP comes from net/http's connection-level RemoteAddr (always
// loopback under httptest), so K and T share the same self_addr in this
// scenario. Real production has them on distinct IPs and the source-IP
// check enforces that — covered by the unit tests in register_test.go.
func TestIntegration_FullLifecycle(t *testing.T) {
	i := newIntegrationServer(t)
	saAuth := map[string]string{"Authorization": "Bearer fake-sa-token"}
	adminAuth := map[string]string{"Authorization": "Bearer " + intAdminToken}
	addr := i.loopbackAddr()

	// 1. /healthz — JSON body with standalone flag.
	code, body := i.get(t, "/healthz", nil)
	if code != http.StatusOK {
		t.Fatalf("healthz: code=%d body=%q", code, body)
	}
	var healthz struct {
		Status     string `json:"status"`
		Standalone bool   `json:"standalone"`
	}
	if err := json.Unmarshal(body, &healthz); err != nil {
		t.Fatalf("healthz body not JSON: %v (body=%q)", err, body)
	}
	if healthz.Status != "ok" || healthz.Standalone {
		t.Fatalf("healthz unexpected: %+v", healthz)
	}

	// 2. Allocate before anything is ready → 503
	code, _ = i.post(t, "/allocate",
		map[string]string{"client_nonce": "n0"}, nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("pre-register allocate: expected 503, got %d", code)
	}

	// 3. Register K
	regK := registerRequest{
		PairID:        intPairID,
		Role:          "K",
		SelfAddr:      addr,
		PeerAddrClaim: addr,
		ImageDigest:   approvedDigest,
	}
	signRegisterBody(&regK)
	code, body = i.post(t, "/register", regK, saAuth)
	if code != http.StatusOK {
		t.Fatalf("register K: code=%d body=%s", code, body)
	}
	var regResp registerResponse
	_ = json.Unmarshal(body, &regResp)
	if regResp.PairID != intPairID || regResp.Status != store.StatusRegistering {
		t.Fatalf("register K response: %+v", regResp)
	}

	// 4. Register T
	regT := regK
	regT.Role = "T"
	signRegisterBody(&regT)
	code, body = i.post(t, "/register", regT, saAuth)
	if code != http.StatusOK {
		t.Fatalf("register T: code=%d body=%s", code, body)
	}

	// 5. Admin sees the pair as Registering (both sides registered but no
	//    healthy heartbeats yet).
	code, body = i.get(t, "/pairs", adminAuth)
	if code != http.StatusOK {
		t.Fatalf("list pairs: %d body=%s", code, body)
	}
	var listResp listPairsResponse
	_ = json.Unmarshal(body, &listResp)
	if len(listResp.Pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(listResp.Pairs))
	}
	if listResp.Pairs[0].Status != store.StatusRegistering {
		t.Fatalf("pre-heartbeat status: %q", listResp.Pairs[0].Status)
	}

	// 6. Heartbeat both sides as healthy.
	for _, role := range []string{"K", "T"} {
		hb := heartbeatRequest{
			PairID: intPairID, Role: role,
			ControlHealthy: true, OTReady: true,
			ActiveSessions: 0, LastPeerContactMS: 50,
		}
		code, body = i.post(t, "/heartbeat", hb, saAuth)
		if code != http.StatusOK {
			t.Fatalf("heartbeat %s: code=%d body=%s", role, code, body)
		}
	}

	// 7. Status should now be Ready.
	code, body = i.get(t, "/pairs", adminAuth)
	_ = json.Unmarshal(body, &listResp)
	if listResp.Pairs[0].Status != store.StatusReady {
		t.Fatalf("post-heartbeat status: %q", listResp.Pairs[0].Status)
	}
	if listResp.Pairs[0].ReadyAt.IsZero() {
		t.Fatal("ReadyAt should be set after first Ready transition")
	}

	// 8. Allocate → JWT bound to pair.
	code, body = i.post(t, "/allocate",
		map[string]string{"client_nonce": "n1"}, nil)
	if code != http.StatusOK {
		t.Fatalf("allocate: %d body=%s", code, body)
	}
	var alloc allocateResponse
	_ = json.Unmarshal(body, &alloc)
	if alloc.PairID != intPairID {
		t.Fatalf("alloc pair_id: %q", alloc.PairID)
	}
	if alloc.JWT == "" {
		t.Fatal("alloc JWT empty")
	}
	pemBytes, err := i.signer.PublicKeyPEM()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	allocClaims := &signer.AllocClaims{}
	parsed, err := jwt.ParseWithClaims(alloc.JWT, allocClaims, func(_ *jwt.Token) (any, error) {
		return mustParsePubKey(t, pemBytes), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("verify alloc JWT: %v", err)
	}
	if allocClaims.ClientNonce != "n1" {
		t.Fatalf("client_nonce mismatch: %q", allocClaims.ClientNonce)
	}
	if aud, _ := allocClaims.GetAudience(); len(aud) != 1 || aud[0] != intPairID {
		t.Fatalf("aud: %v", aud)
	}

	// 9. Drain.
	code, body = i.post(t, "/pairs/"+intPairID+"/drain", nil, adminAuth)
	if code != http.StatusOK {
		t.Fatalf("drain: %d body=%s", code, body)
	}

	// 10. Post-drain allocation fails.
	code, _ = i.post(t, "/allocate",
		map[string]string{"client_nonce": "n2"}, nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("post-drain allocate: expected 503, got %d", code)
	}

	// 11. Kill.
	code, _ = i.post(t, "/pairs/"+intPairID+"/dead", nil, adminAuth)
	if code != http.StatusNoContent {
		t.Fatalf("kill: %d", code)
	}

	// 12. Registry now empty.
	code, body = i.get(t, "/pairs", adminAuth)
	_ = json.Unmarshal(body, &listResp)
	if len(listResp.Pairs) != 0 {
		t.Fatalf("expected empty pairs after kill, got %d", len(listResp.Pairs))
	}
}

// TestIntegration_RegisterRejectsBadAuth confirms the SA-token check is
// actually wired into the route — i.e. a missing Authorization header on
// /register returns 401, not 200.
func TestIntegration_RegisterRejectsBadAuth(t *testing.T) {
	i := newIntegrationServer(t)
	code, _ := i.post(t, "/register", registerRequest{
		PairID:         intPairID,
		Role:           "K",
		SelfAddr:       i.loopbackAddr(),
		PeerAddrClaim:  i.loopbackAddr(),
		ImageDigest:    approvedDigest,
		AttestationJWT: "fake",
	}, nil) // no Authorization
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

// TestIntegration_AllocateNoAuth confirms /allocate is public — clients hit
// it before any TEE connection and don't have credentials yet.
func TestIntegration_AllocateNoAuth(t *testing.T) {
	i := newIntegrationServer(t)
	code, _ := i.post(t, "/allocate",
		map[string]string{"client_nonce": "n"}, nil) // no Authorization
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (no pairs), got %d — auth should not block this", code)
	}
}
