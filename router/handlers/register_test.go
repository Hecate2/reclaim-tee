package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/store"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// testRegKey is the RA-TLS key the test "TEE" signs register bodies with.
var testRegKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

// fakeJWTWithNonce builds a structurally-valid (unsigned) JWT whose
// eat_nonce carries the given value. FindNonceValue only base64-decodes
// the payload; it does not verify the signature.
func fakeJWTWithNonce(nonce string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	pb, _ := json.Marshal(map[string]any{"eat_nonce": []string{nonce}})
	return hdr + "." + base64.RawURLEncoding.EncodeToString(pb) + ".sig"
}

// signRegisterBody fills AttestationJWT (nonce-carrying), SPKIDer, and
// BodySignature for the body's CURRENT field values using testRegKey.
// Call it again after mutating any signed field.
func signRegisterBody(b *registerRequest) {
	spki, err := x509.MarshalPKIXPublicKey(&testRegKey.PublicKey)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(spki)
	nonceRole := "tee_k"
	if store.Role(b.Role) == store.RoleT {
		nonceRole = "tee_t"
	}
	b.AttestationJWT = fakeJWTWithNonce(shared.SPKINoncePrefix(nonceRole) + hex.EncodeToString(hash[:]))
	b.SPKIDer = spki
	digest := shared.RegistrationSigningDigest(b.PairID, b.Role, b.SelfAddr, b.PeerAddrClaim, b.ImageDigest)
	sig, err := ecdsa.SignASN1(rand.Reader, testRegKey, digest[:])
	if err != nil {
		panic(err)
	}
	b.BodySignature = sig
}

type fakeSAValidator struct {
	claims *auth.SAClaims
	err    error
}

func (f *fakeSAValidator) Validate(_ context.Context, _ string) (*auth.SAClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

// testRegSPKIHash is sha256(SPKI) of testRegKey — the value the attestation
// commits to, returned by the fake validator so the binding check passes.
var testRegSPKIHash = func() [32]byte {
	spki, err := x509.MarshalPKIXPublicKey(&testRegKey.PublicKey)
	if err != nil {
		panic(err)
	}
	return sha256.Sum256(spki)
}()

type fakeAttestValidator struct {
	digest   string
	base     string
	spkiHash [32]byte
	err      error
}

func (f *fakeAttestValidator) Validate(_, _ string, _, _ []byte) (string, string, [32]byte, error) {
	if f.err != nil {
		return "", "", [32]byte{}, f.err
	}
	return f.digest, f.base, f.spkiHash, nil
}

const (
	approvedDigest = "sha256:abc123"
	teekIP         = "10.0.0.1"
	teetIP         = "10.0.0.2"
	pairID         = "00000000-0000-0000-0000-000000000001"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st := store.NewMemoryStore()
	allowlist, err := auth.NewAllowlist(t.Context(), st, []string{approvedDigest}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	t.Cleanup(allowlist.Stop)
	return &Server{
		Store: st,
		SAValidator: &fakeSAValidator{
			claims: &auth.SAClaims{
				Email:            "tee-vm-1@new-reclaim-architecture.iam.gserviceaccount.com",
				RegisteredClaims: jwt.RegisteredClaims{},
			},
		},
		AttestValidator: &fakeAttestValidator{digest: approvedDigest, spkiHash: testRegSPKIHash},
		Allowlist:       allowlist,
		Logger:          zap.NewNop(),
		Config: &config.Config{
			HeartbeatStaleness: 15 * time.Second,
			// Thresholds are zero so handler tests see "control/ot bad now → status
			// flips this turn." Sustained-threshold semantics are unit-tested
			// directly on the Pair model in store/types_test.go.
			ControlUnhealthy: 0,
			OTNotReady:       0,
			JWTExpiry:        60 * time.Second,
			JWTIssuer:        "router.test",
		},
	}
}

func doRegister(t *testing.T, s *Server, body registerRequest, remoteAddr, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(raw))
	req.RemoteAddr = remoteAddr
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	s.HandleRegister(w, req)
	return w
}

func validBody(role, selfAddr, peerAddr string) registerRequest {
	b := registerRequest{
		PairID:        pairID,
		Role:          role,
		SelfAddr:      selfAddr,
		PeerAddrClaim: peerAddr,
		ImageDigest:   approvedDigest,
	}
	signRegisterBody(&b)
	return b
}

func TestRegisterHappyPathK(t *testing.T) {
	s := newTestServer(t)
	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer fake-sa-token")

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, body=%s", w.Code, w.Body.String())
	}
	p, err := s.Store.GetPair(t.Context(), pairID)
	if err != nil {
		t.Fatalf("pair not stored: %v", err)
	}
	if p.TEEKAddr != teekIP+":443" || p.TEEKImageDigest != approvedDigest {
		t.Fatalf("K not populated: %+v", p)
	}
	if p.TEETAddr != "" {
		t.Fatalf("T should be empty: %q", p.TEETAddr)
	}
	if got := p.EffectiveStatus(time.Now(), 15*time.Second, 30*time.Second, 60*time.Second); got != store.StatusRegistering {
		t.Fatalf("status: %v", got)
	}
}

func TestRegisterBothSidesCrossConsistency(t *testing.T) {
	s := newTestServer(t)

	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("K status: got %d body=%s", w.Code, w.Body.String())
	}

	w = doRegister(t, s,
		validBody("T", teetIP+":443", teekIP+":443"),
		teetIP+":54321", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("T status: got %d body=%s", w.Code, w.Body.String())
	}

	p, err := s.Store.GetPair(t.Context(), pairID)
	if err != nil {
		t.Fatalf("get pair: %v", err)
	}
	if p.TEEKAddr == "" || p.TEETAddr == "" {
		t.Fatalf("both sides should be set: %+v", p)
	}
}

func TestRegisterAcceptsPeerAddrDivergence(t *testing.T) {
	// In V2 K's self_addr is its external IP (what /allocate returns to
	// clients) while T's peer_addr_claim is K's internal DNS — the two
	// can't match. The router stopped cross-checking them; pair_id +
	// SA token + attestation + image_digest authenticate the caller.
	s := newTestServer(t)

	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("K status: %d", w.Code)
	}

	// T claims a different K address than the one K registered with.
	// Must be accepted now.
	body := validBody("T", teetIP+":443", "10.0.0.99:443")
	w = doRegister(t, s, body, teetIP+":54321", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with diverging peer claims, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRegisterRejectsMissingAuth(t *testing.T) {
	s := newTestServer(t)
	w := doRegister(t, s, validBody("K", teekIP+":443", teetIP+":443"), teekIP+":12345", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRegisterRejectsBadSAToken(t *testing.T) {
	s := newTestServer(t)
	s.SAValidator = &fakeSAValidator{err: errors.New("bad token")}
	w := doRegister(t, s, validBody("K", teekIP+":443", teetIP+":443"), teekIP+":12345", "Bearer x")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRegisterRejectsBadAttestation(t *testing.T) {
	s := newTestServer(t)
	s.AttestValidator = &fakeAttestValidator{err: errors.New("bad attest")}
	w := doRegister(t, s, validBody("K", teekIP+":443", teetIP+":443"), teekIP+":12345", "Bearer x")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRegisterRejectsDigestMismatch(t *testing.T) {
	s := newTestServer(t)
	body := validBody("K", teekIP+":443", teetIP+":443")
	body.ImageDigest = "sha256:claimed-different"
	w := doRegister(t, s, body, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRegisterRejectsDigestNotInAllowlist(t *testing.T) {
	s := newTestServer(t)
	s.AttestValidator = &fakeAttestValidator{digest: "sha256:not-approved"}
	body := validBody("K", teekIP+":443", teetIP+":443")
	body.ImageDigest = "sha256:not-approved"
	w := doRegister(t, s, body, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
}

// SEV-SNP TEEs (no GCP SA) register WITHOUT an SA token: the AMD-rooted
// attestation + allowlisted measurement + SPKI binding is the credential.
func TestRegisterSEVSNPSkipsSAToken(t *testing.T) {
	s := newTestServer(t)
	snpID := "snp-pcr:" + strings.Repeat("ab", 32)
	if err := s.Allowlist.Add(t.Context(), snpID); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	s.AttestValidator = &fakeAttestValidator{digest: snpID, spkiHash: testRegSPKIHash}

	body := registerRequest{
		PairID:          pairID,
		Role:            "T",
		SelfAddr:        teetIP + ":443",
		PeerAddrClaim:   teekIP + ":443",
		ImageDigest:     snpID,
		AttestationType: "sev-snp",
	}
	signRegisterBody(&body)

	// No Authorization header — must still succeed on the SEV-SNP path.
	w := doRegister(t, s, body, teetIP+":12345", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for SEV-SNP without SA token, got %d body=%s", w.Code, w.Body.String())
	}
}

// SEV-SNP base UKI must be allowlisted too: a valid (allowlisted) app on a
// non-allowlisted base — a rogue loader forging the PCR 8 app measurement — is
// rejected fail-closed; allowlisting the base lets the same register through.
func TestRegisterRejectsBaseNotInAllowlist(t *testing.T) {
	s := newTestServer(t)
	snpID := "snp-app:" + strings.Repeat("cd", 32)
	snpBase := "snp-base:" + strings.Repeat("ef", 32)
	if err := s.Allowlist.Add(t.Context(), snpID); err != nil { // app allowlisted; base is NOT
		t.Fatalf("seed allowlist: %v", err)
	}
	s.AttestValidator = &fakeAttestValidator{digest: snpID, base: snpBase, spkiHash: testRegSPKIHash}

	body := registerRequest{
		PairID: pairID, Role: "T", SelfAddr: teetIP + ":443", PeerAddrClaim: teekIP + ":443",
		ImageDigest: snpID, AttestationType: "sev-snp",
	}
	signRegisterBody(&body)

	if w := doRegister(t, s, body, teetIP+":12345", ""); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-allowlisted base, got %d body=%s", w.Code, w.Body.String())
	}
	if err := s.Allowlist.Add(t.Context(), snpBase); err != nil {
		t.Fatalf("seed base: %v", err)
	}
	if w := doRegister(t, s, body, teetIP+":12345", ""); w.Code != http.StatusOK {
		t.Fatalf("expected 200 after base allowlisted, got %d body=%s", w.Code, w.Body.String())
	}
}

// TEE_T's SA presenting role=K is rejected by per-role config pinning.
func TestRegisterRejectsCrossRoleSA(t *testing.T) {
	s := newTestServer(t)
	s.Config.TEEKSAEmail = "tee-k-sa@new-reclaim-architecture.iam.gserviceaccount.com"
	s.Config.TEETSAEmail = "tee-t-sa@new-reclaim-architecture.iam.gserviceaccount.com"

	// SA validator returns the tee-t SA; the request claims role=K.
	s.SAValidator = &fakeSAValidator{
		claims: &auth.SAClaims{
			Email:            "tee-t-sa@new-reclaim-architecture.iam.gserviceaccount.com",
			RegisteredClaims: jwt.RegisteredClaims{},
		},
	}
	w := doRegister(t, s, validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer tee-t-token")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-role registration: got %d body=%s, want 403", w.Code, w.Body.String())
	}
}

// When a second pair_id registers with the same self_addr as an existing
// row, the existing row is by definition orphaned (one VM per address)
// and must be deleted so retire/heartbeat tooling sees just one row.
func TestRegister_OrphanSweep_DeletesPreviousAtSameAddr(t *testing.T) {
	s := newTestServer(t)

	// First TEE_K registers with addr A.
	oldID := "11111111-1111-1111-1111-111111111111"
	body := validBody("K", teekIP+":443", teetIP+":443")
	body.PairID = oldID
	signRegisterBody(&body)
	w := doRegister(t, s, body, teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("first register: got %d body=%s", w.Code, w.Body.String())
	}

	// Same VM restarts (same addr A) with a new pair_id — what uuid.NewV4
	// produces on every boot today.
	newID := "22222222-2222-2222-2222-222222222222"
	body.PairID = newID
	signRegisterBody(&body)
	w = doRegister(t, s, body, teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("second register: got %d body=%s", w.Code, w.Body.String())
	}

	if _, err := s.Store.GetPair(t.Context(), oldID); err == nil {
		t.Fatalf("orphan row %s was not deleted", oldID)
	}
	if _, err := s.Store.GetPair(t.Context(), newID); err != nil {
		t.Fatalf("new row %s missing: %v", newID, err)
	}
}

// Sweep must compare addresses by role: a K-role register at addr A must
// NOT delete a row whose teet_addr happens to equal A (different field).
func TestRegister_OrphanSweep_RoleScoped(t *testing.T) {
	s := newTestServer(t)

	// Seed: pair X has T side at addr A.
	xID := "11111111-1111-1111-1111-111111111111"
	body := validBody("T", teekIP+":443", teekIP+":443")
	body.PairID = xID
	body.SelfAddr = teetIP + ":443"
	signRegisterBody(&body)
	w := doRegister(t, s, body, teetIP+":54321", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("seed T register: got %d body=%s", w.Code, w.Body.String())
	}

	// New pair Y registers K side at the SAME addr as X's T side. Different
	// field → must not delete X.
	yID := "22222222-2222-2222-2222-222222222222"
	body = validBody("K", teetIP+":443", teekIP+":443")
	body.PairID = yID
	signRegisterBody(&body)
	w = doRegister(t, s, body, teetIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("Y K register: got %d body=%s", w.Code, w.Body.String())
	}

	if _, err := s.Store.GetPair(t.Context(), xID); err != nil {
		t.Fatalf("X should still exist (role-scoped sweep): %v", err)
	}
	if _, err := s.Store.GetPair(t.Context(), yID); err != nil {
		t.Fatalf("Y not stored: %v", err)
	}
}

// A pair_id re-registering itself (idempotent boot retry) must not delete
// its own row.
func TestRegister_OrphanSweep_SamePairIDNoOp(t *testing.T) {
	s := newTestServer(t)
	body := validBody("K", teekIP+":443", teetIP+":443")
	for range 3 {
		w := doRegister(t, s, body, teekIP+":12345", "Bearer fake-sa-token")
		if w.Code != http.StatusOK {
			t.Fatalf("re-register: got %d body=%s", w.Code, w.Body.String())
		}
	}
	if _, err := s.Store.GetPair(t.Context(), pairID); err != nil {
		t.Fatalf("self-row deleted by sweep: %v", err)
	}
}

// Registry-takeover regression: a caller with a valid allowlisted
// attestation but WITHOUT the RA-TLS private key the attestation commits
// to cannot register. The body signature can't be forged.
func TestRegisterRejectsBodyNotBoundToAttestation(t *testing.T) {
	s := newTestServer(t)

	// Wrong-key signature: SPKIDer + nonce are the genuine TEE's, but the
	// body is signed by a key the attacker holds instead.
	body := validBody("K", teekIP+":443", teetIP+":443")
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker key: %v", err)
	}
	digest := shared.RegistrationSigningDigest(body.PairID, body.Role, body.SelfAddr, body.PeerAddrClaim, body.ImageDigest)
	sig, err := ecdsa.SignASN1(rand.Reader, attackerKey, digest[:])
	if err != nil {
		t.Fatalf("attacker sign: %v", err)
	}
	body.BodySignature = sig
	w := doRegister(t, s, body, teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong-key body: got %d body=%s, want 403", w.Code, w.Body.String())
	}

	// Missing signature entirely.
	body2 := validBody("K", teekIP+":443", teetIP+":443")
	body2.BodySignature = nil
	w = doRegister(t, s, body2, teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing sig: got %d, want 403", w.Code)
	}

	// Tampered field after signing: attacker keeps a valid signature but
	// swaps self_addr to redirect clients.
	body3 := validBody("K", teekIP+":443", teetIP+":443")
	body3.SelfAddr = "6.6.6.6:443"
	w = doRegister(t, s, body3, teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusForbidden {
		t.Fatalf("tampered self_addr: got %d, want 403", w.Code)
	}
}

func TestRegisterRejectsBadRole(t *testing.T) {
	s := newTestServer(t)
	body := validBody("X", teekIP+":443", teetIP+":443")
	w := doRegister(t, s, body, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}
