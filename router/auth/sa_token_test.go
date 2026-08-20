package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// rsaJWK encodes a public key in JWK form, base64url-encoded modulus and exponent.
func rsaJWK(kid string, pub *rsa.PublicKey) rawJWK {
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return rawJWK{
		Kid: kid,
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func TestRawJWK_ToKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	jwk := rsaJWK("kid-1", &priv.PublicKey)
	k, err := jwk.toKey()
	if err != nil {
		t.Fatalf("toKey: %v", err)
	}
	got, ok := k.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", k)
	}
	if got.N.Cmp(priv.PublicKey.N) != 0 || got.E != priv.PublicKey.E {
		t.Fatal("key round-trip mismatch")
	}
}

func TestRawJWK_ToKey_RejectsNonRSA(t *testing.T) {
	if _, err := (rawJWK{Kid: "x", Kty: "EC"}).toKey(); err == nil {
		t.Fatal("expected error for non-RSA kty")
	}
}

func TestRawJWK_ToKey_RejectsMalformedFields(t *testing.T) {
	_, err := (rawJWK{Kid: "x", Kty: "RSA", N: "!!!not base64!!!", E: "AQAB"}).toKey()
	if err == nil {
		t.Fatal("expected error for malformed N")
	}
	_, err = (rawJWK{Kid: "x", Kty: "RSA", N: "abc", E: "!!!"}).toKey()
	if err == nil {
		t.Fatal("expected error for malformed E")
	}
}

// fakeFetcher returns a fixed key for tests.
type fakeFetcher struct {
	keys map[string]any
	err  error
}

func (f *fakeFetcher) GetKey(_ context.Context, kid string) (any, error) {
	if f.err != nil {
		return nil, f.err
	}
	k, ok := f.keys[kid]
	if !ok {
		return nil, errors.New("kid not in fake fetcher")
	}
	return k, nil
}

// mintSAToken creates a Google-style SA identity token for tests.
func mintSAToken(t *testing.T, kid, issuer, audience, email string, exp time.Time, signer *rsa.PrivateKey) string {
	t.Helper()
	claims := &SAClaims{
		Email:     email,
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(exp),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newValidatorWithKey(t *testing.T, pattern, audience string) (*GoogleSAValidator, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	v := NewGoogleSAValidator(
		&fakeFetcher{keys: map[string]any{"kid-1": &priv.PublicKey}},
		regexp.MustCompile(pattern),
		audience,
	)
	return v, priv
}

const (
	testIssuer   = "https://accounts.google.com"
	testAudience = "https://tee.reclaim.test"
	testEmail    = "tee-vm-abc@new-reclaim-architecture.iam.gserviceaccount.com"
	testPattern  = `^tee-vm-[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$`
)

func TestGoogleSAValidator_HappyPath(t *testing.T) {
	v, priv := newValidatorWithKey(t, testPattern, testAudience)
	tok := mintSAToken(t, "kid-1", testIssuer, testAudience, testEmail, time.Now().Add(time.Minute), priv)
	claims, err := v.Validate(t.Context(), tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Email != testEmail {
		t.Fatalf("email: %q", claims.Email)
	}
}

func TestGoogleSAValidator_RejectsExpired(t *testing.T) {
	v, priv := newValidatorWithKey(t, testPattern, testAudience)
	tok := mintSAToken(t, "kid-1", testIssuer, testAudience, testEmail, time.Now().Add(-time.Minute), priv)
	if _, err := v.Validate(t.Context(), tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestGoogleSAValidator_RejectsWrongAudience(t *testing.T) {
	v, priv := newValidatorWithKey(t, testPattern, testAudience)
	tok := mintSAToken(t, "kid-1", testIssuer, "wrong-aud", testEmail, time.Now().Add(time.Minute), priv)
	if _, err := v.Validate(t.Context(), tok); err == nil {
		t.Fatal("expected wrong-audience token to be rejected")
	}
}

func TestGoogleSAValidator_RejectsWrongIssuer(t *testing.T) {
	v, priv := newValidatorWithKey(t, testPattern, testAudience)
	tok := mintSAToken(t, "kid-1", "https://evil.example", testAudience, testEmail, time.Now().Add(time.Minute), priv)
	if _, err := v.Validate(t.Context(), tok); err == nil {
		t.Fatal("expected wrong-issuer token to be rejected")
	}
}

func TestGoogleSAValidator_RejectsBadEmailPattern(t *testing.T) {
	v, priv := newValidatorWithKey(t, testPattern, testAudience)
	tok := mintSAToken(t, "kid-1", testIssuer, testAudience,
		"random-service@some-other-project.iam.gserviceaccount.com",
		time.Now().Add(time.Minute), priv)
	if _, err := v.Validate(t.Context(), tok); err == nil {
		t.Fatal("expected non-matching email to be rejected")
	}
}

func TestGoogleSAValidator_RejectsMissingKid(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := NewGoogleSAValidator(
		&fakeFetcher{keys: map[string]any{"kid-1": &priv.PublicKey}},
		regexp.MustCompile(testPattern),
		testAudience,
	)

	claims := &SAClaims{
		Email:     testEmail,
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{testAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// no kid header
	signed, _ := tok.SignedString(priv)

	if _, err := v.Validate(t.Context(), signed); err == nil {
		t.Fatal("expected missing-kid to be rejected")
	}
}

func TestGoogleJWKSFetcher_FetchesAndCaches(t *testing.T) {
	// Verify the fetcher hits the JWKS URL once and serves cached keys
	// for subsequent lookups.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubJWK := rsaJWK("kid-1", &priv.PublicKey)
	var hits int
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_ = json.MarshalWrite(w, map[string]any{"keys": []rawJWK{pubJWK}})
	}))
	client := srv.Client()

	g := &GoogleJWKSFetcher{
		url:        srv.URL,
		client:     client,
		refreshTTL: time.Hour,
	}

	k1, err := g.GetKey(t.Context(), "kid-1")
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	k2, err := g.GetKey(t.Context(), "kid-1")
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", hits)
	}
	if _, ok := k1.(*rsa.PublicKey); !ok {
		t.Fatalf("k1 type: %T", k1)
	}
	if _, ok := k2.(*rsa.PublicKey); !ok {
		t.Fatalf("k2 type: %T", k2)
	}
}

func TestGoogleJWKSFetcher_RefreshOnUnknownKid(t *testing.T) {
	// Even within the TTL, an unknown kid should trigger a refresh in case
	// Google rotated keys.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	var serveKid string
	var hits int
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_ = json.MarshalWrite(w, map[string]any{"keys": []rawJWK{rsaJWK(serveKid, &priv.PublicKey)}})
	}))
	client := srv.Client()

	g := &GoogleJWKSFetcher{
		url:        srv.URL,
		client:     client,
		refreshTTL: time.Hour,
	}
	serveKid = "kid-A"
	if _, err := g.GetKey(t.Context(), "kid-A"); err != nil {
		t.Fatalf("get kid-A: %v", err)
	}

	// Server rotates: now serves kid-B. Asking for kid-B should refresh.
	serveKid = "kid-B"
	if _, err := g.GetKey(t.Context(), "kid-B"); err != nil {
		t.Fatalf("get kid-B: %v", err)
	}
	if hits != 2 {
		t.Fatalf("expected 2 fetches (initial + refresh-for-unknown-kid), got %d", hits)
	}
}

func TestGoogleJWKSFetcher_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	client := srv.Client()

	g := &GoogleJWKSFetcher{
		url:        srv.URL,
		client:     client,
		refreshTTL: time.Hour,
	}
	if _, err := g.GetKey(t.Context(), "kid-1"); err == nil {
		t.Fatal("expected error when JWKS endpoint returns 500")
	}
}
