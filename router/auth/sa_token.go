package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SAClaims is the subset of claims we use from a Google service-account
// identity token: signed iss/aud/exp checks come from RegisteredClaims;
// Email is what we match against the approved-SA pattern.
type SAClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// SAValidator validates a Google service-account identity token and returns
// its claims if valid.
type SAValidator interface {
	Validate(ctx context.Context, token string) (*SAClaims, error)
}

// KeyFetcher resolves a JWT `kid` header to a verification key. Production
// uses GoogleJWKSFetcher; tests inject a fake.
type KeyFetcher interface {
	GetKey(ctx context.Context, kid string) (any, error)
}

// GoogleSAValidator verifies tokens against keys returned by a KeyFetcher,
// then enforces issuer, audience, expiry, and an email-pattern match.
type GoogleSAValidator struct {
	fetcher  KeyFetcher
	pattern  *regexp.Regexp
	audience string
}

func NewGoogleSAValidator(fetcher KeyFetcher, pattern *regexp.Regexp, audience string) *GoogleSAValidator {
	return &GoogleSAValidator{fetcher: fetcher, pattern: pattern, audience: audience}
}

// Valid Google issuers for SA identity tokens. Both forms appear in the wild.
var googleIssuers = []string{
	"https://accounts.google.com",
	"accounts.google.com",
}

func (v *GoogleSAValidator) Validate(ctx context.Context, tokenStr string) (*SAClaims, error) {
	claims := &SAClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid header")
		}
		return v.fetcher.GetKey(ctx, kid)
	},
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("parse SA token: %w", err)
	}
	if !slices.Contains(googleIssuers, claims.Issuer) {
		return nil, fmt.Errorf("unexpected issuer %q", claims.Issuer)
	}
	if !v.pattern.MatchString(claims.Email) {
		return nil, fmt.Errorf("SA email %q does not match approved pattern", claims.Email)
	}
	return claims, nil
}

// GoogleJWKSFetcher fetches and caches Google's JWT signing keys. Cache TTL
// is 1 hour; lookups for an unknown kid trigger a refresh first.
type GoogleJWKSFetcher struct {
	url        string
	client     *http.Client
	cache      atomic.Pointer[jwksCache]
	refreshMu  sync.Mutex
	refreshTTL time.Duration
}

type jwksCache struct {
	keys    map[string]any
	fetched time.Time
}

// Google's JWKS is a few KB; these bound what a compromised or misbehaving
// endpoint can make the router allocate or accept as a verification key.
const (
	maxJWKSBytes      = 1 << 20
	minRSAModulusBits = 2048
)

func NewGoogleJWKSFetcher() *GoogleJWKSFetcher {
	return &GoogleJWKSFetcher{
		url:        "https://www.googleapis.com/oauth2/v3/certs",
		client:     &http.Client{Timeout: 10 * time.Second},
		refreshTTL: time.Hour,
	}
}

func (g *GoogleJWKSFetcher) GetKey(ctx context.Context, kid string) (any, error) {
	if k := g.lookupFresh(kid); k != nil {
		return k, nil
	}
	// Either the cache is stale or the requested kid is absent (e.g. Google
	// rotated). Hold the refresh lock for the rest so concurrent callers
	// don't all hit the network, and re-check the cache after acquiring it
	// in case another goroutine refreshed while we waited.
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()
	if k := g.lookupFresh(kid); k != nil {
		return k, nil
	}
	if err := g.fetchAndCache(ctx); err != nil {
		return nil, fmt.Errorf("refresh JWKS: %w", err)
	}
	c := g.cache.Load()
	if c == nil {
		return nil, errors.New("jwks cache empty after refresh")
	}
	k, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not found in Google JWKS", kid)
	}
	return k, nil
}

// lookupFresh returns the cached key for kid if the cache is within TTL and
// the kid is present. Returns nil otherwise (either expired or unknown kid).
func (g *GoogleJWKSFetcher) lookupFresh(kid string) any {
	c := g.cache.Load()
	if c == nil {
		return nil
	}
	if time.Since(c.fetched) >= g.refreshTTL {
		return nil
	}
	return c.keys[kid]
}

func (g *GoogleJWKSFetcher) fetchAndCache(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.url, nil)
	if err != nil {
		return err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("jwks fetch returned %d: %s", resp.StatusCode, string(body))
	}
	var doc struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	keys := make(map[string]any, len(doc.Keys))
	for _, jwk := range doc.Keys {
		k, err := jwk.toKey()
		if err != nil {
			continue
		}
		keys[jwk.Kid] = k
	}
	g.cache.Store(&jwksCache{keys: keys, fetched: time.Now()})
	return nil
}

// rawJWK is the minimal subset of JWK fields needed for RSA verification.
// Google's SA tokens use RS256.
type rawJWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (j rawJWK) toKey() (any, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported kty %q", j.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	if len(eBytes) > 4 {
		return nil, fmt.Errorf("exponent too large")
	}
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	if key.N.BitLen() < minRSAModulusBits {
		return nil, fmt.Errorf("RSA modulus of %d bits is below the %d-bit floor", key.N.BitLen(), minRSAModulusBits)
	}
	if key.E < 3 || key.E%2 == 0 {
		return nil, fmt.Errorf("invalid RSA exponent %d", key.E)
	}
	return key, nil
}
