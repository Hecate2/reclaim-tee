package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/signer"
	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

// Server bundles the dependencies the router HTTP handlers need.
type Server struct {
	Store           store.Store
	SAValidator     auth.SAValidator
	AttestValidator auth.AttestationValidator
	Allowlist       *auth.Allowlist
	Signer          signer.Signer
	Logger          *zap.Logger
	Config          *config.Config

	// allocateLimiter caps /allocate at ~1 req/sec per client IP. Built on
	// first use via getAllocateLimiter so test servers constructed as struct
	// literals don't need to wire it.
	allocateLimiterOnce sync.Once
	allocateLimiter     *ipRateLimiter
}

func (s *Server) getAllocateLimiter() *ipRateLimiter {
	s.allocateLimiterOnce.Do(func() {
		s.allocateLimiter = newIPRateLimiter(allocateRPS, allocateBurst, rateLimiterTTL, rateLimiterMaxLen)
	})
	return s.allocateLimiter
}

// Routes returns the router's HTTP mux. New endpoints are wired here.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.HandleHealthz)
	mux.HandleFunc("GET /jwt-pubkey", s.HandleJWTPubKey)
	mux.HandleFunc("POST /register", s.HandleRegister)
	mux.HandleFunc("POST /heartbeat", s.HandleHeartbeat)
	mux.HandleFunc("POST /allocate", s.HandleAllocate)
	mux.HandleFunc("GET /pairs", s.HandleListPairs)
	mux.HandleFunc("POST /pairs/{id}/drain", s.HandleDrainPair)
	mux.HandleFunc("POST /pairs/{id}/dead", s.HandleKillPair)
	mux.HandleFunc("GET /allowlist", s.HandleListAllowlist)
	mux.HandleFunc("POST /allowlist", s.HandleAddDigest)
	mux.HandleFunc("DELETE /allowlist/{digest}", s.HandleRemoveDigest)
	return mux
}

// authenticateSA validates the Authorization: Bearer SA-identity-token header
// on a request and returns its claims, or an HTTP-friendly error.
func (s *Server) authenticateSA(r *http.Request) (*auth.SAClaims, error) {
	authz := r.Header.Get("Authorization")
	saToken, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return nil, errors.New("missing or malformed Authorization header")
	}
	return s.SAValidator.Validate(r.Context(), saToken)
}

// errAdminDisabled is returned when an admin endpoint is hit but ADMIN_TOKEN
// is not configured. Callers map this to 503 (vs 401) so operators can tell
// "config is missing" apart from "I forgot the token."
var errAdminDisabled = errors.New("admin endpoints not configured")

// authenticateAdmin enforces the static admin bearer token. The router holds
// only the token's SHA-256; a blank AdminTokenHash disables admin entirely.
func (s *Server) authenticateAdmin(r *http.Request) error {
	if s.Config.AdminTokenHash == "" {
		return errAdminDisabled
	}
	authz := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return errors.New("missing or malformed Authorization header")
	}
	sum := sha256.Sum256([]byte(token))
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.Config.AdminTokenHash)) != 1 {
		return errors.New("invalid admin token")
	}
	return nil
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalEncode(jsontext.NewEncoder(w), body)
}
