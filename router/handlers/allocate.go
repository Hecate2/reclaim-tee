package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/selector"
	"github.com/reclaimprotocol/reclaim-tee/router/signer"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type allocateRequest struct {
	ClientNonce string `json:"client_nonce"`
}

// allocateResponse is what the client gets back from /allocate. It
// deliberately does NOT include image digests or SPKI hashes: clients
// don't trust the router for crypto identity — they verify the TEEs'
// attestations themselves on connect. The router's only job is to point
// the client at a healthy pair and authorize the session via the JWT.
type allocateResponse struct {
	PairID   string `json:"pair_id"`
	TEEKAddr string `json:"teek_addr"`
	TEETAddr string `json:"teet_addr"`
	JWT      string `json:"jwt"`
}

// HandleAllocate picks a ready pair and mints a short-lived JWT scoped to it.
// No auth — this is the public endpoint clients hit before any TEE connection.
// The returned JWT is the proof TEEs require at session-start.
func (s *Server) HandleAllocate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := s.Logger

	// Per-IP rate limit (1 req/sec, small burst). /allocate is anonymous +
	// each call drives KMS sign + ties up a TEE pair — without this, a
	// spammer can drive cost and starve real clients. XFF is used as the
	// identity dimension; see clientIP for why that's safe for rate limiting
	// (but not for auth).
	if !s.getAllocateLimiter().Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded; try again in a moment")
		return
	}

	var req allocateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.ClientNonce == "" {
		writeErr(w, http.StatusBadRequest, "client_nonce is required")
		return
	}

	pairs, err := s.Store.ListPairs(ctx)
	if err != nil {
		log.Error("allocate: list pairs failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	now := time.Now()
	picked, err := selector.PickReadyPair(pairs, now,
		s.Config.HeartbeatStaleness, s.Config.ControlUnhealthy, s.Config.OTNotReady)
	switch {
	case errors.Is(err, selector.ErrNoReadyPairs):
		writeErr(w, http.StatusServiceUnavailable, "no ready pairs available")
		return
	case err != nil:
		log.Error("allocate: selector failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "selector error")
		return
	}

	claims := &signer.AllocClaims{
		TEEKAddr:    picked.TEEKAddr,
		TEETAddr:    picked.TEETAddr,
		ClientNonce: req.ClientNonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Config.JWTIssuer,
			Audience:  jwt.ClaimStrings{picked.ID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.Config.JWTExpiry)),
			ID:        uuid.NewString(),
		},
	}
	tokenStr, err := s.Signer.Sign(claims)
	if err != nil {
		log.Error("allocate: sign failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "sign error")
		return
	}

	writeJSON(w, http.StatusOK, allocateResponse{
		PairID:   picked.ID,
		TEEKAddr: picked.TEEKAddr,
		TEETAddr: picked.TEETAddr,
		JWT:      tokenStr,
	})
}
