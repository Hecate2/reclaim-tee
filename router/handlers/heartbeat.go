package handlers

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

type heartbeatRequest struct {
	PairID         string `json:"pair_id"`
	Role           string `json:"role"`
	ControlHealthy bool   `json:"control_healthy"`
	OTReady        bool   `json:"ot_ready"`
	ActiveSessions int    `json:"active_sessions"`
	// LastPeerContactMS is informational only — logged at debug for ops
	// diagnostics but not used in status derivation.
	LastPeerContactMS int64 `json:"last_peer_contact_ms"`
}

type heartbeatResponse struct {
	PairID string       `json:"pair_id"`
	Status store.Status `json:"status"`
}

// HandleHeartbeat updates a pair's liveness + health observations from one
// side. Identity rests on the SA identity token; attestation is not
// re-checked here — the initial /register carries it forward. A source-IP
// cross-check used to live here but was dropped along with the equivalent
// check in /register (XFF leftmost is attacker-controlled behind GCP LB).
func (s *Server) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := s.Logger

	var req heartbeatRequest
	if err := json.UnmarshalRead(http.MaxBytesReader(w, r.Body, 1<<20), &req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Resolve the pair BEFORE authenticating. An unknown pair_id must answer 404
	// so the TEE re-registers (shared.ErrRouterNotFound); falling through to the
	// SA check answers 401 instead, which SNP TEEs retry forever because they
	// hold no SA to satisfy it. Cost one pair 8h of dead heartbeats 2026-08-04.
	existing, gerr := s.Store.GetPair(ctx, req.PairID)
	switch {
	case errors.Is(gerr, store.ErrNotFound) || (gerr == nil && existing == nil):
		log.Warn("heartbeat: unknown pair_id, answering 404 to trigger re-register",
			zap.String("pair_id", req.PairID), zap.String("role", req.Role))
		writeErr(w, http.StatusNotFound, "pair not found")
		return
	case gerr != nil:
		// Transient store failure: 503 keeps the TEE retrying rather than
		// re-registering against a store that may still hold the pair.
		log.Error("heartbeat: pair lookup failed",
			zap.String("pair_id", req.PairID), zap.Error(gerr))
		writeErr(w, http.StatusServiceUnavailable, "pair lookup failed")
		return
	}

	// SEV-SNP pairs hold no GCP SA (same as /register). Detect them by the
	// role's already-registered, allowlisted snp-app: digest and skip the SA
	// token; the allowlist re-check below still gates them. NOTE: heartbeats
	// for SEV-SNP pairs are not yet individually authenticated — a signed
	// heartbeat (RA-TLS key) is the pre-prod follow-up.
	roleDigest := existing.TEEKImageDigest
	if store.Role(req.Role) == store.RoleT {
		roleDigest = existing.TEETImageDigest
	}
	isSEVSNP := strings.HasPrefix(roleDigest, shared.SEVSNPAppPrefix)

	var saEmail string
	if !s.Config.Standalone && !isSEVSNP {
		saClaims, err := s.authenticateSA(r)
		if err != nil {
			log.Warn("heartbeat: SA token invalid", zap.Error(err))
			writeErr(w, http.StatusUnauthorized, "invalid SA token")
			return
		}
		saEmail = saClaims.Email
	}

	expectedSAEmail := s.Config.TEEKSAEmail
	if store.Role(req.Role) == store.RoleT {
		expectedSAEmail = s.Config.TEETSAEmail
	}
	if !s.Config.Standalone && !isSEVSNP && expectedSAEmail != "" && expectedSAEmail != saEmail {
		log.Warn("heartbeat: SA email not approved for role",
			zap.String("role", req.Role),
			zap.String("expected", expectedSAEmail),
			zap.String("got", saEmail))
		writeErr(w, http.StatusForbidden, "SA identity not approved for role")
		return
	}

	now := time.Now()
	var prevStatus, newStatus store.Status
	p, err := s.Store.MutatePair(ctx, req.PairID, func(p *store.Pair, exists bool) error {
		if !exists {
			return store.ErrNotFound
		}
		registeredAddr := p.TEEKAddr
		if store.Role(req.Role) == store.RoleT {
			registeredAddr = p.TEETAddr
		}
		if registeredAddr == "" {
			return store.ErrNotFound
		}
		prevStatus = p.EffectiveStatus(now,
			s.Config.HeartbeatStaleness, s.Config.ControlUnhealthy, s.Config.OTNotReady)
		switch store.Role(req.Role) {
		case store.RoleK:
			p.LastHeartbeatK = now
			applyControlObservation(&p.ControlHealthyK, &p.ControlUnhealthySinceK, req.ControlHealthy, now)
			applyOTObservation(&p.OTReadyK, &p.OTUnreadySinceK, req.OTReady, now)
		case store.RoleT:
			p.LastHeartbeatT = now
			applyControlObservation(&p.ControlHealthyT, &p.ControlUnhealthySinceT, req.ControlHealthy, now)
			applyOTObservation(&p.OTReadyT, &p.OTUnreadySinceT, req.OTReady, now)
		}
		p.ActiveSessions = req.ActiveSessions
		newStatus = p.EffectiveStatus(now,
			s.Config.HeartbeatStaleness, s.Config.ControlUnhealthy, s.Config.OTNotReady)
		if newStatus == store.StatusReady && p.ReadyAt.IsZero() {
			p.ReadyAt = now
		}
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "pair or role not registered")
		return
	case err != nil:
		log.Error("heartbeat: store mutate failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	// Re-check allowlist: if operator removed this digest between /register
	// and now, the pair must stop. Delete the row + refuse the heartbeat.
	if !s.Config.Standalone {
		roleDigest := p.TEEKImageDigest
		if store.Role(req.Role) == store.RoleT {
			roleDigest = p.TEETImageDigest
		}
		if roleDigest != "" && !s.Allowlist.Contains(roleDigest) {
			log.Warn("heartbeat: image digest no longer allowlisted; evicting pair",
				zap.String("pair_id", p.ID), zap.String("role", req.Role), zap.String("digest", roleDigest))
			_ = s.Store.DeletePair(ctx, p.ID)
			if err := s.Store.Tombstone(ctx, p.ID, time.Now().Add(tombstoneTTL)); err != nil {
				log.Warn("heartbeat: tombstone write failed", zap.String("pair_id", p.ID), zap.Error(err))
			}
			writeErr(w, http.StatusGone, "image digest revoked")
			return
		}
	}

	if newStatus != prevStatus {
		log.Info("pair status changed",
			zap.String("pair_id", p.ID),
			zap.String("from", string(prevStatus)),
			zap.String("to", string(newStatus)))
	}
	log.Debug("heartbeat received",
		zap.String("pair_id", p.ID),
		zap.String("role", req.Role),
		zap.Bool("control_healthy", req.ControlHealthy),
		zap.Bool("ot_ready", req.OTReady),
		zap.Int("active_sessions", req.ActiveSessions),
		zap.Int64("last_peer_contact_ms", req.LastPeerContactMS))

	writeJSON(w, http.StatusOK, heartbeatResponse{
		PairID: p.ID,
		Status: newStatus,
	})
}

func (req heartbeatRequest) validate() error {
	switch {
	case req.PairID == "":
		return errors.New("pair_id is required")
	case req.Role != string(store.RoleK) && req.Role != string(store.RoleT):
		return errors.New("role must be K or T")
	}
	if _, err := uuid.Parse(req.PairID); err != nil {
		return errors.New("pair_id must be a valid UUID")
	}
	return nil
}

// applyControlObservation updates the most-recent control_healthy bool and
// the "unhealthy since" timestamp atomically: clear on transition to healthy,
// set on transition into unhealthy, leave alone while still unhealthy.
func applyControlObservation(healthy *bool, since *time.Time, observed bool, now time.Time) {
	*healthy = observed
	switch {
	case observed:
		*since = time.Time{}
	case since.IsZero():
		*since = now
	}
}

// applyOTObservation mirrors applyControlObservation for the ot_ready bit.
func applyOTObservation(ready *bool, since *time.Time, observed bool, now time.Time) {
	*ready = observed
	switch {
	case observed:
		*since = time.Time{}
	case since.IsZero():
		*since = now
	}
}
