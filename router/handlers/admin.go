package handlers

import (
	"errors"
	"net/http"
	"time"
	"uuid"

	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

// pairView is the wire shape returned by GET /pairs. It mirrors store.Pair
// but is decoupled from the persistence schema so we can evolve either side
// without breaking the other. omitzero keeps unset time fields out of the
// JSON entirely.
type pairView struct {
	ID              string       `json:"id"`
	TEEKAddr        string       `json:"teek_addr"`
	TEETAddr        string       `json:"teet_addr"`
	TEEKImageDigest string       `json:"teek_image_digest"`
	TEETImageDigest string       `json:"teet_image_digest"`
	Region          string       `json:"region,omitempty"`
	Status          store.Status `json:"status"`
	ActiveSessions  int          `json:"active_sessions"`
	Draining        bool         `json:"draining"`
	ControlHealthyK bool         `json:"control_healthy_k"`
	ControlHealthyT bool         `json:"control_healthy_t"`
	OTReadyK        bool         `json:"ot_ready_k"`
	OTReadyT        bool         `json:"ot_ready_t"`
	LastHeartbeatK  time.Time    `json:"last_heartbeat_k,omitzero"`
	LastHeartbeatT  time.Time    `json:"last_heartbeat_t,omitzero"`
	RegisteredAt    time.Time    `json:"registered_at,omitzero"`
	ReadyAt         time.Time    `json:"ready_at,omitzero"`
}

type listPairsResponse struct {
	Pairs []pairView `json:"pairs"`
}

// HandleListPairs returns the full registry view for operators. Admin auth
// required. The set is rendered "as of now" — Status is computed for each
// pair against the same wall-clock instant so the snapshot is internally
// consistent.
func (s *Server) HandleListPairs(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}

	pairs, err := s.Store.ListPairs(r.Context())
	if err != nil {
		s.Logger.Error("admin: list pairs failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	now := time.Now()
	views := make([]pairView, 0, len(pairs))
	for _, p := range pairs {
		views = append(views, s.viewOf(p, now))
	}
	writeJSON(w, http.StatusOK, listPairsResponse{Pairs: views})
}

// HandleDrainPair sets the sticky Draining flag. The pair continues to serve
// existing sessions but new allocations skip it. Once active_sessions hits
// zero, an operator can decommission the underlying VMs.
func (s *Server) HandleDrainPair(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	id, ok := pathPairID(w, r)
	if !ok {
		return
	}

	p, err := s.Store.MutatePair(r.Context(), id, func(p *store.Pair, exists bool) error {
		if !exists {
			return store.ErrNotFound
		}
		p.Draining = true
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "pair not found")
		return
	case err != nil:
		s.Logger.Error("admin: drain mutate failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.Logger.Info("admin: pair drained", zap.String("pair_id", id))
	writeJSON(w, http.StatusOK, s.viewOf(p, time.Now()))
}

// errKillNotSafe is the abort signal from /dead's predicate when the pair
// has live sessions and isn't draining / stale.
var errKillNotSafe = errors.New("pair has active sessions and is not draining")

// HandleKillPair removes a pair from the registry. The underlying VMs may
// still be running; the operator is responsible for shutting them down.
// Heartbeats from a deleted pair will return 404 and the TEE will see that
// in its logs.
func (s *Server) HandleKillPair(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	id, ok := pathPairID(w, r)
	if !ok {
		return
	}

	// Atomic precondition: only delete if pair is Draining (operator already
	// drained it) AND ActiveSessions==0 — OR both sides' heartbeats are stale
	// (the pair is gone regardless of the Draining flag).
	now := time.Now()
	err := s.Store.DeletePairIf(r.Context(), id, func(p *store.Pair) error {
		stale := now.Sub(p.LastHeartbeatK) > s.Config.HeartbeatStaleness &&
			now.Sub(p.LastHeartbeatT) > s.Config.HeartbeatStaleness
		if stale {
			return nil
		}
		if p.Draining && p.ActiveSessions == 0 {
			return nil
		}
		return errKillNotSafe
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "pair not found")
		return
	case errors.Is(err, errKillNotSafe):
		writeErr(w, http.StatusConflict, "pair has active sessions and is not draining; /drain first")
		return
	case err != nil:
		s.Logger.Error("admin: delete failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	// Tombstone so a re-register from the same TEE (heartbeat 404 → retry)
	// doesn't resurrect the row before the VM is actually shut down.
	if err := s.Store.Tombstone(r.Context(), id, now.Add(tombstoneTTL)); err != nil {
		s.Logger.Warn("kill: tombstone write failed", zap.String("pair_id", id), zap.Error(err))
	}
	s.Logger.Info("admin: pair killed", zap.String("pair_id", id))
	w.WriteHeader(http.StatusNoContent)
}

// adminAuthOrDeny enforces admin auth and writes the appropriate HTTP response
// on failure. Returns nil if the caller should continue, or the auth error
// (already written to the response writer) so the caller can return early.
func (s *Server) adminAuthOrDeny(w http.ResponseWriter, r *http.Request) error {
	err := s.authenticateAdmin(r)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errAdminDisabled):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	default:
		s.Logger.Warn("admin auth failed",
			zap.String("path", r.URL.Path), zap.Error(err))
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	}
	return err
}

// pathPairID extracts the {id} path parameter and validates it as a UUID.
// On error, writes the response and returns ok=false.
func pathPairID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing pair id")
		return "", false
	}
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusBadRequest, "pair id must be a valid UUID")
		return "", false
	}
	return id, true
}

func (s *Server) viewOf(p *store.Pair, now time.Time) pairView {
	return pairView{
		ID:              p.ID,
		TEEKAddr:        p.TEEKAddr,
		TEETAddr:        p.TEETAddr,
		TEEKImageDigest: p.TEEKImageDigest,
		TEETImageDigest: p.TEETImageDigest,
		Region:          p.Region,
		Status: p.EffectiveStatus(now,
			s.Config.HeartbeatStaleness, s.Config.ControlUnhealthy, s.Config.OTNotReady),
		ActiveSessions:  p.ActiveSessions,
		Draining:        p.Draining,
		ControlHealthyK: p.ControlHealthyK,
		ControlHealthyT: p.ControlHealthyT,
		OTReadyK:        p.OTReadyK,
		OTReadyT:        p.OTReadyT,
		LastHeartbeatK:  p.LastHeartbeatK,
		LastHeartbeatT:  p.LastHeartbeatT,
		RegisteredAt:    p.RegisteredAt,
		ReadyAt:         p.ReadyAt,
	}
}
