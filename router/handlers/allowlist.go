package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

type allowlistView struct {
	Digests []string `json:"digests"`
}

type addDigestRequest struct {
	Digest string `json:"digest"`
}

// HandleListAllowlist returns the current cached allowlist. Admin auth.
func (s *Server) HandleListAllowlist(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	digests := s.Allowlist.List()
	slices.Sort(digests)
	writeJSON(w, http.StatusOK, allowlistView{Digests: digests})
}

// HandleAddDigest adds a digest to the allowlist (persists to store +
// updates cache). Admin auth. Idempotent — adding an already-present
// digest returns 200.
func (s *Server) HandleAddDigest(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	var req addDigestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := validateDigestFormat(req.Digest); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Allowlist.Add(r.Context(), req.Digest); err != nil {
		s.Logger.Error("allowlist add failed", zap.String("digest", req.Digest), zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.Logger.Info("allowlist: digest added", zap.String("digest", req.Digest))
	writeJSON(w, http.StatusOK, map[string]string{"digest": req.Digest})
}

// HandleRemoveDigest removes a digest from the allowlist. Admin auth.
// The path is /allowlist/{digest}; the digest is URL-decoded from the
// path value. Idempotent — removing a missing digest returns 204.
func (s *Server) HandleRemoveDigest(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	raw := r.PathValue("digest")
	digest, err := url.PathUnescape(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	if err := validateDigestFormat(digest); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Allowlist.Remove(r.Context(), digest); err != nil {
		s.Logger.Error("allowlist remove failed", zap.String("digest", digest), zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.Logger.Info("allowlist: digest removed", zap.String("digest", digest))
	s.evictPairsByDigest(r.Context(), digest)
	w.WriteHeader(http.StatusNoContent)
}

// evictPairsByDigest deletes every pair whose K or T side runs the revoked
// digest, and tombstones each so a hot re-register can't resurrect them
// before the heartbeat-side check catches up. Best-effort; failures are
// logged but don't surface as 5xx — the operator already saw the 204 on
// /allowlist Remove and shouldn't see a retry.
func (s *Server) evictPairsByDigest(ctx context.Context, digest string) {
	pairs, err := s.Store.ListPairs(ctx)
	if err != nil {
		s.Logger.Warn("evict-by-digest: list failed", zap.Error(err))
		return
	}
	now := time.Now()
	for _, p := range pairs {
		if p.TEEKImageDigest != digest && p.TEETImageDigest != digest {
			continue
		}
		if err := s.Store.DeletePair(ctx, p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.Logger.Warn("evict-by-digest: delete failed",
				zap.String("pair_id", p.ID), zap.String("digest", digest), zap.Error(err))
			continue
		}
		if err := s.Store.Tombstone(ctx, p.ID, now.Add(tombstoneTTL)); err != nil {
			s.Logger.Warn("evict-by-digest: tombstone write failed",
				zap.String("pair_id", p.ID), zap.Error(err))
		}
		s.Logger.Info("evict-by-digest: pair removed",
			zap.String("pair_id", p.ID), zap.String("digest", digest))
	}
}

// validateDigestFormat enforces one of the supported allowlist identity
// shapes so a typo can't pollute the allowlist with junk no real attestation
// would ever match. Cheap, catches operator mistakes early.
//
//   - Confidential Space: sha256:<64-hex>     (container image digest)
//   - SEV-SNP app:        snp-app:<64-hex>     (sha256(app bundle), cross-cloud)
//   - SEV-SNP base:       snp-base:<N-hex>     (PCR 11 UKI, per-cloud; SHA256/384)
func validateDigestFormat(d string) error {
	if rest, ok := strings.CutPrefix(d, "sha256:"); ok {
		return validateHexLen(rest, 64)
	}
	if rest, ok := strings.CutPrefix(d, shared.SEVSNPAppPrefix); ok {
		return validateHexLen(rest, 64)
	}
	if rest, ok := strings.CutPrefix(d, shared.SEVSNPBasePrefix); ok {
		return validateHexBase(rest)
	}
	return errBadDigestPrefix
}

// validateHexBase accepts a SHA-256 (64) or SHA-384 (96) hex PCR 11 value.
func validateHexBase(rest string) error {
	if len(rest) != 64 && len(rest) != 96 {
		return errBadDigestLength
	}
	return validateHexLen(rest, len(rest))
}

func validateHexLen(rest string, want int) error {
	if len(rest) != want {
		return errBadDigestLength
	}
	for _, c := range rest {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return errBadDigestHex
		}
	}
	return nil
}

var (
	errBadDigestPrefix = &simpleErr{"digest must start with sha256:, snp-app:, or snp-base:"}
	errBadDigestLength = &simpleErr{"digest hex portion has wrong length (sha256:/snp-app: 64, snp-base: 64 or 96)"}
	errBadDigestHex    = &simpleErr{"digest hex portion must be lowercase [0-9a-f]"}
)

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }
