package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
	"uuid"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/geo"
	"github.com/reclaimprotocol/reclaim-tee/router/store"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

type registerRequest struct {
	PairID          string `json:"pair_id"`
	Role            string `json:"role"`
	SelfAddr        string `json:"self_addr"`
	PeerAddrClaim   string `json:"peer_addr_claim"`
	ImageDigest     string `json:"image_digest"`
	AttestationType string `json:"attestation_type,omitempty"`
	AttestationJWT  string `json:"attestation_jwt"`
	SPKIDer         []byte `json:"spki_der,omitempty"`
	BodySignature   []byte `json:"body_signature,omitempty"`
}

type registerResponse struct {
	PairID string       `json:"pair_id"`
	Status store.Status `json:"status"`
}

// HandleRegister implements the /register endpoint. Identity is established
// by provider attestation bound to the registration key. Confidential Space
// also supplies an approved service-account identity. Every path must return an
// app identity in the router's APPROVED_IMAGE_DIGESTS allowlist.
//
// A source-IP cross-check used to live here but was removed: the router runs
// behind a GCP global HTTPS LB, where X-Forwarded-For's leftmost entry is
// attacker-controlled (the LB appends rather than overwrites), and
// r.RemoteAddr is the LB's IP. Any defense-in-depth from a leftmost-XFF
// check would have been bypassable. Move that enforcement to the LB / Cloud
// Armor if needed.
//
// In standalone mode (ROUTER_STANDALONE=true) both signals are skipped —
// the local dev demo can't produce real SA tokens or attestations. The
// claimed image_digest from the body is trusted as-is.
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := s.Logger

	var req registerRequest
	if err := json.UnmarshalRead(http.MaxBytesReader(w, r.Body, 1<<20), &req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// SNP TEEs hold no GCP service account. Their hardware attestation,
	// allowlisted app measurement, and SPKI body binding are the credential.
	// Confidential Space TEEs still present an SA token. Setting either SNP
	// attestation type cannot bypass verification: dispatch requires matching
	// evidence bound to the body-signing key.
	isProviderAttested := req.AttestationType == auth.AttestationTypeSEVSNP || req.AttestationType == auth.AttestationTypeSecureBoot
	var saEmail string
	if !s.Config.Standalone && !isProviderAttested {
		saClaims, err := s.authenticateSA(r)
		if err != nil {
			log.Warn("register: SA token invalid", zap.Error(err))
			writeErr(w, http.StatusUnauthorized, "invalid SA token")
			return
		}
		saEmail = saClaims.Email
	}

	digest := req.ImageDigest
	if !s.Config.Standalone {
		validated, validatedBase, spkiHash, err := s.AttestValidator.Validate(req.AttestationType, req.Role, []byte(req.AttestationJWT), req.SPKIDer)
		if err != nil {
			log.Warn("register: attestation invalid",
				zap.String("pair_id", req.PairID), zap.Error(err))
			writeErr(w, http.StatusUnauthorized, "invalid attestation")
			return
		}
		if validated != req.ImageDigest {
			writeErr(w, http.StatusBadRequest,
				"image_digest body does not match attestation claim")
			return
		}
		if !s.Allowlist.Contains(validated) {
			writeErr(w, http.StatusForbidden, "image digest not in allowlist")
			return
		}
		// Legacy SEV2 pins PCR 11 because that loader extends PCR 8. Secure Boot
		// instead proves an R-authorized loader and returns no base identity. CS
		// attestations also return no separate base identity.
		if req.AttestationType == auth.AttestationTypeSEVSNP && validatedBase != "" && !s.Allowlist.Contains(validatedBase) {
			writeErr(w, http.StatusForbidden, "base UKI not in allowlist")
			return
		}
		digest = validated

		// Bind the request body to the attestation: the SPKI hash the
		// attestation commits to (CS eat_nonce / SEV-SNP report_data) must hash
		// the key that signed this body. Without this, anyone holding a valid
		// allowlisted attestation could register an arbitrary pair (takeover).
		if err := verifyRegistrationBinding(req, digest, spkiHash); err != nil {
			log.Warn("register: attestation binding failed",
				zap.String("pair_id", req.PairID), zap.Error(err))
			writeErr(w, http.StatusForbidden, "registration not bound to attestation")
			return
		}
	}

	// Refuse resurrection of a pair_id that was just /dead'd.
	tombstoned, err := s.Store.IsTombstoned(ctx, req.PairID, time.Now())
	if err != nil {
		log.Error("register: tombstone check failed", zap.String("pair_id", req.PairID), zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if tombstoned {
		writeErr(w, http.StatusGone, "pair_id was retired; generate a fresh one")
		return
	}

	// Per-role SA binding: each role has one expected SA email (config-pinned).
	// SNP has no SA to pin; role/identity binding comes from the attestation and
	// allowlisted app measurement instead.
	if !s.Config.Standalone && !isProviderAttested {
		expected := s.Config.TEEKSAEmail
		if store.Role(req.Role) == store.RoleT {
			expected = s.Config.TEETSAEmail
		}
		if expected != "" && expected != saEmail {
			log.Warn("register: SA email mismatch for role",
				zap.String("role", req.Role),
				zap.String("expected", expected),
				zap.String("got", saEmail))
			writeErr(w, http.StatusForbidden, "SA identity not approved for role")
			return
		}
	}

	// Transactional read-modify-write: create-if-absent, then populate this role.
	now := time.Now()
	p, err := s.Store.MutatePair(ctx, req.PairID, func(p *store.Pair, exists bool) error {
		if !exists {
			p.RegisteredAt = now
			// Seed both heartbeats so stale-row GC's bothHeartbeatsStale
			// never sees a zero-time field while one side races to register.
			p.LastHeartbeatK = now
			p.LastHeartbeatT = now
		}
		// Both halves must use the same attestation generation. This prevents a
		// mixed SEV2/Secure Boot row from inheriting whichever type registered last.
		requestedType := req.AttestationType
		if requestedType == "" {
			requestedType = auth.AttestationTypeCS
		}
		if exists && (p.TEEKAddr != "" || p.TEETAddr != "") {
			storedType := p.AttestationType
			if storedType == "" {
				storedType = auth.AttestationTypeCS
			}
			if storedType != requestedType {
				return errPairAttestationTypeMismatch
			}
		}
		p.AttestationType = requestedType
		switch store.Role(req.Role) {
		case store.RoleK:
			p.TEEKAddr = req.SelfAddr
			p.TEEKRegion = geo.RegionForIP(req.SelfAddr)
			p.TEEKImageDigest = digest
			p.LastHeartbeatK = now
			p.ControlUnhealthySinceK = now
			p.OTUnreadySinceK = now
		case store.RoleT:
			p.TEETAddr = req.SelfAddr
			p.TEETRegion = geo.RegionForIP(req.SelfAddr)
			p.TEETImageDigest = digest
			p.LastHeartbeatT = now
			p.ControlUnhealthySinceT = now
			p.OTUnreadySinceT = now
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errPairAttestationTypeMismatch) {
			writeErr(w, http.StatusConflict, "pair halves use different attestation types")
			return
		}
		log.Error("register: store mutate failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	log.Info("register: pair member registered",
		zap.String("pair_id", req.PairID),
		zap.String("role", req.Role),
		zap.String("sa_email", saEmail),
		zap.String("image_digest", digest))

	// Orphan-row sweep: a TEE registering as role R with self_addr A means
	// it's the live owner of A. Any OTHER pair_id whose same-role address
	// is also A is by definition stale (one VM per address). Delete those
	// — otherwise a TEE restart leaves the previous row in Firestore
	// forever, and retire-pair.sh trips over multiple pair_ids on one IP.
	s.sweepOrphansForAddr(ctx, req.PairID, store.Role(req.Role), req.SelfAddr)

	writeJSON(w, http.StatusOK, registerResponse{
		PairID: p.ID,
		Status: p.EffectiveStatus(now, s.Config.HeartbeatStaleness,
			s.Config.ControlUnhealthy, s.Config.OTNotReady),
	})
}

var errPairAttestationTypeMismatch = errors.New("pair attestation type mismatch")

// errOrphanPreconditionMissed is returned by the DeletePairIf precondition
// when the orphan row's address changed between list and delete — another
// /register raced us. Safe to skip; the winning register already swept.
var errOrphanPreconditionMissed = errors.New("orphan precondition no longer holds")

// sweepOrphansForAddr deletes any pair_id (other than keepID) whose same-role
// address equals addr. Best-effort: a failure here doesn't break the live
// register that just succeeded; we log and move on.
func (s *Server) sweepOrphansForAddr(ctx context.Context, keepID string, role store.Role, addr string) {
	pairs, err := s.Store.ListPairs(ctx)
	if err != nil {
		s.Logger.Warn("orphan sweep: list pairs failed", zap.Error(err))
		return
	}
	for _, other := range pairs {
		if other.ID == keepID {
			continue
		}
		otherAddr := other.TEEKAddr
		if role == store.RoleT {
			otherAddr = other.TEETAddr
		}
		if otherAddr != addr {
			continue
		}
		err := s.Store.DeletePairIf(ctx, other.ID, func(p *store.Pair) error {
			cur := p.TEEKAddr
			if role == store.RoleT {
				cur = p.TEETAddr
			}
			if cur == addr {
				return nil
			}
			return errOrphanPreconditionMissed
		})
		if err != nil && !errors.Is(err, errOrphanPreconditionMissed) {
			s.Logger.Warn("orphan sweep: delete failed",
				zap.String("orphan_pair_id", other.ID),
				zap.String("role", string(role)),
				zap.String("self_addr", addr),
				zap.Error(err))
			continue
		}
		if err == nil {
			s.Logger.Info("orphan sweep: deleted stale row",
				zap.String("orphan_pair_id", other.ID),
				zap.String("kept_pair_id", keepID),
				zap.String("role", string(role)),
				zap.String("self_addr", addr))
		}
	}
}

// verifyRegistrationBinding confirms the register body was signed by the
// enclave whose attestation this is. The attestation commits to sha256(SPKI) of
// the TEE's RA-TLS key (the validator returns it); we recover the key from
// req.SPKIDer, confirm its hash matches, then verify req.BodySignature over the
// canonical body. The RA-TLS private key never leaves the enclave, so a stolen
// attestation alone can't produce a valid signature.
func verifyRegistrationBinding(req registerRequest, imageDigest string, spkiHash [32]byte) error {
	if len(req.SPKIDer) == 0 || len(req.BodySignature) == 0 {
		return errors.New("missing spki_der or body_signature")
	}
	if sha256.Sum256(req.SPKIDer) != spkiHash {
		return errors.New("SPKI does not match attestation")
	}
	pub, err := x509.ParsePKIXPublicKey(req.SPKIDer)
	if err != nil {
		return fmt.Errorf("parse SPKI: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("SPKI is not an ECDSA key")
	}
	digest := shared.RegistrationSigningDigest(req.PairID, req.Role, req.SelfAddr, req.PeerAddrClaim, imageDigest)
	if !ecdsa.VerifyASN1(ecPub, digest[:], req.BodySignature) {
		return errors.New("body signature invalid")
	}
	return nil
}

func (req registerRequest) validate() error {
	// AttestationJWT is intentionally NOT required here — the handler
	// checks it (via AttestValidator) in production mode and skips it
	// entirely in standalone mode. Validation at this layer is purely
	// structural.
	switch {
	case req.PairID == "":
		return errors.New("pair_id is required")
	case req.Role != string(store.RoleK) && req.Role != string(store.RoleT):
		return errors.New("role must be K or T")
	case req.SelfAddr == "":
		return errors.New("self_addr is required")
	case req.PeerAddrClaim == "":
		return errors.New("peer_addr_claim is required")
	case req.ImageDigest == "":
		return errors.New("image_digest is required")
	}
	if _, err := uuid.Parse(req.PairID); err != nil {
		return errors.New("pair_id must be a valid UUID")
	}
	if _, _, err := net.SplitHostPort(req.SelfAddr); err != nil {
		return errors.New("self_addr must be host:port")
	}
	if _, _, err := net.SplitHostPort(req.PeerAddrClaim); err != nil {
		return errors.New("peer_addr_claim must be host:port")
	}
	return nil
}
