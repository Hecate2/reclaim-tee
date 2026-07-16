//go:build !mobile

package shared

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// HeartbeatTarget is satisfied by both TEEK and TEET via small accessor
// methods. The router heartbeat goroutine reads through this interface so
// the loop body lives in shared/ rather than being duplicated per side.
//
// PairID returns "" when the side does not yet know its pair_id (TEE_T at
// boot, before TEE_K's TEEKPairAssignment envelope arrives); RunHeartbeats
// skips ticks in that state.
type HeartbeatTarget interface {
	PairID() string
	Router() *RouterClient
	ControlHealthy() bool
	OTReady() bool
	ActiveSessions() int
}

// RouterHeartbeatInterval is the cadence each side reports liveness +
// observation state to the router. Matches the router's 3-missed-in-15s
// "dead" threshold.
const RouterHeartbeatInterval = 5 * time.Second

// InitialRegisterRetryWindow bounds how long startRouterMode keeps
// retrying /register before giving up. A transient router 5xx or a
// stale source-IP check during router redeploy shouldn't kill the TEE
// VM (tee-restart-policy=Never means a process exit terminates the VM
// permanently). 2 minutes covers a Cloud Run revision swap plus a
// bit of slack.
const InitialRegisterRetryWindow = 2 * time.Minute

// RATLSRefreshInterval is how often each side regenerates its RA-TLS
// cert. GCP Confidential Space attestations expire in ~5 minutes;
// refreshing every 4 keeps new handshakes validating cleanly.
const RATLSRefreshInterval = 4 * time.Minute

// SEV-SNP attestations are bounded by cert validity (AWS NitroTPM leaf), not a
// short TTL, and regenerating them is CPU-heavy. This is now a CEILING: the
// actual cadence is driven by the real leaf NotAfter (SNPAttestationExpiry),
// refreshing SNPRefreshMargin before it expires. The ceiling caps churn when
// the leaf is long-lived; a shorter-than-expected leaf refreshes faster.
const RATLSRefreshIntervalSNP = 2 * time.Hour

// SNPRefreshMargin is how long before the NitroTPM leaf's NotAfter a TEE stops
// serving / regenerates its attestation, so a verifier (peer or attestor) never
// sees a leaf within this window of expiry.
const SNPRefreshMargin = 30 * time.Minute

// ratlsRefreshInterval picks the cert-refresh cadence for the active TEE mode.
func ratlsRefreshInterval() time.Duration {
	if IsSEVSNPMode() {
		return RATLSRefreshIntervalSNP
	}

	return RATLSRefreshInterval
}

// AttestationCacheTTL is how long a TEE may serve a cached attestation before
// regenerating. Kept above the refresh cadence so the periodic postRefresh
// (not a lazy cache-miss) drives regeneration.
func AttestationCacheTTL() time.Duration {
	if IsSEVSNPMode() {
		return RATLSRefreshIntervalSNP + 10*time.Minute
	}

	return 5 * time.Minute
}

// SNPAttestationExpiry returns when a just-generated attestation should be
// considered stale. For AWS it's the real NitroTPM leaf NotAfter minus
// SNPRefreshMargin — so the cadence tracks AWS's actual leaf TTL instead of a
// hardcoded guess. For GCP/CS (no short-lived NitroTPM leaf) it falls back to
// now + AttestationCacheTTL().
func SNPAttestationExpiry(attestation []byte) time.Time {
	if notAfter, ok := SNPNitroLeafNotAfter(attestation); ok {
		return notAfter.Add(-SNPRefreshMargin)
	}
	return time.Now().Add(AttestationCacheTTL())
}

// RunHeartbeats fires a heartbeat to the router every `interval` until
// ctx is cancelled. On ErrRouterNotFound (router lost our pair_id, e.g.
// after a restart in single-replica mode), it calls onLost to re-register;
// other errors are logged but don't abort the loop.
func RunHeartbeats(
	ctx context.Context,
	target HeartbeatTarget,
	role string,
	logger *Logger,
	onLost func(context.Context) error,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pid := target.PairID()
			if pid == "" {
				continue
			}
			req := HeartbeatRequest{
				PairID:         pid,
				Role:           role,
				ControlHealthy: target.ControlHealthy(),
				OTReady:        target.OTReady(),
				ActiveSessions: target.ActiveSessions(),
			}
			_, err := target.Router().Heartbeat(ctx, req)
			switch {
			case err == nil:
				// happy path
			case errors.Is(err, ErrRouterNotFound):
				logger.Warn("router lost pair_id, re-registering",
					zap.String("pair_id", pid))
				if regErr := onLost(ctx); regErr != nil {
					logger.Error("re-register failed", zap.Error(regErr))
				}
			default:
				logger.Error("heartbeat failed", zap.Error(err))
			}
		}
	}
}

// RegisterWithRetry calls the supplied register fn with exponential
// backoff up to InitialRegisterRetryWindow. Use at boot so a transient
// router error (5xx, a stale source-IP check during router redeploy,
// etc.) doesn't kill the TEE process — which would terminate the VM
// permanently under tee-restart-policy=Never. Returns the last error
// only if the window is exhausted.
func RegisterWithRetry(ctx context.Context, register func(context.Context) error, logger *Logger) error {
	deadline := time.Now().Add(InitialRegisterRetryWindow)
	backoff := 1 * time.Second
	var lastErr error
	for {
		err := register(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if time.Now().Add(backoff).After(deadline) {
			return fmt.Errorf("register retry window exhausted: %w", lastErr)
		}
		logger.Warn("register failed, retrying", zap.Duration("backoff", backoff), zap.Error(err))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
	}
}

// RunRATLSRefresh rotates the RA-TLS cert on a fixed interval until ctx
// is cancelled. Errors are logged; the loop continues so a transient
// launcher-socket failure doesn't kill the goroutine.
//
// postRefresh runs synchronously after each successful cert rotation,
// inside the same tick. TEEs use it to regenerate any per-session
// attestation cache that binds to the cert hash — keeping the cert and
// the cached attestation atomically in sync from any consumer's point
// of view (no window where the cert is new but the cached attestation
// still references the old hash). Pass nil if not needed.
// nextInterval, when non-nil, is consulted after each refresh to pick the delay
// until the next one — letting SEV-SNP track the actual NitroTPM leaf expiry
// (refresh SNPRefreshMargin before NotAfter) instead of a fixed cadence. A nil
// callback (or a non-positive return) falls back to the fixed ratlsRefreshInterval().
func RunRATLSRefresh(ctx context.Context, ratls *RATLSManager, postRefresh func() error, nextInterval func() time.Duration, health *AttestationHealth, logger *Logger) {
	// Run postRefresh once immediately so the per-session attestation
	// cache is populated before the server starts accepting traffic.
	// Without this, the cache sits empty for the first RATLSRefreshInterval
	// (4 minutes) after every TEE boot — and any request arriving in that
	// window triggers a lazy fallback to GenerateGCPAttestation. Under
	// concurrent load that's N simultaneous calls to the launcher socket,
	// which can't keep up and starts timing out. NewRATLSManager already
	// generated the initial cert; we just need to prime the cached
	// per-session attestation here.
	if postRefresh != nil {
		if err := postRefresh(); err != nil {
			logger.Error("RA-TLS initial post-refresh failed", zap.Error(err))
		}
	}

	for {
		d := ratlsRefreshInterval()
		if nextInterval != nil {
			if n := nextInterval(); n > 0 {
				d = n
			}
		}
		// Emit as strings: the GCP logging core doesn't serialize zap.Duration
		// or zap.Time (they render as null / {} in jsonPayload).
		nextAt := time.Now().Add(d)
		logger.Info("next RA-TLS attestation refresh scheduled",
			zap.String("in", d.Round(time.Second).String()),
			zap.String("at", nextAt.UTC().Format(time.RFC3339)))
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if err := ratls.Refresh(ctx); err != nil {
				logger.Error("RA-TLS refresh failed", zap.Error(err))
				// The cert path hits the device directly (not via generateAttestationDoc);
				// feed the watchdog here too — the path that goes silent on a wedge.
				health.RecordFailure(err)
				continue
			}
			if postRefresh != nil {
				if err := postRefresh(); err != nil {
					logger.Error("RA-TLS post-refresh hook failed", zap.Error(err))
					continue
				}
			}
			logger.Debug("RA-TLS attestation refreshed")
		}
	}
}

// ExtractIdentityFromRATLS reads the in-flight RA-TLS cert and pulls the
// attestation JWT + container image digest out of it. The same JWT goes
// into the router registration body; the digest is the router's
// allowlist key.
func ExtractIdentityFromRATLS(snap RATLSSnapshot, logger *Logger) (imageDigest, attestationType string, attestation []byte, err error) {
	cert := snap.Certificate()
	if cert == nil || cert.Leaf == nil {
		return "", "", nil, errors.New("RA-TLS manager has no current cert")
	}
	leaf := cert.Leaf
	// SEV-SNP (OID .2) takes precedence when present. The report is binary, so
	// it travels base64-encoded in the JSON register body; the router decodes it.
	if report := findExtension(leaf, AttestationOIDSEVSNP); report != nil {
		spki, serr := snap.PublicKeyDER()
		if serr != nil {
			return "", "", nil, fmt.Errorf("marshal SPKI: %w", serr)
		}
		app, _, verr := VerifyCombinedSEVSNPAttestation(report, spki)
		if verr != nil {
			return "", "", nil, fmt.Errorf("verify SEV-SNP attestation: %w", verr)
		}
		enc := base64.StdEncoding.EncodeToString(report)
		return app, AttestationTypeSEVSNP, []byte(enc), nil
	}
	attestation, err = ExtractAttestationFromCert(leaf)
	if err != nil {
		return "", "", nil, fmt.Errorf("extract attestation: %w", err)
	}
	imageDigest, err = ExtractImageDigestFromGCPAttestation(attestation, logger)
	if err != nil {
		return "", "", nil, fmt.Errorf("extract image digest: %w", err)
	}
	return imageDigest, AttestationTypeCS, attestation, nil
}

// LoadOPRFShare reads (or creates) this side's persistent MPC OPRF key
// share from GCP Secret Manager. role is "tee_k" or "tee_t"; deploymentKey
// is the per-deployment discriminator (e.g. "tk.reclaimprotocol.org") that
// disambiguates the secret name. Requires GOOGLE_PROJECT_ID, GOOGLE_KMS_
// LOCATION, GOOGLE_KMS_KEYRING, GOOGLE_KMS_KEY to be set.
func LoadOPRFShare(role, deploymentKey string, logger *Logger) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// On AWS SEV-SNP the share lives in AWS Secrets Manager (same secret name,
	// seeded from the GCP-exported share); GCP keeps using Secret Manager + KMS.
	if IsAWSSEVSNP() {
		store, err := NewAWSSecretStore(ctx, GetEnvOrDefault("AWS_OPRF_KMS_KEY_ID", ""))
		if err != nil {
			return nil, fmt.Errorf("new aws secret store: %w", err)
		}
		share, err := store.LoadOrCreateOPRFShare(ctx, role, deploymentKey)
		if err != nil {
			return nil, fmt.Errorf("LoadOrCreateOPRFShare (aws): %w", err)
		}
		if logger != nil {
			logger.Info("Loaded OPRF share from AWS Secrets Manager",
				zap.String("role", role),
				zap.String("deployment_key", deploymentKey))
		}
		return share, nil
	}

	required := []struct {
		name, value string
	}{
		{"GOOGLE_PROJECT_ID", GetEnvOrDefault("GOOGLE_PROJECT_ID", "")},
		{"GOOGLE_KMS_LOCATION", GetEnvOrDefault("GOOGLE_KMS_LOCATION", "")},
		{"GOOGLE_KMS_KEYRING", GetEnvOrDefault("GOOGLE_KMS_KEYRING", "")},
		{"GOOGLE_KMS_KEY", GetEnvOrDefault("GOOGLE_KMS_KEY", "")},
	}
	for _, r := range required {
		if r.value == "" {
			return nil, fmt.Errorf("%s required when KMS_ENCLAVE_DOMAIN_KEY is set", r.name)
		}
	}

	store, err := NewSecretStore(ctx, required[0].value, required[1].value, required[2].value, required[3].value)
	if err != nil {
		return nil, fmt.Errorf("new secret store: %w", err)
	}
	share, err := store.LoadOrCreateOPRFShare(ctx, role, deploymentKey)
	if err != nil {
		return nil, fmt.Errorf("LoadOrCreateOPRFShare: %w", err)
	}
	if logger != nil {
		logger.Info("Loaded OPRF share from Secret Manager",
			zap.String("role", role),
			zap.String("deployment_key", deploymentKey))
	}
	return share, nil
}
