//go:build !mobile

package shared

import (
	"context"
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
func RunRATLSRefresh(ctx context.Context, ratls *RATLSManager, postRefresh func() error, logger *Logger) {
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

	ticker := time.NewTicker(RATLSRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ratls.Refresh(ctx); err != nil {
				logger.Error("RA-TLS refresh failed", zap.Error(err))
				continue
			}
			if postRefresh != nil {
				if err := postRefresh(); err != nil {
					logger.Error("RA-TLS post-refresh hook failed", zap.Error(err))
					continue
				}
			}
			logger.Debug("RA-TLS refreshed")
		}
	}
}

// ExtractIdentityFromRATLS reads the in-flight RA-TLS cert and pulls the
// attestation JWT + container image digest out of it. The same JWT goes
// into the router registration body; the digest is the router's
// allowlist key.
func ExtractIdentityFromRATLS(ratls *RATLSManager, logger *Logger) (imageDigest string, attestationJWT []byte, err error) {
	cert := ratls.Certificate()
	if cert == nil || cert.Leaf == nil {
		return "", nil, errors.New("RA-TLS manager has no current cert")
	}
	attestationJWT, err = ExtractAttestationFromCert(cert.Leaf)
	if err != nil {
		return "", nil, fmt.Errorf("extract attestation: %w", err)
	}
	imageDigest, err = ExtractImageDigestFromGCPAttestation(attestationJWT, logger)
	if err != nil {
		return "", nil, fmt.Errorf("extract image digest: %w", err)
	}
	return imageDigest, attestationJWT, nil
}

// LoadOPRFShare reads (or creates) this side's persistent MPC OPRF key
// share from GCP Secret Manager. role is "tee_k" or "tee_t"; deploymentKey
// is the per-deployment discriminator (e.g. "tk.reclaimprotocol.org") that
// disambiguates the secret name. Requires GOOGLE_PROJECT_ID, GOOGLE_KMS_
// LOCATION, GOOGLE_KMS_KEYRING, GOOGLE_KMS_KEY to be set.
func LoadOPRFShare(role, deploymentKey string, logger *Logger) ([]byte, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
