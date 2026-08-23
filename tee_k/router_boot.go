package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"uuid"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// startRouterMode is TEE_K's V2 boot path, used when ROUTER_URL is set.
// In production (running inside a GCP Confidential Space, detected via
// the launcher socket) it brings up RA-TLS identity, serves HTTPS, dials
// the peer over RA-TLS-verified mTLS, and registers with a real
// attestation JWT. In local dev (no launcher socket) it serves plain
// HTTP / dials plain ws:// and registers with a sentinel image digest —
// the JWT / pair-assignment / OPRF / session protocol all still run.
func startRouterMode(parent context.Context, config *TEEKConfig, logger *shared.Logger, boot *shared.BootGuard) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	devMode := !shared.IsProductionTEE()
	logger.Info("=== TEE_K Router Mode ===",
		zap.String("router_url", config.RouterURL),
		zap.String("self_addr", config.SelfAddr),
		zap.String("peer_addr", config.PeerAddr),
		zap.Bool("local_dev", devMode))
	if devMode {
		logger.Warn("LOCAL-DEV MODE: launcher socket absent, attestation checks relaxed — do not run in production")
	}

	if err := validateRouterConfig(config); err != nil {
		return fmt.Errorf("router-mode config invalid: %w", err)
	}
	if err := shared.ValidateSNPAttestationType(); err != nil {
		return fmt.Errorf("router-mode attestation config invalid: %w", err)
	}

	// Discover own external IP from GCE metadata if SELF_ADDR was not
	// explicitly set. Production multi-pair deploys use ephemeral
	// external IPs — assigned at VM boot — so the binary has to
	// auto-discover. Local dev / standalone always sets it explicitly.
	if config.SelfAddr == "" {
		ip, err := shared.DiscoverGCEExternalIP(ctx)
		if err != nil {
			return fmt.Errorf("SELF_ADDR not set and GCE metadata unreachable: %w", err)
		}
		config.SelfAddr = fmt.Sprintf("%s:%d", ip, config.Port)
		logger.Info("Discovered SELF_ADDR from GCE metadata", zap.String("self_addr", config.SelfAddr))
	}

	pairID := uuid.NewV4().String()
	logger.Info("Generated pair ID", zap.String("pair_id", pairID))

	var ratls *shared.RATLSManager
	if !devMode {
		var err error
		ratls, err = shared.NewRATLSManager(ctx, "tee_k", nil)
		if err != nil {
			return fmt.Errorf("RA-TLS manager init failed: %w", err)
		}
		logger.Info("RA-TLS manager initialized",
			zap.String("spki_hash", fmt.Sprintf("%x", ratls.SPKIHash())))
	}

	tokenSource := shared.MetadataServerTokenSource
	if devMode || shared.IsSEVSNPMode() {
		// Local dev has no metadata server; SEV-SNP TEEs hold no GCP SA and
		// the router skips the SA token for them. Either way, send no token.
		tokenSource = shared.NoopTokenSource
	}
	router := shared.NewRouterClient(config.RouterURL, tokenSource)

	teek := NewTEEKForRouter(config, ratls, router, pairID)
	teek.sessionManager.StartCleanupRoutine()

	register := func(ctx context.Context) error {
		var imageDigest, attestationType string
		var attestation []byte
		var snap shared.RATLSSnapshot
		ratlsActive := teek.ratls != nil
		if ratlsActive {
			// One snapshot for the whole body: attestation, SPKI and body
			// signature must all come from the same RA-TLS epoch, since the
			// keypair rotates on every refresh.
			snap = teek.ratls.Snapshot()
			var err error
			imageDigest, attestationType, attestation, err = shared.ExtractIdentityFromRATLS(snap, logger)
			if err != nil {
				return fmt.Errorf("extract identity: %w", err)
			}
		} else {
			// Local-dev: router-standalone trusts the body image_digest.
			imageDigest = "local-dev"
		}
		regReq := shared.RegisterRequest{
			PairID:          teek.pairID,
			Role:            "K",
			SelfAddr:        config.SelfAddr,
			PeerAddrClaim:   config.PeerAddr,
			ImageDigest:     imageDigest,
			AttestationType: attestationType,
			AttestationJWT:  string(attestation),
		}
		// Bind the body to the attestation by signing it with the RA-TLS key
		// from the SAME snapshot used for the attestation above.
		if ratlsActive {
			spki, err := snap.PublicKeyDER()
			if err != nil {
				return fmt.Errorf("marshal SPKI: %w", err)
			}
			digest := shared.RegistrationSigningDigest(regReq.PairID, regReq.Role, regReq.SelfAddr, regReq.PeerAddrClaim, regReq.ImageDigest)
			sig, err := snap.SignRegistration(digest)
			if err != nil {
				return fmt.Errorf("sign registration: %w", err)
			}
			regReq.SPKIDer = spki
			regReq.BodySignature = sig
		}
		resp, err := teek.router.Register(ctx, regReq)
		if err != nil {
			return err
		}
		logger.Info("registered with router",
			zap.String("pair_id", resp.PairID),
			zap.String("status", resp.Status))
		return nil
	}

	if err := shared.RegisterWithRetry(ctx, register, logger); err != nil {
		return fmt.Errorf("router registration failed after retries: %w", err)
	}

	teek.attestHealth = shared.NewAttestationHealth(logger)
	if teek.ratls != nil {
		// Regenerate the per-session cached attestation on every cert
		// rotation so its cert_hash nonce stays in lockstep with the
		// live cert. Single ticker drives both — no drift window.
		go shared.RunRATLSRefresh(ctx, teek.ratls, teek.refreshAttestation, teek.nextRATLSRefresh, teek.attestHealth, logger)
	}
	go shared.RunHeartbeats(ctx, teek, "K", logger, register, shared.RouterHeartbeatInterval)

	// Bring up the control connection to TEE_T. Connection manager picks
	// up router mode via teek.pairID (sends TEEKPairAssignment first);
	// transport choice (wss+RA-TLS vs ws) is driven by teek.ratls.
	go teek.establishSharedTEETConnection()

	server := &http.Server{
		Addr:                fmt.Sprintf(":%d", config.Port),
		Handler:             setupRoutes(teek),
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		MaxHeaderValueCount: 50,
	}
	serveTLS := false
	if teek.ratls != nil {
		srvTLS := teek.ratls.ServerTLSConfig()
		srvTLS.ClientAuth = tls.NoClientCert
		server.TLSConfig = srvTLS
		logger.Info("Starting router-mode HTTPS server", zap.Int("port", config.Port))
		serveTLS = true
	} else {
		logger.Info("Starting router-mode HTTP server (local dev, no RA-TLS)", zap.Int("port", config.Port))
	}
	runningServer, err := shared.StartHTTPServer(server, serveTLS)
	if err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	logger.Info("TEE_K router-mode bootstrap complete",
		zap.String("pair_id", teek.pairID))
	boot.MarkReady()
	serveErr, shutdownErr := shared.WaitAndShutdownHTTPServer(runningServer, sigChan, 10*time.Second)
	logger.Info("shutting down router-mode TEE_K")

	if shutdownErr != nil {
		logger.Error("HTTP server shutdown error", zap.Error(shutdownErr))
	}
	if serveErr != nil {
		return fmt.Errorf("HTTP server failed: %w", serveErr)
	}
	return nil
}

// validateRouterConfig surfaces missing router-mode env vars at boot
// rather than failing mysteriously inside RA-TLS, router-client, or
// OPRF-storage code. Order matters for the error message: we report the
// first unset var encountered. EXPECTED_PEER_IMAGE_DIGEST and
// KMS_ENCLAVE_DOMAIN_KEY are required only inside a real enclave —
// local dev skips attestation + persistent OPRF storage. SELF_ADDR is
// auto-discovered from GCE metadata after this check if empty.
func validateRouterConfig(c *TEEKConfig) error {
	required := []struct {
		name, value string
	}{
		{"PEER_ADDR", c.PeerAddr},
		{"JWT_PUBLIC_KEY", c.JWTPublicKey},
		{"EXPECTED_JWT_ISSUER", c.ExpectedJWTIssuer},
	}
	if shared.IsProductionTEE() {
		// An attested TEE (SEV-SNP or enclave) must use the real KMS-backed OPRF
		// share, never the world-known static dev share. No test exemption: the
		// static path is local-dev-only (see initializeOPRFKeyShare).
		required = append(required,
			struct{ name, value string }{"EXPECTED_PEER_IMAGE_DIGEST", c.ExpectedPeerImageDigest},
			struct{ name, value string }{"KMS_ENCLAVE_DOMAIN_KEY", c.KMSEnclaveDomainKey},
		)
	}
	for _, r := range required {
		if r.value == "" {
			return fmt.Errorf("%s is required in router mode", r.name)
		}
	}
	return nil
}
