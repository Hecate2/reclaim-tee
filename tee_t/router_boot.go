package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// startRouterMode is TEE_T's V2 boot path. TEE_T cannot register at boot —
// it doesn't know the pair_id yet — so it brings up the server, sets an
// onPairAssigned hook that registers + starts the heartbeat the moment
// TEE_K's first envelope arrives, and waits.
//
// In production (running inside GCP Confidential Space, detected via
// launcher socket) the server is HTTPS over RA-TLS + mTLS for peer
// connections. In local dev the server is plain HTTP; JWT validation
// and pair-assignment exchange still happen.
func startRouterMode(parent context.Context, config *TEETConfig, logger *shared.Logger) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	devMode := !shared.IsEnclaveMode()
	logger.Info("=== TEE_T Router Mode ===",
		zap.String("router_url", config.RouterURL),
		zap.String("self_addr", config.SelfAddr),
		zap.String("peer_addr", config.PeerAddr),
		zap.Bool("local_dev", devMode))
	if devMode {
		logger.Warn("LOCAL-DEV MODE: launcher socket absent, attestation checks relaxed — do not run in production")
	}

	if err := validateRouterConfig(config); err != nil {
		logger.Critical("router-mode config invalid", zap.Error(err))
		return
	}

	// Discover own external IP from GCE metadata if SELF_ADDR was not
	// explicitly set. Same reasoning as TEE_K.
	if config.SelfAddr == "" {
		ip, err := shared.DiscoverGCEExternalIP(ctx)
		if err != nil {
			logger.Critical("SELF_ADDR not set and GCE metadata unreachable", zap.Error(err))
			return
		}
		config.SelfAddr = fmt.Sprintf("%s:%d", ip, config.Port)
		logger.Info("Discovered SELF_ADDR from GCE metadata", zap.String("self_addr", config.SelfAddr))
	}

	var ratls *shared.RATLSManager
	if !devMode {
		var err error
		ratls, err = shared.NewRATLSManager(ctx, "tee_t", nil)
		if err != nil {
			logger.Critical("RA-TLS manager init failed", zap.Error(err))
			return
		}
		logger.Info("RA-TLS manager initialized",
			zap.String("spki_hash", fmt.Sprintf("%x", ratls.SPKIHash())))
	}

	tokenSource := shared.MetadataServerTokenSource
	if devMode {
		// Local dev: router-standalone skips SA token validation, and the
		// laptop has no metadata server to mint one anyway.
		tokenSource = shared.NoopTokenSource
	}
	router := shared.NewRouterClient(config.RouterURL, tokenSource)

	teet := NewTEETForRouter(config, ratls, router, logger)
	if config.JWTPublicKey != "" {
		pubKey, err := shared.ParseECDSAPublicKeyPEM([]byte(config.JWTPublicKey))
		if err != nil {
			logger.Critical("parse JWT_PUBLIC_KEY failed", zap.Error(err))
			return
		}
		teet.jwtPubKey = pubKey
		teet.expectedJWTIssuer = config.ExpectedJWTIssuer
		teet.jtiTracker = shared.NewJTITracker(0)
	}
	teet.sessionManager.StartCleanupRoutine()

	register := func(ctx context.Context) error {
		pid := teet.PairID()
		if pid == "" {
			return errors.New("register: pair_id not yet known")
		}
		var imageDigest string
		var attestationJWT []byte
		if teet.ratls != nil {
			var err error
			imageDigest, attestationJWT, err = shared.ExtractIdentityFromRATLS(teet.ratls, logger)
			if err != nil {
				return fmt.Errorf("extract identity: %w", err)
			}
		} else {
			imageDigest = "local-dev"
		}
		regReq := shared.RegisterRequest{
			PairID:         pid,
			Role:           "T",
			SelfAddr:       config.SelfAddr,
			PeerAddrClaim:  config.PeerAddr,
			ImageDigest:    imageDigest,
			AttestationJWT: string(attestationJWT),
		}
		// Bind the body to the attestation by signing it with the RA-TLS key.
		if teet.ratls != nil {
			spki, err := teet.ratls.PublicKeyDER()
			if err != nil {
				return fmt.Errorf("marshal SPKI: %w", err)
			}
			digest := shared.RegistrationSigningDigest(regReq.PairID, regReq.Role, regReq.SelfAddr, regReq.PeerAddrClaim, regReq.ImageDigest)
			sig, err := teet.ratls.SignRegistration(digest)
			if err != nil {
				return fmt.Errorf("sign registration: %w", err)
			}
			regReq.SPKIDer = spki
			regReq.BodySignature = sig
		}
		resp, err := teet.router.Register(ctx, regReq)
		if err != nil {
			return err
		}
		logger.Info("registered with router",
			zap.String("pair_id", resp.PairID),
			zap.String("status", resp.Status))
		return nil
	}

	// The pair_id arrives on the wire from TEE_K, not the env. When it does,
	// register + spin up the heartbeat. TEE_K may reconnect over the life
	// of the process, firing this hook each time; sync.Once guarantees we
	// register + start the heartbeat exactly once. The pair_id never
	// changes for the life of this process.
	// onPairAssigned must return fast — it's called synchronously from the
	// peer-link read path, and blocking here stalls every subsequent
	// envelope from TEE_K. Push the (potentially long) register+retry +
	// heartbeat goroutine off to its own goroutine so the read loop
	// proceeds to the TEEKAttestation handshake immediately. startOnce
	// guarantees we only spawn ONE such goroutine even if K reconnects.
	var startOnce sync.Once
	teet.onPairAssigned = func(pairID string) {
		startOnce.Do(func() {
			go func() {
				if err := shared.RegisterWithRetry(ctx, register, logger); err != nil {
					logger.Critical("router registration failed after retries", zap.Error(err))
					return
				}
				shared.RunHeartbeats(ctx, teet, "T", logger, register, shared.RouterHeartbeatInterval)
			}()
		})
	}

	if teet.ratls != nil {
		// Regenerate per-session cached attestation on every cert rotation
		// — single ticker drives both so cert_hash nonce can't drift from
		// the live cert.
		go shared.RunRATLSRefresh(ctx, teet.ratls, teet.refreshAttestation, logger)
	}

	// Build the mux once; choose whether to wrap it with the peer-mTLS
	// gate based on whether we're serving HTTPS (production) or plain
	// HTTP (local dev — TEE_K dials over plain ws:// without a client
	// cert, so the gate would reject all peer traffic).
	mux := setupRoutes(teet)
	var handler http.Handler = mux
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	serveErrCh := make(chan error, 1)
	if teet.ratls != nil {
		// Production: RA-TLS-protected HTTPS, RequestClientCert so peers
		// can present an attested client cert (gated on the peer routes
		// by enforcePeerMTLS) while anonymous clients hit /ws.
		srvTLS := ratls.ServerTLSConfig()
		srvTLS.ClientAuth = tls.RequestClientCert
		// VerifyPeerCertificate fires for every handshake — including
		// anonymous /ws clients who send no cert. Skip the RA-TLS check
		// in that case; enforcePeerMTLS rejects no-cert connections on
		// the peer-only routes at the HTTP layer.
		verifyPeer := shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
			PeerRole:            "tee_k",
			ExpectedImageDigest: teet.expectedPeerImageDigest,
			Logger:              logger,
		})
		srvTLS.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}
			return verifyPeer(rawCerts, chains)
		}
		server.TLSConfig = srvTLS
		handler = enforcePeerMTLS(mux)
		server.Handler = handler
		logger.Info("Starting router-mode HTTPS server", zap.Int("port", config.Port))
		go func() { serveErrCh <- server.ListenAndServeTLS("", "") }()
	} else {
		server.Handler = handler
		logger.Info("Starting router-mode HTTP server (local dev, no RA-TLS)", zap.Int("port", config.Port))
		go func() { serveErrCh <- server.ListenAndServe() }()
	}
	go func() {
		if err := <-serveErrCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("HTTP server failed", zap.Error(err))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_T router-mode bootstrap complete; awaiting peer")
	<-sigChan
	logger.Info("shutting down router-mode TEE_T")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}
}

// enforcePeerMTLS gates the peer routes (/ws/control, /ws/session) on a
// verified RA-TLS client certificate. Only used in production (HTTPS
// mode) — local dev wires setupRoutes(teet) directly without this
// middleware because there is no client cert to check.
//
// A non-empty r.TLS.PeerCertificates here means the cert ALSO passed
// tls.Config.VerifyPeerCertificate (image_digest + SPKI binding).
func enforcePeerMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws/control", "/ws/session":
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "peer certificate required", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// validateRouterConfig surfaces missing router-mode env vars at boot.
// SELF_ADDR is intentionally NOT required here — startRouterMode
// auto-discovers it from GCE metadata when unset.
func validateRouterConfig(c *TEETConfig) error {
	required := []struct {
		name, value string
	}{
		{"PEER_ADDR", c.PeerAddr},
		{"JWT_PUBLIC_KEY", c.JWTPublicKey},
		{"EXPECTED_JWT_ISSUER", c.ExpectedJWTIssuer},
	}
	if shared.IsEnclaveMode() {
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
