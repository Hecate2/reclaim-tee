package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/geo"
	"github.com/reclaimprotocol/reclaim-tee/router/handlers"
	"github.com/reclaimprotocol/reclaim-tee/router/signer"
	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer func() { _ = logger.Sync() }()

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("config load failed", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pairStore, storeCloser, err := buildStore(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("store init failed", zap.Error(err))
	}
	defer func() { _ = storeCloser.Close() }()

	tokenSigner, signerCloser, err := buildSigner(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("signer init failed", zap.Error(err))
	}
	defer func() { _ = signerCloser.Close() }()

	// Load cloud IP ranges for geo-affinity routing. Best-effort: on failure,
	// /allocate falls back to uniform-random pair selection.
	geoCtx, geoCancel := context.WithTimeout(ctx, 15*time.Second)
	if err := geo.Load(geoCtx, &http.Client{Timeout: 15 * time.Second}); err != nil {
		logger.Warn("geo IP ranges not loaded; allocation falls back to random", zap.Error(err))
	} else {
		logger.Info("geo IP ranges loaded for region-aware allocation")
	}
	geoCancel()

	srv := &handlers.Server{
		Store:  pairStore,
		Signer: tokenSigner,
		Logger: logger,
		Config: cfg,
	}
	if cfg.Standalone {
		logger.Warn("router running in STANDALONE mode — no SA token, attestation, allowlist, or source-IP checks. Local dev only.")
	} else {
		srv.SAValidator = auth.NewGoogleSAValidator(
			auth.NewGoogleJWKSFetcher(),
			cfg.ApprovedSAPattern,
			cfg.SATokenAudience,
		)
		srv.AttestValidator = auth.NewDispatchingValidator(logger)
		allowlist, err := auth.NewAllowlist(ctx, pairStore, cfg.ApprovedDigests, logger)
		if err != nil {
			logger.Fatal("allowlist init failed", zap.Error(err))
		}
		defer allowlist.Stop()
		srv.Allowlist = allowlist
	}

	httpSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("router listening", zap.String("port", cfg.Port))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()
	go srv.RunStaleRowGC(ctx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("shutting down")
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown failed", zap.Error(err))
	}
}

// buildStore returns a Firestore-backed store if FIRESTORE_PROJECT_ID is set,
// otherwise an in-memory store. The second return value is a closer; for
// MemoryStore it's a no-op.
func buildStore(ctx context.Context, cfg *config.Config, logger *zap.Logger) (store.Store, io.Closer, error) {
	if cfg.FirestoreProjectID == "" {
		logger.Warn("using in-memory pair store — state will not survive restart; do not run multi-replica",
			zap.String("hint", "set FIRESTORE_PROJECT_ID for production"))
		return store.NewMemoryStore(), noopCloser{}, nil
	}
	fs, err := store.NewFirestoreStore(ctx, cfg.FirestoreProjectID, cfg.FirestoreDatabaseID)
	if err != nil {
		return nil, nil, err
	}
	db := cfg.FirestoreDatabaseID
	if db == "" {
		db = "(default)"
	}
	logger.Info("using Firestore pair store",
		zap.String("project_id", cfg.FirestoreProjectID),
		zap.String("database", db),
		zap.String("collection", store.FirestoreCollection))
	return fs, fs, nil
}

// buildSigner returns a KMS-backed signer if KMS_KEY_NAME is set, otherwise
// a local in-process signer. Logs the public key at startup either way so
// operators can copy it into TEE image metadata.
func buildSigner(ctx context.Context, cfg *config.Config, logger *zap.Logger) (signer.Signer, io.Closer, error) {
	var s signer.Signer
	var closer io.Closer
	if cfg.KMSKeyName == "" {
		if pemKey := os.Getenv("JWT_SIGNING_KEY"); pemKey != "" {
			priv, err := parseECPrivateKeyPEM(pemKey)
			if err != nil {
				return nil, nil, fmt.Errorf("parse JWT_SIGNING_KEY: %w", err)
			}
			logger.Info("using persistent local signer from JWT_SIGNING_KEY (stable across restarts)")
			s, closer = signer.NewLocalSignerFromKey(priv), noopCloser{}
		} else {
			logger.Warn("using local in-process signer — pub key will change on restart",
				zap.String("hint", "set KMS_KEY_NAME or JWT_SIGNING_KEY for a stable key"))
			ls, err := signer.NewLocalSigner()
			if err != nil {
				return nil, nil, err
			}
			s, closer = ls, noopCloser{}
		}
	} else {
		ks, err := signer.NewKMSSigner(ctx, cfg.KMSKeyName)
		if err != nil {
			return nil, nil, err
		}
		logger.Info("using KMS signer", zap.String("key", cfg.KMSKeyName))
		s, closer = ks, ks
	}

	pem, err := s.PublicKeyPEM()
	if err != nil {
		return nil, nil, err
	}
	logger.Info("signer public key (embed into TEE metadata as JWT_PUBLIC_KEY)",
		zap.String("pem", string(pem)))
	return s, closer, nil
}

// parseECPrivateKeyPEM parses an ECDSA P-256 private key from PEM (SEC1
// "EC PRIVATE KEY" or PKCS#8 "PRIVATE KEY"). Used by the test router to load a
// stable JWT signing key so its public key survives restarts.
func parseECPrivateKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	// Allow a single-line value with literal \n escapes so the multi-line PEM
	// fits a Cloud Run env var without delimiter headaches.
	pemStr = strings.ReplaceAll(pemStr, `\n`, "\n")
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return ec, nil
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }
