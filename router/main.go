package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
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
		srv.AttestValidator = auth.NewCSAttestationValidator(logger)
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
	fs, err := store.NewFirestoreStore(ctx, cfg.FirestoreProjectID)
	if err != nil {
		return nil, nil, err
	}
	logger.Info("using Firestore pair store",
		zap.String("project_id", cfg.FirestoreProjectID),
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
		logger.Warn("using local in-process signer — pub key will change on restart",
			zap.String("hint", "set KMS_KEY_NAME for production"))
		ls, err := signer.NewLocalSigner()
		if err != nil {
			return nil, nil, err
		}
		s, closer = ls, noopCloser{}
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

type noopCloser struct{}

func (noopCloser) Close() error { return nil }
