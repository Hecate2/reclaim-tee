package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

func main() {
	config := LoadTEETConfig()

	// Get the TEE_T logger for this service
	logger := shared.GetTEETLogger()
	defer logger.Sync()

	// Diagnostic safety net.
	defer shared.RecoverAndCrash(logger, "tee_t.main")
	shared.InstallSignalCrashHandler(logger)
	go shared.RunRuntimeStatsLogger(context.Background(), logger)
	go shared.RunDeadlockWatchdog(context.Background(), logger)

	// SEV-SNP attestation self-test (env SNP_ATTEST_DUMP=1): emit + self-verify
	// the combined attestation, log app/base identities, then hold.
	if os.Getenv("SNP_ATTEST_DUMP") == "1" {
		dumpSEVSNPAttestation(logger)
		return
	}

	// Router mode is the production path (multi-pair, RA-TLS, router-mediated).
	// Standalone mode remains for local dev only — no TLS, no attestation.
	// Armed before any fatal path can be reached; disarmed once serving.
	boot := shared.NewBootGuard(logger, shared.BootReadyDeadline)

	if config.RouterMode() {
		if err := startRouterMode(context.Background(), config, logger, boot); err != nil {
			shared.FatalBootReset(logger, err)
		}
		return
	}

	logger.Info("Starting TEE_T in standalone mode")
	startStandaloneMode(config, logger, boot)
}

func startStandaloneMode(config *TEETConfig, logger *shared.Logger, boot *shared.BootGuard) {
	teet := NewTEETWithLogger(config.Port, logger)
	teet.sessionManager.StartCleanupRoutine()

	// Start periodic connection status logging (every minute)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if teet.connManager != nil {
				teet.connManager.LogConnectionStatus()
			}
		}
	}()

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teet),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start server
	logger.Info("Starting standalone server", zap.Int("port", config.Port))
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("Server failed", zap.Error(err))
			// Signal shutdown instead of crashing
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGTERM)
			select {
			case sigChan <- syscall.SIGTERM:
				// Signal sent
			default:
				// Channel full, ignore
			}
		}
	}()

	// Wait for interrupt signal
	boot.MarkReady()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Shutdown error", zap.Error(err))
	}

	logger.Info("Shutdown complete")
}

func setupRoutes(teet *TEET) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", teet.handleClientWebSocket)

	// Per-session connection architecture (TEEs work in pairs)
	mux.HandleFunc("/ws/control", teet.handleControlWebSocket) // Control: attestation, OT, session lifecycle
	mux.HandleFunc("/ws/session", teet.handleSessionWebSocket) // Per-session: all session data

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_T Healthy")
	})
	return mux
}

// dumpSEVSNPAttestation is a hardware self-test (env SNP_ATTEST_DUMP=1) mirroring
// tee_k: build RA-TLS, emit the combined SEV-SNP attestation, self-verify it, and
// log the app + base identities. Holds afterward (PID 1 must not exit).
func dumpSEVSNPAttestation(logger *shared.Logger) {
	ctx := context.Background()
	ratls, err := shared.NewRATLSManager(ctx, "tee_t", nil)
	if err != nil {
		logger.Critical("SNP-ATTEST-DUMP ratls init failed", zap.Error(err))
		select {}
	}
	cert := ratls.Certificate()
	if cert == nil || cert.Leaf == nil {
		logger.Critical("SNP-ATTEST-DUMP no RA-TLS cert")
		select {}
	}
	var ext []byte
	for _, e := range cert.Leaf.Extensions {
		if e.Id.Equal(shared.AttestationOIDSEVSNP) {
			ext = e.Value
		}
	}
	spki, _ := ratls.PublicKeyDER()
	logger.Info("SNP-ATTEST-DUMP", zap.Int("ext_len", len(ext)), zap.String("app_hash_env", os.Getenv("SNP_APP_HASH")))
	app, base, verr := shared.VerifyCombinedSEVSNPAttestation(ext, spki)
	if verr != nil {
		logger.Critical("SNP-ATTEST-VERIFY FAILED", zap.Error(verr))
	} else {
		logger.Info("SNP-ATTEST-VERIFY OK", zap.String("app", app), zap.String("base", base))
	}
	select {}
}
