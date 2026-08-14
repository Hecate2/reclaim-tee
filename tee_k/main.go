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

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func main() {
	// Load .env file first (before any env var checks)
	_ = godotenv.Load()

	logger := shared.GetTEEKLogger()
	defer logger.Sync()

	// Diagnostic safety net.
	defer shared.RecoverAndCrash(logger, "tee_k.main")
	shared.InstallSignalCrashHandler(logger)
	go shared.RunRuntimeStatsLogger(context.Background(), logger)
	go shared.RunDeadlockWatchdog(context.Background(), logger)

	StartRootCAUpdater(logger)

	// Hardware attestation self-test: bring up RA-TLS, emit the SEV-SNP combined
	// attestation, self-verify (loader PCR 8 + producer + verifier agree), then hold.
	if os.Getenv("SNP_ATTEST_DUMP") == "1" {
		dumpSEVSNPAttestation(logger)
		return
	}

	config := LoadTEEKConfig()

	// Armed before any fatal path can be reached; disarmed once serving.
	boot := shared.NewBootGuard(logger, shared.BootReadyDeadline)

	if config.RouterMode() {
		if err := startRouterMode(context.Background(), config, logger, boot); err != nil {
			shared.FatalBootReset(logger, err)
		}
		return
	}

	logger.Info("=== TEE_K Standalone Mode ===")
	if err := startStandaloneMode(config, logger, boot); err != nil {
		shared.FatalBootReset(logger, err)
	}
}

func startStandaloneMode(config *TEEKConfig, logger *shared.Logger, boot *shared.BootGuard) error {
	teek := NewTEEKWithConfig(config)
	teek.sessionManager.StartCleanupRoutine()

	// IMPORTANT: Establish TEE_T connection and complete OT precomputation BEFORE accepting clients
	// This ensures no client work is wasted if OT setup fails
	logger.Info("Establishing shared connection to TEE_T and completing OT precomputation...")
	teek.establishSharedTEETConnection()

	// Only start HTTP server AFTER OT pool is ready
	if !teek.isOTPoolReady() {
		return errors.New("OT pool not ready after establishSharedTEETConnection")
	}

	// Start periodic connection status logging (every minute)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if teek.connManager != nil {
				teek.connManager.LogConnectionStatus()
			}
		}
	}()

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teek),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logger.Info("OT precomputation complete, starting HTTP server", zap.Int("port", config.Port))
	runningServer, err := shared.StartHTTPServer(server, false)
	if err != nil {
		return err
	}

	// TEE_T URL and TLS configuration already set via NewTEEKWithConfig
	logger.Info("TEE_K ready to accept clients",
		zap.String("teet_url", config.TEETURL),
		zap.String("tls_version", config.ForceTLSVersion))
	boot.MarkReady()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	serveErr, shutdownErr := shared.WaitAndShutdownHTTPServer(runningServer, sigChan, 10*time.Second)

	logger.Info("Shutting down...")

	if shutdownErr != nil {
		logger.Error("Shutdown error", zap.Error(shutdownErr))
	}
	if serveErr != nil {
		return fmt.Errorf("HTTP server failed: %w", serveErr)
	}

	logger.Info("Shutdown complete")
	return nil
}

func setupRoutes(teek *TEEK) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", teek.handleWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_K Healthy")
	})
	return mux
}

// dumpSEVSNPAttestation is a hardware self-test (env SNP_ATTEST_DUMP=1): it
// builds the RA-TLS identity (which generates the combined SEV-SNP attestation),
// extracts the attestation extension + SPKI, verifies them with the same code
// the router uses, and logs the resulting app + base identities to the serial
// console. It holds afterward (PID 1 in the minimal image must not exit).
func dumpSEVSNPAttestation(logger *shared.Logger) {
	ctx := context.Background()
	ratls, err := shared.NewRATLSManager(ctx, "tee_k", nil)
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
	logger.Info("SNP-ATTEST-DUMP",
		zap.Int("ext_len", len(ext)),
		zap.String("app_hash_env", os.Getenv("SNP_APP_HASH")))
	app, base, verr := shared.VerifyCombinedSEVSNPAttestation(ext, spki)
	if verr != nil {
		logger.Critical("SNP-ATTEST-VERIFY FAILED", zap.Error(verr))
	} else {
		logger.Info("SNP-ATTEST-VERIFY OK", zap.String("app", app), zap.String("base", base))
	}
	select {}
}
