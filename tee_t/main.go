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

	// Router mode is the production path (multi-pair, RA-TLS, router-mediated).
	// Standalone mode remains for local dev only — no TLS, no attestation.
	if config.RouterMode() {
		startRouterMode(context.Background(), config, logger)
		return
	}

	logger.Info("Starting TEE_T in standalone mode")
	startStandaloneMode(config, logger)
}

func startStandaloneMode(config *TEETConfig, logger *shared.Logger) {
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
	mux.HandleFunc("/ws/control", teet.handleControlWebSocket)  // Control: attestation, OT, session lifecycle
	mux.HandleFunc("/ws/session", teet.handleSessionWebSocket)  // Per-session: all session data

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_T Healthy")
	})
	return mux
}
