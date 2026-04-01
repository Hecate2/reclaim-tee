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

	// Start background root CA updater (fetches fresh certs from curl.se daily)
	StartRootCAUpdater(logger)

	enclaveMode := shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true"

	var config *TEEKConfig
	if enclaveMode {
		logger.Info("=== TEE_K Enclave Mode ===")

		// GCP: Configuration comes from environment variables
		config = LoadTEEKConfig()
		logger.Info("Loaded config from environment",
			zap.String("domain", config.Domain))

		startEnclaveMode(config, logger)
	} else {
		logger.Info("=== TEE_K Standalone Mode ===")
		config = LoadTEEKConfig()
		startStandaloneMode(config, logger)
	}
}

func startStandaloneMode(config *TEEKConfig, logger *shared.Logger) {
	teek := NewTEEKWithConfig(config)
	teek.sessionManager.StartCleanupRoutine()

	// IMPORTANT: Establish TEE_T connection and complete OT precomputation BEFORE accepting clients
	// This ensures no client work is wasted if OT setup fails
	logger.Info("Establishing shared connection to TEE_T and completing OT precomputation...")
	teek.establishSharedTEETConnection()

	// Only start HTTP server AFTER OT pool is ready
	if !teek.isOTPoolReady() {
		logger.Critical("OT pool not ready after establishSharedTEETConnection - this should not happen")
		return
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

	// Start server in goroutine - OT is ready, safe to accept clients
	go func() {
		logger.Info("OT precomputation complete, starting HTTP server", zap.Int("port", config.Port))
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

	// TEE_T URL and TLS configuration already set via NewTEEKWithConfig
	logger.Info("TEE_K ready to accept clients",
		zap.String("teet_url", config.TEETURL),
		zap.String("tls_version", config.ForceTLSVersion))

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

func setupRoutes(teek *TEEK) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", teek.handleWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_K Healthy")
	})
	return mux
}
