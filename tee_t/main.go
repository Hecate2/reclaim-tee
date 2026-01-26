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

	if config.EnclaveMode {
		logger.Info("Starting TEE_T in enclave mode")
		startEnclaveMode(config, logger)
	} else {
		logger.Info("Starting TEE_T in standalone mode")
		startStandaloneMode(config, logger)
	}
}

func startStandaloneMode(config *TEETConfig, logger *shared.Logger) {
	teet := NewTEETWithLogger(config.Port, logger)

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
	mux.HandleFunc("/teek", teet.handleTEEKWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_T Healthy")
	})
	return mux
}
