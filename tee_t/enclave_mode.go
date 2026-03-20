package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
)

func startEnclaveMode(config *TEETConfig, logger *shared.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger.Info("Starting enclave mode", zap.String("kms_provider", config.KMSProvider))

	platformConfig := &shared.PlatformConfig{
		Platform:         "gcp",
		KMSProvider:      config.KMSProvider,
		GoogleProjectID:  config.GoogleProjectID,
		GoogleLocation:   config.GoogleLocation,
		GoogleKeyRing:    config.GoogleKeyRing,
		GoogleKeyName:    config.GoogleKeyName,
		ACMEDirectoryURL: shared.GetEnvOrDefault("ACME_DIRECTORY_URL", ""),
	}

	enclaveConfig := &shared.EnclaveConfig{
		Domain:      config.Domain,
		ServiceName: "tee_t",
		HTTPPort:    uint32(config.HTTPPort),
		HTTPSPort:   uint32(config.HTTPSPort),
		Platform:    platformConfig,
	}

	enclaveManager, err := shared.NewEnclaveManager(ctx, enclaveConfig, config.KMSKey)
	if err != nil {
		logger.Critical("Failed to initialize enclave manager", zap.Error(err))
		// Return gracefully instead of crashing enclave
		return
	}
	defer enclaveManager.Shutdown(ctx)

	// Phase 1: Bootstrap certificates via ACME
	if err = enclaveManager.BootstrapCertificates(ctx); err != nil {
		logger.Critical("Certificate bootstrap failed", zap.Error(err))
		// Return gracefully instead of crashing enclave
		return
	}

	// Phase 2: Start production HTTPS server with WebSocket support
	teet := NewTEETWithEnclaveManagerAndLogger(int(enclaveConfig.HTTPSPort), enclaveManager, logger)

	// Start background attestation refresh for performance optimization
	go teet.startAttestationRefresh(ctx)

	// Create HTTPS server with integrated WebSocket handler
	httpsHandler := setupEnclaveRoutes(teet, enclaveManager, logger)
	httpsServer := enclaveManager.CreateHTTPSServer(httpsHandler)

	// Start HTTPS server in background
	go func() {
		logger.Info("Starting production HTTPS server", zap.Int("port", int(enclaveConfig.HTTPSPort)))
		if err := httpsServer.ListenAndServeTLS(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("HTTPS server failed", zap.Error(err))
			// Signal main goroutine to shut down gracefully
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Enclave mode started successfully",
		zap.String("domain", config.Domain),
		zap.Int("https_port", int(enclaveConfig.HTTPSPort)))

	<-sigChan
	logger.Info("Shutting down enclave mode...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTPS server shutdown error", zap.Error(err))
	}

	cancel() // Cancel main context
	logger.Info("Enclave mode shutdown complete")
}

func setupEnclaveRoutes(teet *TEET, enclaveManager *shared.EnclaveManager, logger *shared.Logger) http.Handler {
	mux := http.NewServeMux()

	// WebSocket upgrade endpoint for clients
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade HTTPS connection to WebSocket
		teet.handleClientWebSocket(w, r)
	})

	// WebSocket endpoint for TEE_K connections
	mux.HandleFunc("/teek", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade HTTPS connection to WebSocket for TEE_K
		teet.handleTEEKWebSocket(w, r)
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy","mode":"enclave"}`)
	})

	// Attestation endpoint with ECDSA public key in user data
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Attestation request received")

		// Get the ECDSA public key from the TEET signing key pair
		if teet.signingKeyPair == nil {
			logger.Error("No signing key pair available for attestation")
			http.Error(w, "No signing key pair available", http.StatusInternalServerError)
			return
		}

		// Use cached attestation instead of generating new one every time
		attestationReport, err := teet.getCachedAttestation("http_attest")
		if err != nil {
			logger.Error("Failed to get cached attestation", zap.Error(err))
			http.Error(w, "Failed to get attestation", http.StatusInternalServerError)
			return
		}

		// Encode attestation document as base64
		attestationBase64 := base64.StdEncoding.EncodeToString(attestationReport.Report)
		logger.Debug("Returning cached attestation")

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave-Service", "tee_t")
		w.Header().Set("X-Attestation-Type", attestationReport.Type)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(attestationBase64))
	})

	// Default handler for the root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Received HTTP request", zap.String("path", r.URL.Path))

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave-Service", "tee_t")
		w.Header().Set("X-Enclave-Mode", "production")

		// Create response content for enclave service info
		response := fmt.Sprintf("TEE_T Enclave Service\nMode: Production\nDomain: %s\nStatus: Ready\n",
			enclaveManager.GetConfig().Domain)
		w.Write([]byte(response))
	})

	return mux
}
