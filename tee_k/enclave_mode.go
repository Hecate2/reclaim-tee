package main

import (
	"context"
	"encoding/base64"
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

func startEnclaveMode(config *TEEKConfig, logger *shared.Logger) {
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

	// Initialize enclave manager with production configuration
	enclaveConfig := &shared.EnclaveConfig{
		Domain:      config.Domain,
		ServiceName: "tee_k",
		HTTPPort:    80,  // For ACME challenges (standard HTTP port for GCP)
		HTTPSPort:   443, // For production HTTPS (standard HTTPS port for GCP)
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
	if err := enclaveManager.BootstrapCertificates(ctx); err != nil {
		logger.Critical("Certificate bootstrap failed", zap.Error(err))
		// Return gracefully instead of crashing enclave
		return
	}

	// Phase 2: Start production HTTPS server with WebSocket support
	teek := NewTEEKWithEnclaveManager(int(enclaveConfig.HTTPSPort), enclaveManager)

	// Start background attestation refresh for performance optimization
	go teek.startAttestationRefresh(ctx)

	// Apply TLS configuration
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)

	// Create HTTPS server with integrated WebSocket handler
	httpsHandler := setupEnclaveRoutes(teek, enclaveManager, logger)
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

	// Set TEE_T URL for per-session connections
	teek.SetTEETURL(config.TEETURL)
	logger.Info("Enclave mode configuration", zap.String("teet_url", config.TEETURL))

	// Establish shared persistent connection to TEE_T after server is ready
	logger.Info("HTTPS server started, establishing shared connection to TEE_T")
	teek.establishSharedTEETConnection()

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

func setupEnclaveRoutes(teek *TEEK, enclaveManager *shared.EnclaveManager, logger *shared.Logger) http.Handler {
	mux := http.NewServeMux()

	// WebSocket upgrade endpoint (main TEE protocol)
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade HTTPS connection to WebSocket
		teek.handleWebSocket(w, r)
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

		// Get the ECDSA public key from the TEEK signing key pair
		if teek.signingKeyPair == nil {
			logger.Error("No signing key pair available for attestation")
			http.Error(w, "No signing key pair available", http.StatusInternalServerError)
			return
		}

		ethAddress := teek.signingKeyPair.GetEthAddress()

		// Create user data containing the ETH address
		userData := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())
		logger.Debug("Including ETH address in attestation")

		attestationDoc, err := enclaveManager.GenerateAttestation(r.Context(), []byte(userData))
		if err != nil {
			logger.Error("Attestation generation failed", zap.Error(err))
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		// Encode attestation document as base64
		attestationBase64 := base64.StdEncoding.EncodeToString(attestationDoc)
		logger.Debug("Generated attestation document")

		// Attestation type is always GCP
		attestationType := "gcp"

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave-Service", "tee_k")
		w.Header().Set("X-Attestation-Type", attestationType)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(attestationBase64))
	})

	// Default handler for the root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Received HTTP request", zap.String("path", r.URL.Path))

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave-Service", "tee_k")
		w.Header().Set("X-Enclave-Mode", "production")

		fmt.Fprintf(w, "TEE_K Enclave Service\nMode: Production\nDomain: %s\nStatus: Ready\n",
			enclaveManager.GetConfig().Domain)
	})

	return mux
}
