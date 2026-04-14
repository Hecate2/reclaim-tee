//go:build !mobile

package shared

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// EnclaveManager provides production-ready enclave functionality for GCP
type EnclaveManager struct {
	config      *EnclaveConfig
	certManager *LegoManager
	cache       *EnclaveCache
	kmsProvider KMSProvider
	logger      *Logger

	// HTTP server for certificate renewal (started/stopped as needed)
	renewalHTTPServer interface {
		Shutdown(ctx context.Context) error
	}
	renewalHTTPServerMu sync.Mutex
}

type PlatformConfig struct {
	Platform         string
	KMSProvider      string
	GoogleProjectID  string
	GoogleLocation   string
	GoogleKeyRing    string
	GoogleKeyName    string
	ACMEDirectoryURL string
}

type EnclaveConfig struct {
	Domain      string
	ServiceName string
	HTTPPort    uint32
	HTTPSPort   uint32
	Platform    *PlatformConfig
}

// HTTPSServer is the interface for HTTPS servers
type HTTPSServer interface {
	ListenAndServeTLS(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// StandardHTTPSServer wraps standard http.Server with a compatible interface
type StandardHTTPSServer struct {
	*http.Server
}

// ListenAndServeTLS starts the standard HTTPS server
func (s *StandardHTTPSServer) ListenAndServeTLS(ctx context.Context) error {
	return s.Server.ListenAndServeTLS("", "")
}

// Shutdown gracefully shuts down the server
func (s *StandardHTTPSServer) Shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}

// NewEnclaveManager creates a new enclave manager with GCP configuration
func NewEnclaveManager(ctx context.Context, config *EnclaveConfig, kmsKeyID string) (*EnclaveManager, error) {
	if config.Platform == nil {
		return nil, fmt.Errorf("platform config is required")
	}

	// Initialize Google KMS provider
	gcpProvider, err := NewGoogleKMSProvider(ctx,
		config.Platform.GoogleProjectID,
		config.Platform.GoogleLocation,
		config.Platform.GoogleKeyRing,
		config.Platform.GoogleKeyName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init Google KMS provider: %v", err)
	}

	// Initialize cache with GCP Secret Manager
	cache := NewEnclaveCacheWithProvider(gcpProvider, nil, config.ServiceName, config.Platform)

	// Standard HTTP client for GCP
	httpClient := &http.Client{Timeout: 30 * time.Second}

	acmeURL := config.Platform.ACMEDirectoryURL
	if acmeURL == "" {
		acmeURL = LetsEncryptStaging
	}

	// Get service-specific logger
	var logger *Logger
	if config.ServiceName == "tee_k" {
		logger = GetTEEKLogger()
	} else if config.ServiceName == "tee_t" {
		logger = GetTEETLogger()
	} else {
		logger = GetTEEKLogger() // Default fallback
	}

	certManager, err := NewLegoManager(ctx, &LegoConfig{
		Domain:      config.Domain,
		Email:       "alex@reclaimprotocol.org",
		CADirURL:    acmeURL,
		ServiceName: config.ServiceName,
		HTTPPort:    config.HTTPPort,
		HTTPSPort:   config.HTTPSPort,
		Cache:       cache,
		HTTPClient:  httpClient,
		Logger:      logger.Logger,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to init certificate manager: %v", err)
	}

	em := &EnclaveManager{
		config:      config,
		certManager: certManager,
		cache:       cache,
		kmsProvider: gcpProvider,
		logger:      logger,
	}

	// Set renewal callbacks to start/stop HTTP server during renewal
	certManager.SetRenewalCallbacks(&RenewalCallbacks{
		BeforeRenewal: em.startHTTPServerForRenewal,
		AfterRenewal:  em.stopHTTPServerAfterRenewal,
	})

	// Start certificate renewal checker
	certManager.StartCertificateRenewalChecker(ctx)

	return em, nil
}

// BootstrapCertificates ensures certificates are available before starting HTTPS server
func (em *EnclaveManager) BootstrapCertificates(ctx context.Context) error {
	em.logger.Info("Bootstrapping certificates for domain", zap.String("domain", em.config.Domain))

	// Check if we already have a valid certificate WITHOUT triggering ACME operations
	// First check the certificate manager's in-memory cache
	em.certManager.mu.RLock()
	if cert, exists := em.certManager.certificates[em.config.Domain]; exists {
		if em.certManager.IsValidCertificate(cert) {
			em.certManager.mu.RUnlock()
			em.logger.Info("Found valid certificate in memory - skipping ACME process")
			return nil
		}
	}
	em.certManager.mu.RUnlock()

	// Then check the persistent cache directly (without triggering ACME)
	if em.cache != nil {
		cachedData, err := em.cache.Get(ctx, em.config.Domain)
		if err == nil {
			cert, err := tls.X509KeyPair(cachedData, cachedData)
			if err == nil && em.certManager.IsValidCertificate(&cert) {
				em.logger.Info("Found valid certificate in persistent cache - skipping ACME process")
				// Store in memory for future use
				em.certManager.mu.Lock()
				em.certManager.certificates[em.config.Domain] = &cert
				em.certManager.mu.Unlock()
				return nil
			}
		}
	}

	em.logger.Info("No valid certificate found - starting ACME challenge", zap.String("domain", em.config.Domain))

	// GCP: Standard HTTP server for ACME
	em.logger.Info("Starting standard HTTP server for ACME", zap.Uint32("port", em.config.HTTPPort))

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", em.config.HTTPPort),
		Handler: em.certManager.CreateHTTPHandler(nil),
	}

	serverErrChan := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	time.Sleep(500 * time.Millisecond)

	em.logger.Info("Starting ACME certificate request", zap.String("domain", em.config.Domain))
	err := em.certManager.BootstrapCertificates(ctx)
	if err != nil {
		em.logger.Info("ACME failed, stopping HTTP server")
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			em.logger.Error("Failed to shutdown HTTP server after ACME error", zap.Error(shutdownErr))
		}
		return err
	}

	_, certErr := em.certManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: em.config.Domain,
	})

	// Stop HTTP server after ACME challenge completes
	em.logger.Info("Stopping HTTP server after ACME challenge")
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
		em.logger.Error("Failed to shutdown HTTP server", zap.Error(shutdownErr))
	} else {
		em.logger.Info("HTTP server stopped successfully")
	}

	if certErr != nil {
		return fmt.Errorf("certificate validation failed: %v", certErr)
	}

	em.logger.Info("Successfully bootstrapped certificate for domain", zap.String("domain", em.config.Domain))
	return nil
}

// CreateHTTPSServer creates an HTTPS server with TLS configuration
func (em *EnclaveManager) CreateHTTPSServer(handler http.Handler) HTTPSServer {
	tlsConfig := &tls.Config{
		GetCertificate:         em.certManager.GetCertificate,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}

	return &StandardHTTPSServer{
		Server: &http.Server{
			Addr:         fmt.Sprintf(":%d", em.config.HTTPSPort),
			Handler:      handler,
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
}

// GenerateAttestation creates a GCP attestation document with optional user data
func (em *EnclaveManager) GenerateAttestation(ctx context.Context, userData []byte) ([]byte, error) {
	return GenerateGCPAttestation(ctx, userData)
}

// GetConfig returns the enclave configuration
func (em *EnclaveManager) GetConfig() *EnclaveConfig {
	return em.config
}

// GetCache returns the enclave cache for storing persistent data
func (em *EnclaveManager) GetCache() *EnclaveCache {
	return em.cache
}

// Shutdown gracefully closes all connections and resources
func (em *EnclaveManager) Shutdown(ctx context.Context) error {
	log.Printf("[%s] Shutting down enclave manager", em.config.ServiceName)
	return nil
}

func (em *EnclaveManager) GetCertificateRaw() ([]byte, error) {
	// Get current certificate from cache
	cert, err := em.certManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: em.config.Domain,
	})
	if err != nil {
		return nil, err
	}

	// Parse certificate and return raw bytes
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate available")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return x509Cert.Raw, nil
}

// startHTTPServerForRenewal starts a temporary HTTP server for ACME challenges during renewal
func (em *EnclaveManager) startHTTPServerForRenewal(ctx context.Context) error {
	em.renewalHTTPServerMu.Lock()
	defer em.renewalHTTPServerMu.Unlock()

	if em.renewalHTTPServer != nil {
		log.Printf("[%s] HTTP server already running for renewal", em.config.ServiceName)
		return nil
	}

	log.Printf("[%s] Starting temporary HTTP server on port %d for certificate renewal", em.config.ServiceName, em.config.HTTPPort)

	// GCP: Standard HTTP server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", em.config.HTTPPort),
		Handler: em.certManager.CreateHTTPHandler(nil),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[%s] Renewal HTTP server error: %v", em.config.ServiceName, err)
		}
	}()

	em.renewalHTTPServer = server

	// Wait for server to be ready to accept connections
	time.Sleep(500 * time.Millisecond)

	log.Printf("[%s] Temporary HTTP server started and ready for ACME challenges", em.config.ServiceName)
	return nil
}

// stopHTTPServerAfterRenewal stops the temporary HTTP server after renewal completes
func (em *EnclaveManager) stopHTTPServerAfterRenewal(ctx context.Context) error {
	em.renewalHTTPServerMu.Lock()
	defer em.renewalHTTPServerMu.Unlock()

	if em.renewalHTTPServer == nil {
		log.Printf("[%s] No HTTP server running to stop", em.config.ServiceName)
		return nil
	}

	log.Printf("[%s] Stopping temporary HTTP server after certificate renewal", em.config.ServiceName)

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := em.renewalHTTPServer.Shutdown(shutdownCtx)
	if err != nil {
		log.Printf("[%s] Error shutting down renewal HTTP server: %v", em.config.ServiceName, err)
	} else {
		log.Printf("[%s] Temporary HTTP server stopped successfully", em.config.ServiceName)
	}

	em.renewalHTTPServer = nil
	return err
}
