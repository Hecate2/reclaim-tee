//go:build !mobile

package shared

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

// EnclaveManager provides production-ready enclave functionality
type EnclaveManager struct {
	config        *EnclaveConfig
	connectionMgr *VSockConnectionManager
	certManager   *VSockLegoManager
	cache         *EnclaveCache
	kmsProvider   KMSProvider
	logger        *Logger

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
	Domain       string
	KMSKey       string
	ParentCID    uint32
	ServiceName  string
	HTTPPort     uint32
	HTTPSPort    uint32
	InternetPort uint32
	KMSPort      uint32
	Platform     *PlatformConfig
}

type EnclaveHandle struct {
	nsm              *nsm.Session
	key              *rsa.PrivateKey
	mu               sync.RWMutex
	attestationCache map[string]attestationCacheEntry
}

type attestationCacheEntry struct {
	doc       []byte
	createdAt time.Time
}

type AttestationOptions struct {
	Nonce, UserData []byte
	NoPublicKey     bool
	PublicKey       any
}

// VSockHTTPServer provides HTTP server functionality over VSock
type VSockHTTPServer struct {
	Handler      http.Handler
	Port         uint32
	ParentCID    uint32
	ServiceName  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	server   *http.Server
	listener net.Listener
	ready    chan bool
	mu       sync.RWMutex
}

// ListenAndServeVSock starts the VSock HTTP server
func (vs *VSockHTTPServer) ListenAndServeVSock(ctx context.Context) error {
	listener, err := vsock.Listen(vs.Port, nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", vs.Port, err)
	}
	vs.listener = listener

	vs.server = &http.Server{
		Handler:      vs.Handler,
		ReadTimeout:  vs.ReadTimeout,
		WriteTimeout: vs.WriteTimeout,
		IdleTimeout:  vs.IdleTimeout,
	}

	log.Printf("[%s] HTTP server listening on VSock port %d", vs.ServiceName, vs.Port)

	// Signal that the server is ready
	vs.mu.Lock()
	if vs.ready != nil {
		select {
		case vs.ready <- true:
		default:
		}
	}
	vs.mu.Unlock()

	return vs.server.Serve(listener)
}

// WaitUntilReady waits for the server to be ready to accept connections
func (vs *VSockHTTPServer) WaitUntilReady(ctx context.Context) error {
	vs.mu.Lock()
	vs.ready = make(chan bool, 1)
	readyChan := vs.ready
	vs.mu.Unlock()

	select {
	case <-readyChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown gracefully shuts down the VSock HTTP server
func (vs *VSockHTTPServer) Shutdown(ctx context.Context) error {
	if vs.server != nil {
		return vs.server.Shutdown(ctx)
	}
	return nil
}

// VSockHTTPSServer provides HTTPS server functionality over VSock
type VSockHTTPSServer struct {
	Handler      http.Handler
	TLSConfig    *tls.Config
	Port         uint32
	ParentCID    uint32
	ServiceName  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	server   *http.Server
	listener net.Listener
}

// ListenAndServeTLS starts the VSock HTTPS server
func (vs *VSockHTTPSServer) ListenAndServeTLS(ctx context.Context) error {
	listener, err := vsock.Listen(vs.Port, nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", vs.Port, err)
	}
	vs.listener = listener

	vs.server = &http.Server{
		Handler:           vs.Handler,
		TLSConfig:         vs.TLSConfig,
		ReadTimeout:       vs.ReadTimeout,
		WriteTimeout:      vs.WriteTimeout,
		IdleTimeout:       vs.IdleTimeout,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("[%s] HTTPS server listening on VSock port %d", vs.ServiceName, vs.Port)

	// Create TLS listener
	tlsListener := tls.NewListener(listener, vs.TLSConfig)
	return vs.server.Serve(tlsListener)
}

// Shutdown gracefully shuts down the VSock HTTPS server
func (vs *VSockHTTPSServer) Shutdown(ctx context.Context) error {
	if vs.server != nil {
		return vs.server.Shutdown(ctx)
	}
	return nil
}

// NewEnclaveManager creates a new enclave manager with production configuration
func NewEnclaveManager(ctx context.Context, config *EnclaveConfig, kmsKeyID string) (*EnclaveManager, error) {
	if config.Platform == nil {
		return nil, fmt.Errorf("platform config is required")
	}

	var connectionMgr *VSockConnectionManager

	if config.Platform.Platform == "nitro" {
		connectionMgr = NewVSockConnectionManager(&VSockConfig{
			ParentCID:    config.ParentCID,
			KMSPort:      config.KMSPort,
			InternetPort: config.InternetPort,
			KMSKeyID:     kmsKeyID,
		})

		err := connectionMgr.Start(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to start VSockConnectionManager: %v", err)
		}
	}

	var provider KMSProvider
	if config.Platform.KMSProvider == "google" {
		gcpProvider, err := NewGoogleKMSProvider(ctx,
			config.Platform.GoogleProjectID,
			config.Platform.GoogleLocation,
			config.Platform.GoogleKeyRing,
			config.Platform.GoogleKeyName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to init Google KMS provider: %v", err)
		}
		provider = gcpProvider
	} else {
		if connectionMgr == nil {
			return nil, fmt.Errorf("AWS KMS requires VSock connection manager")
		}
		provider = NewAWSKMSProvider(connectionMgr, config.ServiceName)
	}

	var cache *EnclaveCache
	if config.Platform.KMSProvider == "google" {
		cache = NewEnclaveCacheWithProvider(provider, nil, config.ServiceName, config.Platform)
	} else {
		cache = NewEnclaveCache(connectionMgr, kmsKeyID, config.ServiceName)
	}

	var httpClient *http.Client
	if config.Platform.Platform == "gcp" {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	} else {
		httpClient = createVSockHTTPClient(config.ParentCID, config.InternetPort)
	}

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

	certManager, err := NewVSockLegoManager(ctx, &LegoVSockConfig{
		Domain:       config.Domain,
		Email:        "alex@reclaimprotocol.org",
		CADirURL:     acmeURL,
		ServiceName:  config.ServiceName,
		HTTPPort:     config.HTTPPort,
		HTTPSPort:    config.HTTPSPort,
		ParentCID:    config.ParentCID,
		InternetPort: config.InternetPort,
		Cache:        cache,
		HTTPClient:   httpClient,
		Logger:       logger.Logger,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to init certificate manager: %v", err)
	}

	em := &EnclaveManager{
		config:        config,
		connectionMgr: connectionMgr,
		certManager:   certManager,
		cache:         cache,
		kmsProvider:   provider,
		logger:        logger,
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
	em.logger.Info("Platform check", zap.String("platform", em.config.Platform.Platform), zap.Bool("is_gcp", em.config.Platform.Platform == "gcp"))

	if em.config.Platform.Platform == "gcp" {
		return em.bootstrapCertificatesGCP(ctx)
	}

	httpServer := em.createVSockHTTPServer(em.certManager.CreateVSockHTTPHandler(nil), em.config.HTTPPort)

	serverErrChan := make(chan error, 1)
	go func() {
		em.logger.Info("Starting VSock HTTP server for ACME challenges", zap.Uint32("port", em.config.HTTPPort))

		if err := httpServer.ListenAndServeVSock(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			em.logger.Error("VSock HTTP server error", zap.Error(err))
			serverErrChan <- err
		}
	}()

	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()

	if err := httpServer.WaitUntilReady(readyCtx); err != nil {
		return fmt.Errorf("HTTP server failed to become ready: %v", err)
	}

	em.logger.Info("HTTP server is ready and listening", zap.Uint32("port", em.config.HTTPPort))

	// Additional wait to ensure server is fully ready to handle connections
	time.Sleep(500 * time.Millisecond)

	em.logger.Info("Starting ACME certificate request", zap.String("domain", em.config.Domain))
	em.logger.Info("ACME Client Directory URL", zap.String("url", em.certManager.config.CADirURL))

	// Now it's safe to call BootstrapCertificates which will trigger ACME operations
	err := em.certManager.BootstrapCertificates(ctx)
	if err != nil {
		// Shutdown HTTP server before returning error
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
		return err
	}

	// After successful ACME certificate request, try to get the certificate for validation
	certCtx, certCancel := context.WithTimeout(ctx, 30*time.Second)
	defer certCancel()

	// Channel to handle the GetCertificate call with timeout
	certResult := make(chan error, 1)
	go func() {
		em.logger.Info("Validating obtained certificate", zap.String("domain", em.config.Domain))
		_, certErr := em.certManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: em.config.Domain,
		})
		em.logger.Info("Certificate validation completed", zap.String("domain", em.config.Domain))
		certResult <- certErr
	}()

	// Wait for certificate validation to complete or timeout
	select {
	case err = <-certResult:
		if err != nil {
			em.logger.Error("Certificate validation failed", zap.Error(err))
		} else {
			em.logger.Info("Certificate validation succeeded!")

			// Verify it's now cached
			if cachedCert, cacheErr := em.cache.Get(ctx, em.config.Domain); cacheErr == nil {
				em.logger.Info("Certificate now cached - ready for TLS!", zap.Int("bytes", len(cachedCert)))
			} else {
				em.logger.Warn("Certificate not cached", zap.Error(cacheErr))
			}
		}
	case <-certCtx.Done():
		err = fmt.Errorf("certificate validation timed out after 30 seconds")
		em.logger.Error("Certificate validation TIMED OUT")
	}

	// Shutdown HTTP server
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	em.logger.Info("Shutting down ACME HTTP server")
	httpServer.Shutdown(shutdownCtx)

	// Check for server errors
	select {
	case serverErr := <-serverErrChan:
		if err == nil {
			err = fmt.Errorf("VSock HTTP server failed: %v", serverErr)
		}
	default:
		// No server error
	}

	if err != nil {
		return fmt.Errorf("failed to bootstrap certificate for %s: %v", em.config.Domain, err)
	}

	em.logger.Info("Successfully bootstrapped certificate for domain", zap.String("domain", em.config.Domain))
	return nil
}

func (em *EnclaveManager) bootstrapCertificatesGCP(ctx context.Context) error {
	em.logger.Info("Starting standard HTTP server for ACME", zap.Uint32("port", em.config.HTTPPort))

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", em.config.HTTPPort),
		Handler: em.certManager.CreateVSockHTTPHandler(nil),
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
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
		return err
	}

	_, certErr := em.certManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: em.config.Domain,
	})

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	httpServer.Shutdown(shutdownCtx)

	if certErr != nil {
		return fmt.Errorf("certificate validation failed: %v", certErr)
	}

	em.logger.Info("Successfully bootstrapped certificate for domain", zap.String("domain", em.config.Domain))
	return nil
}

// CreateHTTPSServer creates an HTTPS server with TLS configuration and debugging
func (em *EnclaveManager) CreateHTTPSServer(handler http.Handler) HTTPSServer {
	tlsConfig := &tls.Config{
		GetCertificate:         em.certManager.GetCertificate,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}

	if em.config.Platform.Platform == "gcp" {
		return em.createStandardHTTPSServer(handler, tlsConfig, em.config.HTTPSPort)
	}

	return em.createVSockHTTPSServer(handler, tlsConfig, em.config.HTTPSPort)
}

// createVSockHTTPServer creates an HTTP server that listens on VSock
func (em *EnclaveManager) createVSockHTTPServer(handler http.Handler, port uint32) *VSockHTTPServer {
	return &VSockHTTPServer{
		Handler:      handler,
		Port:         port,
		ParentCID:    em.config.ParentCID,
		ServiceName:  em.config.ServiceName,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// createVSockHTTPSServer creates an HTTPS server that listens on VSock
func (em *EnclaveManager) createVSockHTTPSServer(handler http.Handler, tlsConfig *tls.Config, port uint32) *VSockHTTPSServer {
	return &VSockHTTPSServer{
		Handler:      handler,
		TLSConfig:    tlsConfig,
		Port:         port,
		ParentCID:    em.config.ParentCID,
		ServiceName:  em.config.ServiceName,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// HTTPSServer is the common interface for both VSock and standard HTTPS servers
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

// createStandardHTTPSServer creates a standard HTTPS server for GCP
func (em *EnclaveManager) createStandardHTTPSServer(handler http.Handler, tlsConfig *tls.Config, port uint32) *StandardHTTPSServer {
	return &StandardHTTPSServer{
		Server: &http.Server{
			Addr:         fmt.Sprintf(":%d", port),
			Handler:      handler,
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
}

// GenerateAttestation creates an attestation document with optional user data
func (em *EnclaveManager) GenerateAttestation(ctx context.Context, userData []byte) ([]byte, error) {
	if em.config.Platform.Platform == "gcp" {
		return GenerateGCPAttestation(ctx, userData)
	}

	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get enclave handle: %v", err)
	}

	return handle.generateAttestation(userData)
}

// GetConnectionManager returns the VSock connection manager for KMS operations
func (em *EnclaveManager) GetConnectionManager() *VSockConnectionManager {
	return em.connectionMgr
}

// GetConfig returns the enclave configuration
func (em *EnclaveManager) GetConfig() *EnclaveConfig {
	return em.config
}

// Shutdown gracefully closes all connections and resources
func (em *EnclaveManager) Shutdown(ctx context.Context) error {
	log.Printf("[%s] Shutting down enclave manager", em.config.ServiceName)

	if em.connectionMgr != nil {
		em.connectionMgr.Shutdown(ctx)
	}

	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return err
	}
	handle.nsm.Close()

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

func (e *EnclaveHandle) Attest(args AttestationOptions) ([]byte, error) {
	var publicKey []byte
	var err error
	if args.PublicKey != nil && !args.NoPublicKey {
		if publicKey, err = x509.MarshalPKIXPublicKey(args.PublicKey); err != nil {
			return nil, err
		}
	} else if !args.NoPublicKey {
		if publicKey, err = x509.MarshalPKIXPublicKey(e.PublicKey()); err != nil {
			return nil, err
		}
	}

	res, err := e.nsm.Send(&request.Attestation{Nonce: args.Nonce, UserData: args.UserData, PublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("attestation response missing attestation document")
	}
	return res.Attestation.Document, nil
}

const attestationTTL = 4*time.Minute + 50*time.Second

func (e *EnclaveHandle) generateAttestation(userData []byte) ([]byte, error) {
	// Use "Reclaim Protocol" as default user data if none provided
	if userData == nil {
		userData = []byte("Reclaim Protocol")
	}

	// Generate cache key based on userData
	cacheKey := string(userData)

	// Check cache
	e.mu.RLock()
	entry, found := e.attestationCache[cacheKey]
	if found && time.Since(entry.createdAt) < attestationTTL {
		log.Printf("Using cached attestation for userData: %s", cacheKey)
		e.mu.RUnlock()
		return entry.doc, nil
	}
	e.mu.RUnlock()

	// Generate 32-byte random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	attestationDoc, err := e.Attest(AttestationOptions{
		Nonce:    []byte(hex.EncodeToString(nonce)),
		UserData: userData,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to request attestation: %v", err)
	}

	// Store in cache
	e.mu.Lock()
	e.attestationCache[cacheKey] = attestationCacheEntry{
		doc:       attestationDoc,
		createdAt: time.Now(),
	}
	e.mu.Unlock()

	return attestationDoc, nil
}

// PrivateKey returns the enclave's private key for cryptographic operations
func (e *EnclaveHandle) PrivateKey() *rsa.PrivateKey {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.key
}

// createVSockHTTPClient creates an HTTP client that uses VSock for internet connections
func createVSockHTTPClient(parentCID, internetPort uint32) *http.Client {
	manager := &VSockConnectionManager{
		parentCID:    parentCID,
		internetPort: internetPort,
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return manager.CreateInternetConnection(ctx, addr)
			},
			IdleConnTimeout: 30 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

// generateRSAKey generates a new RSA private key
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
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

	if em.config.Platform.Platform == "gcp" {
		// GCP: Standard HTTP server
		server := &http.Server{
			Addr:    fmt.Sprintf(":%d", em.config.HTTPPort),
			Handler: em.certManager.CreateVSockHTTPHandler(nil),
		}

		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[%s] Renewal HTTP server error: %v", em.config.ServiceName, err)
			}
		}()

		em.renewalHTTPServer = server
	} else {
		// AWS Nitro: VSock HTTP server
		vsockServer := em.createVSockHTTPServer(em.certManager.CreateVSockHTTPHandler(nil), em.config.HTTPPort)

		go func() {
			if err := vsockServer.ListenAndServeVSock(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[%s] Renewal VSock HTTP server error: %v", em.config.ServiceName, err)
			}
		}()

		// Wait for server to be ready
		readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := vsockServer.WaitUntilReady(readyCtx); err != nil {
			return fmt.Errorf("renewal HTTP server failed to start: %v", err)
		}

		em.renewalHTTPServer = vsockServer
	}

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
