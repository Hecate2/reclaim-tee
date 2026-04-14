//go:build !mobile

package shared

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"
)

// RenewalCallbacks provides hooks for certificate renewal operations
type RenewalCallbacks struct {
	// BeforeRenewal is called before starting renewal (e.g., to start HTTP server)
	BeforeRenewal func(ctx context.Context) error
	// AfterRenewal is called after renewal completes (e.g., to stop HTTP server)
	AfterRenewal func(ctx context.Context) error
}

// LegoManager integrates Lego ACME with enclave certificate management
type LegoManager struct {
	config           *LegoConfig
	client           *lego.Client
	cache            *EnclaveCache
	challengeServer  *ChallengeServer
	mu               sync.RWMutex
	certificates     map[string]*tls.Certificate
	storage          CertificateStorage
	renewalCallbacks *RenewalCallbacks
	logger           *zap.Logger
}

type LegoConfig struct {
	Domain      string        `json:"domain"`
	Email       string        `json:"email"`
	CADirURL    string        `json:"ca_dir_url"`
	ServiceName string        `json:"service_name"`
	HTTPPort    uint32        `json:"http_port"`
	HTTPSPort   uint32        `json:"https_port"`
	Cache       *EnclaveCache `json:"-"`
	HTTPClient  *http.Client  `json:"-"`
	Logger      *zap.Logger   `json:"-"`
}

// ChallengeServer handles HTTP-01 ACME challenges
type ChallengeServer struct {
	httpProvider *http01.ProviderServer
	challenges   map[string]string // token -> keyAuth
	mu           sync.RWMutex
}

// Supported ACME CAs
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ZeroSSLProduction     = "https://acme.zerossl.com/v2/DV90"
	BuyPassProduction     = "https://api.buypass.com/acme/directory"
	BuyPassStaging        = "https://api.buypass.com/acme-v02/directory"
)

// LegoUser implements the required User interface for Lego
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string {
	return u.Email
}

func (u *LegoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// serializeLegoUser serializes a LegoUser to bytes for caching
func serializeLegoUser(user *LegoUser) ([]byte, error) {
	// Marshal private key
	keyBytes, err := x509.MarshalECPrivateKey(user.key.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	// Create a simple serialization format: [keyLen(4)][key][regURI]
	var buf []byte

	// Add key length (4 bytes)
	keyLen := uint32(len(keyBytes))
	buf = append(buf, byte(keyLen>>24), byte(keyLen>>16), byte(keyLen>>8), byte(keyLen))

	// Add key bytes
	buf = append(buf, keyBytes...)

	// Add registration URI if available
	if user.Registration != nil && user.Registration.URI != "" {
		buf = append(buf, []byte(user.Registration.URI)...)
	}

	return buf, nil
}

// deserializeLegoUser deserializes a LegoUser from cached bytes
func deserializeLegoUser(data []byte) (*LegoUser, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("invalid cached account data: too short")
	}

	// Read key length
	keyLen := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if len(data) < int(4+keyLen) {
		return nil, fmt.Errorf("invalid cached account data: truncated key")
	}

	// Parse private key
	keyBytes := data[4 : 4+keyLen]
	privateKey, err := x509.ParseECPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Parse registration URI if present
	var reg *registration.Resource
	if len(data) > int(4+keyLen) {
		regURI := string(data[4+keyLen:])
		reg = &registration.Resource{
			URI: regURI,
		}
	}

	return &LegoUser{
		Email:        "alex@reclaimprotocol.org", // Email is static
		key:          privateKey,
		Registration: reg,
	}, nil
}

// isValidCachedCertificate checks if a cached certificate is valid and not expiring soon
// This is a standalone version of isValidCertificate for use before creating a manager
func isValidCachedCertificate(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// Check if certificate expires within 7 days
	timeUntilExpiry := time.Until(x509Cert.NotAfter)
	isValid := timeUntilExpiry > 7*24*time.Hour

	if isValid {
		log.Printf("Certificate validation: expires in %v (valid)", timeUntilExpiry.Round(time.Hour))
	} else {
		log.Printf("Certificate validation: expires in %v (needs renewal)", timeUntilExpiry.Round(time.Hour))
	}

	return isValid
}

// NewLegoManager creates a new Lego ACME certificate manager
func NewLegoManager(ctx context.Context, config *LegoConfig) (*LegoManager, error) {
	// Create logger if not provided
	logger := config.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	logger.Info("Initializing Lego certificate manager", zap.String("service", config.ServiceName))
	logger.Info("CA Directory", zap.String("service", config.ServiceName), zap.String("url", config.CADirURL))
	logger.Info("Domain", zap.String("service", config.ServiceName), zap.String("domain", config.Domain))

	// Check if valid certificate exists in cache
	var cachedCert *tls.Certificate
	logger.Info("Checking cache for existing certificate...", zap.String("service", config.ServiceName))
	if config.Cache != nil {
		// Try to load certificate from cache
		cacheKey := config.Domain
		cachedData, err := config.Cache.Get(ctx, cacheKey)
		if err == nil {
			logger.Info("Found cached certificate data ", zap.String("service", config.ServiceName), zap.Int("bytes", len(cachedData)))

			// Try to parse the cached certificate
			cert, err := tls.X509KeyPair(cachedData, cachedData)
			if err == nil {
				// Validate the certificate
				if isValidCachedCertificate(&cert) {
					logger.Info("Valid certificate found in cache", zap.String("service", config.ServiceName))
					cachedCert = &cert
				} else {
					logger.Info("Cached certificate expired or invalid, will request new one", zap.String("service", config.ServiceName))
				}
			} else {
				logger.Info("Failed to parse cached certificate", zap.String("service", config.ServiceName), zap.Error(err))
			}
		} else {
			logger.Info("No cached certificate found", zap.String("service", config.ServiceName), zap.Error(err))
		}
	}

	// Always initialize ACME client for renewals, even if we have a cached cert
	logger.Info("Initializing ACME client for certificate operations", zap.String("service", config.ServiceName))

	// Try to load existing ACME account from cache
	var user *LegoUser
	var legoClient *lego.Client

	accountCacheKey := config.Domain + "-acme-account"
	if config.Cache != nil {
		accountData, err := config.Cache.Get(ctx, accountCacheKey)
		if err == nil && len(accountData) > 0 {
			logger.Info("Found cached ACME account, loading...", zap.String("service", config.ServiceName), zap.Int("bytes", len(accountData)))
			user, err = deserializeLegoUser(accountData)
			if err == nil {
				// Create Lego configuration with cached user
				legoConfig := lego.NewConfig(user)
				legoConfig.CADirURL = config.CADirURL
				legoConfig.Certificate.KeyType = certcrypto.EC256
				if config.HTTPClient != nil {
					legoConfig.HTTPClient = config.HTTPClient
				}

				legoClient, err = lego.NewClient(legoConfig)
				if err == nil {
					logger.Info("Successfully using cached ACME account", zap.String("service", config.ServiceName))
				} else {
					logger.Info("Failed to create Lego client with cached account", zap.String("service", config.ServiceName), zap.Error(err))
				}
			} else {
				logger.Info("Failed to deserialize cached ACME account", zap.String("service", config.ServiceName), zap.Error(err))
			}
		} else {
			if err != nil {
				logger.Info("No cached ACME account found", zap.String("service", config.ServiceName), zap.Error(err))
			} else {
				logger.Info("No cached ACME account found (empty data)", zap.String("service", config.ServiceName))
			}
		}
	}

	// If no cached account or loading failed, create new one
	if legoClient == nil {
		logger.Info("Creating new ACME account", zap.String("service", config.ServiceName))

		// Create or load user private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %v", err)
		}

		user = &LegoUser{
			Email: config.Email,
			key:   privateKey,
		}

		// Create Lego configuration
		legoConfig := lego.NewConfig(user)
		legoConfig.CADirURL = config.CADirURL
		legoConfig.Certificate.KeyType = certcrypto.EC256

		// Use custom HTTP client if provided
		if config.HTTPClient != nil {
			legoConfig.HTTPClient = config.HTTPClient
			logger.Info("Using custom HTTP client for ACME requests", zap.String("service", config.ServiceName))
		}

		// Create Lego client
		legoClient, err = lego.NewClient(legoConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Lego client: %v", err)
		}

		// Register user account
		logger.Info("Registering ACME user account...", zap.String("service", config.ServiceName))
		reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("failed to register user: %v", err)
		}
		user.Registration = reg

		logger.Info("ACME account registered successfully", zap.String("service", config.ServiceName))

		// Cache the account for future use
		if config.Cache != nil {
			accountData, err := serializeLegoUser(user)
			if err == nil {
				err = config.Cache.Put(ctx, accountCacheKey, accountData)
				if err != nil {
					logger.Info("Warning: failed to cache ACME account", zap.String("service", config.ServiceName), zap.Error(err))
				} else {
					logger.Info("ACME account cached for future use", zap.String("service", config.ServiceName))
				}
			}
		}
	}

	manager := &LegoManager{
		config:       config,
		client:       legoClient,
		cache:        config.Cache,
		certificates: make(map[string]*tls.Certificate),
		storage:      NewEnclaveCacheStorage(config.Cache),
		logger:       logger,
	}

	// If we found a valid cached certificate, store it in memory
	if cachedCert != nil {
		logger.Info("Using cached certificate, ACME client ready for renewals", zap.String("service", config.ServiceName))
		manager.mu.Lock()
		manager.certificates[config.Domain] = cachedCert
		manager.mu.Unlock()
	}

	// Setup HTTP-01 challenge solver
	if err := manager.setupHTTPChallenge(); err != nil {
		return nil, fmt.Errorf("failed to setup HTTP challenge: %v", err)
	}

	return manager, nil
}

// setupHTTPChallenge configures the HTTP-01 ACME challenge provider
func (m *LegoManager) setupHTTPChallenge() error {
	log.Printf("[%s] Setting up HTTP-01 challenge provider", m.config.ServiceName)

	// Create a custom challenge server for ACME HTTP-01 challenges
	m.challengeServer = &ChallengeServer{
		challenges: make(map[string]string),
	}

	// Create a custom HTTP-01 provider that uses our challenge server
	httpProvider := &HTTP01Provider{
		challengeServer: m.challengeServer,
		serviceName:     m.config.ServiceName,
	}

	err := m.client.Challenge.SetHTTP01Provider(httpProvider)
	if err != nil {
		return fmt.Errorf("failed to set HTTP-01 provider: %v", err)
	}

	log.Printf("[%s] HTTP-01 challenge provider configured", m.config.ServiceName)
	return nil
}

// HTTP01Provider implements the HTTP-01 challenge provider interface
type HTTP01Provider struct {
	challengeServer *ChallengeServer
	serviceName     string
}

// Present implements the challenge.Provider interface
func (p *HTTP01Provider) Present(domain, token, keyAuth string) error {
	log.Printf("[%s] HTTP-01 challenge: Presenting token for domain %s", p.serviceName, domain)

	p.challengeServer.mu.Lock()
	p.challengeServer.challenges[token] = keyAuth
	p.challengeServer.mu.Unlock()

	log.Printf("[%s] Challenge token stored: %s", p.serviceName, token[:8]+"...")
	return nil
}

// CleanUp implements the challenge.Provider interface
func (p *HTTP01Provider) CleanUp(domain, token, keyAuth string) error {
	log.Printf("[%s] HTTP-01 challenge: Cleaning up token for domain %s", p.serviceName, domain)

	p.challengeServer.mu.Lock()
	delete(p.challengeServer.challenges, token)
	p.challengeServer.mu.Unlock()

	return nil
}

// CreateHTTPHandler creates an HTTP handler for ACME challenges
func (m *LegoManager) CreateHTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log all incoming requests for debugging
		log.Printf("[%s] HTTP request: %s %s from %s", m.config.ServiceName, r.Method, r.URL.Path, r.RemoteAddr)

		// Check if this is an ACME challenge request
		if after, ok := strings.CutPrefix(r.URL.Path, "/.well-known/acme-challenge/"); ok {
			token := after

			log.Printf("[%s] ACME challenge request for token: %s", m.config.ServiceName, token[:8]+"...")

			m.challengeServer.mu.RLock()
			keyAuth, exists := m.challengeServer.challenges[token]
			m.challengeServer.mu.RUnlock()

			if exists {
				log.Printf("[%s] ACME challenge: Serving keyAuth for token (length: %d)", m.config.ServiceName, len(keyAuth))
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(keyAuth))
				return
			}

			log.Printf("[%s] ACME challenge: Token not found in challenge store", m.config.ServiceName)
			log.Printf("[%s] Available tokens: %d", m.config.ServiceName, len(m.challengeServer.challenges))
			http.NotFound(w, r)
			return
		}

		// Fall back to default handler for non-ACME requests
		if fallback != nil {
			log.Printf("[%s] HTTP request: Falling back to default handler", m.config.ServiceName)
			fallback.ServeHTTP(w, r)
		} else {
			log.Printf("[%s] HTTP request: No fallback handler, returning 404", m.config.ServiceName)
			http.NotFound(w, r)
		}
	})
}

// BootstrapCertificates obtains certificates for the configured domain via ACME
func (m *LegoManager) BootstrapCertificates(ctx context.Context) error {
	log.Printf("[%s] Bootstrapping certificates for domain: %s", m.config.ServiceName, m.config.Domain)

	// Check if we already have a valid certificate loaded (from cache)
	if m.client == nil {
		log.Printf("[%s] Certificate manager has no ACME client - checking for cached certificate...", m.config.ServiceName)

		// Check if we have a valid cached certificate in memory
		m.mu.RLock()
		if cert, exists := m.certificates[m.config.Domain]; exists {
			if m.IsValidCertificate(cert) {
				m.mu.RUnlock()
				log.Printf("[%s] Valid cached certificate already loaded - skipping bootstrap", m.config.ServiceName)
				return nil
			}
		}
		m.mu.RUnlock()

		return fmt.Errorf("no ACME client available and no valid cached certificate found")
	}

	// Request new certificate
	request := certificate.ObtainRequest{
		Domains: []string{m.config.Domain},
		Bundle:  true,
	}

	log.Printf("[%s] Requesting certificate from %s", m.config.ServiceName, GetCAName(m.config.CADirURL))
	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// Store certificate in cache
	err = m.storeCertificate(ctx, m.config.Domain, certificates)
	if err != nil {
		log.Printf("[%s] Warning: failed to cache certificate: %v", m.config.ServiceName, err)
	}

	log.Printf("[%s] Certificate successfully obtained and cached", m.config.ServiceName)
	return nil
}

// GetCertificate returns a certificate for TLS configuration
func (m *LegoManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		domain = m.config.Domain
	}

	// Validate domain before attempting certificate operations
	if !m.isValidDomain(domain) {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	// First try in-memory cache
	m.mu.RLock()
	if cert, exists := m.certificates[domain]; exists {
		if m.IsValidCertificate(cert) {
			m.mu.RUnlock()
			return cert, nil
		}
	}
	m.mu.RUnlock()

	// Then try persistent cache via storage
	cert, err := m.storage.RetrieveCertificate(domain)
	if err == nil && m.IsValidCertificate(cert) {
		m.mu.Lock()
		m.certificates[domain] = cert
		m.mu.Unlock()
		return cert, nil
	}

	// No valid certificate found - attempt renewal
	log.Printf("[%s] No valid certificate found for %s, attempting renewal", m.config.ServiceName, domain)

	if m.client == nil {
		return nil, fmt.Errorf("no ACME client available for certificate renewal")
	}

	// Start HTTP server for ACME challenge if callbacks are configured
	if m.renewalCallbacks != nil && m.renewalCallbacks.BeforeRenewal != nil {
		log.Printf("[%s] Starting HTTP server for certificate renewal", m.config.ServiceName)
		if err := m.renewalCallbacks.BeforeRenewal(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to start HTTP server for renewal: %v", err)
		}
		defer func() {
			if m.renewalCallbacks.AfterRenewal != nil {
				log.Printf("[%s] Stopping HTTP server after certificate renewal", m.config.ServiceName)
				m.renewalCallbacks.AfterRenewal(context.Background())
			}
		}()
	}

	// Request new certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %v", err)
	}

	// Store in persistent storage
	err = m.storeCertificate(context.Background(), domain, certificates)
	if err != nil {
		log.Printf("[%s] Warning: failed to cache renewed certificate: %v", m.config.ServiceName, err)
	}

	// Parse and store in memory
	certPEM := certificates.Certificate
	keyPEM := certificates.PrivateKey
	newCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %v", err)
	}

	m.mu.Lock()
	m.certificates[domain] = &newCert
	m.mu.Unlock()

	log.Printf("[%s] Successfully renewed certificate for %s", m.config.ServiceName, domain)
	return &newCert, nil
}

// isValidDomain validates that a domain is acceptable for certificate issuance
func (m *LegoManager) isValidDomain(domain string) bool {
	// Reject empty domains
	if domain == "" {
		return false
	}

	// Reject IP addresses (both IPv4 and IPv6)
	if net.ParseIP(domain) != nil {
		log.Printf("[%s] Rejecting IP address as domain: %s", m.config.ServiceName, domain)
		return false
	}

	// Only allow the configured domain or its subdomains
	configDomain := m.config.Domain
	if domain != configDomain && !strings.HasSuffix(domain, "."+configDomain) {
		log.Printf("[%s] Rejecting unauthorized domain: %s (expected %s or subdomain)", m.config.ServiceName, domain, configDomain)
		return false
	}

	// Basic domain format validation
	if len(domain) > 253 {
		log.Printf("[%s] Rejecting domain: too long (%d chars)", m.config.ServiceName, len(domain))
		return false
	}

	// Check for invalid characters
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			log.Printf("[%s] Rejecting domain: invalid character '%c' in %s", m.config.ServiceName, c, domain)
			return false
		}
	}

	return true
}

// CreateTLSConfig creates a TLS configuration with certificate management
func (m *LegoManager) CreateTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13, // Allow both TLS 1.2 and 1.3
	}
}

// SetRenewalCallbacks sets the callbacks for certificate renewal operations
func (m *LegoManager) SetRenewalCallbacks(callbacks *RenewalCallbacks) {
	m.renewalCallbacks = callbacks
}

// StartCertificateRenewalChecker starts a background goroutine that periodically checks
// for certificate expiration and renews certificates proactively
func (m *LegoManager) StartCertificateRenewalChecker(ctx context.Context) {
	go func() {
		// Check every 12 hours
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		// Also do an initial check after 1 minute
		initialCheck := time.NewTimer(1 * time.Minute)
		defer initialCheck.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("[%s] Certificate renewal checker stopped", m.config.ServiceName)
				return

			case <-initialCheck.C:
				log.Printf("[%s] Running initial certificate expiration check", m.config.ServiceName)
				m.checkAndRenewCertificate(ctx)

			case <-ticker.C:
				log.Printf("[%s] Running periodic certificate expiration check", m.config.ServiceName)
				m.checkAndRenewCertificate(ctx)
			}
		}
	}()

	log.Printf("[%s] Started certificate renewal checker (checks every 12 hours)", m.config.ServiceName)
}

// checkAndRenewCertificate checks if the certificate needs renewal and renews it if necessary
func (m *LegoManager) checkAndRenewCertificate(ctx context.Context) {
	domain := m.config.Domain

	m.mu.RLock()
	cert, exists := m.certificates[domain]
	m.mu.RUnlock()

	if !exists {
		// Try to load from persistent storage
		var err error
		cert, err = m.storage.RetrieveCertificate(domain)
		if err != nil {
			log.Printf("[%s] No certificate found for renewal check: %v", m.config.ServiceName, err)
			return
		}
	}

	// Check if certificate needs renewal (renew if less than 30 days remaining)
	needsRenewal, daysRemaining := m.needsRenewal(cert)
	if !needsRenewal {
		log.Printf("[%s] Certificate for %s is valid (%.1f days remaining)", m.config.ServiceName, domain, daysRemaining)
		return
	}

	log.Printf("[%s] Certificate for %s expires soon (%.1f days remaining), initiating renewal", m.config.ServiceName, domain, daysRemaining)

	// Attempt renewal
	if m.client == nil {
		log.Printf("[%s] No ACME client available, cannot renew certificate", m.config.ServiceName)
		return
	}

	// Call before-renewal callback (e.g., start HTTP server for ACME challenge)
	if m.renewalCallbacks != nil && m.renewalCallbacks.BeforeRenewal != nil {
		log.Printf("[%s] Calling before-renewal callback", m.config.ServiceName)
		if err := m.renewalCallbacks.BeforeRenewal(ctx); err != nil {
			log.Printf("[%s] Before-renewal callback failed: %v", m.config.ServiceName, err)
			return
		}
	}

	// Ensure after-renewal callback is called even if renewal fails
	defer func() {
		if m.renewalCallbacks != nil && m.renewalCallbacks.AfterRenewal != nil {
			log.Printf("[%s] Calling after-renewal callback", m.config.ServiceName)
			if err := m.renewalCallbacks.AfterRenewal(ctx); err != nil {
				log.Printf("[%s] After-renewal callback failed: %v", m.config.ServiceName, err)
			}
		}
	}()

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		log.Printf("[%s] Failed to renew certificate for %s: %v", m.config.ServiceName, domain, err)
		return
	}

	// Store the renewed certificate
	err = m.storeCertificate(ctx, domain, certificates)
	if err != nil {
		log.Printf("[%s] Warning: failed to cache renewed certificate: %v", m.config.ServiceName, err)
	}

	// Parse and store in memory
	certPEM := certificates.Certificate
	keyPEM := certificates.PrivateKey
	newCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("[%s] Failed to parse renewed certificate: %v", m.config.ServiceName, err)
		return
	}

	m.mu.Lock()
	m.certificates[domain] = &newCert
	m.mu.Unlock()

	log.Printf("[%s] Successfully renewed certificate for %s", m.config.ServiceName, domain)
}

// needsRenewal checks if a certificate needs renewal (renew if <30 days remaining)
func (m *LegoManager) needsRenewal(cert *tls.Certificate) (bool, float64) {
	if cert == nil || len(cert.Certificate) == 0 {
		return true, 0
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true, 0
	}

	now := time.Now()
	daysRemaining := parsed.NotAfter.Sub(now).Hours() / 24

	// Renew if less than 30 days remaining
	return daysRemaining < 30, daysRemaining
}

// getCachedCertificate retrieves a certificate from cache
// Deprecated: kept for compatibility (no-op)
func (m *LegoManager) getCachedCertificate(ctx context.Context, domain string) (*tls.Certificate, error) {
	return m.storage.RetrieveCertificate(domain)
}

// storeCertificate stores a certificate in cache
func (m *LegoManager) storeCertificate(ctx context.Context, domain string, certificates *certificate.Resource) error {
	// Combine certificate and private key like autocert does
	certPEM := certificates.Certificate
	keyPEM := certificates.PrivateKey
	// Store via configured storage
	parsed, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate for storage: %v", err)
	}
	return m.storage.StoreCertificate(domain, &parsed)
}

// IsValidCertificate checks if a certificate is valid and not expiring soon
func (m *LegoManager) IsValidCertificate(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// Check if certificate expires within 7 days
	timeUntilExpiry := time.Until(x509Cert.NotAfter)
	return timeUntilExpiry > 7*24*time.Hour
}

// GetCAName Helper function to get CA name from directory URL
func GetCAName(dirURL string) string {
	switch dirURL {
	case LetsEncryptProduction:
		return "Let's Encrypt Production"
	case LetsEncryptStaging:
		return "Let's Encrypt Staging"
	case ZeroSSLProduction:
		return "ZeroSSL Production"
	case BuyPassProduction:
		return "BuyPass Production"
	case BuyPassStaging:
		return "BuyPass Staging"
	default:
		return "Custom CA"
	}
}
