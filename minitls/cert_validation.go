package minitls

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.mozilla.org/pkcs7"
	"go.uber.org/zap"
)

// verifyCertificateChain performs comprehensive certificate validation including:
// - Chain signature validation
// - System root CA validation
// - Hostname verification
// - Certificate expiry checks
func (c *Client) verifyCertificateChain(certs []*x509.Certificate, serverName string, config *Config) error {
	return c.verifyCertificateChainWithDepth(certs, serverName, config, 0)
}

// verifyCertificateChainWithDepth is an internal version with recursion depth tracking
// to prevent infinite recursion via AIA fetching
func (c *Client) verifyCertificateChainWithDepth(certs []*x509.Certificate, serverName string, config *Config, aiaDepth int) error {
	// Protection: Prevent infinite recursion via AIA fetch
	// Set to 2 to allow one retry after queue-based AIA fetching
	const maxAIADepth = 2
	if aiaDepth > maxAIADepth {
		c.logger.Warn("Maximum AIA fetch depth reached, preventing recursion")
		// Continue with validation without further AIA fetches
	}
	if len(certs) == 0 {
		return &CertificateError{
			Type:    CertErrorInvalidChain,
			Message: "no certificates provided",
		}
	}

	leafCert := certs[0]

	// Verify key usage - server certificate must be valid for server authentication
	if len(leafCert.ExtKeyUsage) > 0 {
		validUsage := false
		for _, usage := range leafCert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				validUsage = true
				break
			}
		}
		if !validUsage {
			return &CertificateError{
				Type:    CertErrorVerification,
				Message: "server certificate not valid for server authentication",
			}
		}
	}

	// Verify key usage flags — digitalSignature is required when KeyUsage
	// is present. Matches Chrome/Firefox/NSS/JSSE/OpenSSL-TLS behavior;
	// CA/B Forum BR §7.1.2.7.6 mandates it on public WebPKI subscriber
	// certs (100% of top sites checked). Cert lacking the extension
	// entirely (KeyUsage == 0) still passes — that's the legacy/IoT escape.
	if leafCert.KeyUsage != 0 && leafCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &CertificateError{
			Type:    CertErrorVerification,
			Message: fmt.Sprintf("server certificate KeyUsage 0x%x lacks digitalSignature", leafCert.KeyUsage),
		}
	}

	// Build intermediate certificate pool
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
		c.logger.Debug("Added to intermediate pool",
			zap.Int("index", i),
			zap.String("subject", certs[i].Subject.String()),
			zap.String("issuer", certs[i].Issuer.String()))
	}

	// Get root CA pool (custom if set, otherwise system)
	roots := shared.GetRootCAPool()
	isCustomPool := shared.IsCustomRootCAPool()
	c.logger.Debug("Using root CA pool",
		zap.Bool("is_custom_pool", isCustomPool),
		zap.Int("intermediate_count", len(certs)-1))

	// Verify certificate chain with hostname
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName, // This performs RFC 6125 hostname verification
	}

	chains, err := leafCert.Verify(opts)
	if err != nil {
		// Debug: Log verification failure details
		c.logger.Debug("Certificate verification failed",
			zap.String("leaf_subject", leafCert.Subject.String()),
			zap.String("leaf_issuer", leafCert.Issuer.String()),
			zap.Int("chain_length", len(certs)),
			zap.Int("aia_depth", aiaDepth),
			zap.Error(err))

		// Log intermediate chain details for debugging
		for i, cert := range certs {
			c.logger.Debug("Chain certificate",
				zap.Int("index", i),
				zap.String("subject", cert.Subject.String()),
				zap.String("issuer", cert.Issuer.String()),
				zap.Bool("is_ca", cert.IsCA))
		}

		// Only try to fetch missing intermediates if:
		// 1. Config is not nil and has CertFetcher
		// 2. We haven't exceeded AIA fetch depth limit
		// 3. Certificate has AIA URLs
		// 4. Error is about unknown authority (missing intermediate)
		if config == nil || config.CertFetcher == nil {
			// No cert fetcher configured, return error immediately
			c.logger.Debug("No cert fetcher configured, cannot attempt AIA fetch")
			return &CertificateError{
				Type:    CertErrorVerification,
				Message: fmt.Sprintf("certificate verification failed for %s", serverName),
				Err:     err,
			}
		}

		if aiaDepth < maxAIADepth && len(leafCert.IssuingCertificateURL) > 0 {
			// Check if error is due to unknown authority (missing intermediate)
			// Use errors.As to handle wrapped errors
			if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
				c.logger.Info("Certificate chain incomplete, fetching missing intermediates",
					zap.String("cert", leafCert.Subject.String()),
					zap.Int("aia_depth", aiaDepth),
					zap.Strings("aia_urls", leafCert.IssuingCertificateURL))
				completedChain, fetchErr := c.fetchMissingIntermediates(certs, config.CertFetcher)
				if fetchErr == nil && len(completedChain) > len(certs) {
					// Retry validation with completed chain (increment depth to prevent infinite recursion)
					c.logger.Info("Retrying validation with fetched intermediates",
						zap.Int("chain_length", len(completedChain)))
					return c.verifyCertificateChainWithDepth(completedChain, serverName, config, aiaDepth+1)
				}
				c.logger.Warn("Failed to complete certificate chain via AIA", zap.Error(fetchErr))
			} else {
				c.logger.Debug("Verification error is not UnknownAuthorityError, skipping AIA fetch",
					zap.String("error_type", fmt.Sprintf("%T", err)))
			}
		} else {
			c.logger.Debug("AIA fetch not attempted",
				zap.Int("aia_depth", aiaDepth),
				zap.Int("max_aia_depth", maxAIADepth),
				zap.Int("aia_url_count", len(leafCert.IssuingCertificateURL)))
		}

		return &CertificateError{
			Type:    CertErrorVerification,
			Message: fmt.Sprintf("certificate verification failed for %s", serverName),
			Err:     err,
		}
	}

	if len(chains) == 0 {
		return &CertificateError{
			Type:    CertErrorInvalidChain,
			Message: "no valid certificate chains found",
		}
	}

	return nil
}

// parseCertificateData attempts to parse certificate data in multiple formats:
// - DER (binary ASN.1) - most common for AIA per RFC 5280
// - PEM (base64-encoded DER with -----BEGIN CERTIFICATE----- header)
// - PKCS7/P7C (certificate bundle format, e.g., validation.identrust.com)
// Returns a slice of certificates (may contain multiple for PKCS7 bundles)
func parseCertificateData(data []byte) ([]*x509.Certificate, error) {
	// Try DER format first (most common for AIA - RFC 5280)
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return []*x509.Certificate{cert}, nil
	}

	// Try PEM format (some CAs use this)
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err == nil {
			return []*x509.Certificate{cert}, nil
		}
	}

	// Try PKCS7 format (used by some CAs like IdenTrust)
	p7, err := pkcs7.Parse(data)
	if err == nil && len(p7.Certificates) > 0 {
		// PKCS7 bundles may contain multiple certificates
		// We want intermediate CAs, NOT root CAs (which should be in system trust store)
		// Strategy: Return ALL non-self-signed certificates, error if all are self-signed
		var intermediates []*x509.Certificate
		for _, cert := range p7.Certificates {
			// Check if it's self-signed (root CA)
			if cert.Subject.String() != cert.Issuer.String() {
				// Not self-signed, this is an intermediate we want
				intermediates = append(intermediates, cert)
			}
		}

		if len(intermediates) == 0 {
			// All certificates are self-signed (roots) - this is invalid for AIA
			return nil, fmt.Errorf("PKCS7 bundle contains only self-signed certificates (roots), expected intermediates")
		}

		return intermediates, nil
	}

	return nil, fmt.Errorf("unable to parse certificate (tried DER, PEM, and PKCS7 formats)")
}

// isValidAIAURL validates that an AIA URL uses an allowed scheme
// Protection against file://, javascript:, data:, etc. schemes
func isValidAIAURL(urlStr string) bool {
	if len(urlStr) > 2048 {
		return false // Unreasonably long URL
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Only allow http and https schemes
	return u.Scheme == "http" || u.Scheme == "https"
}

// fetchMissingIntermediates attempts to download missing intermediate certificates
// using the Authority Information Access (AIA) extension
// This function fetches from ALL certs in the chain that have AIA URLs to handle
// cases where intermediate certificates also need their issuers fetched.
// Protection against attacks:
// - Infinite recursion: prevented by maxChainLength limit
// - Circular AIA references: prevented by fingerprint tracking
// - Chain depth attacks: prevented by maxChainLength limit
func (c *Client) fetchMissingIntermediates(certs []*x509.Certificate, fetcher CertificateFetcher) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return certs, fmt.Errorf("no certificates provided")
	}

	// Protection: Limit total chain length to prevent chain depth attacks
	const maxChainLength = 10
	if len(certs) >= maxChainLength {
		return certs, fmt.Errorf("certificate chain too long (max %d)", maxChainLength)
	}

	result := make([]*x509.Certificate, len(certs))
	copy(result, certs)

	// Protection: Track certificate fingerprints to detect circular references
	existingFingerprints := make(map[string]bool)
	for _, cert := range certs {
		fingerprint := fmt.Sprintf("%x", cert.SerialNumber)
		existingFingerprints[fingerprint] = true
	}

	// Queue of certificates to process AIA URLs from
	// Start with all certs in the chain, then add newly fetched ones
	toProcess := make([]*x509.Certificate, len(certs))
	copy(toProcess, certs)
	processIdx := 0

	// Process all certificates (including newly fetched ones)
	for processIdx < len(toProcess) && len(result) < maxChainLength {
		cert := toProcess[processIdx]
		processIdx++

		if len(cert.IssuingCertificateURL) == 0 {
			continue
		}
		c.logger.Debug("Checking AIA URLs for certificate",
			zap.Int("process_index", processIdx-1),
			zap.String("subject", cert.Subject.String()),
			zap.Strings("aia_urls", cert.IssuingCertificateURL))

		// Try each AIA URL until one succeeds
		for _, url := range cert.IssuingCertificateURL {
			// Protection: Only allow HTTP and HTTPS schemes
			if !isValidAIAURL(url) {
				c.logger.Warn("Invalid AIA URL scheme", zap.String("url", url))
				continue
			}
			c.logger.Info("Fetching intermediate cert(s)", zap.String("url", url))
			certData, err := fetcher.FetchCertificate(url)
			if err != nil {
				c.logger.Warn("Failed to fetch intermediate cert", zap.String("url", url), zap.Error(err))
				continue // Try next URL
			}

			// Parse certificate(s) (supports DER, PEM, and PKCS7 formats)
			// May return multiple certificates for PKCS7 bundles
			intermediates, err := parseCertificateData(certData)
			if err != nil {
				c.logger.Warn("Failed to parse intermediate cert", zap.String("url", url), zap.Error(err))
				continue // Try next URL
			}

			// Log fetched intermediate details
			for _, intermediate := range intermediates {
				c.logger.Debug("Fetched intermediate certificate",
					zap.String("subject", intermediate.Subject.String()),
					zap.String("issuer", intermediate.Issuer.String()),
					zap.Bool("is_ca", intermediate.IsCA),
					zap.Strings("issuer_aia", intermediate.IssuingCertificateURL))
			}

			// Verify all intermediates are actually CA certificates and not duplicates
			for _, intermediate := range intermediates {
				if !intermediate.IsCA {
					c.logger.Warn("Skipping non-CA certificate from bundle",
						zap.String("subject", intermediate.Subject.String()))
					continue
				}

				// SECURITY: Skip self-signed certificates (roots)
				// Roots must come from the trusted store, NOT from AIA fetching
				if intermediate.Subject.String() == intermediate.Issuer.String() {
					c.logger.Info("Skipping self-signed certificate (root CA) - must come from trusted store",
						zap.String("subject", intermediate.Subject.String()))
					continue
				}

				// Protection: Check for circular reference (certificate already in chain)
				fingerprint := fmt.Sprintf("%x", intermediate.SerialNumber)
				if existingFingerprints[fingerprint] {
					c.logger.Warn("Skipping duplicate certificate (circular reference protection)",
						zap.String("subject", intermediate.Subject.String()),
						zap.String("serial", fingerprint))
					continue
				}

				// Track this fingerprint for future duplicates
				existingFingerprints[fingerprint] = true

				// Add to result and queue for AIA processing
				result = append(result, intermediate)
				toProcess = append(toProcess, intermediate)

				c.logger.Info("Added intermediate to chain",
					zap.String("subject", intermediate.Subject.String()),
					zap.String("issuer", intermediate.Issuer.String()),
					zap.Int("total_chain_length", len(result)))
			}
		}
	}

	if len(result) > len(certs) {
		c.logger.Info("AIA fetch complete",
			zap.Int("original_chain_length", len(certs)),
			zap.Int("final_chain_length", len(result)))
		return result, nil
	}

	return result, fmt.Errorf("failed to fetch intermediate certificate from any AIA URL")
}
