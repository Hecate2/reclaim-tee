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
	const maxAIADepth = 1 // Only allow ONE level of AIA fetching (no recursive fetches)
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

	// Verify key usage flags - digitalSignature is required for TLS
	// (keyEncipherment is for RSA key exchange, but we only use ECDHE)
	if leafCert.KeyUsage != 0 {
		requiredUsage := x509.KeyUsageDigitalSignature
		if leafCert.KeyUsage&requiredUsage == 0 {
			c.logger.Warn("Server certificate missing digitalSignature key usage",
				zap.String("key_usage", fmt.Sprintf("0x%x", leafCert.KeyUsage)))
			// Note: We log a warning but don't fail, as some valid certificates
			// may not set this flag. The ExtKeyUsage check above is more important.
		}
	}

	// Build intermediate certificate pool
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	// Get root CA pool (custom if set, otherwise system)
	roots := shared.GetRootCAPool()

	// Verify certificate chain with hostname
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName, // This performs RFC 6125 hostname verification
	}

	chains, err := leafCert.Verify(opts)
	if err != nil {
		// Only try to fetch missing intermediates if:
		// 1. Config is not nil and has CertFetcher
		// 2. We haven't exceeded AIA fetch depth limit
		// 3. Certificate has AIA URLs
		// 4. Error is about unknown authority (missing intermediate)
		if config == nil || config.CertFetcher == nil {
			// No cert fetcher configured, return error immediately
			return &CertificateError{
				Type:    CertErrorVerification,
				Message: fmt.Sprintf("certificate verification failed for %s", serverName),
				Err:     err,
			}
		}

		if aiaDepth < maxAIADepth && len(leafCert.IssuingCertificateURL) > 0 {
			// Check if error is due to unknown authority (missing intermediate)
			// Use errors.As to handle wrapped errors
			var unknownAuthorityErr x509.UnknownAuthorityError
			if errors.As(err, &unknownAuthorityErr) {
				c.logger.Info("Certificate chain incomplete, fetching missing intermediates",
					zap.String("cert", leafCert.Subject.String()),
					zap.Int("aia_depth", aiaDepth))
				completedChain, fetchErr := c.fetchMissingIntermediates(certs, config.CertFetcher)
				if fetchErr == nil && len(completedChain) > len(certs) {
					// Retry validation with completed chain (increment depth to prevent infinite recursion)
					c.logger.Info("Retrying validation with fetched intermediates",
						zap.Int("chain_length", len(completedChain)))
					return c.verifyCertificateChainWithDepth(completedChain, serverName, config, aiaDepth+1)
				}
				c.logger.Warn("Failed to complete certificate chain via AIA", zap.Error(fetchErr))
			}
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
// This function is called only ONCE per verification attempt (not recursive) to prevent:
// - Infinite recursion attacks
// - Circular AIA reference attacks
// - Chain depth attacks
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

	leafCert := certs[0]

	// Protection: Track certificate fingerprints to detect circular references
	existingFingerprints := make(map[string]bool)
	for _, cert := range certs {
		fingerprint := fmt.Sprintf("%x", cert.SerialNumber)
		existingFingerprints[fingerprint] = true
	}

	// Try each AIA URL until one succeeds
	for _, url := range leafCert.IssuingCertificateURL {
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

		// Verify all intermediates are actually CA certificates and not duplicates
		validIntermediates := make([]*x509.Certificate, 0, len(intermediates))
		for _, intermediate := range intermediates {
			if !intermediate.IsCA {
				c.logger.Warn("Skipping non-CA certificate from bundle",
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

			validIntermediates = append(validIntermediates, intermediate)
		}

		if len(validIntermediates) == 0 {
			c.logger.Warn("No valid CA certificates found in bundle", zap.String("url", url))
			continue // Try next URL
		}

		// Add all valid intermediates to chain (insert after leaf)
		result = append(result, validIntermediates...)
		c.logger.Info("Successfully fetched intermediate cert(s)",
			zap.String("url", url),
			zap.Int("count", len(validIntermediates)))
		return result, nil
	}

	return result, fmt.Errorf("failed to fetch intermediate certificate from any AIA URL")
}
