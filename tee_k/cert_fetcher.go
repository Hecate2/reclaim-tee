package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tee-mpc/minitls"
	"tee-mpc/shared"
)

// StandardHTTPFetcher fetches certificates using standard HTTP client
type StandardHTTPFetcher struct {
	client *http.Client
}

// NewStandardHTTPFetcher creates a new HTTP-based certificate fetcher
func NewStandardHTTPFetcher() minitls.CertificateFetcher {
	return &StandardHTTPFetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Protection: Limit redirects to prevent redirect loops
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects (max 3)")
				}
				return nil
			},
		},
	}
}

// FetchCertificate downloads a certificate from the given URL using standard HTTP
func (f *StandardHTTPFetcher) FetchCertificate(urlStr string) ([]byte, error) {
	resp, err := f.client.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// Limit response size to 10KB to prevent downloading large files
	// (protect against malicious leaf certs with URLs pointing to movies, etc.)
	limitedReader := io.LimitReader(resp.Body, 10*1024) // 10KB max
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Check if we hit the limit (would indicate file is too large)
	if len(data) == 10*1024 {
		// Try reading one more byte to see if there's more data
		extraByte := make([]byte, 1)
		n, _ := resp.Body.Read(extraByte)
		if n > 0 {
			return nil, fmt.Errorf("certificate data exceeds 10KB limit")
		}
	}

	return data, nil
}

// VSockProxyFetcher fetches certificates via VSOCK internet proxy using VSockConnectionManager
type VSockProxyFetcher struct {
	connectionMgr *shared.VSockConnectionManager
}

// NewVSockProxyFetcher creates a new VSOCK proxy-based certificate fetcher
func NewVSockProxyFetcher(connectionMgr *shared.VSockConnectionManager) minitls.CertificateFetcher {
	return &VSockProxyFetcher{
		connectionMgr: connectionMgr,
	}
}

// FetchCertificate downloads a certificate from the given URL via VSOCK proxy
func (f *VSockProxyFetcher) FetchCertificate(urlStr string) ([]byte, error) {
	// Parse URL to extract host
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	// Determine host:port for the proxy connection
	host := u.Host
	if !strings.Contains(host, ":") {
		// Default port based on scheme
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Create custom transport that uses VSock proxy connection
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Use VSockConnectionManager to create internet connection
			return f.connectionMgr.CreateInternetConnection(ctx, host)
		},
		TLSClientConfig: shared.GetTLSConfig(),
	}

	// Create HTTP client with custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		// Protection: Limit redirects to prevent redirect loops
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects (max 3)")
			}
			return nil
		},
	}

	// Use standard HTTP client to make the request
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// Limit response size to 10KB to prevent downloading large files
	// (protect against malicious leaf certs with URLs pointing to movies, etc.)
	limitedReader := io.LimitReader(resp.Body, 10*1024) // 10KB max
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Check if we hit the limit (would indicate file is too large)
	if len(data) == 10*1024 {
		// Try reading one more byte to see if there's more data
		extraByte := make([]byte, 1)
		n, _ := resp.Body.Read(extraByte)
		if n > 0 {
			return nil, fmt.Errorf("certificate data exceeds 10KB limit")
		}
	}

	return data, nil
}

// NewCertificateFetcher creates an appropriate certificate fetcher based on enclave manager
// Returns a cached fetcher that wraps the base fetcher (VSock or HTTP)
func NewCertificateFetcher(enclaveManager *shared.EnclaveManager, logger *shared.Logger) (minitls.CertificateFetcher, error) {
	var baseFetcher minitls.CertificateFetcher

	if enclaveManager != nil {
		// Enclave mode: use VSock proxy via connection manager
		connectionMgr := enclaveManager.GetConnectionManager()
		baseFetcher = NewVSockProxyFetcher(connectionMgr)
	} else {
		// Standalone mode: use standard HTTP
		baseFetcher = NewStandardHTTPFetcher()
	}

	// Wrap with cached fetcher (1 week TTL, 24h cleanup, max 1000 entries)
	cachedFetcher, err := minitls.NewCachedCertificateFetcher(baseFetcher, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create cached certificate fetcher: %v", err)
	}

	return cachedFetcher, nil
}
