package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/shared"
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

// NewCertificateFetcher returns a cached HTTP-based certificate fetcher
// used by miniTLS for AIA chain building during target-server handshakes.
func NewCertificateFetcher(logger *shared.Logger) (minitls.CertificateFetcher, error) {
	cachedFetcher, err := minitls.NewCachedCertificateFetcher(NewStandardHTTPFetcher(), logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create cached certificate fetcher: %v", err)
	}
	return cachedFetcher, nil
}
