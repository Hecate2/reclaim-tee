package client

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KGKallasmaa/countries"
	"go.uber.org/zap"
)

// bufferedConn wraps a net.Conn with a bufio.Reader to preserve any buffered data
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func newBufferedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	// Check if there's any buffered data
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}
	}
	return conn
}

// validateGeoLocation validates that the geoLocation is a valid 2-letter ISO country code
func validateGeoLocation(geoLocation string) error {
	if len(geoLocation) != 2 {
		return fmt.Errorf("geoLocation must be a 2-letter ISO country code, got: %q", geoLocation)
	}

	// Use countries library to validate against known ISO 3166-1 alpha-2 codes
	code := countries.ISO2CountryCode(strings.ToUpper(geoLocation))
	for _, valid := range countries.AllISO2Countries {
		if code == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid ISO 3166-1 alpha-2 country code: %q", geoLocation)
}

// parseProxyURL parses an HTTPS proxy URL and substitutes geoLocation
// Format: https://username-country-{{geoLocation}}:password@host:port/
func parseProxyURL(proxyURLTemplate string, geoLocation string) (scheme string, host string, port string, username string, password string, err error) {
	// Verify template contains {{geoLocation}} placeholder
	if !strings.Contains(proxyURLTemplate, "{{geoLocation}}") {
		return "", "", "", "", "", fmt.Errorf("proxy URL template must contain {{geoLocation}} placeholder")
	}

	// Substitute {{geoLocation}} placeholder
	proxyURLStr := strings.ReplaceAll(proxyURLTemplate, "{{geoLocation}}", strings.ToLower(geoLocation))

	parsed, err := url.Parse(proxyURLStr)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to parse proxy URL: %w", err)
	}

	scheme = parsed.Scheme
	host = parsed.Hostname()
	port = parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "22225" // default proxy port
		}
	}

	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}

	return scheme, host, port, username, password, nil
}

// connectViaProxy establishes a TCP connection through an HTTPS CONNECT proxy
func (c *Client) connectViaProxy(targetHost string, targetPort int) (net.Conn, error) {
	geoLocation := ""
	if c.providerParams != nil {
		geoLocation = c.providerParams.GeoLocation
	}

	// Validate geoLocation
	if err := validateGeoLocation(geoLocation); err != nil {
		return nil, fmt.Errorf("invalid geoLocation: %w", err)
	}

	// Parse proxy URL with geoLocation substitution
	scheme, proxyHost, proxyPort, username, password, err := parseProxyURL(c.proxyURL, geoLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
	}

	// Note: BrightData and most HTTP proxies use plain HTTP CONNECT, not TLS to the proxy.
	// The https:// in proxy URLs is just a URL convention for credentials, not the protocol.
	// TLS happens end-to-end with the target through the tunnel.
	_ = scheme // scheme in URL is ignored - always use plain HTTP CONNECT

	c.logger.Info("Connecting via HTTP proxy",
		zap.String("proxy_host", proxyHost),
		zap.String("proxy_port", proxyPort),
		zap.String("geo_location", geoLocation),
		zap.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))

	// Connect to proxy using plain TCP (HTTP CONNECT)
	proxyAddr := fmt.Sprintf("%s:%s", proxyHost, proxyPort)
	d := net.Dialer{Timeout: time.Second * 30}
	proxyConn, err := d.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyAddr, err)
	}

	c.logger.Debug("TCP connection to proxy established", zap.String("proxy_addr", proxyAddr))

	// Disable Nagle's algorithm to ensure immediate send
	if tcpConn, ok := proxyConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Set deadline for the CONNECT handshake
	proxyConn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send CONNECT request
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication
	if username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	c.logger.Debug("Sending CONNECT request to proxy",
		zap.String("target", targetAddr))

	n, err := proxyConn.Write([]byte(connectReq))
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	c.logger.Debug("CONNECT request sent, waiting for response",
		zap.Int("bytes_written", n))

	// Read response
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}

	c.logger.Debug("Received proxy response",
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status))

	// Read and discard response body
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed with status: %d %s", resp.StatusCode, resp.Status)
	}

	// Clear deadline for subsequent operations
	proxyConn.SetDeadline(time.Time{})

	c.logger.Info("Proxy tunnel established",
		zap.String("target", targetAddr),
		zap.String("geo_location", geoLocation),
		zap.Int("buffered_bytes", br.Buffered()))

	// Return connection wrapped with buffered reader if there's buffered data
	return newBufferedConn(proxyConn, br), nil
}

// shouldUseProxy determines if proxy should be used based on geoLocation and proxy URL config
func (c *Client) shouldUseProxy() bool {
	// No proxy URL configured
	if c.proxyURL == "" {
		return false
	}

	// No geoLocation means no proxy needed
	if c.providerParams == nil || c.providerParams.GeoLocation == "" {
		return false
	}

	return true
}
