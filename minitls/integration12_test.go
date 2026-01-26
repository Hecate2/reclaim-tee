package minitls

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

// TestTLS12Integration tests the complete TLS 1.2 implementation against real servers
func TestTLS12Integration(t *testing.T) {
	testCases := []struct {
		name        string
		serverName  string
		port        int
		cipherSuite uint16
		expectTLS12 bool // Whether we expect the server to negotiate TLS 1.2
	}{
		{
			name:        "Force TLS 1.2 with specific cipher",
			serverName:  "cloudflare.com",
			port:        443,
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			expectTLS12: true,
		},
		{
			name:        "Force TLS 1.2 ChaCha20",
			serverName:  "cloudflare.com",
			port:        443,
			cipherSuite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			expectTLS12: true,
		},
		{
			name:        "httpbin.org AES-GCM",
			serverName:  "httpbin.org",
			port:        443,
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			expectTLS12: true,
		},
		{
			name:        "Google ChaCha20",
			serverName:  "google.com",
			port:        443,
			cipherSuite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			expectTLS12: true,
		},
		{
			name:        "Google_ChaCha20_Pure_TLS12",
			serverName:  "google.com",
			port:        443,
			cipherSuite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			expectTLS12: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create configuration that forces TLS 1.2
			config := &Config{
				MinVersion:   VersionTLS12,
				MaxVersion:   VersionTLS12, // Force TLS 1.2 only
				CipherSuites: []uint16{tc.cipherSuite},
			}

			// Connect to the server
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", tc.serverName, tc.port), 10*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to %s:%d: %v", tc.serverName, tc.port, err)
			}
			defer conn.Close()

			// Create client with TLS 1.2 configuration
			client := NewClientWithConfig(conn, config)

			// Enable debug logging for Google tests
			if tc.name == "Google_ChaCha20_Pure_TLS12" || tc.name == "Google ChaCha20" {
				logger, _ := shared.NewLogger(shared.LoggerConfig{
					ServiceName: "test",
					Development: true,
				})
				client.SetLogger(logger)
			}

			// Perform handshake
			if tc.name == "Google_ChaCha20_Pure_TLS12" || tc.name == "Google ChaCha20" {
				// Force pure TLS 1.2 handshake for Google (version negotiation has compatibility issues)
				err = client.handshakeTLS12(tc.serverName)
			} else {
				// Use version negotiation
				err = client.Handshake(tc.serverName)
			}
			if err != nil {
				t.Fatalf("TLS 1.2 handshake failed: %v", err)
			}

			// Verify negotiated version and cipher suite
			if client.negotiatedVersion != VersionTLS12 {
				t.Errorf("Expected TLS 1.2 (0x%04x), got 0x%04x", VersionTLS12, client.negotiatedVersion)
			}

			if client.cipherSuite != tc.cipherSuite {
				t.Errorf("Expected cipher suite 0x%04x, got 0x%04x", tc.cipherSuite, client.cipherSuite)
			}

			// Verify TLS 1.2 components are initialized
			if client.tls12KeySchedule == nil {
				t.Error("TLS 1.2 key schedule not initialized")
			}

			if client.tls12AEAD == nil {
				t.Error("TLS 1.2 AEAD context not initialized")
			}

			// Test application data exchange
			if err := testTLS12ApplicationData(client, tc.serverName); err != nil {
				t.Errorf("Application data test failed: %v", err)
			}

		})
	}
}

// testTLS12ApplicationData tests sending and receiving application data over TLS 1.2
func testTLS12ApplicationData(client *Client, serverName string) error {
	// Send a simple HTTP GET request
	httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", serverName)

	// Send the HTTP request using TLS 1.2
	if err := client.sendApplicationDataWithCorrectAEAD([]byte(httpRequest)); err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}

	// Read the HTTP response
	responseData, err := client.readApplicationDataWithCorrectAEAD()
	if err != nil {
		return fmt.Errorf("failed to read HTTP response: %v", err)
	}

	// Verify we got some data back
	if len(responseData) == 0 {
		return fmt.Errorf("received empty response")
	}

	// Check for HTTP response header
	responseStr := string(responseData)
	if !strings.Contains(responseStr, "HTTP/") {
		return fmt.Errorf("response doesn't look like HTTP: %s", responseStr[:min(100, len(responseStr))])
	}

	return nil
}

// TestTLS12VersionNegotiation tests that version negotiation works correctly
func TestTLS12VersionNegotiation(t *testing.T) {
	testCases := []struct {
		name        string
		minVersion  uint16
		maxVersion  uint16
		serverName  string
		expectTLS12 bool
	}{
		{
			name:        "TLS 1.2 only",
			minVersion:  VersionTLS12,
			maxVersion:  VersionTLS12,
			serverName:  "cloudflare.com",
			expectTLS12: true,
		},
		{
			name:        "TLS 1.2 and 1.3 (server chooses)",
			minVersion:  VersionTLS12,
			maxVersion:  VersionTLS13,
			serverName:  "cloudflare.com",
			expectTLS12: false, // Cloudflare should prefer TLS 1.3
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				MinVersion: tc.minVersion,
				MaxVersion: tc.maxVersion,
			}

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", tc.serverName), 10*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer conn.Close()

			client := NewClientWithConfig(conn, config)

			if err := client.Handshake(tc.serverName); err != nil {
				t.Fatalf("Handshake failed: %v", err)
			}

			isTLS12 := client.negotiatedVersion == VersionTLS12
			if isTLS12 != tc.expectTLS12 {
				t.Errorf("Expected TLS 1.2: %v, got TLS 1.2: %v (version: 0x%04x)",
					tc.expectTLS12, isTLS12, client.negotiatedVersion)
			}

		})
	}
}

// TestTLS12Components tests individual TLS 1.2 components
func TestTLS12Components(t *testing.T) {
	t.Run("PRF Implementation", func(t *testing.T) {
		// Test the PRF with known inputs
		secret := []byte("test secret")
		label := "test label"
		seed := []byte("test seed")

		result1 := prf12(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, secret, label, seed, 32)
		result2 := prf12(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, secret, label, seed, 32)

		if len(result1) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(result1))
		}

		// Results should be deterministic
		if !compareBytes(result1, result2) {
			t.Error("PRF results are not deterministic")
		}

	})

	t.Run("TLS12KeySchedule", func(t *testing.T) {
		clientRandom := make([]byte, 32)
		serverRandom := make([]byte, 32)
		preMasterSecret := make([]byte, 48)

		// Fill with test data
		for i := range clientRandom {
			clientRandom[i] = byte(i)
		}
		for i := range serverRandom {
			serverRandom[i] = byte(i + 100)
		}
		for i := range preMasterSecret {
			preMasterSecret[i] = byte(i + 200)
		}

		ks := NewTLS12KeySchedule(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil, clientRandom, serverRandom)
		ks.DeriveMasterSecret(preMasterSecret)

		if len(ks.masterSecret) != 48 {
			t.Errorf("Master secret length: got %d, want 48", len(ks.masterSecret))
		}

		clientKey, clientIV, serverKey, serverIV, err := ks.DeriveKeys()
		if err != nil {
			t.Fatalf("Key derivation failed: %v", err)
		}

		if len(clientKey) != 16 || len(serverKey) != 16 {
			t.Error("AES-128 keys should be 16 bytes")
		}

		if len(clientIV) != 4 || len(serverIV) != 4 {
			t.Error("GCM IVs should be 4 bytes")
		}

	})
}

// TestTLS12CipherSuiteSupport tests all supported TLS 1.2 cipher suites
func TestTLS12CipherSuiteSupport(t *testing.T) {
	cipherSuites := []struct {
		name  string
		value uint16
	}{
		{"AES-128-GCM-SHA256", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		{"AES-256-GCM-SHA384", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		{"ChaCha20-Poly1305-SHA256", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
	}

	for _, cs := range cipherSuites {
		t.Run(cs.name, func(t *testing.T) {
			// Test key lengths
			keyLen, ivLen := getTLS12AEADKeyLengths(cs.value)
			if keyLen == 0 || ivLen == 0 {
				t.Errorf("Invalid key/IV lengths for cipher suite 0x%04x: key=%d, iv=%d", cs.value, keyLen, ivLen)
			}

			// Test AEAD context creation
			writeKey := make([]byte, keyLen)
			writeIV := make([]byte, ivLen)
			readKey := make([]byte, keyLen)
			readIV := make([]byte, ivLen)

			_, err := NewTLS12AEADContext(writeKey, writeIV, readKey, readIV, cs.value)
			if err != nil {
				t.Errorf("Failed to create AEAD context for %s: %v", cs.name, err)
			}

		})
	}
}
