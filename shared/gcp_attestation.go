//go:build !mobile

package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func GenerateGCPAttestation(ctx context.Context, userData []byte) ([]byte, error) {
	// Request a custom attestation token with nonce containing the ETH address
	// This binds the ETH address to the attestation via the eat_nonce claim
	socketPath := "/run/container_launcher/teeserver.sock"

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	// Ensure nonce is within required length (8-88 bytes per GCP documentation)
	nonce := string(userData)
	if len(nonce) < 8 {
		// Pad if too short (minimum 8 bytes)
		nonce = fmt.Sprintf("%s%s", nonce, "        ")[:8]
	} else if len(nonce) > 88 {
		// Truncate if too long (maximum 88 bytes)
		nonce = nonce[:88]
	}

	// Create POST request with JSON body
	// Use PKI token type to get x5c (certificate chain) instead of kid (JWKS lookup)
	requestBody := map[string]interface{}{
		"audience":   "https://reclaimprotocol.org",
		"token_type": "PKI",
		"nonces":     []string{nonce},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/v1/token", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call launcher socket: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("launcher returned %d: %s", resp.StatusCode, string(body))
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %v", err)
	}

	// Token now includes submods.container.image_digest + eat_nonce with ETH address
	return token, nil
}
