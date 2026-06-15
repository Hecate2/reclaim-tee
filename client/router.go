package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AllocationResponse is what the router returns from POST /allocate.
// Mirrors router/handlers/allocate.go's allocateResponse — duplicated
// here so client/ doesn't import the router module.
type AllocationResponse struct {
	PairID   string `json:"pair_id"`
	TEEKAddr string `json:"teek_addr"`
	TEETAddr string `json:"teet_addr"`
	JWT      string `json:"jwt"`
}

// AllocatePair hits the router's /allocate endpoint with the supplied
// client nonce and returns the pair allocation + JWT. routerURL is the
// base URL (e.g. http://localhost:9090 or https://tee.reclaimprotocol.org).
func AllocatePair(routerURL, clientNonce string) (*AllocationResponse, error) {
	body, err := json.Marshal(map[string]string{"client_nonce": clientNonce})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Post(routerURL+"/allocate", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST /allocate: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/allocate returned %d: %s", resp.StatusCode, respBody)
	}
	var out AllocationResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}
