package client

import (
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"time"
)

// ClientConfig contains all configuration options for the ReclaimClient.
// Direct TEE addresses are intentionally absent — V2 clients always go
// through the router. Set RouterURL and the constructor will resolve
// the pair via /allocate.
type ClientConfig struct {
	RouterURL            string                              // Router base URL; defaults to DefaultRouterURL (https://tee.reclaimprotocol.org) when empty
	AttestorURL          string                              // Attestor WebSocket URL
	Timeout              time.Duration                       // Connection timeout
	Mode                 ClientMode                          // Client operational mode
	ProviderParams       *providers.HTTPProviderParams       // Provider params for automatic response redactions
	ProviderSecretParams *providers.HTTPProviderSecretParams // Provider secret params for automatic response redactions
	ProviderContext      string                              // Optional provider context
	ForceTLSVersion      string                              // Force specific TLS version: "1.2", "1.3", or "" for auto
	ForceCipherSuite     string                              // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
	Logger               *shared.Logger                      // Optional logger with request context
	RequestId            string                              // Request ID for tracking across system
}

// RedactionSpec defines a redaction specification for request data
type RedactionSpec struct {
	Pattern     string `json:"pattern"`     // Regex or literal pattern to match
	Type        string `json:"type"`        // Use shared.RedactionTypeSensitive or shared.RedactionTypeSensitiveProof
	Replacement string `json:"replacement"` // Optional replacement value
}

// HTTPResponse contains the complete HTTP response data
type HTTPResponse struct {
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Body         []byte            `json:"body"`          // Just the HTTP body part
	FullResponse []byte            `json:"full_response"` // Complete HTTP response (status + headers + body)
}

// ProviderRequestData represents the JSON structure for provider-based request data (production format)
type ProviderRequestData struct {
	Name         string                              `json:"name"`              // Provider name (e.g., "http")
	Params       *providers.HTTPProviderParams       `json:"params"`            // Public provider parameters
	SecretParams *providers.HTTPProviderSecretParams `json:"secretParams"`      // Secret provider parameters
	Context      string                              `json:"context,omitempty"` // Optional context for the claim (JSON string)
}
