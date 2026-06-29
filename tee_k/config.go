package main

import (
	"log"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/joho/godotenv"
)

// TEEKConfig holds the runtime configuration for TEE_K. Router mode is the
// production path; standalone mode is local-dev only (no TLS, no attestation).
type TEEKConfig struct {
	Port    int    `json:"port"`
	TEETURL string `json:"teet_url"` // only consulted in standalone mode

	// TLS configuration applied to outbound TLS sessions to target servers
	// (the actual workload — proving data from external HTTPS endpoints).
	ForceTLSVersion  string `json:"force_tls_version"`  // "1.2", "1.3", or "" for auto
	ForceCipherSuite string `json:"force_cipher_suite"` // hex ID (e.g. "0xc02f") or name, or "" for auto

	// Router-mode settings (multi-pair architecture). Presence of RouterURL
	// flips boot into router mode. The TEE mints SA identity tokens with
	// RouterURL as the `aud` claim; the router validates against its own
	// SA_TOKEN_AUDIENCE env var.
	RouterURL               string `json:"router_url,omitempty"`
	SelfAddr                string `json:"self_addr,omitempty"`
	PeerAddr                string `json:"peer_addr,omitempty"`
	ExpectedPeerImageDigest string `json:"expected_peer_image_digest,omitempty"`
	ExpectedPeerBaseDigest  string `json:"expected_peer_base_digest,omitempty"`
	JWTPublicKey            string `json:"jwt_public_key,omitempty"`
	ExpectedJWTIssuer       string `json:"expected_jwt_issuer,omitempty"`
	KMSEnclaveDomainKey     string `json:"kms_enclave_domain_key,omitempty"`
}

// RouterMode returns true when the router-mode boot path should be used.
// Detection is by presence of ROUTER_URL.
func (c *TEEKConfig) RouterMode() bool {
	return c.RouterURL != ""
}

func LoadTEEKConfig() *TEEKConfig {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	} else {
		log.Printf("Successfully loaded .env file")
	}

	return &TEEKConfig{
		Port:             shared.GetEnvIntOrDefault("PORT", 8080),
		TEETURL:          shared.GetEnvOrDefault("TEET_URL", "ws://localhost:8081/teek"),
		ForceTLSVersion:  shared.GetEnvOrDefault("FORCE_TLS_VERSION", ""),
		ForceCipherSuite: shared.GetEnvOrDefault("FORCE_CIPHER_SUITE", ""),

		RouterURL:               shared.GetEnvOrDefault("ROUTER_URL", ""),
		SelfAddr:                shared.GetEnvOrDefault("SELF_ADDR", ""),
		PeerAddr:                shared.GetEnvOrDefault("PEER_ADDR", ""),
		ExpectedPeerImageDigest: shared.GetEnvOrDefault("EXPECTED_PEER_IMAGE_DIGEST", ""),
		ExpectedPeerBaseDigest:  shared.GetEnvOrDefault("EXPECTED_PEER_BASE_DIGEST", ""),
		JWTPublicKey:            shared.GetEnvOrDefault("JWT_PUBLIC_KEY", ""),
		ExpectedJWTIssuer:       shared.GetEnvOrDefault("EXPECTED_JWT_ISSUER", ""),
		KMSEnclaveDomainKey:     shared.GetEnvOrDefault("KMS_ENCLAVE_DOMAIN_KEY", ""),
	}
}
