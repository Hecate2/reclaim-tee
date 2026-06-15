package main

import (
	"log"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/joho/godotenv"
)

// TEETConfig holds the runtime configuration for TEE_T. Router mode is the
// production path; standalone mode is local-dev only (no TLS, no attestation).
type TEETConfig struct {
	Port int `json:"port"`

	// Router-mode settings (multi-pair architecture). Presence of RouterURL
	// flips boot into router mode. The TEE mints SA identity tokens with
	// RouterURL as the `aud` claim; the router validates against its own
	// SA_TOKEN_AUDIENCE env var.
	RouterURL               string `json:"router_url,omitempty"`
	SelfAddr                string `json:"self_addr,omitempty"`
	PeerAddr                string `json:"peer_addr,omitempty"`
	ExpectedPeerImageDigest string `json:"expected_peer_image_digest,omitempty"`
	JWTPublicKey            string `json:"jwt_public_key,omitempty"`
	ExpectedJWTIssuer       string `json:"expected_jwt_issuer,omitempty"`
	KMSEnclaveDomainKey     string `json:"kms_enclave_domain_key,omitempty"`
}

// RouterMode returns true when the router-mode boot path should be used.
// Detection is by presence of ROUTER_URL.
func (c *TEETConfig) RouterMode() bool {
	return c.RouterURL != ""
}

func LoadTEETConfig() *TEETConfig {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	} else {
		log.Printf("Successfully loaded .env file")
	}

	return &TEETConfig{
		Port: shared.GetEnvIntOrDefault("PORT", 8081),

		RouterURL:               shared.GetEnvOrDefault("ROUTER_URL", ""),
		SelfAddr:                shared.GetEnvOrDefault("SELF_ADDR", ""),
		PeerAddr:                shared.GetEnvOrDefault("PEER_ADDR", ""),
		ExpectedPeerImageDigest: shared.GetEnvOrDefault("EXPECTED_PEER_IMAGE_DIGEST", ""),
		JWTPublicKey:            shared.GetEnvOrDefault("JWT_PUBLIC_KEY", ""),
		ExpectedJWTIssuer:       shared.GetEnvOrDefault("EXPECTED_JWT_ISSUER", ""),
		KMSEnclaveDomainKey:     shared.GetEnvOrDefault("KMS_ENCLAVE_DOMAIN_KEY", ""),
	}
}
