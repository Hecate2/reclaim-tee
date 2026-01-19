package main

import (
	"log"
	"tee-mpc/shared"

	"github.com/joho/godotenv"
)

type TEEKConfig struct {
	// Standalone mode settings
	Port    int    `json:"port"`
	TEETURL string `json:"teet_url"`

	// Enclave mode settings
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`
	KMSKey      string `json:"kms_key"`

	// KMS provider (Google KMS)
	KMSProvider     string `json:"kms_provider"`
	GoogleProjectID string `json:"google_project_id,omitempty"`
	GoogleLocation  string `json:"google_location,omitempty"`
	GoogleKeyRing   string `json:"google_key_ring,omitempty"`
	GoogleKeyName   string `json:"google_key_name,omitempty"`

	// TLS configuration
	ForceTLSVersion  string `json:"force_tls_version"`  // Force specific TLS version: "1.2", "1.3", or "" for auto
	ForceCipherSuite string `json:"force_cipher_suite"` // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
}

func LoadTEEKConfig() *TEEKConfig {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	} else {
		log.Printf("Successfully loaded .env file")
	}

	// GCP uses Google KMS
	kmsProvider := "google"

	log.Printf("Configuration loaded - KMSProvider: %s", kmsProvider)

	enclaveMode := shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true"

	// Determine TEE_T URL
	var teetURL string
	if enclaveMode {
		// GCP enclave mode - use production URL from env
		teetURL = shared.GetEnvOrDefault("TEET_URL", "wss://tt.reclaimprotocol.org/teek")
	} else {
		// Standalone mode
		teetURL = shared.GetEnvOrDefault("TEET_URL", "ws://localhost:8081/teek")
	}

	// Determine TEE_K domain from env
	domain := shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "tk.reclaimprotocol.org")

	return &TEEKConfig{
		Port:             shared.GetEnvIntOrDefault("PORT", 8080),
		TEETURL:          teetURL,
		EnclaveMode:      enclaveMode,
		Domain:           domain,
		KMSKey:           shared.GetEnvOrDefault("KMS_KEY", ""),
		KMSProvider:      kmsProvider,
		GoogleProjectID:  shared.GetEnvOrDefault("GOOGLE_PROJECT_ID", ""),
		GoogleLocation:   shared.GetEnvOrDefault("GOOGLE_KMS_LOCATION", ""),
		GoogleKeyRing:    shared.GetEnvOrDefault("GOOGLE_KMS_KEYRING", ""),
		GoogleKeyName:    shared.GetEnvOrDefault("GOOGLE_KMS_KEY", ""),
		ForceTLSVersion:  shared.GetEnvOrDefault("FORCE_TLS_VERSION", ""),
		ForceCipherSuite: shared.GetEnvOrDefault("FORCE_CIPHER_SUITE", ""),
	}
}
