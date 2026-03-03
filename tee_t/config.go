package main

import (
	"log"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/joho/godotenv"
)

type TEETConfig struct {
	// Standalone mode
	Port int `json:"port"`

	// Enclave mode settings
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`
	KMSKey      string `json:"kms_key"`
	HTTPPort    int    `json:"http_port"`
	HTTPSPort   int    `json:"https_port"`

	// KMS provider (Google KMS)
	KMSProvider     string `json:"kms_provider"`
	GoogleProjectID string `json:"google_project_id,omitempty"`
	GoogleLocation  string `json:"google_location,omitempty"`
	GoogleKeyRing   string `json:"google_key_ring,omitempty"`
	GoogleKeyName   string `json:"google_key_name,omitempty"`
}

func LoadTEETConfig() *TEETConfig {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	} else {
		log.Printf("Successfully loaded .env file")
	}

	// GCP uses Google KMS
	kmsProvider := "google"

	log.Printf("Configuration loaded - KMSProvider: %s", kmsProvider)

	return &TEETConfig{
		Port:            shared.GetEnvIntOrDefault("PORT", 8081),
		EnclaveMode:     shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Domain:          shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "eu.tt.reclaimprotocol.org"),
		KMSKey:          shared.GetEnvOrDefault("KMS_KEY", ""),
		HTTPPort:        shared.GetEnvIntOrDefault("HTTP_PORT", 80),
		HTTPSPort:       shared.GetEnvIntOrDefault("HTTPS_PORT", 443),
		KMSProvider:     kmsProvider,
		GoogleProjectID: shared.GetEnvOrDefault("GOOGLE_PROJECT_ID", ""),
		GoogleLocation:  shared.GetEnvOrDefault("GOOGLE_KMS_LOCATION", ""),
		GoogleKeyRing:   shared.GetEnvOrDefault("GOOGLE_KMS_KEYRING", ""),
		GoogleKeyName:   shared.GetEnvOrDefault("GOOGLE_KMS_KEY", ""),
	}
}
