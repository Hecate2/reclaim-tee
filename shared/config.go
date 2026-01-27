package shared

import (
	"os"
	"strconv"
)

// Helper functions for environment variable handling
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func GetEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetHTTPSProxyURL returns the HTTPS proxy URL template from env
func GetHTTPSProxyURL() string {
	return os.Getenv("HTTPS_PROXY_URL")
}
