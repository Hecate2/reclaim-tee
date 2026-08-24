package minitls

import (
	"testing"
)

// TestConfigDefaults verifies that Config struct has correct default behavior
func TestConfigDefaults(t *testing.T) {
	// Test default config (should support both TLS 1.2 and 1.3)
	config := &Config{}

	versions := config.supportedVersions()
	expectedVersions := []uint16{VersionTLS13, VersionTLS12}

	if len(versions) != len(expectedVersions) {
		t.Errorf("supportedVersions() = %v, want %v", versions, expectedVersions)
	}

	for i, v := range versions {
		if v != expectedVersions[i] {
			t.Errorf("supportedVersions()[%d] = 0x%04x, want 0x%04x", i, v, expectedVersions[i])
		}
	}

	// Test maxSupportedVersion
	maxVer := config.maxSupportedVersion()
	if maxVer != VersionTLS13 {
		t.Errorf("maxSupportedVersion() = 0x%04x, want 0x%04x", maxVer, VersionTLS13)
	}

	t.Logf("Config defaults verified: versions=%v, max=0x%04x", versions, maxVer)
}

// TestConfigVersionRange verifies custom version ranges work correctly
func TestConfigVersionRange(t *testing.T) {
	// Test TLS 1.2 only
	config12 := &Config{
		MinVersion: VersionTLS12,
		MaxVersion: VersionTLS12,
	}

	versions12 := config12.supportedVersions()
	expected12 := []uint16{VersionTLS12}

	if len(versions12) != 1 || versions12[0] != VersionTLS12 {
		t.Errorf("TLS 1.2 only config: supportedVersions() = %v, want %v", versions12, expected12)
	}

	// Test TLS 1.3 only
	config13 := &Config{
		MinVersion: VersionTLS13,
		MaxVersion: VersionTLS13,
	}

	versions13 := config13.supportedVersions()
	expected13 := []uint16{VersionTLS13}

	if len(versions13) != 1 || versions13[0] != VersionTLS13 {
		t.Errorf("TLS 1.3 only config: supportedVersions() = %v, want %v", versions13, expected13)
	}

	t.Logf("Custom version ranges verified: TLS1.2-only=%v, TLS1.3-only=%v", versions12, versions13)
}

// TestCipherSuitesDefaults verifies that cipher suite defaults work correctly
func TestCipherSuitesDefaults(t *testing.T) {
	// Test TLS 1.3 default cipher suites
	config13 := &Config{
		MinVersion: VersionTLS13,
		MaxVersion: VersionTLS13,
	}

	cipherSuites13 := config13.cipherSuites()
	expectedTLS13 := defaultCipherSuites(VersionTLS13)

	if len(cipherSuites13) != len(expectedTLS13) {
		t.Errorf("TLS 1.3 cipherSuites() length = %d, want %d", len(cipherSuites13), len(expectedTLS13))
	}

	for i, suite := range cipherSuites13 {
		if suite != expectedTLS13[i] {
			t.Errorf("TLS 1.3 cipherSuites()[%d] = 0x%04x, want 0x%04x", i, suite, expectedTLS13[i])
		}
	}

	// Test TLS 1.2 default cipher suites
	config12 := &Config{
		MinVersion: VersionTLS12,
		MaxVersion: VersionTLS12,
	}

	cipherSuites12 := config12.cipherSuites()
	expectedTLS12 := append(defaultCipherSuites(VersionTLS12), tls12CBCCipherSuites()...)

	if len(cipherSuites12) != len(expectedTLS12) {
		t.Errorf("TLS 1.2 cipherSuites() length = %d, want %d", len(cipherSuites12), len(expectedTLS12))
	}

	for i, suite := range cipherSuites12 {
		if suite != expectedTLS12[i] {
			t.Errorf("TLS 1.2 cipherSuites()[%d] = 0x%04x, want 0x%04x", i, suite, expectedTLS12[i])
		}
	}

	t.Logf("Cipher suite defaults verified: TLS1.3=%d suites, TLS1.2=%d suites", len(cipherSuites13), len(cipherSuites12))
}

// TestCipherSuitesCustom verifies custom cipher suite configuration
func TestCipherSuitesCustom(t *testing.T) {
	customSuites := []uint16{TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}

	config := &Config{
		CipherSuites: customSuites,
	}

	resultSuites := config.cipherSuites()

	if len(resultSuites) != len(customSuites) {
		t.Errorf("Custom cipherSuites() length = %d, want %d", len(resultSuites), len(customSuites))
	}

	for i, suite := range resultSuites {
		if suite != customSuites[i] {
			t.Errorf("Custom cipherSuites()[%d] = 0x%04x, want 0x%04x", i, suite, customSuites[i])
		}
	}

	t.Logf("Custom cipher suites verified: %v", resultSuites)
}

// TestTLS12CipherSuiteConstants verifies TLS 1.2 cipher suite constants match Go's crypto/tls
func TestTLS12CipherSuiteConstants(t *testing.T) {
	// Test that our TLS 1.2 cipher suite constants match Go's crypto/tls values
	testCases := []struct {
		name     string
		constant uint16
		expected uint16
	}{
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0xc02f},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0xc02b},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 0xc030},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 0xc02c},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0xcca8},
		{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0xcca9},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.constant != tc.expected {
				t.Errorf("%s = 0x%04x, want 0x%04x", tc.name, tc.constant, tc.expected)
			}
		})
	}

	t.Logf("All TLS 1.2 cipher suite constants verified")
}
