package main

import (
	"fmt"
	"github.com/reclaimprotocol/reclaim-tee/minitls"
)

// configureCipherSuites configures the TLS config with specific cipher suites
func configureCipherSuites(config *minitls.Config, forceCipherSuite string, tlsVersion string) error {
	if forceCipherSuite == "" {
		// No specific cipher suite requested, use defaults
		return nil
	}

	cipherSuiteID, err := minitls.ParseCipherSuite(forceCipherSuite)
	if err != nil {
		return fmt.Errorf("failed to parse cipher suite: %v", err)
	}

	// Validate cipher suite compatibility with TLS version
	cipherInfo := minitls.GetCipherSuiteInfo(cipherSuiteID)
	if cipherInfo == nil {
		return fmt.Errorf("unknown cipher suite: 0x%04x", cipherSuiteID)
	}

	switch tlsVersion {
	case "1.2":
		if cipherInfo.IsTLS13 {
			return fmt.Errorf("cipher suite %s is not compatible with TLS 1.2", cipherInfo.Name)
		}
	case "1.3":
		if !cipherInfo.IsTLS13 {
			return fmt.Errorf("cipher suite %s is not compatible with TLS 1.3", cipherInfo.Name)
		}
	}

	// Set cipher suites in config
	config.CipherSuites = []uint16{cipherSuiteID}

	return nil
}
