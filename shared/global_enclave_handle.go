//go:build !mobile

package shared

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/hf/nsm"
)

var (
	globalHandle        *EnclaveHandle
	initializationError error
	initOnce            sync.Once
)

// SafeGetEnclaveHandle returns the global singleton enclave handle with error handling
// NEVER panics - always returns error instead of crashing enclave
func SafeGetEnclaveHandle() (*EnclaveHandle, error) {
	initOnce.Do(func() {

		if globalHandle == nil && initializationError == nil {
			enclave := &EnclaveHandle{
				attestationCache: make(map[string]attestationCacheEntry),
			}
			if err := enclave.initialize(); err != nil {
				initializationError = fmt.Errorf("enclave initialization failed: %v", err)
				return
			}
			globalHandle = enclave
		}
	})

	if initializationError != nil {
		return nil, initializationError
	}

	if globalHandle == nil {
		return nil, fmt.Errorf("enclave handle not initialized")
	}

	return globalHandle, nil
}

// initialize initializes the enclave handle with proper error handling
func (e *EnclaveHandle) initialize() error {
	var err error

	// Open NSM session with error handling
	if e.nsm, err = nsm.OpenDefaultSession(); err != nil {
		return fmt.Errorf("failed to open NSM session: %v", err)
	}
	rand.Reader = e.nsm

	// Generate RSA key with proper error handling
	if e.key, err = generateRSAKey(); err != nil {
		// Clean up NSM session on error
		if e.nsm != nil {
			e.nsm.Close()
			e.nsm = nil
		}
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	return nil
}

// PublicKey returns the enclave's public key safely
func (e *EnclaveHandle) PublicKey() *rsa.PublicKey {
	if e == nil || e.key == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return &e.key.PublicKey
}
