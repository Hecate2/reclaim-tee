package client

import (
	"fmt"
	"sync"

	prover "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
)

// Algorithm IDs - mirrors impl package constants
const (
	CHACHA20      uint8 = 0
	AES_128       uint8 = 1
	AES_256       uint8 = 2
	CHACHA20_OPRF uint8 = 3
	AES_128_OPRF  uint8 = 4
	AES_256_OPRF  uint8 = 5
)

// cipherToAlgorithmID maps cipher names to algorithm IDs
var cipherToAlgorithmID = map[string]uint8{
	"chacha20":          CHACHA20,
	"aes-128-ctr":       AES_128,
	"aes-256-ctr":       AES_256,
	"chacha20-toprf":    CHACHA20_OPRF,
	"aes-128-ctr-toprf": AES_128_OPRF,
	"aes-256-ctr-toprf": AES_256_OPRF,
}

// algorithmIDToCipher maps algorithm IDs to cipher names
var algorithmIDToCipher = map[uint8]string{
	CHACHA20:      "chacha20",
	AES_128:       "aes-128-ctr",
	AES_256:       "aes-256-ctr",
	CHACHA20_OPRF: "chacha20-toprf",
	AES_128_OPRF:  "aes-128-ctr-toprf",
	AES_256_OPRF:  "aes-256-ctr-toprf",
}

// ZKInitCallback is called before proving when an algorithm is not yet initialized.
// The callback receives the algorithm ID and should call InitAlgorithm with the
// appropriate proving key and r1cs data.
// Returns a channel that will receive true if initialization succeeded, false otherwise.
type ZKInitCallback func(algorithmID uint8) <-chan bool

var (
	zkInitCallback     ZKInitCallback
	zkInitCallbackLock sync.RWMutex
	initializedAlgs    = make(map[uint8]bool)
	initializedLock    sync.RWMutex
)

// SetZKInitCallback sets the callback function that will be called when Prove
// is invoked for an algorithm that hasn't been initialized yet.
// The callback should load the circuit files and call InitAlgorithm.
// Returns the previous callback (if any).
func SetZKInitCallback(cb ZKInitCallback) ZKInitCallback {
	zkInitCallbackLock.Lock()
	defer zkInitCallbackLock.Unlock()
	prev := zkInitCallback
	zkInitCallback = cb
	return prev
}

// MarkAlgorithmInitialized marks an algorithm as initialized.
// This should be called after a successful InitAlgorithm call.
func MarkAlgorithmInitialized(algorithmID uint8) {
	initializedLock.Lock()
	defer initializedLock.Unlock()
	initializedAlgs[algorithmID] = true
}

// IsAlgorithmInitialized checks if an algorithm has been initialized.
func IsAlgorithmInitialized(algorithmID uint8) bool {
	initializedLock.RLock()
	defer initializedLock.RUnlock()
	return initializedAlgs[algorithmID]
}

// GetAlgorithmID returns the algorithm ID for a given cipher name.
// Returns (id, true) if found, (0, false) otherwise.
func GetAlgorithmID(cipher string) (uint8, bool) {
	id, ok := cipherToAlgorithmID[cipher]
	return id, ok
}

// GetCipherName returns the cipher name for a given algorithm ID.
// Returns (name, true) if found, ("", false) otherwise.
func GetCipherName(algorithmID uint8) (string, bool) {
	name, ok := algorithmIDToCipher[algorithmID]
	return name, ok
}

// InitAlgorithmWithTracking wraps impl.InitAlgorithm and tracks initialization state.
func InitAlgorithmWithTracking(algorithmID uint8, provingKey []byte, r1cs []byte) bool {
	success := prover.InitAlgorithm(algorithmID, provingKey, r1cs)
	if success {
		MarkAlgorithmInitialized(algorithmID)
	}
	return success
}

// EnsureAlgorithmInitialized ensures an algorithm is initialized before proving.
// If not initialized and a callback is set, it calls the callback.
// Returns an error if initialization fails or no callback is set.
func EnsureAlgorithmInitialized(cipher string) error {
	algorithmID, ok := GetAlgorithmID(cipher)
	if !ok {
		return fmt.Errorf("unknown cipher: %s", cipher)
	}

	if IsAlgorithmInitialized(algorithmID) {
		return nil
	}

	zkInitCallbackLock.RLock()
	cb := zkInitCallback
	zkInitCallbackLock.RUnlock()

	if cb == nil {
		return fmt.Errorf("algorithm %s (ID=%d) is not initialized and no init callback is set", cipher, algorithmID)
	}

	successChan := cb(algorithmID)
	success := <-successChan
	if !success {
		return fmt.Errorf("failed to initialize algorithm %s (ID=%d) via callback", cipher, algorithmID)
	}

	return nil
}
