//go:build !mobile

package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/vsock"
)

// VSockConnectionManager provides VSock connection management
type VSockConnectionManager struct {
	parentCID    uint32
	kmsPort      uint32
	internetPort uint32

	// Caching components
	attestationCache *AttestationCache
	memoryCache      *MemoryCache

	mu           sync.Mutex
	isRunning    bool
	shutdownOnce sync.Once
}

// VSockConfig holds configuration for the connection manager
type VSockConfig struct {
	ParentCID    uint32
	KMSPort      uint32
	InternetPort uint32
	KMSKeyID     string // AWS KMS key ARN for encryption

	// Cache configurations
	AttestationCacheTTL time.Duration
}

// NewVSockConnectionManager creates a new connection manager
func NewVSockConnectionManager(config *VSockConfig) *VSockConnectionManager {
	if config == nil {
		config = &VSockConfig{
			ParentCID:           3,
			KMSPort:             5000,
			InternetPort:        8444,
			AttestationCacheTTL: 4 * time.Minute,
		}
	}

	manager := &VSockConnectionManager{
		parentCID:    config.ParentCID,
		kmsPort:      config.KMSPort,
		internetPort: config.InternetPort,
		memoryCache:  NewSmartMemoryCache(nil),
	}

	// Initialize attestation cache using global singleton handle
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		log.Printf("[VSock] Warning: Failed to get global handle for attestation cache: %v", err)
	} else {
		manager.attestationCache = NewAttestationCache(handle, config.AttestationCacheTTL)
	}

	return manager
}

// Start initializes all components
func (evm *VSockConnectionManager) Start(ctx context.Context) error {
	evm.mu.Lock()
	defer evm.mu.Unlock()

	if evm.isRunning {
		return fmt.Errorf("connection manager is already running")
	}

	log.Printf("[VSock] Starting VSock connection manager")

	// Start attestation cache
	if evm.attestationCache != nil {
		if err := evm.attestationCache.Start(ctx); err != nil {
			log.Printf("[VSock] Warning: Failed to start attestation cache: %v", err)
		}
	}

	// Start memory cache
	if evm.memoryCache != nil {
		if err := evm.memoryCache.Start(ctx); err != nil {
			log.Printf("[VSock] Warning: Failed to start memory cache: %v", err)
		}
	}

	evm.isRunning = true
	log.Printf("[VSock] Connection manager started successfully")
	return nil
}

// CreateInternetConnection creates a new VSock connection to the internet proxy with the specified target
func (evm *VSockConnectionManager) CreateInternetConnection(ctx context.Context, target string) (net.Conn, error) {
	conn, err := vsock.Dial(evm.parentCID, evm.internetPort, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to internet proxy: %v", err)
	}

	// Set a deadline for sending the target address
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	// Send target address to internet proxy
	if _, err := fmt.Fprintf(conn, "%s\n", target); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send target address: %v", err)
	}

	// Clear the write deadline
	conn.SetWriteDeadline(time.Time{})

	return conn, nil
}

// SendKMSRequest sends a request to KMS
func (evm *VSockConnectionManager) SendKMSRequest(ctx context.Context, operation string, serviceName string, data interface{}) ([]byte, error) {
	// Use crypto-secure retry logic
	var result []byte
	err := RetryWithBackoff(DefaultRetryConfig(), func() error {
		// Create a new connection for each request
		conn, err := vsock.Dial(evm.parentCID, evm.kmsPort, nil)
		if err != nil {
			return fmt.Errorf("failed to connect to KMS: %v", err)
		}
		defer conn.Close()

		// Prepare request
		request := map[string]interface{}{
			"operation":    operation,
			"service_name": serviceName,
			"input":        data,
		}

		// Send request with timeout
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err = json.NewEncoder(conn).Encode(request); err != nil {
			return fmt.Errorf("failed to send KMS request: %v", err)
		}

		// Read response with timeout
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var response struct {
			Output json.RawMessage `json:"output,omitempty"`
			Error  string          `json:"error,omitempty"`
		}

		if err := json.NewDecoder(conn).Decode(&response); err != nil {
			return fmt.Errorf("failed to read KMS response: %v", err)
		}

		if response.Error != "" {
			return fmt.Errorf("KMS operation failed: %s", response.Error)
		}

		result = response.Output
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("KMS request failed after retries: %v", err)
	}

	return result, nil
}

// GetCachedAttestation retrieves an attestation document with caching
func (evm *VSockConnectionManager) GetCachedAttestation(ctx context.Context, userData []byte) ([]byte, error) {
	if evm.attestationCache == nil {
		return nil, fmt.Errorf("attestation cache not initialized")
	}
	return evm.attestationCache.GetAttestation(ctx, userData)
}

// StoreInCache stores data in the memory cache
func (evm *VSockConnectionManager) StoreInCache(key string, data interface{}) {
	if evm.memoryCache != nil {
		evm.memoryCache.Put(key, data)
	}
}

// GetFromCache retrieves data from the memory cache
func (evm *VSockConnectionManager) GetFromCache(ctx context.Context, key string) (interface{}, error) {
	if evm.memoryCache == nil {
		return nil, fmt.Errorf("memory cache not initialized")
	}

	return evm.memoryCache.Get(ctx, key)
}

// Shutdown gracefully shuts down the connection manager
func (evm *VSockConnectionManager) Shutdown(ctx context.Context) error {
	evm.shutdownOnce.Do(func() {
		evm.mu.Lock()
		defer evm.mu.Unlock()

		if !evm.isRunning {
			return
		}

		log.Printf("[VSock] Shutting down connection manager")

		// Shutdown attestation cache
		if evm.attestationCache != nil {
			if err := evm.attestationCache.Shutdown(ctx); err != nil {
				log.Printf("[VSock] Warning: Failed to shutdown attestation cache: %v", err)
			}
		}

		// Shutdown memory cache
		if evm.memoryCache != nil {
			if err := evm.memoryCache.Shutdown(ctx); err != nil {
				log.Printf("[VSock] Warning: Failed to shutdown memory cache: %v", err)
			}
		}

		evm.isRunning = false
		log.Printf("[VSock] Connection manager shutdown completed")
	})

	return nil
}
