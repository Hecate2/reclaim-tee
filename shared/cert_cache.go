//go:build !mobile

package shared

import "context"

// CacheInterface defines the interface for certificate caching
// This interface is compatible with both autocert.Cache and Lego's needs
type CacheInterface interface {
	// Get retrieves a cached certificate by key
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores a certificate in the cache
	Put(ctx context.Context, key string, data []byte) error

	// Delete removes a certificate from the cache
	Delete(ctx context.Context, key string) error
}

// Ensure EnclaveCache implements CacheInterface
var _ CacheInterface = (*EnclaveCache)(nil)
