//go:build !mobile

package shared

import (
	"context"
	"log"
	"sync"
)

type CacheStorageAdapter interface {
	EncryptAndStoreCacheItem(ctx context.Context, data []byte, filename string) error
	LoadAndDecryptCacheItem(ctx context.Context, filename string) ([]byte, error)
	DeleteCacheItem(ctx context.Context, filename string) error
}

type EnclaveCache struct {
	gcpAdapter  *GCPSecretManagerCache
	serviceName string
	mu          sync.RWMutex
	memoryCache map[string][]byte
	stats       struct {
		hits   int
		misses int
	}
}

// NewEnclaveCacheWithProvider creates a new enclave cache with GCP Secret Manager
func NewEnclaveCacheWithProvider(provider KMSProvider, connectionMgr interface{}, serviceName string, platformConfig *PlatformConfig) *EnclaveCache {
	cache := &EnclaveCache{
		serviceName: serviceName,
		memoryCache: make(map[string][]byte),
	}

	gcpAdapter, err := NewGCPSecretManagerCache(provider, platformConfig.GoogleProjectID, serviceName)
	if err != nil {
		log.Printf("[EnclaveCache:%s] WARNING: Failed to create GCP cache adapter: %v", serviceName, err)
	}
	cache.gcpAdapter = gcpAdapter
	log.Printf("[EnclaveCache:%s] Creating cache with GCP Secret Manager", serviceName)

	return cache
}

// Get retrieves and decrypts a cached item
func (c *EnclaveCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	// Check memory cache first
	if data, exists := c.memoryCache[key]; exists {
		c.mu.RUnlock()
		c.stats.hits++
		log.Printf("[EnclaveCache:%s] CACHE HIT (%d hits/%d misses) - Found %s in memory cache (%d bytes)",
			c.serviceName, c.stats.hits, c.stats.misses, key, len(data))
		return data, nil
	}
	c.mu.RUnlock()

	c.stats.misses++
	log.Printf("[EnclaveCache:%s] CACHE MISS (%d hits/%d misses) - %s not in memory cache, loading from Secret Manager",
		c.serviceName, c.stats.hits, c.stats.misses, key)

	if c.gcpAdapter == nil {
		return nil, nil
	}

	data, err := c.gcpAdapter.LoadAndDecryptCacheItem(ctx, key)
	if err != nil {
		log.Printf("[EnclaveCache:%s] Failed to load %s from Secret Manager: %v", c.serviceName, key, err)
		return nil, err
	}

	// Store successfully retrieved data in memory cache
	c.mu.Lock()
	c.memoryCache[key] = data
	c.mu.Unlock()

	log.Printf("[EnclaveCache:%s] Successfully loaded %s from Secret Manager and cached in memory (%d bytes)", c.serviceName, key, len(data))
	return data, nil
}

// Put encrypts and stores a cached item
func (c *EnclaveCache) Put(ctx context.Context, key string, data []byte) error {
	// Store in memory cache first
	c.mu.Lock()
	c.memoryCache[key] = data
	c.mu.Unlock()
	log.Printf("[EnclaveCache:%s] Stored %s in memory cache", c.serviceName, key)

	if c.gcpAdapter == nil {
		return nil
	}

	err := c.gcpAdapter.EncryptAndStoreCacheItem(ctx, data, key)
	if err != nil {
		log.Printf("[EnclaveCache:%s] ERROR storing %s in Secret Manager: %v", c.serviceName, key, err)
		return err
	}

	log.Printf("[EnclaveCache:%s] Successfully stored %s in Secret Manager cache", c.serviceName, key)
	return nil
}

// Delete removes a cached item
func (c *EnclaveCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	delete(c.memoryCache, key)
	c.mu.Unlock()

	if c.gcpAdapter != nil {
		return c.gcpAdapter.DeleteCacheItem(ctx, key)
	}
	return nil
}
