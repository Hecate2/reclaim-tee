//go:build !mobile

package shared

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	defaultAttestationTTL      = 5 * time.Minute // Cache attestation for 5 minutes
	attestationCleanupInterval = 1 * time.Minute // Cleanup expired entries every minute
	maxCacheSize               = 100             // Maximum cache entries
	attestationCacheKeyPrefix  = "attestation_"
)

// AttestationCache provides caching for attestation documents with TTL management
type AttestationCache struct {
	enclaveHandle *EnclaveHandle
	cache         map[string]*attestationEntry
	mu            sync.RWMutex
	ttl           time.Duration
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	isRunning     bool
}

// attestationEntry represents a cached attestation document
type attestationEntry struct {
	document   []byte
	userData   []byte // User data used for the attestation
	createdAt  time.Time
	expiresAt  time.Time
	hitCount   int64
	lastUsedAt time.Time
}

// NewAttestationCache creates a new attestation cache
func NewAttestationCache(enclaveHandle *EnclaveHandle, ttl time.Duration) *AttestationCache {
	if ttl == 0 {
		ttl = defaultAttestationTTL
	}

	return &AttestationCache{
		enclaveHandle: enclaveHandle,
		cache:         make(map[string]*attestationEntry),
		ttl:           ttl,
		stopChan:      make(chan struct{}),
	}
}

// Start begins the cache cleanup routine
func (ac *AttestationCache) Start(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.isRunning {
		return fmt.Errorf("attestation cache is already running")
	}

	log.Printf("[AttestationCache] Starting attestation cache with TTL: %v", ac.ttl)

	// Start cleanup routine
	ac.cleanupTicker = time.NewTicker(attestationCleanupInterval)
	ac.isRunning = true

	go ac.cleanupRoutine(ctx)

	return nil
}

// GetAttestation retrieves or generates an attestation document
func (ac *AttestationCache) GetAttestation(ctx context.Context, userData []byte) ([]byte, error) {

	// Generate cache key based on user data
	cacheKey := ac.generateCacheKey(userData)

	// Try to get from cache first
	ac.mu.RLock()
	if entry, exists := ac.cache[cacheKey]; exists && !ac.isExpired(entry) {
		// Cache hit
		entry.hitCount++
		entry.lastUsedAt = time.Now()
		ac.mu.RUnlock()

		log.Printf("[AttestationCache] Cache hit for attestation (key: %s, hit count: %d)",
			cacheKey[:8], entry.hitCount)
		return entry.document, nil
	}
	ac.mu.RUnlock()

	// Cache miss - generate new attestation
	log.Printf("[AttestationCache] Cache miss - generating new attestation (key: %s)", cacheKey[:8])

	// Generate attestation document
	attestationDoc, err := ac.enclaveHandle.generateAttestation(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	// Store in cache
	ac.storeInCache(cacheKey, attestationDoc, userData)

	log.Printf("[AttestationCache] Generated and cached new attestation (%d bytes)", len(attestationDoc))
	return attestationDoc, nil
}

// InvalidateAttestation removes a specific attestation from cache
func (ac *AttestationCache) InvalidateAttestation(userData []byte) {
	cacheKey := ac.generateCacheKey(userData)

	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, exists := ac.cache[cacheKey]; exists {
		delete(ac.cache, cacheKey)
		log.Printf("[AttestationCache] Invalidated attestation (key: %s)", cacheKey[:8])
	}
}

// InvalidateAll clears the entire cache
func (ac *AttestationCache) InvalidateAll() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	count := len(ac.cache)
	ac.cache = make(map[string]*attestationEntry)
	log.Printf("[AttestationCache] Invalidated all cached attestations (%d entries)", count)
}

// Shutdown stops the cache and cleanup routines
func (ac *AttestationCache) Shutdown(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if !ac.isRunning {
		return nil
	}

	log.Printf("[AttestationCache] Shutting down attestation cache")

	// Stop cleanup routine
	close(ac.stopChan)
	if ac.cleanupTicker != nil {
		ac.cleanupTicker.Stop()
	}

	// Clear cache
	count := len(ac.cache)
	ac.cache = make(map[string]*attestationEntry)
	ac.isRunning = false

	log.Printf("[AttestationCache] Cache shutdown completed (%d entries cleared)", count)
	return nil
}

// Private methods

func (ac *AttestationCache) generateCacheKey(userData []byte) string {
	hasher := sha256.New()
	hasher.Write([]byte(attestationCacheKeyPrefix))
	hasher.Write(userData)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (ac *AttestationCache) storeInCache(key string, document []byte, userData []byte) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	now := time.Now()
	entry := &attestationEntry{
		document:   document,
		userData:   userData,
		createdAt:  now,
		expiresAt:  now.Add(ac.ttl),
		hitCount:   1,
		lastUsedAt: now,
	}

	// Check if we need to evict entries
	if len(ac.cache) >= maxCacheSize {
		ac.evictOldestEntry()
	}

	ac.cache[key] = entry
}

func (ac *AttestationCache) isExpired(entry *attestationEntry) bool {
	return time.Now().After(entry.expiresAt)
}

func (ac *AttestationCache) evictOldestEntry() {
	if len(ac.cache) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	isFirst := true

	// Find the least recently used entry
	for key, entry := range ac.cache {
		if isFirst || entry.lastUsedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastUsedAt
			isFirst = false
		}
	}

	if oldestKey != "" {
		delete(ac.cache, oldestKey)
		log.Printf("[AttestationCache] Evicted oldest entry (key: %s)", oldestKey[:8])
	}
}

func (ac *AttestationCache) cleanupRoutine(ctx context.Context) {
	defer log.Printf("[AttestationCache] Cleanup routine stopped")

	for {
		select {
		case <-ac.cleanupTicker.C:
			ac.performCleanup()
		case <-ac.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (ac *AttestationCache) performCleanup() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	expiredKeys := make([]string, 0)

	// Find expired entries
	for key, entry := range ac.cache {
		if ac.isExpired(entry) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// Remove expired entries
	for _, key := range expiredKeys {
		delete(ac.cache, key)
	}

	if len(expiredKeys) > 0 {
		log.Printf("[AttestationCache] Cleaned up %d expired attestation entries", len(expiredKeys))
	}
}

// PrewarmAttestation pre-generates and caches an attestation for the given user data
func (ac *AttestationCache) PrewarmAttestation(ctx context.Context, userData []byte) error {
	log.Printf("[AttestationCache] Pre-warming attestation cache")

	_, err := ac.GetAttestation(ctx, userData)
	if err != nil {
		return fmt.Errorf("failed to pre-warm attestation: %v", err)
	}

	return nil
}

// GetCachedAttestationCount returns the number of cached attestations
func (ac *AttestationCache) GetCachedAttestationCount() int {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return len(ac.cache)
}

// GetAttestationInfo returns information about a cached attestation
func (ac *AttestationCache) GetAttestationInfo(userData []byte) map[string]interface{} {
	cacheKey := ac.generateCacheKey(userData)

	ac.mu.RLock()
	defer ac.mu.RUnlock()

	if entry, exists := ac.cache[cacheKey]; exists {
		return map[string]interface{}{
			"exists":        true,
			"created_at":    entry.createdAt,
			"expires_at":    entry.expiresAt,
			"hit_count":     entry.hitCount,
			"last_used_at":  entry.lastUsedAt,
			"is_expired":    ac.isExpired(entry),
			"document_size": len(entry.document),
		}
	}

	return map[string]interface{}{
		"exists": false,
	}
}
