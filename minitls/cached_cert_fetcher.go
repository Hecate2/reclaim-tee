package minitls

import (
	"context"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// CachedCertificateFetcher wraps a CertificateFetcher with SmartMemoryCache
// to cache downloaded intermediate certificates for 1 week
type CachedCertificateFetcher struct {
	fetcher CertificateFetcher
	cache   *shared.MemoryCache
	logger  *shared.Logger
}

// certCacheLoader implements shared.CacheLoader for certificate fetching
type certCacheLoader struct {
	fetcher CertificateFetcher
	logger  *shared.Logger
}

// Load implements shared.CacheLoader interface
func (cl *certCacheLoader) Load(ctx context.Context, key string) (interface{}, error) {
	if cl.logger != nil {
		cl.logger.Info("Fetching certificate from network", zap.String("url", key))
	}

	certData, err := cl.fetcher.FetchCertificate(key)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate: %v", err)
	}

	if cl.logger != nil {
		cl.logger.Info("Successfully fetched certificate",
			zap.String("url", key),
			zap.Int("bytes", len(certData)))
	}

	return certData, nil
}

// ShouldPreload implements shared.CacheLoader interface
// For certificates, we don't need preloading as they're long-lived (1 week TTL)
func (cl *certCacheLoader) ShouldPreload(key string, entry *shared.MemoryCacheEntry) bool {
	return false
}

// NewCachedCertificateFetcher creates a new cached certificate fetcher
func NewCachedCertificateFetcher(fetcher CertificateFetcher, logger *shared.Logger) (*CachedCertificateFetcher, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("fetcher cannot be nil")
	}

	// Create cache loader
	loader := &certCacheLoader{
		fetcher: fetcher,
		logger:  logger,
	}

	// Create cache with 1 week TTL, 24 hour cleanup, max 1000 entries, no preload
	cache := shared.NewSmartMemoryCache(&shared.SmartMemoryCacheConfig{
		TTL:             7 * 24 * time.Hour, // 1 week
		CleanupInterval: 24 * time.Hour,     // 24 hours
		MaxSize:         1000,               // 1000 certificates max
		PreloadEnabled:  false,              // No preload for certificates
		Loader:          loader,
	})

	// Start cache background routines
	if err := cache.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to start certificate cache: %v", err)
	}

	if logger != nil {
		logger.Info("Certificate cache initialized",
			zap.Duration("ttl", 7*24*time.Hour),
			zap.Duration("cleanup_interval", 24*time.Hour),
			zap.Int("max_size", 1000))
	}

	return &CachedCertificateFetcher{
		fetcher: fetcher,
		cache:   cache,
		logger:  logger,
	}, nil
}

// FetchCertificate implements CertificateFetcher interface with caching
func (ccf *CachedCertificateFetcher) FetchCertificate(url string) ([]byte, error) {
	// Try to get from cache first
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	data, err := ccf.cache.Get(ctx, url)
	if err != nil {
		if ccf.logger != nil {
			ccf.logger.Warn("Certificate cache fetch failed",
				zap.String("url", url),
				zap.Error(err))
		}
		return nil, err
	}

	// Type assert to []byte
	certData, ok := data.([]byte)
	if !ok {
		return nil, fmt.Errorf("cached data is not []byte for url: %s", url)
	}

	if ccf.logger != nil {
		ccf.logger.Debug("Certificate retrieved from cache",
			zap.String("url", url),
			zap.Int("bytes", len(certData)))
	}

	return certData, nil
}

// Shutdown stops the cache and cleanup routines
func (ccf *CachedCertificateFetcher) Shutdown(ctx context.Context) error {
	if ccf.cache != nil {
		return ccf.cache.Shutdown(ctx)
	}
	return nil
}

// GetCacheStats returns cache statistics
func (ccf *CachedCertificateFetcher) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"size": ccf.cache.Size(),
	}
}

// ClearCache clears all cached certificates
func (ccf *CachedCertificateFetcher) ClearCache() {
	ccf.cache.Clear()
}
