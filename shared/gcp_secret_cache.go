//go:build !mobile

package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func sanitizeSecretID(id string) string {
	id = strings.ReplaceAll(id, ".", "-")
	id = strings.ReplaceAll(id, "_", "-")
	return id
}

type GCPSecretManagerCache struct {
	client      GCPSecretManagerInner
	provider    KMSProvider
	projectID   string
	serviceName string
}

func NewGCPSecretManagerCache(provider KMSProvider, projectID string, serviceName string) (*GCPSecretManagerCache, error) {
	client, err := NewGCPSecretManagerInner()
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %v", err)
	}

	return &GCPSecretManagerCache{
		client:      client,
		provider:    provider,
		projectID:   projectID,
		serviceName: serviceName,
	}, nil
}

func (g *GCPSecretManagerCache) EncryptAndStoreCacheItem(ctx context.Context, data []byte, filename string) error {
	dk, err := g.provider.GenerateDataKey("")
	if err != nil {
		return fmt.Errorf("failed to generate data key: %v", err)
	}

	encrypted, err := aesGCMOperation(dk.Plaintext, data, true)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	payload, err := json.Marshal(struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}{
		Data: encrypted,
		Key:  dk.CiphertextBlob,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	secretID := sanitizeSecretID(fmt.Sprintf("cache-%s-%s", g.serviceName, filename))

	if err := g.client.CreateIfNotExists(ctx, g.projectID, secretID); err != nil {
		return fmt.Errorf("failed to create secret: %v", err)
	}

	return g.client.AddVersion(ctx, g.projectID, secretID, payload)
}

func (g *GCPSecretManagerCache) LoadAndDecryptCacheItem(ctx context.Context, filename string) ([]byte, error) {
	secretID := sanitizeSecretID(fmt.Sprintf("cache-%s-%s", g.serviceName, filename))

	payload, err := g.client.AccessLatest(ctx, g.projectID, secretID)
	if err != nil {
		return nil, fmt.Errorf("cache miss: %v", err)
	}

	var pkg struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}

	if err := json.Unmarshal(payload, &pkg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	return g.provider.Decrypt(pkg.Data, "", pkg.Key)
}

func (g *GCPSecretManagerCache) DeleteCacheItem(ctx context.Context, filename string) error {
	return nil
}
