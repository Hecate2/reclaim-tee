//go:build !mobile

package shared

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// CertificateStorage abstracts where TLS certificates are persisted
type CertificateStorage interface {
	StoreCertificate(domain string, cert *tls.Certificate) error
	RetrieveCertificate(domain string) (*tls.Certificate, error)
}

// EnclaveCacheStorage stores combined cert+key PEM in the existing enclave cache
type EnclaveCacheStorage struct {
	cache CacheInterface
}

func NewEnclaveCacheStorage(cache CacheInterface) *EnclaveCacheStorage {
	return &EnclaveCacheStorage{cache: cache}
}

func (s *EnclaveCacheStorage) StoreCertificate(domain string, cert *tls.Certificate) error {
	certPEM, keyPEM, err := tlsCertificateToPEM(cert)
	if err != nil {
		return err
	}
	combined := append(certPEM, keyPEM...)
	return s.cache.Put(context.Background(), domain, combined)
}

func (s *EnclaveCacheStorage) RetrieveCertificate(domain string) (*tls.Certificate, error) {
	data, err := s.cache.Get(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cached certificate: %v", err)
	}
	return &cert, nil
}

// SecretManagerStorage stores certs in Google Secret Manager as combined PEM
type SecretManagerStorage struct {
	client    SecretManagerClient
	projectID string
}

// SecretManagerClient is a minimal interface for GCP Secret Manager client
type SecretManagerClient interface {
	CreateSecret(ctx context.Context, projectID, secretID string) error
	AddSecretVersion(ctx context.Context, projectID, secretID string, payload []byte) error
	AccessLatestVersion(ctx context.Context, projectID, secretID string) ([]byte, error)
}

func NewSecretManagerStorage(client SecretManagerClient, projectID string) *SecretManagerStorage {
	return &SecretManagerStorage{client: client, projectID: projectID}
}

func (s *SecretManagerStorage) secretIDForDomain(domain string) string {
	// Keep it simple and deterministic
	return fmt.Sprintf("tls-cert-%s", domain)
}

func (s *SecretManagerStorage) StoreCertificate(domain string, cert *tls.Certificate) error {
	certPEM, keyPEM, err := tlsCertificateToPEM(cert)
	if err != nil {
		return err
	}
	combined := append(certPEM, keyPEM...)

	secretID := s.secretIDForDomain(domain)

	// Best-effort: create secret if not exists, then add a new version
	if err := s.client.CreateSecret(context.Background(), s.projectID, secretID); err != nil {
		// ignore if already exists; rely on client implementation to tolerate
		_ = err
	}
	return s.client.AddSecretVersion(context.Background(), s.projectID, secretID, combined)
}

func (s *SecretManagerStorage) RetrieveCertificate(domain string) (*tls.Certificate, error) {
	secretID := s.secretIDForDomain(domain)
	data, err := s.client.AccessLatestVersion(context.Background(), s.projectID, secretID)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret certificate: %v", err)
	}
	return &cert, nil
}

// tlsCertificateToPEM converts tls.Certificate into PEM-encoded cert chain and private key
// We use PKCS#8 for private key to avoid algorithm-specific marshaling.
func tlsCertificateToPEM(cert *tls.Certificate) ([]byte, []byte, error) {
	if cert == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, nil, fmt.Errorf("invalid certificate or private key")
	}
	// Encode full chain
	var certPEM []byte
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	// Encode private key as PKCS#8
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	return certPEM, keyPEM, nil
}

// --- GCP Secret Manager concrete client ---

// We implement the client in this file to keep integration surgical.
// It is a thin wrapper over GCP SDK methods but behind a small interface to ease testing.

type gcpSecretManagerClient struct {
	inner GCPSecretManagerInner
}

// GCPSecretManagerInner lets us wrap the actual SDK client calls; defined in secret_manager_impl.go
type GCPSecretManagerInner interface {
	CreateIfNotExists(ctx context.Context, projectID, secretID string) error
	AddVersion(ctx context.Context, projectID, secretID string, payload []byte) error
	AccessLatest(ctx context.Context, projectID, secretID string) ([]byte, error)
}

func (c *gcpSecretManagerClient) CreateSecret(ctx context.Context, projectID, secretID string) error {
	return c.inner.CreateIfNotExists(ctx, projectID, secretID)
}
func (c *gcpSecretManagerClient) AddSecretVersion(ctx context.Context, projectID, secretID string, payload []byte) error {
	return c.inner.AddVersion(ctx, projectID, secretID, payload)
}
func (c *gcpSecretManagerClient) AccessLatestVersion(ctx context.Context, projectID, secretID string) ([]byte, error) {
	return c.inner.AccessLatest(ctx, projectID, secretID)
}

// Helper to initialize a default SecretManagerStorage with real GCP client (defined in secret_manager_impl.go)
func NewDefaultSecretManagerStorage(projectID string) (*SecretManagerStorage, error) {
	inner, err := NewGCPSecretManagerInner()
	if err != nil {
		return nil, err
	}
	client := &gcpSecretManagerClient{inner: inner}
	return NewSecretManagerStorage(client, projectID), nil
}

// JSON marshalling helpers for testing/logging
func (s *SecretManagerStorage) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"project_id": s.projectID,
	})
}
