//go:build !mobile

package shared

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// KMSProvider defines an abstraction over key management systems
// Implementations MUST NOT persist any plaintext keys. They should return
// plaintext data keys to the caller only for in-memory usage.
type KMSProvider interface {
	Encrypt(data []byte, keyID string) ([]byte, error)
	Decrypt(data []byte, keyID string, ciphertextBlob []byte) ([]byte, error)
	GenerateDataKey(keyID string) (*DataKey, error)
}

// DataKey represents a generated data key
type DataKey struct {
	Plaintext      []byte
	CiphertextBlob []byte
}

// GoogleKMSProvider implements KMSProvider using Google Cloud KMS
type GoogleKMSProvider struct {
	kmsClient   *kms.KeyManagementClient
	keyResource string
}

// NewGoogleKMSProvider initializes a GoogleKMSProvider
func NewGoogleKMSProvider(ctx context.Context, projectID, location, keyRing, keyName string) (*GoogleKMSProvider, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP KMS client: %v", err)
	}
	keyResource := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectID, location, keyRing, keyName)
	return &GoogleKMSProvider{kmsClient: client, keyResource: keyResource}, nil
}

func (p *GoogleKMSProvider) GenerateDataKey(keyID string) (*DataKey, error) {
	// Generate 32 random bytes locally and wrap with Cloud KMS
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate random data key: %v", err)
	}
	resp, err := p.kmsClient.Encrypt(context.Background(), &kmspb.EncryptRequest{
		Name:      p.keyResource,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms Encrypt failed: %v", err)
	}
	return &DataKey{Plaintext: plaintext, CiphertextBlob: resp.Ciphertext}, nil
}

func (p *GoogleKMSProvider) Encrypt(data []byte, keyID string) ([]byte, error) {
	dk, err := p.GenerateDataKey("")
	if err != nil {
		return nil, err
	}
	return aesGCMOperation(dk.Plaintext, data, true)
}

func (p *GoogleKMSProvider) Decrypt(data []byte, keyID string, ciphertextBlob []byte) ([]byte, error) {
	if len(ciphertextBlob) == 0 {
		return nil, fmt.Errorf("missing wrapped data key for decryption")
	}
	resp, err := p.kmsClient.Decrypt(context.Background(), &kmspb.DecryptRequest{
		Name:       p.keyResource,
		Ciphertext: ciphertextBlob,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms Decrypt failed: %v", err)
	}
	return aesGCMOperation(resp.Plaintext, data, false)
}

// aesGCMOperation handles AES-GCM encryption or decryption based on the encrypt flag
func aesGCMOperation(key, data []byte, encrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()

	if encrypt {
		// Encryption: generate nonce and encrypt
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %v", err)
		}
		// Return nonce + ciphertext
		return append(nonce, gcm.Seal(nil, nonce, data, nil)...), nil
	} else {
		// Decryption: extract nonce and decrypt
		if len(data) < nonceSize {
			return nil, errors.New("encrypted data too short")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		return gcm.Open(nil, nonce, ciphertext, nil)
	}
}
