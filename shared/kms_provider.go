//go:build !mobile

package shared

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/austinast/nitro-enclaves-sdk-go/crypto/cms"
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

// AWSKMSProvider implements KMSProvider using the existing VSock KMS proxy
// and Nitro attestation flow already present in the codebase.
type AWSKMSProvider struct {
	connectionMgr *VSockConnectionManager
	serviceName   string
}

func NewAWSKMSProvider(connectionMgr *VSockConnectionManager, serviceName string) *AWSKMSProvider {
	return &AWSKMSProvider{
		connectionMgr: connectionMgr,
		serviceName:   serviceName,
	}
}

// shared request/response types to match proxy expectations
type kmsRecipientInfo struct {
	AttestationDocument    []byte `json:"attestation_document"`
	KeyEncryptionAlgorithm string `json:"key_encryption_algorithm"`
}

type kmsGenerateDataKeyInput struct {
	KeyId     string            `json:"key_id"`
	KeySpec   string            `json:"key_spec"`
	Recipient *kmsRecipientInfo `json:"recipient"`
}

type kmsGenerateDataKeyOutput struct {
	CiphertextBlob         []byte `json:"ciphertext_blob"`
	CiphertextForRecipient []byte `json:"ciphertext_for_recipient"`
}

type kmsDecryptInput struct {
	KeyId               string            `json:"key_id"`
	CiphertextBlob      []byte            `json:"ciphertext_blob"`
	EncryptionAlgorithm string            `json:"encryption_algorithm"`
	Recipient           *kmsRecipientInfo `json:"recipient"`
}

type kmsDecryptOutput struct {
	CiphertextForRecipient []byte `json:"ciphertext_for_recipient"`
}

func (p *AWSKMSProvider) GenerateDataKey(keyID string) (*DataKey, error) {
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get enclave handle: %v", err)
	}

	attestationDoc, err := handle.generateAttestation(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	input := kmsGenerateDataKeyInput{
		KeyId:   keyID,
		KeySpec: "AES_256",
		Recipient: &kmsRecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256",
		},
	}

	// Send to KMS proxy via VSock
	raw, err := p.connectionMgr.SendKMSRequest(context.Background(), "GenerateDataKey", p.serviceName, input)
	if err != nil {
		return nil, fmt.Errorf("KMS GenerateDataKey failed: %v", err)
	}

	var out kmsGenerateDataKeyOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("failed to parse KMS output: %v", err)
	}

	// Decrypt the enveloped key using enclave's private key
	plaintextKey, err := decryptWithEnclavePrivateKey(out.CiphertextForRecipient)
	if err != nil {
		return nil, err
	}

	return &DataKey{Plaintext: plaintextKey, CiphertextBlob: out.CiphertextBlob}, nil
}

// Encrypt returns AES-GCM encrypted bytes using a fresh data key from KMS.
// The caller is responsible for persisting the returned ciphertext alongside
// the DataKey.CiphertextBlob (returned via GenerateDataKey) for later decryption.
func (p *AWSKMSProvider) Encrypt(data []byte, keyID string) ([]byte, error) {
	dk, err := p.GenerateDataKey(keyID)
	if err != nil {
		return nil, err
	}
	// Encrypt data using the plaintext data key
	return aesGCMOperation(dk.Plaintext, data, true)
}

// Decrypt uses KMS to unwrap the data key, then AES-GCM to decrypt data.
// Requires the original CiphertextBlob corresponding to the data key used.
func (p *AWSKMSProvider) Decrypt(data []byte, keyID string, ciphertextBlob []byte) ([]byte, error) {
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get enclave handle: %v", err)
	}

	attestationDoc, err := handle.generateAttestation(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	input := kmsDecryptInput{
		KeyId:               keyID,
		CiphertextBlob:      ciphertextBlob,
		EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
		Recipient: &kmsRecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256",
		},
	}

	raw, err := p.connectionMgr.SendKMSRequest(context.Background(), "Decrypt", p.serviceName, input)
	if err != nil {
		return nil, fmt.Errorf("KMS Decrypt failed: %v", err)
	}

	var out kmsDecryptOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("failed to parse KMS decrypt response: %v", err)
	}

	// Unwrap data key and decrypt
	plaintextKey, err := decryptWithEnclavePrivateKey(out.CiphertextForRecipient)
	if err != nil {
		return nil, err
	}
	return aesGCMOperation(plaintextKey, data, false)
}

// decryptWithEnclavePrivateKey is a thin wrapper to reuse CMS decryption
func decryptWithEnclavePrivateKey(ciphertextForRecipient []byte) ([]byte, error) {
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get enclave handle: %v", err)
	}
	plaintextKey, err := decryptEnvelopedKey(handle, ciphertextForRecipient)
	if err != nil {
		return nil, err
	}
	return plaintextKey, nil
}

// decryptEnvelopedKey uses the enclave private key via CMS helper in kms_handler.go
func decryptEnvelopedKey(handle *EnclaveHandle, ciphertextForRecipient []byte) ([]byte, error) {
	return cms.DecryptEnvelopedKey(handle.PrivateKey(), ciphertextForRecipient)
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
