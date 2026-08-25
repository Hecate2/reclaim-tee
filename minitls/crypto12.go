package minitls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

// TLS 1.2 AEAD Implementation
// Adapts existing AEAD ciphers for TLS 1.2 explicit sequence numbers and nonce construction
// Based on RFC 5246 and Go's crypto/tls implementation

// TLS12AEADContext manages AEAD encryption/decryption for TLS 1.2
type TLS12AEADContext struct {
	writeKey    []byte // Encryption key for outgoing data
	writeIV     []byte // 4-byte implicit IV for outgoing data
	readKey     []byte // Decryption key for incoming data
	readIV      []byte // 4-byte implicit IV for incoming data
	writeSeq    uint64 // Explicit sequence number for writes
	readSeq     uint64 // Explicit sequence number for reads
	cipherSuite uint16 // TLS 1.2 cipher suite
}

// NewTLS12AEADContext creates a new TLS 1.2 AEAD context
func NewTLS12AEADContext(writeKey, writeIV, readKey, readIV []byte, cipherSuite uint16) (*TLS12AEADContext, error) {
	// Validate key and IV lengths based on cipher suite
	expectedKeyLen, expectedIVLen := getTLS12AEADKeyLengths(cipherSuite)

	if len(writeKey) != expectedKeyLen {
		return nil, fmt.Errorf("invalid write key length: got %d, expected %d", len(writeKey), expectedKeyLen)
	}
	if len(readKey) != expectedKeyLen {
		return nil, fmt.Errorf("invalid read key length: got %d, expected %d", len(readKey), expectedKeyLen)
	}
	if len(writeIV) != expectedIVLen {
		return nil, fmt.Errorf("invalid write IV length: got %d, expected %d", len(writeIV), expectedIVLen)
	}
	if len(readIV) != expectedIVLen {
		return nil, fmt.Errorf("invalid read IV length: got %d, expected %d", len(readIV), expectedIVLen)
	}

	ctx := &TLS12AEADContext{
		writeKey:    make([]byte, len(writeKey)),
		writeIV:     make([]byte, len(writeIV)),
		readKey:     make([]byte, len(readKey)),
		readIV:      make([]byte, len(readIV)),
		writeSeq:    0,
		readSeq:     0,
		cipherSuite: cipherSuite,
	}

	// Copy the actual key and IV data
	copy(ctx.writeKey, writeKey)
	copy(ctx.writeIV, writeIV)
	copy(ctx.readKey, readKey)
	copy(ctx.readIV, readIV)

	return ctx, nil
}

// getTLS12AEADKeyLengths returns the key and IV lengths for TLS 1.2 AEAD cipher suites
func getTLS12AEADKeyLengths(cipherSuite uint16) (keyLen int, ivLen int) {
	switch cipherSuite {
	case TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return 16, 4 // AES-128: 16-byte key, 4-byte implicit IV
	case TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return 32, 4 // AES-256: 32-byte key, 4-byte implicit IV
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return 32, 12 // ChaCha20: 32-byte key, 12-byte implicit IV
	default:
		return 0, 0 // Unknown cipher suite
	}
}

// Encrypt encrypts plaintext using TLS 1.2 AEAD as per RFC 5246 Section 6.2.3.3
func (ctx *TLS12AEADContext) Encrypt(plaintext []byte, recordHeader []byte) ([]byte, error) {
	if ctx.writeSeq == math.MaxUint64 {
		return nil, ErrSequenceNumberOverflow
	}
	// Create AEAD instance using native Go crypto (not our TLS 1.3 implementation!)
	var aead cipher.AEAD
	var err error

	switch ctx.cipherSuite {
	case TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		// AES-GCM using native Go crypto
		block, err := aes.NewCipher(ctx.writeKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %v", err)
		}
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		// ChaCha20-Poly1305 using native Go crypto
		aead, err = chacha20poly1305.New(ctx.writeKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", ctx.cipherSuite)
	}

	// RFC 5246: additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length
	additionalData := make([]byte, 8+len(recordHeader))
	binary.BigEndian.PutUint64(additionalData[0:8], ctx.writeSeq)
	copy(additionalData[8:], recordHeader)

	// RFC 5246/RFC 5288: Nonce construction for TLS 1.2
	var nonce []byte
	if ctx.cipherSuite == TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
		ctx.cipherSuite == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
		// ChaCha20-Poly1305: RFC 7905 Section 2
		// "The padded sequence number is XORed with the client_write_IV (when the client is sending)
		// or server_write_IV (when the server is sending)."
		nonce = make([]byte, 12)
		copy(nonce, ctx.writeIV) // Start with 12-byte implicit IV
		// XOR sequence number into the nonce (same as TLS 1.3)
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(ctx.writeSeq >> (8 * i))
		}
	} else {
		// AES-GCM: RFC 5288 Section 3
		// 12-byte nonce = implicit_iv(4) || explicit_nonce(8)
		// explicit_nonce = sequence_number
		nonce = make([]byte, 12)
		copy(nonce[0:4], ctx.writeIV)                         // 4-byte salt
		binary.BigEndian.PutUint64(nonce[4:12], ctx.writeSeq) // 8-byte explicit nonce
	}

	// Encrypt using native Go AEAD - no overriding sequence numbers!
	aeadCiphertext := aead.Seal(nil, nonce, plaintext, additionalData)

	// For AES-GCM, prepend explicit IV to ciphertext (RFC 5288 Section 3)
	var ciphertext []byte
	if IsTLS12AESGCMCipherSuite(ctx.cipherSuite) {
		// AES-GCM: record = explicit_iv || AEAD_ciphertext
		explicitIV := make([]byte, 8)
		binary.BigEndian.PutUint64(explicitIV, ctx.writeSeq)
		ciphertext = append(explicitIV, aeadCiphertext...)
	} else {
		// ChaCha20: record = AEAD_ciphertext (no explicit IV)
		ciphertext = aeadCiphertext
	}

	// Increment sequence number
	ctx.writeSeq++

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using TLS 1.2 AEAD as per RFC 5246 Section 6.2.3.3
func (ctx *TLS12AEADContext) Decrypt(ciphertext []byte, recordHeader []byte) ([]byte, error) {
	if ctx.readSeq == math.MaxUint64 {
		return nil, ErrSequenceNumberOverflow
	}
	// Create AEAD instance using native Go crypto (not our TLS 1.3 implementation!)
	var aead cipher.AEAD
	var err error

	switch ctx.cipherSuite {
	case TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		// AES-GCM using native Go crypto
		block, err := aes.NewCipher(ctx.readKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %v", err)
		}
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		// ChaCha20-Poly1305 using native Go crypto
		aead, err = chacha20poly1305.New(ctx.readKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", ctx.cipherSuite)
	}

	// RFC 5246: additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length
	additionalData := make([]byte, 8+len(recordHeader))
	binary.BigEndian.PutUint64(additionalData[0:8], ctx.readSeq)
	copy(additionalData[8:], recordHeader)

	// RFC 5246/RFC 5288: Nonce construction for TLS 1.2
	var nonce []byte
	if ctx.cipherSuite == TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
		ctx.cipherSuite == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
		// ChaCha20-Poly1305: RFC 7905 Section 2
		// Nonce = implicit_iv XOR sequence_number
		nonce = make([]byte, 12)
		copy(nonce, ctx.readIV) // Start with 12-byte implicit IV
		// XOR sequence number into the nonce
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(ctx.readSeq >> (8 * i))
		}
	} else {
		// AES-GCM: RFC 5288 Section 3
		// For AES-GCM, extract explicit IV from ciphertext
		if len(ciphertext) < 8 {
			return nil, fmt.Errorf("AES-GCM ciphertext too short for explicit IV")
		}
		explicitIV := binary.BigEndian.Uint64(ciphertext[0:8])

		// RFC 5288 Section 3: the explicit nonce SHOULD be the sequence number,
		// but many servers use random values. AEAD authentication ensures integrity
		// regardless of the explicit IV value, so we accept whatever the server sends.

		// 12-byte nonce = implicit_iv(4) || explicit_nonce(8)
		nonce = make([]byte, 12)
		copy(nonce[0:4], ctx.readIV)                        // 4-byte salt
		binary.BigEndian.PutUint64(nonce[4:12], explicitIV) // 8-byte explicit IV from record

	}

	// For AES-GCM, strip explicit IV from ciphertext before decryption
	var aeadCiphertext []byte
	if IsTLS12AESGCMCipherSuite(ctx.cipherSuite) {
		// AES-GCM: strip 8-byte explicit IV
		aeadCiphertext = ciphertext[8:]
	} else {
		// ChaCha20: use full ciphertext
		aeadCiphertext = ciphertext
	}

	// Decrypt using native Go AEAD - no overriding sequence numbers!
	plaintext, err := aead.Open(nil, nonce, aeadCiphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("AEAD decryption failed: %v", err)
	}

	// Increment sequence number
	ctx.readSeq++

	return plaintext, nil
}

// Getter methods for TEE integration

// GetWriteKey returns the client write key
func (ctx *TLS12AEADContext) GetWriteKey() []byte {
	return ctx.writeKey
}

// GetWriteIV returns the client write IV
func (ctx *TLS12AEADContext) GetWriteIV() []byte {
	return ctx.writeIV
}

// GetReadKey returns the server write key (used for reading server data)
func (ctx *TLS12AEADContext) GetReadKey() []byte {
	return ctx.readKey
}

// GetReadIV returns the server write IV (used for reading server data)
func (ctx *TLS12AEADContext) GetReadIV() []byte {
	return ctx.readIV
}

// GetWriteSequence returns the current write sequence number
func (ctx *TLS12AEADContext) GetWriteSequence() uint64 {
	return ctx.writeSeq
}

// GetReadSequence returns the current read sequence number
func (ctx *TLS12AEADContext) GetReadSequence() uint64 {
	return ctx.readSeq
}
