package minitls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"

	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
)

// TLS 1.3 Key Schedule
type KeySchedule struct {
	cipherSuite     uint16
	sharedSecret    []byte
	handshakeHash   []byte
	handshakeSecret []byte

	// Handshake keys
	clientHandshakeKey []byte
	clientHandshakeIV  []byte
	serverHandshakeKey []byte
	serverHandshakeIV  []byte

	// Finished keys
	clientFinishedKey []byte
	serverFinishedKey []byte

	// Application keys
	clientAppKey []byte
	clientAppIV  []byte
	serverAppKey []byte
	serverAppIV  []byte
}

// NewKeySchedule creates a new key schedule with the given parameters
func NewKeySchedule(cipherSuite uint16, sharedSecret []byte, transcript []byte) *KeySchedule {
	// Calculate initial handshake hash from transcript
	ks := &KeySchedule{
		cipherSuite:  cipherSuite,
		sharedSecret: sharedSecret,
	}

	// Hash the transcript to get handshake hash
	hasher := ks.getHashFunc()()
	hasher.Write(transcript)
	ks.handshakeHash = hasher.Sum(nil)

	//	cipherSuite, len(transcript), len(ks.handshakeHash))

	return ks
}

func (ks *KeySchedule) getHashFunc() func() hash.Hash {
	switch ks.cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256:
		return sha256.New
	case TLS_AES_256_GCM_SHA384:
		return sha512.New384
	default:
		return sha256.New
	}
}

func (ks *KeySchedule) getHashSize() int {
	switch ks.cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256:
		return 32
	case TLS_AES_256_GCM_SHA384:
		return 48
	default:
		return 32
	}
}

// DeriveHandshakeKeys derives the handshake encryption keys
func (ks *KeySchedule) DeriveHandshakeKeys() error {
	var keyLen, ivLen int
	hashSize := ks.getHashSize()

	// Determine key and IV lengths based on cipher suite
	switch ks.cipherSuite {
	case TLS_AES_128_GCM_SHA256:
		keyLen, ivLen = 16, 12
	case TLS_AES_256_GCM_SHA384:
		keyLen, ivLen = 32, 12
	case TLS_CHACHA20_POLY1305_SHA256:
		keyLen, ivLen = 32, 12
	default:
		return fmt.Errorf("unsupported cipher suite: 0x%04x", ks.cipherSuite)
	}

	// TLS 1.3 key schedule:
	// Early Secret = HKDF-Extract(0, 0)
	// dHS = HKDF-Expand-Label(Early Secret, "derived", Hash(""), Hash.length)
	// Handshake Secret = HKDF-Extract(dHS, ECDHE)
	// [sender]_handshake_traffic_secret = HKDF-Expand-Label(Handshake Secret, "[sender] hs traffic", ClientHello...ServerHello, Hash.length)

	// Step 1: Early Secret = HKDF-Extract(salt=0, ikm=0)
	earlySecret := ks.hkdfExtract(nil, make([]byte, hashSize))

	// Step 2: Derive handshake secret
	// dHS = HKDF-Expand-Label(Early Secret, "derived", Hash(""), Hash.length)
	emptyHash := ks.getHashFunc()().Sum(nil)
	derivedSecret := ks.hkdfExpandLabel(earlySecret, "derived", emptyHash, hashSize)

	// Handshake Secret = HKDF-Extract(dHS, shared_secret)
	handshakeSecret := ks.hkdfExtract(derivedSecret, ks.sharedSecret)
	ks.handshakeSecret = handshakeSecret

	// Step 3: Derive traffic secrets
	// client_handshake_traffic_secret = HKDF-Expand-Label(Handshake Secret, "c hs traffic", handshake_hash, Hash.length)
	clientTrafficSecret := ks.hkdfExpandLabel(handshakeSecret, "c hs traffic", ks.handshakeHash, hashSize)

	// server_handshake_traffic_secret = HKDF-Expand-Label(Handshake Secret, "s hs traffic", handshake_hash, Hash.length)
	serverTrafficSecret := ks.hkdfExpandLabel(handshakeSecret, "s hs traffic", ks.handshakeHash, hashSize)

	// Step 4: Derive finished keys and store them
	ks.clientFinishedKey = ks.hkdfExpandLabel(clientTrafficSecret, "finished", nil, hashSize)
	ks.serverFinishedKey = ks.hkdfExpandLabel(serverTrafficSecret, "finished", nil, hashSize)

	// Step 5: Derive keys and IVs
	ks.clientHandshakeKey = ks.hkdfExpandLabel(clientTrafficSecret, "key", nil, keyLen)
	ks.clientHandshakeIV = ks.hkdfExpandLabel(clientTrafficSecret, "iv", nil, ivLen)
	ks.serverHandshakeKey = ks.hkdfExpandLabel(serverTrafficSecret, "key", nil, keyLen)
	ks.serverHandshakeIV = ks.hkdfExpandLabel(serverTrafficSecret, "iv", nil, ivLen)

	return nil
}

// DeriveApplicationKeys derives the application data encryption keys
func (ks *KeySchedule) DeriveApplicationKeys(transcriptHash []byte) error {
	var keyLen, ivLen int
	hashSize := ks.getHashSize()

	// Determine key and IV lengths
	switch ks.cipherSuite {
	case TLS_AES_128_GCM_SHA256:
		keyLen, ivLen = 16, 12
	case TLS_AES_256_GCM_SHA384:
		keyLen, ivLen = 32, 12
	case TLS_CHACHA20_POLY1305_SHA256:
		keyLen, ivLen = 32, 12
	default:
		return fmt.Errorf("unsupported cipher suite: 0x%04x", ks.cipherSuite)
	}

	if ks.handshakeSecret == nil {
		return fmt.Errorf("handshake secret not derived or stored")
	}

	// Derive master secret from the stored handshake secret
	// dMS = HKDF-Expand-Label(Handshake Secret, "derived", Hash(""), Hash.length)
	emptyHash := ks.getHashFunc()().Sum(nil)
	derivedMasterSecret := ks.hkdfExpandLabel(ks.handshakeSecret, "derived", emptyHash, hashSize)
	masterSecret := ks.hkdfExtract(derivedMasterSecret, make([]byte, hashSize))

	// Derive application traffic secrets using the full transcript hash
	clientAppTrafficSecret := ks.hkdfExpandLabel(masterSecret, "c ap traffic", transcriptHash, hashSize)
	serverAppTrafficSecret := ks.hkdfExpandLabel(masterSecret, "s ap traffic", transcriptHash, hashSize)

	// Derive application keys and IVs
	ks.clientAppKey = ks.hkdfExpandLabel(clientAppTrafficSecret, "key", nil, keyLen)
	ks.clientAppIV = ks.hkdfExpandLabel(clientAppTrafficSecret, "iv", nil, ivLen)
	ks.serverAppKey = ks.hkdfExpandLabel(serverAppTrafficSecret, "key", nil, keyLen)
	ks.serverAppIV = ks.hkdfExpandLabel(serverAppTrafficSecret, "iv", nil, ivLen)

	return nil
}

// createAEAD is a unified helper for creating AEADs with optional sequence number override
func (ks *KeySchedule) createAEAD(key, iv []byte, startSeq *uint64) (*AEAD, error) {
	aead, err := NewAEAD(key, iv, ks.cipherSuite)
	if err != nil {
		return nil, err
	}
	if startSeq != nil {
		aead.seq = *startSeq
	}
	return aead, nil
}

// CreateServerHandshakeAEAD creates an AEAD for decrypting server handshake messages
func (ks *KeySchedule) CreateServerHandshakeAEAD() (*AEAD, error) {
	return ks.createAEAD(ks.serverHandshakeKey, ks.serverHandshakeIV, nil)
}

// CreateClientHandshakeAEAD creates an AEAD for encrypting client handshake messages
func (ks *KeySchedule) CreateClientHandshakeAEAD() (*AEAD, error) {
	return ks.createAEAD(ks.clientHandshakeKey, ks.clientHandshakeIV, nil)
}

// CreateClientApplicationAEAD creates an AEAD for encrypting client application data
func (ks *KeySchedule) CreateClientApplicationAEAD() (*AEAD, error) {
	var seq uint64 = 0
	return ks.createAEAD(ks.clientAppKey, ks.clientAppIV, &seq)
}

// CreateServerApplicationAEAD creates an AEAD for decrypting server application data
func (ks *KeySchedule) CreateServerApplicationAEAD() (*AEAD, error) {
	var seq uint64 = 0
	return ks.createAEAD(ks.serverAppKey, ks.serverAppIV, &seq)
}

// HKDF-Extract for TLS 1.3
func (ks *KeySchedule) hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, ks.getHashSize())
	}
	return hkdf.Extract(ks.getHashFunc(), ikm, salt)
}

// HKDF-Expand-Label for TLS 1.3
func (ks *KeySchedule) hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	hkdfLabel := make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
	hkdfLabel = append(hkdfLabel, "tls13 "...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	reader := hkdf.Expand(ks.getHashFunc(), secret, hkdfLabel)
	result := make([]byte, length)
	reader.Read(result)

	return result
}

// AEAD provides authenticated encryption with associated data
type AEAD struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

// NewAEAD creates a new AEAD instance
func NewAEAD(key, iv []byte, cipherSuite uint16) (*AEAD, error) {
	var aead cipher.AEAD
	var err error

	// Select cipher based on TLS cipher suite, not just key length
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		// AES-128-GCM
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

	case TLS_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		// AES-256-GCM
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

	case TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		// ChaCha20-Poly1305
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	return &AEAD{
		aead: aead,
		iv:   iv,
		seq:  0,
	}, nil
}

func (a *AEAD) Encrypt(plaintext, additionalData []byte) []byte {
	nonce := make([]byte, len(a.iv))
	copy(nonce, a.iv)

	// XOR sequence number into nonce
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(a.seq >> (8 * i))
	}

	ciphertext := a.aead.Seal(nil, nonce, plaintext, additionalData)
	a.seq++
	return ciphertext
}

func (a *AEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, len(a.iv))
	copy(nonce, a.iv)

	// XOR sequence number into nonce
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(a.seq >> (8 * i))
	}

	plaintext, err := a.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	a.seq++
	return plaintext, nil
}

// GetSequence returns the current sequence number of the AEAD
func (a *AEAD) GetSequence() uint64 {
	return a.seq
}

var ErrSequenceNumberOverflow = fmt.Errorf("sequence number overflow: must renegotiate connection")

func (a *AEAD) EncryptChecked(plaintext, additionalData []byte) ([]byte, error) {
	if a.seq == math.MaxUint64 {
		return nil, ErrSequenceNumberOverflow
	}
	return a.Encrypt(plaintext, additionalData), nil
}

func (a *AEAD) DecryptChecked(ciphertext, additionalData []byte) ([]byte, error) {
	if a.seq == math.MaxUint64 {
		return nil, ErrSequenceNumberOverflow
	}
	return a.Decrypt(ciphertext, additionalData)
}

// CalculateServerFinishedVerifyData calculates the expected verify_data for server Finished message
func (ks *KeySchedule) CalculateServerFinishedVerifyData(transcriptHash []byte) ([]byte, error) {
	if ks.serverFinishedKey == nil {
		return nil, fmt.Errorf("server finished key not derived")
	}

	// Calculate HMAC(finished_key, transcript_hash)
	mac := hmac.New(ks.getHashFunc(), ks.serverFinishedKey)
	mac.Write(transcriptHash)
	verifyData := mac.Sum(nil)

	return verifyData, nil
}

// CalculateClientFinishedVerifyData calculates the expected verify_data for the client's Finished message
func (ks *KeySchedule) CalculateClientFinishedVerifyData(transcriptHash []byte) ([]byte, error) {
	if ks.clientFinishedKey == nil {
		return nil, fmt.Errorf("client finished key not derived")
	}

	// Calculate HMAC(finished_key, transcript_hash)
	mac := hmac.New(ks.getHashFunc(), ks.clientFinishedKey)
	mac.Write(transcriptHash)
	verifyData := mac.Sum(nil)

	return verifyData, nil
}

// Phase 2: Split AEAD Implementation for TEE_K/TEE_T Protocol

// SplitAEAD represents split AEAD implementation for TEE_K/TEE_T protocol
type SplitAEAD struct {
	key         []byte
	iv          []byte
	cipherSuite uint16
	seq         uint64
}

// NewSplitAEAD creates a new split AEAD instance for TEE_K
func NewSplitAEAD(key, iv []byte, cipherSuite uint16) *SplitAEAD {
	return &SplitAEAD{
		key:         key,
		iv:          iv,
		cipherSuite: cipherSuite,
		seq:         0,
	}
}

// EncryptWithoutTag encrypts plaintext but doesn't compute the tag (TEE_K responsibility)
func (sa *SplitAEAD) EncryptWithoutTag(plaintext, additionalData []byte) ([]byte, []byte, error) {
	if sa.seq == math.MaxUint64 {
		return nil, nil, ErrSequenceNumberOverflow
	}
	// Use cipher-suite-specific nonce construction
	nonce := sa.constructNonce(sa.seq)

	var ciphertext []byte
	var tagSecrets []byte

	switch sa.cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		// AES-GCM case: split AEAD - encrypt with CTR mode, let TEE_T compute GCM tag
		block, err := aes.NewCipher(sa.key)
		if err != nil {
			return nil, nil, err
		}

		// For AES-CTR, we need 16-byte IV. TLS uses 12-byte IV, so pad with 4 bytes counter
		// GCM nonce format: IV (12 bytes) || counter (4 bytes) starting with 2
		ctrNonce := make([]byte, 16)
		copy(ctrNonce, nonce) // Copy 12-byte TLS nonce
		// Set counter to 2 (matches Go GCM implementation)
		ctrNonce[15] = 2

		// Encrypt plaintext using AES-CTR mode (GCM encryption without tag)
		stream := cipher.NewCTR(block, ctrNonce)
		ciphertext = make([]byte, len(plaintext))
		stream.XORKeyStream(ciphertext, plaintext)

		// Generate tag computation material for AES-GCM:
		// This provides TEE_T with the secrets needed to compute the GCM tag
		tagSecrets = sa.generateGCMTagSecrets(block, nonce)

	case TLS_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		// ChaCha20-Poly1305 case: encrypt with ChaCha20 stream directly

		// Create ChaCha20 cipher
		cphr, err := chacha20.NewUnauthenticatedCipher(sa.key, nonce)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ChaCha20 cipher: %v", err)
		}

		// Set counter to 1 for data encryption (counter 0 is reserved for Poly1305 key)
		cphr.SetCounter(1)

		// Encrypt plaintext using ChaCha20
		ciphertext = make([]byte, len(plaintext))
		cphr.XORKeyStream(ciphertext, plaintext)

		// Generate tag computation material for ChaCha20-Poly1305:
		// First 32 bytes of the Stream Block derived using key K, nonce N and counter 0
		tagSecrets = sa.generateChaChaTagSecrets(nonce)

	default:
		return nil, nil, fmt.Errorf("unsupported cipher suite for split AEAD: 0x%04x", sa.cipherSuite)
	}

	sa.seq++
	return ciphertext, tagSecrets, nil
}

// SetSequence sets the sequence number for the SplitAEAD
func (sa *SplitAEAD) SetSequence(seq uint64) {
	sa.seq = seq
}

// GetSequence returns the current sequence number
func (sa *SplitAEAD) GetSequence() uint64 {
	return sa.seq
}

// constructNonce creates a nonce based on the cipher suite and sequence number
// This consolidates nonce construction logic from TEE_K
func (sa *SplitAEAD) constructNonce(seqNum uint64) []byte {
	switch sa.cipherSuite {
	// TLS 1.3 cipher suites - IV XOR sequence number (RFC 8446)
	case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256:
		nonce := make([]byte, len(sa.iv))
		copy(nonce, sa.iv)
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
		}
		return nonce

	// TLS 1.2 AES-GCM - explicit nonce format (RFC 5288)
	case TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		// 12-byte nonce = implicit_iv(4) || explicit_nonce(8)
		nonce := make([]byte, 12)
		copy(nonce[0:4], sa.iv) // 4-byte implicit IV
		// 8-byte explicit nonce = sequence number (big-endian)
		binary.BigEndian.PutUint64(nonce[4:12], seqNum)
		return nonce

	// TLS 1.2 ChaCha20 - IV XOR sequence number (RFC 7905)
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		nonce := make([]byte, len(sa.iv))
		copy(nonce, sa.iv)
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
		}
		return nonce

	default:
		// Fallback to TLS 1.3 style for unknown cipher suites
		nonce := make([]byte, len(sa.iv))
		copy(nonce, sa.iv)
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
		}
		return nonce
	}
}

// generateGCMTagSecrets generates tag computation material for AES-GCM
// Returns E_K(0^{128}) and E_K(IV || 0^{31} || 1)
func (sa *SplitAEAD) generateGCMTagSecrets(block cipher.Block, nonce []byte) []byte {
	secrets := make([]byte, 32) // 16 bytes for each encryption

	// E_K(0^{128}) - encrypt block of zeros
	zeros := make([]byte, 16)
	block.Encrypt(secrets[0:16], zeros)

	// E_K(IV || 0^{31} || 1) - encrypt nonce padded with zeros and ending with 1
	counterBlock := make([]byte, 16)
	copy(counterBlock, nonce[:min(len(nonce), 12)]) // Copy up to 12 bytes of nonce
	counterBlock[15] = 1                            // Set counter to 1
	block.Encrypt(secrets[16:32], counterBlock)

	return secrets
}

// ConstructTLS12NonceWithExplicitIV constructs TLS 1.2 nonce using explicit IV from TLS record
// This handles the special case where TLS 1.2 AES-GCM uses explicit IV in the record
func ConstructTLS12NonceWithExplicitIV(implicitIV, explicitIV []byte, cipherSuite uint16) ([]byte, error) {
	// Only applies to TLS 1.2 AES-GCM cipher suites
	if !IsTLS12AESGCMCipherSuite(cipherSuite) {
		return nil, fmt.Errorf("explicit IV only used with TLS 1.2 AES-GCM, got cipher suite 0x%04x", cipherSuite)
	}

	if len(implicitIV) != 4 {
		return nil, fmt.Errorf("TLS 1.2 implicit IV must be 4 bytes, got %d", len(implicitIV))
	}
	if len(explicitIV) != 8 {
		return nil, fmt.Errorf("TLS 1.2 explicit IV must be 8 bytes, got %d", len(explicitIV))
	}

	// TLS 1.2 AES-GCM nonce: implicit_iv(4) || explicit_iv(8)
	nonce := make([]byte, 12)
	copy(nonce[0:4], implicitIV)  // 4-byte implicit IV
	copy(nonce[4:12], explicitIV) // 8-byte explicit IV from actual TLS record

	return nonce, nil
}

// GenerateDecryptionStream generates a decryption stream for response decryption
// This consolidates decryption stream logic from TEE_K
// GenerateDecryptionStreamWithNonce generates a decryption stream and returns the nonce used
func GenerateDecryptionStreamWithNonce(key, iv []byte, seqNum uint64, length int, cipherSuite uint16, explicitIV []byte) ([]byte, []byte, error) {
	// Create split AEAD instance for nonce construction
	splitAEAD := NewSplitAEAD(key, iv, cipherSuite)

	var nonce []byte
	if explicitIV != nil && len(explicitIV) == 8 {
		// Use explicit IV for TLS 1.2 AES-GCM
		var err error
		nonce, err = ConstructTLS12NonceWithExplicitIV(iv, explicitIV, cipherSuite)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Use standard nonce construction
		nonce = splitAEAD.constructNonce(seqNum)
	}

	// Generate decryption stream based on cipher suite
	var stream []byte
	var err error
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		stream, err = generateAESDecryptionStream(key, nonce, length)

	case TLS_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		stream, err = generateChaCha20DecryptionStream(key, nonce, length)

	default:
		return nil, nil, fmt.Errorf("unsupported cipher suite for decryption stream: 0x%04x", cipherSuite)
	}

	if err != nil {
		return nil, nil, err
	}

	return stream, nonce, nil
}

// GenerateAESKeystream generates AES-CTR keystream using a nonce
func GenerateAESKeystream(key, nonce []byte, length int) ([]byte, error) {
	return generateAESDecryptionStream(key, nonce, length)
}

// generateAESDecryptionStream generates AES-CTR decryption stream
func generateAESDecryptionStream(key, nonce []byte, length int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create CTR stream with GCM counter format: nonce (12 bytes) + counter (4 bytes)
	ctrNonce := make([]byte, 16)
	copy(ctrNonce, nonce) // 12-byte nonce
	ctrNonce[15] = 2      // Use counter = 2 (matches encryption)

	stream := cipher.NewCTR(block, ctrNonce)
	decryptionStream := make([]byte, length)

	// Generate keystream by XORing with zeros
	stream.XORKeyStream(decryptionStream, make([]byte, length))

	return decryptionStream, nil
}

// GenerateKeystream generates keystream for any supported cipher suite
func GenerateKeystream(cipherSuite uint16, key, nonce []byte, length int) ([]byte, error) {
	if IsChaCha20(cipherSuite) {
		return GenerateChaCha20Keystream(key, nonce, length)
	} else if IsAESGCM(cipherSuite) {
		return GenerateAESKeystream(key, nonce, length)
	}
	return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
}

// GenerateSingleBlockKeystream generates keystream for a single cipher block
// This is used for OPRF block-level operations in ZK circuits
func GenerateSingleBlockKeystream(cipherSuite uint16, serverKey, nonce []byte, counter uint32) ([]byte, error) {
	info := GetCipherSuiteInfo(cipherSuite)
	if info == nil {
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	blockSize := info.BlockSize

	if IsChaCha20(cipherSuite) {
		// ChaCha20: Generate keystream for specific counter position
		fullKeystream, err := GenerateChaCha20Keystream(serverKey, nonce, int(counter)*blockSize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ChaCha20 keystream: %v", err)
		}
		// Extract just the block we need (counter-1 since ChaCha20 counter starts at 1)
		start := int(counter-1) * blockSize
		end := min(start+blockSize, len(fullKeystream))
		return fullKeystream[start:end], nil
	} else {
		// AES-GCM: Account for counter offset
		adjustedBlock := int(counter - 2) // AES-GCM starts at counter=2
		if adjustedBlock < 0 {
			return nil, fmt.Errorf("invalid AES-GCM counter: %d (must be >= 2)", counter)
		}

		// Generate keystream for the exact number of blocks we need
		fullKeystream, err := GenerateAESKeystream(serverKey, nonce, (adjustedBlock+1)*blockSize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate AES keystream: %v", err)
		}

		// Extract the specific block
		start := adjustedBlock * blockSize
		end := start + blockSize
		if end > len(fullKeystream) {
			// Handle partial block
			return fullKeystream[start:], nil
		}
		return fullKeystream[start:end], nil
	}
}

// GetBlockCounter calculates the appropriate counter value for a block number
// based on the cipher suite's specific requirements
func GetBlockCounter(cipherSuite uint16, blockNum int) uint32 {
	if IsChaCha20(cipherSuite) {
		// ChaCha20: counter starts at 1 for data
		return uint32(blockNum + 1)
	} else {
		// AES-GCM: counter starts at 2 (0 for auth tag, 1 skipped, data at 2+)
		return uint32(blockNum + 2)
	}
}

// GenerateChaCha20Keystream generates ChaCha20 keystream using a nonce
func GenerateChaCha20Keystream(key, nonce []byte, length int) ([]byte, error) {
	return generateChaCha20DecryptionStream(key, nonce, length)
}

// generateChaCha20DecryptionStream generates ChaCha20 decryption stream
func generateChaCha20DecryptionStream(key, nonce []byte, length int) ([]byte, error) {
	chachaCipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20 cipher: %v", err)
	}

	// Set counter to 1 for data decryption (matches encryption)
	chachaCipher.SetCounter(1)

	// Generate keystream by XORing with zeros
	decryptionStream := make([]byte, length)
	chachaCipher.XORKeyStream(decryptionStream, make([]byte, length))

	return decryptionStream, nil
}

// generateChaChaTagSecrets generates tag computation material for ChaCha20-Poly1305
// Returns first 32 bytes of the Stream Block derived using key K, nonce N and counter 0
func (sa *SplitAEAD) generateChaChaTagSecrets(nonce []byte) []byte {
	cphr, err := chacha20.NewUnauthenticatedCipher(sa.key, nonce)
	if err != nil {
		// This should not happen with valid key/nonce lengths
		return nil
	}

	// Set counter to 0 for Poly1305 key generation
	cphr.SetCounter(0)

	// Get first 32 bytes of keystream (counter 0) for Poly1305 key
	poly1305Key := make([]byte, 32)
	zeros := make([]byte, 32)
	cphr.XORKeyStream(poly1305Key, zeros)

	return poly1305Key
}

// ComputeTagFromSecrets computes GCM authentication tag using proper GHASH (TEE_T responsibility)
func ComputeTagFromSecrets(ciphertext, tagSecrets []byte, cipherSuite uint16, additionalData []byte) ([]byte, error) {
	// 	cipherSuite, len(additionalData), len(ciphertext))

	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		// Extract E_K(0^128) and E_K(IV || 0^31 || 1) from tag secrets
		if len(tagSecrets) != 32 {
			return nil, fmt.Errorf("tag secrets wrong size: got %d, need 32", len(tagSecrets))
		}

		// E_K(0^128) - GHASH key H (first 16 bytes)
		var ghashKey [16]byte
		copy(ghashKey[:], tagSecrets[0:16])

		// E_K(IV || 0^31 || 1) - encrypted counter block (second 16 bytes)
		encryptedCounter := tagSecrets[16:32]

		// Step 1: Prepare GHASH input: AAD, Ciphertext, len(AAD) || len(Ciphertext) as SEPARATE slices
		// All lengths are in bits, encoded as 64-bit big-endian
		aadBitLen := uint64(len(additionalData)) * 8
		ciphertextBitLen := uint64(len(ciphertext)) * 8

		// Create the length block (64-bit big-endian each)
		lengthBlock := make([]byte, 16)
		binary.BigEndian.PutUint64(lengthBlock[0:8], aadBitLen)
		binary.BigEndian.PutUint64(lengthBlock[8:16], ciphertextBitLen)

		ghashResult := ghash(&ghashKey, additionalData, ciphertext, lengthBlock)

		// Step 3: Final GCM tag = GHASH ⊕ E_K(IV || 0^31 || 1)
		tag := make([]byte, 16)
		for i := range 16 {
			tag[i] = ghashResult[i] ^ encryptedCounter[i]
		}

		return tag, nil

	case TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		// ChaCha20-Poly1305 tag computation using Poly1305 key from tag secrets
		if len(tagSecrets) != 32 {
			return nil, fmt.Errorf("ChaCha20-Poly1305 tag secrets wrong size: got %d, need 32", len(tagSecrets))
		}

		// Use Poly1305 key from tag secrets to compute authentication tag
		poly1305Key := tagSecrets[:32]

		// Create ChaCha20-Poly1305 AEAD with dummy key for tag computation
		// We'll use the poly1305Key directly for tag computation
		tag, err := computePoly1305Tag(poly1305Key, additionalData, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to compute Poly1305 tag: %v", err)
		}

		return tag, nil

	default:
		return nil, fmt.Errorf("unsupported cipher suite for tag computation: 0x%04x", cipherSuite)
	}
}

// gcmFieldElement represents a value in GF(2^128) for GHASH computation
type gcmFieldElement struct {
	low, high uint64
}

// ghash implements GHASH using the algorithm from Go's crypto library
// Adapted from https://raw.githubusercontent.com/golang/go/refs/heads/master/src/crypto/internal/fips140/aes/gcm/ghash.go
func ghash(key *[16]byte, data ...[]byte) []byte {
	var out [16]byte

	// Convert key to field element
	x := gcmFieldElement{
		binary.BigEndian.Uint64(key[:8]),
		binary.BigEndian.Uint64(key[8:]),
	}

	// Precompute multiplication table for efficiency
	var productTable [16]gcmFieldElement
	productTable[reverseBits(1)] = x
	for i := 2; i < 16; i += 2 {
		productTable[reverseBits(i)] = ghashDouble(&productTable[reverseBits(i/2)])
		productTable[reverseBits(i+1)] = ghashAdd(&productTable[reverseBits(i)], &x)
	}

	var y gcmFieldElement
	// Process each data slice separately (like Go's standard implementation)
	for _, slice := range data {
		ghashUpdate(&productTable, &y, slice)
	}

	binary.BigEndian.PutUint64(out[:8], y.low)
	binary.BigEndian.PutUint64(out[8:], y.high)

	return out[:]
}

// Helper functions for GHASH (from Go's crypto library)
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

func ghashAdd(x, y *gcmFieldElement) gcmFieldElement {
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

func ghashDouble(x *gcmFieldElement) (double gcmFieldElement) {
	msbSet := x.high&1 == 1
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	if msbSet {
		double.low ^= 0xe100000000000000
	}
	return
}

var ghashReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

func ghashMul(productTable *[16]gcmFieldElement, y *gcmFieldElement) {
	var z gcmFieldElement
	for i := range 2 {
		word := y.high
		if i == 1 {
			word = y.low
		}

		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(ghashReductionTable[msw]) << 48

			t := productTable[word&0xf]
			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}
	*y = z
}

func ghashUpdate(productTable *[16]gcmFieldElement, y *gcmFieldElement, data []byte) {
	const gcmBlockSize = 16

	// Process full 16-byte blocks
	for len(data) >= gcmBlockSize {
		y.low ^= binary.BigEndian.Uint64(data[:8])
		y.high ^= binary.BigEndian.Uint64(data[8:16])
		ghashMul(productTable, y)
		data = data[gcmBlockSize:]
	}

	// Process remaining bytes (zero-padded)
	if len(data) > 0 {
		var block [gcmBlockSize]byte
		copy(block[:], data)
		y.low ^= binary.BigEndian.Uint64(block[:8])
		y.high ^= binary.BigEndian.Uint64(block[8:16])
		ghashMul(productTable, y)
	}
}

// GetClientApplicationKey returns the client application key for split AEAD
func (ks *KeySchedule) GetClientApplicationKey() []byte {
	return ks.clientAppKey
}

// GetClientApplicationIV returns the client application IV for split AEAD
func (ks *KeySchedule) GetClientApplicationIV() []byte {
	return ks.clientAppIV
}

// GetServerApplicationKey returns the server application key for split AEAD
func (ks *KeySchedule) GetServerApplicationKey() []byte {
	return ks.serverAppKey
}

// GetServerApplicationIV returns the server application IV for split AEAD
func (ks *KeySchedule) GetServerApplicationIV() []byte {
	return ks.serverAppIV
}

// computePoly1305Tag computes Poly1305 authentication tag
func computePoly1305Tag(key []byte, additionalData, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Poly1305 key must be 32 bytes, got %d", len(key))
	}

	// Prepare data for Poly1305 computation according to RFC 8439
	// Format: AAD || pad(AAD) || ciphertext || pad(ciphertext) || len(AAD) || len(ciphertext)

	var polyData []byte

	// Add additional data
	polyData = append(polyData, additionalData...)

	// Pad AAD to 16-byte boundary
	aadPadding := (16 - (len(additionalData) % 16)) % 16
	for range aadPadding {
		polyData = append(polyData, 0)
	}

	// Add ciphertext
	polyData = append(polyData, ciphertext...)

	// Pad ciphertext to 16-byte boundary
	ctPadding := (16 - (len(ciphertext) % 16)) % 16
	for range ctPadding {
		polyData = append(polyData, 0)
	}

	// Add lengths (8 bytes each, little-endian)
	aadLen := make([]byte, 8)
	ctLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(aadLen, uint64(len(additionalData)))
	binary.LittleEndian.PutUint64(ctLen, uint64(len(ciphertext)))
	polyData = append(polyData, aadLen...)
	polyData = append(polyData, ctLen...)

	// Compute Poly1305 tag
	var keyArray [32]byte
	copy(keyArray[:], key)

	var tagArray [16]byte
	poly1305.Sum(&tagArray, polyData, &keyArray)

	return tagArray[:], nil
}

// TLS Record Types
const (
	RecordTypeChangeCipherSpec = 0x14
	RecordTypeAlert            = 0x15
	RecordTypeHandshake        = 0x16
	RecordTypeApplicationData  = 0x17
	RecordTypeHeartbeat        = 0x18
)

// CreateTLSRecord creates a TLS record with the given type and payload
func CreateTLSRecord(recordType byte, payload []byte) []byte {
	recordLength := len(payload)
	tlsRecord := make([]byte, 5+recordLength)
	tlsRecord[0] = recordType                // Record type
	tlsRecord[1] = 0x03                      // TLS version major (compatibility)
	tlsRecord[2] = 0x03                      // TLS version minor (compatibility)
	tlsRecord[3] = byte(recordLength >> 8)   // Length high byte
	tlsRecord[4] = byte(recordLength & 0xFF) // Length low byte
	copy(tlsRecord[5:], payload)             // Payload
	return tlsRecord
}

// CreateApplicationDataRecord creates a TLS ApplicationData record
func CreateApplicationDataRecord(payload []byte) []byte {
	return CreateTLSRecord(RecordTypeApplicationData, payload)
}

// CreateTLS12AEADPayload creates the payload for TLS 1.2 AEAD cipher suites
// Format: explicit_iv(8) + encrypted_data + auth_tag(16)
func CreateTLS12AEADPayload(seqNum uint64, encryptedData, authTag []byte) []byte {
	// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
	explicitIV := make([]byte, 8)
	binary.BigEndian.PutUint64(explicitIV, seqNum)

	payload := make([]byte, 8+len(encryptedData)+len(authTag))
	copy(payload[0:8], explicitIV)
	copy(payload[8:8+len(encryptedData)], encryptedData)
	copy(payload[8+len(encryptedData):], authTag)
	return payload
}

// CreateTLS13AEADPayload creates the payload for TLS 1.3 AEAD cipher suites
// Format: encrypted_data + auth_tag
func CreateTLS13AEADPayload(encryptedData, authTag []byte) []byte {
	payload := make([]byte, len(encryptedData)+len(authTag))
	copy(payload, encryptedData)
	copy(payload[len(encryptedData):], authTag)
	return payload
}

// CreateAdditionalDataTLS12 creates the additional data for TLS 1.2 AEAD
// Format: seq_num(8) + record_header(5) with plaintext length
func CreateAdditionalDataTLS12(seqNum uint64, plaintextLength int) []byte {
	additionalData := make([]byte, 13)
	binary.BigEndian.PutUint64(additionalData[0:8], seqNum)
	additionalData[8] = RecordTypeApplicationData
	additionalData[9] = 0x03
	additionalData[10] = 0x03
	binary.BigEndian.PutUint16(additionalData[11:13], uint16(plaintextLength))
	return additionalData
}

// CreateAdditionalDataTLS13 creates the additional data for TLS 1.3 AEAD
// Format: record_header(5) with ciphertext length (includes tag)
func CreateAdditionalDataTLS13(ciphertextLength int) []byte {
	return []byte{
		RecordTypeApplicationData,
		0x03,
		0x03,
		byte(ciphertextLength >> 8),
		byte(ciphertextLength & 0xFF),
	}
}

// PrepareDataForTLS13 adds inner content type and padding for TLS 1.3
func PrepareDataForTLS13(data []byte) []byte {
	// TLS 1.3 requires inner content type + at least one padding byte
	result := make([]byte, len(data)+2)
	copy(result, data)
	result[len(data)] = RecordTypeApplicationData // Inner content type
	result[len(data)+1] = 0x00                    // Required padding byte
	return result
}

// PrepareDataForEncryption prepares data for encryption based on cipher suite
// TLS 1.3 cipher suites need inner content type and padding
// TLS 1.2 cipher suites use raw data
func PrepareDataForEncryption(data []byte, cipherSuite uint16) []byte {
	if IsTLS13CipherSuite(cipherSuite) {
		return PrepareDataForTLS13(data)
	}
	// TLS 1.2: no modification needed
	return data
}

// CreateAdditionalData creates the additional data for AEAD based on cipher suite
func CreateAdditionalData(cipherSuite uint16, seqNum uint64, plaintextLength int) []byte {
	if IsTLS13CipherSuite(cipherSuite) {
		// TLS 1.3: record header with ciphertext+tag length
		tagSize := 16
		ciphertextLength := plaintextLength + tagSize
		return CreateAdditionalDataTLS13(ciphertextLength)
	}
	// TLS 1.2: sequence number + record header with plaintext length
	return CreateAdditionalDataTLS12(seqNum, plaintextLength)
}

// CreateAEADPayload creates the AEAD payload based on cipher suite
func CreateAEADPayload(cipherSuite uint16, seqNum uint64, encryptedData, authTag []byte) []byte {
	if IsTLS12AESGCMCipherSuite(cipherSuite) {
		// TLS 1.2 AES-GCM needs explicit IV
		return CreateTLS12AEADPayload(seqNum, encryptedData, authTag)
	}
	// TLS 1.3 or TLS 1.2 ChaCha20: no explicit IV
	return CreateTLS13AEADPayload(encryptedData, authTag)
}
