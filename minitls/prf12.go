package minitls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// TLS 1.2 PRF Implementation
// Based on RFC 5246 Section 5 - HMAC and the Pseudorandom Function

// pHash implements the P_hash function from RFC 5246
// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//
//	HMAC_hash(secret, A(2) + seed) +
//	HMAC_hash(secret, A(3) + seed) + ...
//
// where A(0) = seed
//
//	A(i) = HMAC_hash(secret, A(i-1))
func pHash(hashFunc func() hash.Hash, secret, seed []byte, length int) []byte {
	h := hmac.New(hashFunc, secret)
	h.Write(seed)
	a := h.Sum(nil) // A(1)

	result := make([]byte, 0, length)
	for len(result) < length {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)

		todo := len(b)
		if len(result)+todo > length {
			todo = length - len(result)
		}
		result = append(result, b[:todo]...)

		// Calculate A(i+1)
		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}

	return result
}

// prf12 implements the TLS 1.2 PRF function
// PRF(secret, label, seed) = P_SHA256(secret, label + seed) for SHA-256 based ciphers
// PRF(secret, label, seed) = P_SHA384(secret, label + seed) for SHA-384 based ciphers
func prf12(cipherSuite uint16, secret []byte, label string, seed []byte, length int) []byte {
	// TLS 1.2 suites carry their PRF hash in the negotiated suite metadata.
	hashFunc := sha256.New
	if info := GetCipherSuiteInfo(cipherSuite); info != nil && info.HashFunc == "SHA384" {
		hashFunc = sha512.New384
	}

	// Construct the seed: label + seed
	labelSeed := make([]byte, len(label)+len(seed))
	copy(labelSeed, label)
	copy(labelSeed[len(label):], seed)

	return pHash(hashFunc, secret, labelSeed, length)
}

// TLS12KeySchedule manages TLS 1.2 key derivation
type TLS12KeySchedule struct {
	cipherSuite  uint16
	masterSecret []byte
	clientRandom []byte
	serverRandom []byte
}

// NewTLS12KeySchedule creates a new TLS 1.2 key schedule
func NewTLS12KeySchedule(cipherSuite uint16, masterSecret, clientRandom, serverRandom []byte) *TLS12KeySchedule {
	ks := &TLS12KeySchedule{
		cipherSuite:  cipherSuite,
		masterSecret: make([]byte, len(masterSecret)),
		clientRandom: make([]byte, len(clientRandom)),
		serverRandom: make([]byte, len(serverRandom)),
	}

	// Copy the actual content to the allocated arrays
	if masterSecret != nil {
		copy(ks.masterSecret, masterSecret)
	}
	copy(ks.clientRandom, clientRandom)
	copy(ks.serverRandom, serverRandom)

	return ks
}

// DeriveMasterSecret derives the master secret from the pre-master secret
// Standard: master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]
// RFC 7627: master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..47]
func (ks *TLS12KeySchedule) DeriveMasterSecret(preMasterSecret []byte) {
	// Concatenate client and server random values (standard algorithm)
	randomBytes := make([]byte, len(ks.clientRandom)+len(ks.serverRandom))
	copy(randomBytes, ks.clientRandom)
	copy(randomBytes[len(ks.clientRandom):], ks.serverRandom)

	// Derive master secret using PRF
	ks.masterSecret = prf12(ks.cipherSuite, preMasterSecret, "master secret", randomBytes, 48)
}

// DeriveMasterSecretExtended derives the master secret using Extended Master Secret (RFC 7627)
func (ks *TLS12KeySchedule) DeriveMasterSecretExtended(preMasterSecret []byte, sessionHash []byte) {
	// RFC 7627: master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..47]
	ks.masterSecret = prf12(ks.cipherSuite, preMasterSecret, "extended master secret", sessionHash, 48)
}

// DeriveKeyBlock derives the key block for encryption keys and IVs
// key_block = PRF(SecurityParameters.master_secret, "key expansion",
//
//	SecurityParameters.server_random + SecurityParameters.client_random)
func (ks *TLS12KeySchedule) DeriveKeyBlock(keyBlockLength int) []byte {
	// for key derivation, we use server_random + client_random (opposite order from master secret)
	randomBytes := make([]byte, len(ks.serverRandom)+len(ks.clientRandom))
	copy(randomBytes, ks.serverRandom)
	copy(randomBytes[len(ks.serverRandom):], ks.clientRandom)

	return prf12(ks.cipherSuite, ks.masterSecret, "key expansion", randomBytes, keyBlockLength)
}

// DeriveFinishedKeys derives the finished message verification keys
// finished_label = "client finished" or "server finished"
// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1]
func (ks *TLS12KeySchedule) DeriveFinishedData(handshakeHash []byte, isClient bool) []byte {
	var label string
	if isClient {
		label = "client finished"
	} else {
		label = "server finished"
	}

	// For TLS 1.2, finished data length is 12 bytes
	return prf12(ks.cipherSuite, ks.masterSecret, label, handshakeHash, 12)
}

// GetKeyAndIVLengths returns the key and IV lengths for the cipher suite
func (ks *TLS12KeySchedule) GetKeyAndIVLengths() (keyLen, ivLen int) {
	switch ks.cipherSuite {
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return 16, 4 // AES-128: 16-byte key, 4-byte implicit IV
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return 32, 4 // AES-256: 32-byte key, 4-byte implicit IV
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return 32, 12 // ChaCha20: 32-byte key, 12-byte implicit IV
	default:
		return 0, 0 // Unknown cipher suite
	}
}

// DeriveKeys derives all the necessary keys and IVs for TLS 1.2 AEAD
func (ks *TLS12KeySchedule) DeriveKeys() (clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV []byte, err error) {
	keyLen, ivLen := ks.GetKeyAndIVLengths()
	if keyLen == 0 || ivLen == 0 {
		return nil, nil, nil, nil, fmt.Errorf("unsupported cipher suite: 0x%04x", ks.cipherSuite)
	}

	// Total key block length: 2 * (keyLen + ivLen)
	keyBlockLength := 2 * (keyLen + ivLen)
	keyBlock := ks.DeriveKeyBlock(keyBlockLength)

	// Extract keys and IVs from key block
	// key_block = client_write_key + server_write_key + client_write_IV + server_write_IV
	offset := 0

	clientWriteKey = make([]byte, keyLen)
	copy(clientWriteKey, keyBlock[offset:offset+keyLen])
	offset += keyLen

	serverWriteKey = make([]byte, keyLen)
	copy(serverWriteKey, keyBlock[offset:offset+keyLen])
	offset += keyLen

	clientWriteIV = make([]byte, ivLen)
	copy(clientWriteIV, keyBlock[offset:offset+ivLen])
	offset += ivLen

	serverWriteIV = make([]byte, ivLen)
	copy(serverWriteIV, keyBlock[offset:offset+ivLen])

	return clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV, nil
}

// TLS12CBCKeys contains the six values derived for a TLS 1.2 block-cipher
// connection. The ordering follows RFC 5246 section 6.3.
type TLS12CBCKeys struct {
	ClientMACKey []byte
	ServerMACKey []byte
	ClientKey    []byte
	ServerKey    []byte
	ClientIV     []byte
	ServerIV     []byte
}

// DeriveCBCKeys derives the MAC keys, AES keys, and IVs for a supported
// TLS 1.2 AES-CBC suite.
func (ks *TLS12KeySchedule) DeriveCBCKeys() (*TLS12CBCKeys, error) {
	info := GetCipherSuiteInfo(ks.cipherSuite)
	if info == nil || !info.IsCBC || info.MACSize == 0 || info.IVSize == 0 {
		return nil, fmt.Errorf("unsupported TLS 1.2 CBC cipher suite: 0x%04x", ks.cipherSuite)
	}

	keyBlock := ks.DeriveKeyBlock(2 * (info.MACSize + info.KeySize + info.IVSize))
	offset := 0
	take := func(length int) []byte {
		value := append([]byte(nil), keyBlock[offset:offset+length]...)
		offset += length
		return value
	}

	return &TLS12CBCKeys{
		ClientMACKey: take(info.MACSize),
		ServerMACKey: take(info.MACSize),
		ClientKey:    take(info.KeySize),
		ServerKey:    take(info.KeySize),
		ClientIV:     take(info.IVSize),
		ServerIV:     take(info.IVSize),
	}, nil
}
