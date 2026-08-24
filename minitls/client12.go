package minitls

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	cryptoed25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"go.uber.org/zap"
)

// TLS 1.2 Client Handshake Implementation
// Implements the 2-RTT handshake flow as specified in RFC 5246

// continueTLS12HandshakeAfterServerHello continues TLS 1.2 handshake after ServerHello has been processed
func (c *Client) continueTLS12HandshakeAfterServerHello() error {
	c.logger.Debug("Continuing TLS 1.2 handshake after ServerHello")

	// Step 3: Read Certificate message
	certificate, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read Certificate: %v", err)
	}
	c.transcript = append(c.transcript, certificate...)

	// Process and verify the certificate (TLS 1.2 format)
	if err := c.processServerCertificateTLS12(certificate); err != nil {
		return fmt.Errorf("failed to process server certificate: %v", err)
	}

	// Steps 4-7 depend on the selected key exchange. ECDHE consumes and
	// verifies ServerKeyExchange; static RSA goes directly to
	// CertificateRequest/ServerHelloDone and encrypts a fresh pre-master secret.
	sharedSecret, clientKeyExchangeMsg, certRequestReceived, err := c.prepareTLS12KeyExchange()
	if err != nil {
		return err
	}

	// An empty client Certificate is a handshake message and therefore must be
	// included in an EMS session hash before ClientKeyExchange.
	if certRequestReceived {
		c.logger.Info("Sending empty Certificate in response to server's CertificateRequest")
		emptyCert := c.buildEmptyCertificateMessageTLS12()
		emptyCertRecord := c.wrapHandshakeMessage(emptyCert)
		if _, err := c.conn.Write(emptyCertRecord); err != nil {
			return fmt.Errorf("failed to send empty Certificate: %v", err)
		}
		c.transcript = append(c.transcript, emptyCert...)
		c.logger.Debug("Sent empty Certificate")
	}

	// Step 8: Calculate session hash for Extended Master Secret INCLUDING ClientKeyExchange
	// RFC 7627 Section 4: "handshake_messages" includes all handshake messages from ClientHello
	// up to and INCLUDING the ClientKeyExchange message
	var sessionHash []byte
	if c.extendedMasterSecret {
		// Copy rather than append in place: c.transcript keeps growing after
		// this and appending to it here would write into its spare capacity.
		transcriptWithCKE := make([]byte, 0, len(c.transcript)+len(clientKeyExchangeMsg))
		transcriptWithCKE = append(transcriptWithCKE, c.transcript...)
		transcriptWithCKE = append(transcriptWithCKE, clientKeyExchangeMsg...)

		hashFunc := c.getHashFuncForCipher(c.cipherSuite)
		hasher := hashFunc()
		hasher.Write(transcriptWithCKE)
		sessionHash = hasher.Sum(nil)
		c.logger.Debug("EMS: Extended Master Secret session hash (including ClientKeyExchange)",
			zap.Int("bytes", len(sessionHash)),
			zap.String("hash", fmt.Sprintf("%x", sessionHash)))
	}

	// Step 9: Initialize TLS 1.2 key schedule and derive master secret
	c.tls12KeySchedule = NewTLS12KeySchedule(c.cipherSuite, nil, c.clientRandom, c.serverRandom)

	if c.extendedMasterSecret {
		// RFC 7627: Use Extended Master Secret
		c.logger.Debug("Using Extended Master Secret (RFC 7627)")
		c.logger.Debug("Pre-master secret generated", zap.Int("bytes", len(sharedSecret)))
		c.logger.Debug("Session hash", zap.Int("bytes", len(sessionHash)), zap.String("hash", fmt.Sprintf("%x", sessionHash)))
		c.tls12KeySchedule.DeriveMasterSecretExtended(sharedSecret, sessionHash)
	} else {
		// Standard master secret derivation
		c.logger.Debug("Using standard master secret derivation")
		c.logger.Debug("Pre-master secret generated", zap.Int("bytes", len(sharedSecret)))
		c.logger.Debug("Client random", zap.String("random", fmt.Sprintf("%x", c.clientRandom)))
		c.logger.Debug("Server random", zap.String("random", fmt.Sprintf("%x", c.serverRandom)))
		c.tls12KeySchedule.DeriveMasterSecret(sharedSecret)
	}

	c.logger.Debug("Master secret derived successfully")

	// Step 10: Now send ClientKeyExchange

	// Wrap in TLS record
	clientKeyExchangeRecord := c.wrapHandshakeMessage(clientKeyExchangeMsg)
	if _, err := c.conn.Write(clientKeyExchangeRecord); err != nil {
		return fmt.Errorf("failed to send ClientKeyExchange: %v", err)
	}

	c.transcript = append(c.transcript, clientKeyExchangeMsg...)
	c.logger.Debug("Sent ClientKeyExchange")

	// Step 9: Send ChangeCipherSpec
	changeCipherSpec := &ChangeCipherSpecMsg{}
	changeCipherSpecRecord := changeCipherSpec.Marshal()
	if _, err := c.conn.Write(changeCipherSpecRecord); err != nil {
		return fmt.Errorf("failed to send ChangeCipherSpec: %v", err)
	}

	c.logger.Debug("Sent ChangeCipherSpec")

	// Step 10: Derive session keys and initialize the negotiated record layer.
	if err := c.initTLS12RecordProtection(); err != nil {
		return fmt.Errorf("failed to initialize TLS 1.2 record protection: %v", err)
	}

	// Step 11: Send Finished message (encrypted)
	if err := c.sendTLS12Finished(true); err != nil {
		return fmt.Errorf("failed to send client Finished: %v", err)
	}

	// Step 12: Read server ChangeCipherSpec
	if err := c.readChangeCipherSpec(); err != nil {
		return fmt.Errorf("failed to read server ChangeCipherSpec: %v", err)
	}

	// Step 13: Read and verify server Finished message
	if err := c.readAndVerifyTLS12Finished(false); err != nil {
		return fmt.Errorf("failed to verify server Finished: %v", err)
	}

	// Step 14: TLS 1.2 sequence numbers continue from handshake (no reset needed)
	// Client has sent 1 encrypted message (Finished), so writeSeq=1
	// Server has sent 1 encrypted message (Finished), so readSeq=1

	return nil
}

func (c *Client) prepareTLS12KeyExchange() (preMasterSecret, clientKeyExchange []byte, certRequestReceived bool, err error) {
	switch TLS12CipherSuiteKeyExchange(c.cipherSuite) {
	case TLS12KeyExchangeECDHE:
		serverKeyExchange, readErr := c.readHandshakeMessage()
		if readErr != nil {
			return nil, nil, false, fmt.Errorf("failed to read ServerKeyExchange: %v", readErr)
		}
		c.transcript = append(c.transcript, serverKeyExchange...)
		msg, parseErr := ParseServerKeyExchange(serverKeyExchange)
		if parseErr != nil {
			return nil, nil, false, fmt.Errorf("failed to parse ServerKeyExchange: %v", parseErr)
		}
		if verifyErr := c.verifyServerKeyExchangeSignature(msg); verifyErr != nil {
			return nil, nil, false, fmt.Errorf("ServerKeyExchange signature verification failed: %v", verifyErr)
		}
		serverPublicKey, parseErr := c.parseServerKeyExchange(serverKeyExchange)
		if parseErr != nil {
			return nil, nil, false, fmt.Errorf("failed to parse ServerKeyExchange public key: %v", parseErr)
		}

		var clientCurve ecdh.Curve
		switch msg.GetNamedCurve() {
		case X25519:
			clientCurve = ecdh.X25519()
		case secp256r1:
			clientCurve = ecdh.P256()
		case secp384r1:
			clientCurve = ecdh.P384()
		case secp521r1:
			clientCurve = ecdh.P521()
		default:
			return nil, nil, false, fmt.Errorf("unsupported client curve: %d", msg.GetNamedCurve())
		}
		privateKey, generateErr := clientCurve.GenerateKey(rand.Reader)
		if generateErr != nil {
			return nil, nil, false, fmt.Errorf("failed to generate client ECDH key: %v", generateErr)
		}
		c.logger.Debug("Generated client ECDH key pair", zap.Uint16("curve", msg.GetNamedCurve()))
		certRequestReceived, err = c.readTLS12ServerHelloDone()
		if err != nil {
			return nil, nil, false, err
		}
		secret, ecdhErr := privateKey.ECDH(serverPublicKey)
		if ecdhErr != nil {
			return nil, nil, false, fmt.Errorf("ECDH failed: %v", ecdhErr)
		}
		return secret, NewClientKeyExchange(privateKey.PublicKey().Bytes()).Marshal(), certRequestReceived, nil

	case TLS12KeyExchangeRSA:
		certRequestReceived, err = c.readTLS12ServerHelloDone()
		if err != nil {
			return nil, nil, false, err
		}
		if len(c.serverCertificates) == 0 {
			return nil, nil, false, fmt.Errorf("server certificate is unavailable for RSA key exchange")
		}
		publicKey, ok := c.serverCertificates[0].PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, false, fmt.Errorf("static RSA cipher suite requires an RSA server certificate")
		}
		secret := make([]byte, 48)
		if _, randomErr := io.ReadFull(rand.Reader, secret); randomErr != nil {
			return nil, nil, false, fmt.Errorf("failed to generate RSA pre-master secret: %v", randomErr)
		}
		secret[0] = byte(VersionTLS12 >> 8)
		secret[1] = byte(VersionTLS12 & 0xff)
		encryptedSecret, encryptErr := rsa.EncryptPKCS1v15(rand.Reader, publicKey, secret)
		if encryptErr != nil {
			return nil, nil, false, fmt.Errorf("failed to encrypt RSA pre-master secret: %v", encryptErr)
		}
		return secret, NewRSAClientKeyExchange(encryptedSecret).Marshal(), certRequestReceived, nil
	default:
		return nil, nil, false, fmt.Errorf("unsupported TLS 1.2 key exchange for cipher suite 0x%04x", c.cipherSuite)
	}
}

func (c *Client) readTLS12ServerHelloDone() (bool, error) {
	nextMsg, err := c.readHandshakeMessage()
	if err != nil {
		return false, fmt.Errorf("failed to read next handshake message: %v", err)
	}
	c.transcript = append(c.transcript, nextMsg...)
	if len(nextMsg) == 0 {
		return false, fmt.Errorf("empty handshake message before ServerHelloDone")
	}

	if HandshakeType(nextMsg[0]) == typeCertificateRequest {
		c.logger.Info("Server requested client certificate")
		serverHelloDone, readErr := c.readHandshakeMessage()
		if readErr != nil {
			return false, fmt.Errorf("failed to read ServerHelloDone after CertificateRequest: %v", readErr)
		}
		c.transcript = append(c.transcript, serverHelloDone...)
		if _, parseErr := ParseServerHelloDone(serverHelloDone); parseErr != nil {
			return false, fmt.Errorf("failed to parse ServerHelloDone: %v", parseErr)
		}
		c.logger.Debug("Received Server Hello Done")
		return true, nil
	}
	if HandshakeType(nextMsg[0]) != typeServerHelloDone {
		return false, fmt.Errorf("unexpected handshake message type %d before ServerHelloDone", nextMsg[0])
	}
	if _, err := ParseServerHelloDone(nextMsg); err != nil {
		return false, fmt.Errorf("failed to parse ServerHelloDone: %v", err)
	}
	c.logger.Debug("Received Server Hello Done")
	return false, nil
}

// processServerCertificateTLS12 processes a TLS 1.2 server certificate message
func (c *Client) processServerCertificateTLS12(data []byte) error {
	c.logger.Debug("Processing TLS 1.2 Server Certificate")
	// data is the entire handshake message, including its 4-byte header.
	payload := data[4:]

	// TLS 1.2 Certificate message format (no certificate request context):
	// - Certificate list length (3 bytes)
	// - Certificate list (variable length)

	// 1. Parse Certificate List (3-byte length prefix)
	if len(payload) < 3 {
		return fmt.Errorf("payload too short for certificate list length")
	}
	certListLen := uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])
	if uint32(len(payload)-3) < certListLen {
		return fmt.Errorf("certificate list length (%d) is larger than remaining payload (%d)",
			certListLen, len(payload)-3)
	}
	// Advance payload to the start of the actual list entries
	listBytes := payload[3 : 3+certListLen]

	// 2. Parse each certificate from the list (TLS 1.2 format)
	var certs []*x509.Certificate
	offset := 0
	for offset < len(listBytes) {
		// In TLS 1.2, each certificate entry is just:
		// - Certificate length (3 bytes)
		// - Certificate data (variable length)

		if len(listBytes[offset:]) < 3 {
			return fmt.Errorf("not enough data for certificate length")
		}
		certLen := int(listBytes[offset])<<16 | int(listBytes[offset+1])<<8 | int(listBytes[offset+2])
		offset += 3
		if len(listBytes[offset:]) < certLen {
			return fmt.Errorf("not enough data for certificate body")
		}
		certData := listBytes[offset : offset+certLen]
		offset += certLen

		// Parse the X.509 certificate
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates received")
	}
	if err := c.validateTLS12CertificateAuthentication(certs[0]); err != nil {
		return err
	}

	// Store certificates for signature verification
	c.serverCertificates = certs

	// Extract structured certificate info immediately
	c.certificateInfo = c.extractCertificateInfo(certs)

	// Perform comprehensive certificate validation
	if err := c.verifyCertificateChain(certs, c.serverName, c.Config); err != nil {
		c.logger.Error("Certificate validation failed",
			zap.String("hostname", c.serverName),
			zap.Error(err))
		return err
	}

	c.logger.Debug("Certificate chain validated successfully",
		zap.String("hostname", c.serverName),
		zap.Int("cert_count", len(certs)))

	return nil
}

func (c *Client) validateTLS12CertificateAuthentication(certificate *x509.Certificate) error {
	if certificate == nil {
		return fmt.Errorf("TLS 1.2 server certificate is nil")
	}
	switch TLS12CipherSuiteAuthentication(c.cipherSuite) {
	case TLS12AuthenticationRSA:
		if _, ok := certificate.PublicKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("TLS 1.2 RSA-authenticated cipher suite requires an RSA server certificate")
		}
	case TLS12AuthenticationECDSA:
		if _, ok := certificate.PublicKey.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("TLS 1.2 ECDSA-authenticated cipher suite requires an ECDSA server certificate")
		}
	default:
		return fmt.Errorf("unsupported TLS 1.2 authentication for cipher suite 0x%04x", c.cipherSuite)
	}
	return nil
}

// signatureAlgorithmType represents the type of signature algorithm
type signatureAlgorithmType int

const (
	sigTypeECDSA signatureAlgorithmType = iota
	sigTypeRSAPSS
	sigTypeRSAPKCS1
	sigTypeEd25519
)

// signatureAlgorithmInfo contains metadata about a signature algorithm
type signatureAlgorithmInfo struct {
	algType signatureAlgorithmType
	hash    crypto.Hash
	name    string
}

// supportedSignatureAlgorithms maps signature algorithm IDs to their verification info
var supportedSignatureAlgorithms = map[uint16]signatureAlgorithmInfo{
	// ECDSA algorithms
	ecdsa_secp256r1_sha256: {sigTypeECDSA, crypto.SHA256, "ECDSA-P256-SHA256"},
	ecdsa_secp384r1_sha384: {sigTypeECDSA, crypto.SHA384, "ECDSA-P384-SHA384"},
	ecdsa_secp521r1_sha512: {sigTypeECDSA, crypto.SHA512, "ECDSA-P521-SHA512"},

	// RSA-PSS algorithms with rsaEncryption OID
	rsa_pss_rsae_sha256: {sigTypeRSAPSS, crypto.SHA256, "RSA-PSS-RSAE-SHA256"},
	rsa_pss_rsae_sha384: {sigTypeRSAPSS, crypto.SHA384, "RSA-PSS-RSAE-SHA384"},
	rsa_pss_rsae_sha512: {sigTypeRSAPSS, crypto.SHA512, "RSA-PSS-RSAE-SHA512"},

	// RSA-PSS algorithms with id-RSASSA-PSS OID
	rsa_pss_pss_sha256: {sigTypeRSAPSS, crypto.SHA256, "RSA-PSS-PSS-SHA256"},
	rsa_pss_pss_sha384: {sigTypeRSAPSS, crypto.SHA384, "RSA-PSS-PSS-SHA384"},
	rsa_pss_pss_sha512: {sigTypeRSAPSS, crypto.SHA512, "RSA-PSS-PSS-SHA512"},

	// RSA PKCS#1 v1.5 algorithms
	rsa_pkcs1_sha256: {sigTypeRSAPKCS1, crypto.SHA256, "RSA-PKCS1-SHA256"},
	rsa_pkcs1_sha384: {sigTypeRSAPKCS1, crypto.SHA384, "RSA-PKCS1-SHA384"},
	rsa_pkcs1_sha512: {sigTypeRSAPKCS1, crypto.SHA512, "RSA-PKCS1-SHA512"},

	// EdDSA algorithms
	ed25519: {sigTypeEd25519, 0, "Ed25519"},
}

// verifyServerKeyExchangeSignature verifies the signature on the ServerKeyExchange message
func (c *Client) verifyServerKeyExchangeSignature(msg *ServerKeyExchangeMsg) error {
	if len(c.serverCertificates) == 0 {
		return fmt.Errorf("no server certificates available for signature verification")
	}

	// Use the leaf certificate (first in chain) for verification
	serverCert := c.serverCertificates[0]

	// Build the signed data: ClientHello.random + ServerHello.random + ServerParams
	// RFC 5246 Section 7.4.3: The hash is taken over the concatenation of ClientHello.random,
	// ServerHello.random, and ServerKeyExchange.params
	signedData := make([]byte, 0, 32+32+len(msg.GetServerParams()))
	signedData = append(signedData, c.clientRandom...)
	signedData = append(signedData, c.serverRandom...)
	signedData = append(signedData, msg.GetServerParams()...)

	signAlg := msg.GetSignatureAlgorithm()
	signature := msg.GetSignature()

	// Look up signature algorithm info
	algInfo, supported := supportedSignatureAlgorithms[signAlg]
	if !supported {
		return fmt.Errorf("unsupported signature algorithm: 0x%04x", signAlg)
	}
	switch TLS12CipherSuiteAuthentication(c.cipherSuite) {
	case TLS12AuthenticationRSA:
		if algInfo.algType != sigTypeRSAPSS && algInfo.algType != sigTypeRSAPKCS1 {
			return fmt.Errorf("TLS 1.2 RSA-authenticated cipher suite received %s signature", algInfo.name)
		}
	case TLS12AuthenticationECDSA:
		if algInfo.algType != sigTypeECDSA {
			return fmt.Errorf("TLS 1.2 ECDSA-authenticated cipher suite received %s signature", algInfo.name)
		}
	default:
		return fmt.Errorf("unsupported TLS 1.2 authentication for cipher suite 0x%04x", c.cipherSuite)
	}

	c.logger.Debug("Verifying ServerKeyExchange signature",
		zap.Uint16("signature_algorithm", signAlg),
		zap.String("algorithm_name", algInfo.name),
		zap.Int("signature_length", len(signature)),
		zap.Int("signed_data_length", len(signedData)))

	// Dispatch to appropriate verification function based on algorithm type
	switch algInfo.algType {
	case sigTypeECDSA:
		return c.verifyECDSASignature(serverCert, signedData, signature, algInfo.hash)
	case sigTypeRSAPSS:
		return c.verifyRSAPSSSignature(serverCert, signedData, signature, algInfo.hash)
	case sigTypeRSAPKCS1:
		return c.verifyRSAPKCS1Signature(serverCert, signedData, signature, algInfo.hash)
	case sigTypeEd25519:
		return c.verifyEd25519Signature(serverCert, signedData, signature)
	default:
		return fmt.Errorf("unknown signature algorithm type for 0x%04x", signAlg)
	}
}

// verifyECDSASignature verifies an ECDSA signature
func (c *Client) verifyECDSASignature(cert *x509.Certificate, data, signature []byte, hash crypto.Hash) error {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an ECDSA public key")
	}

	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	if !ecdsa.VerifyASN1(pubKey, hashed, signature) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	c.logger.Debug("ECDSA signature verified successfully")
	return nil
}

// verifyRSAPSSSignature verifies an RSA-PSS signature
func (c *Client) verifyRSAPSSSignature(cert *x509.Certificate, data, signature []byte, hash crypto.Hash) error {
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an RSA public key")
	}

	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hash,
	}

	if err := rsa.VerifyPSS(pubKey, hash, hashed, signature, opts); err != nil {
		return fmt.Errorf("RSA-PSS signature verification failed: %v", err)
	}

	c.logger.Debug("RSA-PSS signature verified successfully")
	return nil
}

// verifyRSAPKCS1Signature verifies an RSA PKCS#1 v1.5 signature
func (c *Client) verifyRSAPKCS1Signature(cert *x509.Certificate, data, signature []byte, hash crypto.Hash) error {
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an RSA public key")
	}

	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, hash, hashed, signature); err != nil {
		return fmt.Errorf("RSA PKCS#1 v1.5 signature verification failed: %v", err)
	}

	c.logger.Debug("RSA PKCS#1 v1.5 signature verified successfully")
	return nil
}

// verifyEd25519Signature verifies an Ed25519 signature
func (c *Client) verifyEd25519Signature(cert *x509.Certificate, data, signature []byte) error {
	pubKey, ok := cert.PublicKey.(cryptoed25519.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an Ed25519 public key")
	}

	if !cryptoed25519.Verify(pubKey, data, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	c.logger.Debug("Ed25519 signature verified successfully")
	return nil
}

// parseServerKeyExchange parses the ServerKeyExchange message and returns the server's public key
func (c *Client) parseServerKeyExchange(data []byte) (*ecdh.PublicKey, error) {
	msg, err := ParseServerKeyExchange(data)
	if err != nil {
		return nil, err
	}

	// Use the curve specified by the server
	var curve ecdh.Curve
	switch msg.GetNamedCurve() {
	case X25519:
		curve = ecdh.X25519()
	case secp256r1:
		curve = ecdh.P256()
	case secp384r1:
		curve = ecdh.P384()
	case secp521r1:
		curve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %d", msg.GetNamedCurve())
	}

	// Convert the raw public key bytes to an ECDH public key
	publicKey, err := curve.NewPublicKey(msg.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	return publicKey, nil
}

// initTLS12AEAD initializes the TLS 1.2 AEAD context with derived keys
func (c *Client) initTLS12AEAD() error {
	// Derive keys using TLS 1.2 key schedule
	clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV, err := c.tls12KeySchedule.DeriveKeys()
	if err != nil {
		return fmt.Errorf("failed to derive TLS 1.2 keys: %v", err)
	}

	// Initialize TLS 1.2 AEAD context
	c.tls12AEAD, err = NewTLS12AEADContext(clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV, c.cipherSuite)
	if err != nil {
		return fmt.Errorf("failed to create TLS 1.2 AEAD context: %v", err)
	}

	return nil
}

func (c *Client) initTLS12RecordProtection() error {
	if !IsTLS12CBCCipherSuite(c.cipherSuite) {
		return c.initTLS12AEAD()
	}
	keys, err := c.tls12KeySchedule.DeriveCBCKeys()
	if err != nil {
		return err
	}
	mode := TLS12CBCRecordModeMACThenEncrypt
	if c.encryptThenMAC {
		mode = TLS12CBCRecordModeEncryptThenMAC
	}
	c.tls12CBC, err = NewTLS12CBCContext(keys, c.cipherSuite, mode)
	if err != nil {
		return fmt.Errorf("create TLS 1.2 CBC context: %v", err)
	}
	return nil
}

// sendTLS12Finished sends a TLS 1.2 Finished message
func (c *Client) sendTLS12Finished(isClient bool) error {
	// Calculate handshake hash for finished message
	transcriptHash := c.calculateHandshakeHash()

	c.logger.Debug("TLS 1.2 Finished: Handshake hash",
		zap.Int("bytes", len(transcriptHash)),
		zap.String("hash", fmt.Sprintf("%x", transcriptHash)),
		zap.Bool("is_client", isClient))

	// Derive finished data using TLS 1.2 PRF
	finishedData := c.tls12KeySchedule.DeriveFinishedData(transcriptHash, isClient)

	c.logger.Debug("TLS 1.2 Finished: Verify data",
		zap.Int("bytes", len(finishedData)),
		zap.String("data", fmt.Sprintf("%x", finishedData)))

	// Create finished message
	finishedMsg, err := NewTLS12Finished(finishedData)
	if err != nil {
		return fmt.Errorf("failed to create TLS 1.2 Finished message: %v", err)
	}
	finishedMsgBytes := finishedMsg.Marshal()

	// Calculate the expected ciphertext length
	plaintext := finishedMsgBytes // Encrypt the entire handshake message (header + verify_data)
	if c.tls12CBC != nil {
		record, err := c.tls12CBC.EncryptRecord(recordTypeHandshake, plaintext)
		if err != nil {
			return fmt.Errorf("failed to encrypt CBC Finished message: %v", err)
		}
		if _, err := c.conn.Write(record); err != nil {
			return fmt.Errorf("failed to send Finished message: %v", err)
		}
		c.transcript = append(c.transcript, finishedMsgBytes...)
		return nil
	}

	// For AES-GCM: explicit_iv(8) + plaintext + AEAD_tag(16)
	// For ChaCha20: plaintext + AEAD_tag(16)
	var expectedCiphertextLen int
	if c.cipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
		c.cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
		c.cipherSuite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
		c.cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
		expectedCiphertextLen = 8 + len(plaintext) + 16 // AES-GCM: explicit_iv + plaintext + auth_tag
	} else {
		expectedCiphertextLen = len(plaintext) + 16 // ChaCha20: plaintext + auth_tag
	}

	// Create record header for AAD with PLAINTEXT length (RFC 5246)
	aadRecordHeader := []byte{recordTypeHandshake, 0x03, 0x03,
		byte(len(plaintext) >> 8), byte(len(plaintext))}

	// Create actual record header for sending with CIPHERTEXT length
	sendRecordHeader := []byte{recordTypeHandshake, 0x03, 0x03,
		byte(expectedCiphertextLen >> 8), byte(expectedCiphertextLen)}

	// Encrypt the finished message using TLS 1.2 AEAD with correct AAD
	encryptedFinished, err := c.tls12AEAD.Encrypt(plaintext, aadRecordHeader)
	if err != nil {
		return fmt.Errorf("failed to encrypt Finished message: %v", err)
	}

	// Verify the actual ciphertext length matches our expectation
	if len(encryptedFinished) != expectedCiphertextLen {
		return fmt.Errorf("unexpected ciphertext length: got %d, expected %d",
			len(encryptedFinished), expectedCiphertextLen)
	}

	// Send the encrypted record
	record := append(sendRecordHeader, encryptedFinished...)
	if _, err := c.conn.Write(record); err != nil {
		return fmt.Errorf("failed to send Finished message: %v", err)
	}

	// Add to transcript AFTER encryption (for future server Finished verification)
	c.transcript = append(c.transcript, finishedMsgBytes...)

	return nil
}

// readAndVerifyTLS12Finished reads and verifies the server's Finished message
func (c *Client) readAndVerifyTLS12Finished(isClient bool) error {
	// Read encrypted handshake record
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return fmt.Errorf("failed to read Finished record header: %v", err)
	}

	recordLength := int(header[3])<<8 | int(header[4])
	if header[0] != recordTypeHandshake || binary.BigEndian.Uint16(header[1:3]) != VersionTLS12 {
		return fmt.Errorf("invalid TLS 1.2 Finished record header")
	}
	encryptedPayload := make([]byte, recordLength)
	if _, err := io.ReadFull(c.conn, encryptedPayload); err != nil {
		return fmt.Errorf("failed to read encrypted Finished: %v", err)
	}

	var plaintext []byte
	var err error
	if c.tls12CBC != nil {
		plaintext, err = c.tls12CBC.DecryptRecord(header, encryptedPayload)
		if err != nil {
			return fmt.Errorf("failed to decrypt Finished message: %v", err)
		}
	} else {
		// For AEAD AAD, use the plaintext length rather than wire length.
		plaintextLength := recordLength - 16
		if IsTLS12AESGCMCipherSuite(c.cipherSuite) {
			plaintextLength -= 8
		}
		if plaintextLength < 0 {
			return fmt.Errorf("invalid TLS 1.2 Finished record length")
		}
		aadHeader := []byte{header[0], header[1], header[2],
			byte(plaintextLength >> 8), byte(plaintextLength)}
		plaintext, err = c.tls12AEAD.Decrypt(encryptedPayload, aadHeader)
		if err != nil {
			return fmt.Errorf("failed to decrypt Finished message: %v", err)
		}
	}

	// Parse the Finished message
	// The plaintext should be the complete handshake message (header + verify_data)
	finishedMsg, err := ParseTLS12Finished(plaintext)
	if err != nil {
		return fmt.Errorf("failed to parse Finished message: %v", err)
	}

	// Verify the finished data
	expectedFinishedData := c.tls12KeySchedule.DeriveFinishedData(c.calculateHandshakeHash(), isClient)
	if !compareBytes(finishedMsg.GetVerifyData(), expectedFinishedData) {
		return fmt.Errorf("Finished message verification failed")
	}

	// Add to transcript
	c.transcript = append(c.transcript, plaintext...)

	return nil
}

// calculateHandshakeHash calculates the handshake hash for TLS 1.2
func (c *Client) calculateHandshakeHash() []byte {
	hasher := c.getHashFuncForCipher(c.cipherSuite)()

	hasher.Write(c.transcript)
	return hasher.Sum(nil)
}

// getHashFuncForCipher returns the hash function for a given cipher suite
func (c *Client) getHashFuncForCipher(cipherSuite uint16) func() hash.Hash {
	info := GetCipherSuiteInfo(cipherSuite)
	if info != nil && info.HashFunc == "SHA384" {
		return sha512.New384
	}
	return sha256.New
}

// readChangeCipherSpec reads and validates a ChangeCipherSpec message
func (c *Client) readChangeCipherSpec() error {
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return fmt.Errorf("failed to read ChangeCipherSpec header: %v", err)
	}

	if header[0] != recordTypeChangeCipherSpec {
		if header[0] == recordTypeAlert {
			// Read and decode the alert
			recordLength := int(header[3])<<8 | int(header[4])
			alertData := make([]byte, recordLength)
			if _, err := io.ReadFull(c.conn, alertData); err != nil {
				return fmt.Errorf("failed to read alert data: %v", err)
			}
			if len(alertData) >= 2 {
				alertLevel := alertData[0]
				alertDescription := alertData[1]
				return fmt.Errorf("server sent alert: level=%d, description=%d (expected ChangeCipherSpec)", alertLevel, alertDescription)
			}
			return fmt.Errorf("server sent malformed alert (expected ChangeCipherSpec)")
		}
		return fmt.Errorf("expected ChangeCipherSpec record, got %d", header[0])
	}

	recordLength := int(header[3])<<8 | int(header[4])
	if recordLength != 1 {
		return fmt.Errorf("ChangeCipherSpec should be 1 byte, got %d", recordLength)
	}

	payload := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return fmt.Errorf("failed to read ChangeCipherSpec payload: %v", err)
	}

	if payload[0] != 1 {
		return fmt.Errorf("invalid ChangeCipherSpec value: %d", payload[0])
	}

	return nil
}

// wrapHandshakeMessage wraps a handshake message in a TLS record
func (c *Client) wrapHandshakeMessage(msg []byte) []byte {
	record := make([]byte, 5+len(msg))
	record[0] = recordTypeHandshake
	record[1] = 0x03 // TLS 1.2 version
	record[2] = 0x03
	record[3] = byte(len(msg) >> 8)
	record[4] = byte(len(msg))
	copy(record[5:], msg)
	return record
}

// compareBytes securely compares two byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// buildEmptyCertificateMessageTLS12 builds an empty Certificate message for TLS 1.2
// RFC 5246 Section 7.4.2: Certificate message format
// When server requests client cert but we have none, send empty certificate list
func (c *Client) buildEmptyCertificateMessageTLS12() []byte {
	// Certificate message:
	// - Handshake type: 0x0b (Certificate)
	// - Length: 3 bytes (total length of certificate_list field)
	// - certificate_list length: 3 bytes (0 for empty)
	msg := make([]byte, 7)
	msg[0] = 0x0b // typeCertificate
	msg[1] = 0x00 // Length high byte
	msg[2] = 0x00 // Length mid byte
	msg[3] = 0x03 // Length low byte (3 bytes for the cert list length field)
	msg[4] = 0x00 // Certificate list length high byte
	msg[5] = 0x00 // Certificate list length mid byte
	msg[6] = 0x00 // Certificate list length low byte (empty list)
	return msg
}
