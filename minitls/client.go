package minitls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"slices"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

type Client struct {
	conn net.Conn

	// AEAD ciphers are managed across the client's lifetime
	clientAEAD *AEAD
	serverAEAD *AEAD

	// Configuration
	Config *Config        // TLS configuration (min/max versions, cipher suites)
	logger *shared.Logger // Logger for structured logging

	// Version-specific components
	negotiatedVersion uint16            // Negotiated TLS version (0x0303 for 1.2, 0x0304 for 1.3)
	keySchedule       *KeySchedule      // TLS 1.3 key schedule
	tls12KeySchedule  *TLS12KeySchedule // TLS 1.2 key schedule
	tls12AEAD         *TLS12AEADContext // TLS 1.2 AEAD context

	// Handshake state
	transcript           []byte // Running transcript of all handshake messages
	finishedTranscript   []byte // Transcript for Finished message verification
	readBuffer           []byte // Buffer for incoming TLS records
	handshakeBuffer      []byte // Buffer for reassembling handshake messages
	pendingHandshakeData []byte // Buffer for leftover handshake data from coalesced TLS 1.2 records
	cipherSuite          uint16 // Negotiated cipher suite

	// Certificate info storage
	certificateInfo    *teeproto.CertificateInfo // Store structured certificate data
	serverCertificates []*x509.Certificate       // Store actual certificate chain for signature verification
	serverName         string                    // Server hostname for certificate validation

	// Random values for TLS 1.2 key derivation
	clientRandom []byte
	serverRandom []byte

	// Store original ClientHello values for HelloRetryRequest
	originalClientRandom []byte
	originalSessionId    []byte

	// Extended Master Secret support (RFC 7627)
	extendedMasterSecret bool

	// Client certificate request flag
	certRequestReceived bool // True if server requested client certificate

	// TLS 1.3 handshake state tracking for security
	certificateReceived       bool // True if server Certificate was received and processed
	certificateVerifyReceived bool // True if server CertificateVerify was received and validated

	// ALPN negotiation
	negotiatedProtocol string // Server's selected ALPN protocol

	// TLS 1.3 key pairs for different groups
	clientPrivateKeyX25519 *ecdh.PrivateKey
	clientPrivateKeyP256   *ecdh.PrivateKey
	clientPrivateKeyP384   *ecdh.PrivateKey
	clientPrivateKeyP521   *ecdh.PrivateKey
	selectedKeyGroup       uint16
}

// SetLogger sets the logger for the client
func (c *Client) SetLogger(logger *shared.Logger) {
	c.logger = logger
}

// NewClientWithConfig creates a new client with custom configuration
func NewClientWithConfig(conn net.Conn, config *Config) *Client {
	if config == nil {
		config = &Config{}
	}
	return &Client{
		conn:   conn,
		Config: config,
		logger: shared.NewNopLogger(), // Default to no-op logger
	}
}

// getCipherSuites returns the cipher suites to use for the handshake
func (c *Client) getCipherSuites() []uint16 {
	if c.Config != nil && len(c.Config.CipherSuites) > 0 {
		return c.Config.CipherSuites
	}
	// Return appropriate default cipher suites based on supported versions
	return c.Config.cipherSuites()
}

func (c *Client) Handshake(serverName string) error {
	c.logger.Debug("Starting TLS Handshake (version negotiation)")

	// Store server name for certificate validation
	c.serverName = serverName

	// Step 1: Send ClientHello that supports both TLS 1.2 and 1.3
	clientHello, err := c.buildClientHello(serverName)
	if err != nil {
		return fmt.Errorf("failed to build ClientHello: %v", err)
	}

	c.logger.Debug("Sending ClientHello", zap.Int("bytes", len(clientHello)))
	if _, err := c.conn.Write(clientHello); err != nil {
		return fmt.Errorf("failed to send ClientHello: %v", err)
	}

	// Initialize transcript with ClientHello (handshake message only, not record header)
	clientHelloMsg := clientHello[5:]
	c.transcript = append(c.transcript, clientHelloMsg...)

	// Step 2: Read and process ServerHello to determine negotiated version
	serverHello, err := c.readServerHello()
	if err != nil {
		return fmt.Errorf("failed to read ServerHello: %v", err)
	}

	c.transcript = append(c.transcript, serverHello...)

	// Step 3: Detect negotiated TLS version and route to appropriate implementation
	negotiatedVersion, cipherSuite, err := c.detectTLSVersion(serverHello)
	if err != nil {
		if err.Error() == "HELLO_RETRY_REQUEST" {
			// Handle HelloRetryRequest - this completes the full handshake
			return c.handleHelloRetryRequestFlow(serverHello, serverName)
		}
		return fmt.Errorf("failed to detect TLS version: %v", err)
	}

	c.negotiatedVersion = negotiatedVersion
	c.cipherSuite = cipherSuite

	c.logger.Debug("Negotiated TLS version and cipher suite",
		zap.Uint16("version", negotiatedVersion),
		zap.Uint16("cipher_suite", cipherSuite))

	// Route to the appropriate handshake implementation
	switch negotiatedVersion {
	case VersionTLS12:
		c.logger.Debug("Proceeding with TLS 1.2 handshake")
		// For TLS 1.2, we need to extract server random from ServerHello
		if err := c.extractServerRandomTLS12(serverHello); err != nil {
			return fmt.Errorf("failed to extract server random: %v", err)
		}
		return c.continueTLS12Handshake()
	case VersionTLS13:
		c.logger.Debug("Proceeding with TLS 1.3 handshake")
		return c.continueTLS13Handshake(cipherSuite)
	default:
		return fmt.Errorf("unsupported TLS version: 0x%04x", negotiatedVersion)
	}
}

func (c *Client) processEncryptedHandshakeMessages() error {
	c.logger.Debug("Processing Encrypted Handshake Messages")

	// This loop will exit when the Finished message has been processed,
	// which is signaled by the processHandshakeBuffer function.
	for {
		// Attempt to process any complete handshake messages already in the buffer.
		done, err := c.processHandshakeBuffer()
		if err != nil {
			return err
		}
		if done {
			return nil // Handshake complete
		}

		// If we're here, it means the buffer doesn't contain a full message yet.
		// We need to read the next TLS record from the network.
		c.logger.Debug("Handshake buffer incomplete, reading next record")
		header := make([]byte, 5)
		if _, err := io.ReadFull(c.conn, header); err != nil {
			return fmt.Errorf("failed to read record header: %v", err)
		}

		recordType := header[0]
		recordLength := int(header[3])<<8 | int(header[4])
		c.logger.Debug("TLS record received",
			zap.Uint8("type", recordType),
			zap.Uint16("version", uint16(header[1])<<8|uint16(header[2])),
			zap.Int("length", recordLength))

		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			return fmt.Errorf("failed to read record payload: %v", err)
		}

		if recordType == recordTypeChangeCipherSpec {
			c.logger.Debug("Received ChangeCipherSpec (TLS 1.3 compatibility - ignored)")
			continue
		}
		if recordType != recordTypeApplicationData {
			return fmt.Errorf("expected application_data record for encrypted handshake, got %d", recordType)
		}

		// Decrypt the payload and add it to our handshake buffer
		c.logger.Debug("Encrypted handshake record - attempting to decrypt",
			zap.Int("bytes", len(payload)),
			zap.Uint64("sequence", c.serverAEAD.seq))
		plaintext, err := c.serverAEAD.Decrypt(payload, header)
		if err != nil {
			return fmt.Errorf("decryption failed during handshake: %v", err)
		}

		// The decrypted plaintext contains one or more handshake messages (or fragments).
		// We must find the content type byte to extract the actual handshake data.
		i := len(plaintext) - 1
		for i >= 0 && plaintext[i] == 0 {
			i--
		}
		if i < 0 {
			return fmt.Errorf("handshake record is all padding")
		}
		contentType := plaintext[i]
		actualData := plaintext[:i]

		if contentType != recordTypeHandshake {
			return fmt.Errorf("expected handshake content type in encrypted record, got %d", contentType)
		}

		c.handshakeBuffer = append(c.handshakeBuffer, actualData...)
	}
}

// processHandshakeBuffer loops over the handshake buffer and processes any
// complete handshake messages it finds. It returns true if the handshake
// is complete (i.e., the Finished message was processed).
func (c *Client) processHandshakeBuffer() (bool, error) {
	for {
		// Check if we have enough data for a handshake message header.
		if len(c.handshakeBuffer) < 4 {
			return false, nil // Need more data
		}

		msgLen := uint32(c.handshakeBuffer[1])<<16 | uint32(c.handshakeBuffer[2])<<8 | uint32(c.handshakeBuffer[3])
		totalMsgLen := 4 + msgLen

		// Check if the full message is in the buffer.
		if uint32(len(c.handshakeBuffer)) < totalMsgLen {
			c.logger.Debug("Entire message not yet in buffer, reading more",
				zap.Uint32("need", totalMsgLen),
				zap.Int("have", len(c.handshakeBuffer)))
			return false, nil // Need more data
		}

		// We have a full message, so let's process it.
		msg := c.handshakeBuffer[:totalMsgLen]
		msgType := HandshakeType(msg[0])
		c.logger.Debug("Processing buffered handshake message",
			zap.String("type", handshakeTypeString(msgType)),
			zap.Uint32("length", msgLen))

		// Process the message.
		done, err := c.processSingleHandshakeMessage(msg)
		if err != nil {
			return false, err
		}

		// Consume the message from the buffer.
		c.handshakeBuffer = c.handshakeBuffer[totalMsgLen:]

		if done {
			return true, nil // Finished message was processed.
		}
	}
}

// processSingleHandshakeMessage handles a single, complete handshake message.
func (c *Client) processSingleHandshakeMessage(data []byte) (bool, error) {
	msgType := HandshakeType(data[0])

	switch msgType {
	case typeEncryptedExtensions:
		c.logger.Debug("Received EncryptedExtensions")
		c.finishedTranscript = append(c.finishedTranscript, data...)

	case typeCertificateVerify:
		c.logger.Debug("Received CertificateVerify")
		// SECURITY: Certificate must be received before CertificateVerify
		if !c.certificateReceived {
			return false, fmt.Errorf("received CertificateVerify before Certificate")
		}
		// Verify signature BEFORE adding to transcript (signature is over transcript up to this point)
		if err := c.verifyCertificateVerifyTLS13(data); err != nil {
			return false, fmt.Errorf("CertificateVerify verification failed: %v", err)
		}
		c.certificateVerifyReceived = true
		c.finishedTranscript = append(c.finishedTranscript, data...)

	case typeCertificateRequest:
		c.logger.Info("Server requested client certificate (TLS 1.3)")
		c.certRequestReceived = true
		c.finishedTranscript = append(c.finishedTranscript, data...)

	case typeCertificate:
		if err := c.processServerCertificate(data); err != nil {
			return false, err
		}
		c.certificateReceived = true
		c.finishedTranscript = append(c.finishedTranscript, data...)

	case typeFinished:
		c.logger.Debug("Received Finished message")
		// SECURITY: Enforce TLS 1.3 handshake state machine
		// Server must send Certificate and CertificateVerify before Finished
		if !c.certificateReceived {
			return false, fmt.Errorf("received Finished before Certificate - invalid handshake sequence")
		}
		if !c.certificateVerifyReceived {
			return false, fmt.Errorf("received Finished before CertificateVerify - invalid handshake sequence")
		}
		hasherForVerify := c.keySchedule.getHashFunc()()
		hasherForVerify.Write(c.finishedTranscript)
		transcriptHashForVerify := hasherForVerify.Sum(nil)
		c.logger.Debug("Transcript hash for verification",
			zap.Int("bytes", len(transcriptHashForVerify)),
			zap.String("hash", fmt.Sprintf("%x", transcriptHashForVerify)))

		if err := c.verifyServerFinished(data, transcriptHashForVerify); err != nil {
			return false, fmt.Errorf("server Finished verification failed: %v", err)
		}

		c.finishedTranscript = append(c.finishedTranscript, data...)

		// Compute application key hash NOW - before client auth messages
		// Application keys derived from hash(ClientHello...ServerFinished) only
		hasherForApp := c.keySchedule.getHashFunc()()
		hasherForApp.Write(c.finishedTranscript)
		fullTranscriptHash := hasherForApp.Sum(nil)

		// Send empty Certificate if server requested it (TLS 1.3)
		// Must be sent BEFORE deriving application keys (uses handshake keys)
		if c.certRequestReceived {
			if err := c.sendEmptyCertificateTLS13(); err != nil {
				return false, fmt.Errorf("failed to send empty Certificate: %v", err)
			}
		}

		if err := c.sendClientFinished(); err != nil {
			return false, fmt.Errorf("failed to send client Finished: %v", err)
		}

		// NOW derive application keys using hash computed before client messages
		if err := c.deriveApplicationKeys(fullTranscriptHash); err != nil {
			return false, err
		}
		return true, nil // Handshake is complete.

	default:
		c.logger.Debug("Received unknown handshake message type", zap.Uint8("type", uint8(msgType)))
		c.finishedTranscript = append(c.finishedTranscript, data...)
	}

	return false, nil // Handshake is not yet complete.
}

func (c *Client) verifyServerFinished(msg []byte, transcriptHash []byte) error {
	if len(msg) < 4 {
		return fmt.Errorf("Finished message too short")
	}

	msgType := msg[0]
	if msgType != 20 {
		return fmt.Errorf("expected Finished message type 20, got %d", msgType)
	}
	msgLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if len(msg) < 4+msgLen {
		return fmt.Errorf("Finished message incomplete: expected %d bytes, got %d", 4+msgLen, len(msg))
	}

	// Extract the verify_data from the server's Finished message
	serverVerifyData := msg[4 : 4+msgLen]
	c.logger.Debug("Server verify_data",
		zap.Int("bytes", len(serverVerifyData)),
		zap.String("data", fmt.Sprintf("%x", serverVerifyData)))

	// Calculate what the verify_data should be.
	expectedVerifyData, err := c.keySchedule.CalculateServerFinishedVerifyData(transcriptHash)
	if err != nil {
		return fmt.Errorf("failed to calculate expected verify_data: %v", err)
	}
	c.logger.Debug("Expected verify_data",
		zap.Int("bytes", len(expectedVerifyData)),
		zap.String("data", fmt.Sprintf("%x", expectedVerifyData)))

	if !hmac.Equal(serverVerifyData, expectedVerifyData) {
		return fmt.Errorf("verify_data mismatch")
	}

	return nil
}

func (c *Client) deriveApplicationKeys(transcriptHash []byte) error {
	c.logger.Debug("Deriving Application Keys")

	// The handshake hash should be the hash of ClientHello...ServerFinished
	c.logger.Debug("Using full transcript hash for application key derivation",
		zap.Int("bytes", len(transcriptHash)))

	if err := c.keySchedule.DeriveApplicationKeys(transcriptHash); err != nil {
		return fmt.Errorf("failed to derive application keys: %v", err)
	}

	// Create application AEADs to replace the handshake AEADs
	clientAppAEAD, err := c.keySchedule.CreateClientApplicationAEAD()
	if err != nil {
		return fmt.Errorf("failed to create client application AEAD: %v", err)
	}

	serverAppAEAD, err := c.keySchedule.CreateServerApplicationAEAD()
	if err != nil {
		return fmt.Errorf("failed to create server application AEAD: %v", err)
	}

	// Replace handshake AEADs with application AEADs
	c.clientAEAD = clientAppAEAD
	c.serverAEAD = serverAppAEAD

	c.logger.Debug("Application keys derived successfully")
	return nil
}

func (c *Client) sendClientFinished() error {
	c.logger.Debug("Sending Client Finished")

	// The transcript hash for the client's Finished message includes the server's Finished.
	hasher := c.keySchedule.getHashFunc()()
	hasher.Write(c.finishedTranscript)
	transcriptHash := hasher.Sum(nil)
	c.logger.Debug("Transcript hash for client Finished",
		zap.Int("bytes", len(transcriptHash)),
		zap.String("hash", fmt.Sprintf("%x", transcriptHash)))

	// Calculate verify_data - use version-specific method
	var verifyData []byte
	var err error
	if c.negotiatedVersion == VersionTLS12 {
		// TLS 1.2 uses PRF-based Finished calculation
		verifyData = c.tls12KeySchedule.DeriveFinishedData(transcriptHash, true) // true = client
	} else {
		// TLS 1.3 uses HKDF-based Finished calculation
		verifyData, err = c.keySchedule.CalculateClientFinishedVerifyData(transcriptHash)
		if err != nil {
			return fmt.Errorf("failed to calculate client verify_data: %v", err)
		}
	}

	// Construct the Finished message
	msg := make([]byte, 4+len(verifyData))
	msg[0] = byte(typeFinished)
	putUint24(msg[1:4], uint32(len(verifyData)))
	copy(msg[4:], verifyData)

	// Encrypt the Finished message using the client's HANDSHAKE keys.
	// We need to create a record for it.
	plaintextWithContentType := make([]byte, 0, len(msg)+1)
	plaintextWithContentType = append(plaintextWithContentType, msg...)
	plaintextWithContentType = append(plaintextWithContentType, recordTypeHandshake) // Real content type

	ciphertextLen := len(plaintextWithContentType) + c.clientAEAD.aead.Overhead()
	header := make([]byte, 5)
	header[0] = recordTypeApplicationData // Encrypted handshake messages are sent in application_data records
	header[1] = 0x03                      // Legacy version
	header[2] = 0x03
	header[3] = byte(ciphertextLen >> 8)
	header[4] = byte(ciphertextLen)

	c.logger.Debug("AEAD Encrypt (Client Finished)", zap.Uint64("seq", c.clientAEAD.seq))
	ciphertext := c.clientAEAD.Encrypt(plaintextWithContentType, header)

	// Send the encrypted record
	record := append(header, ciphertext...)
	if _, err := c.conn.Write(record); err != nil {
		return fmt.Errorf("failed to write client Finished record: %v", err)
	}

	c.logger.Debug("Client Finished message sent successfully")
	return nil
}

func (c *Client) buildClientHello(serverName string) ([]byte, error) {
	// Generate X25519 key pair (primary)
	curveX25519 := ecdh.X25519()
	privateKeyX25519, err := curveX25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %v", err)
	}

	// Generate P-256 key pair
	curveP256 := ecdh.P256()
	privateKeyP256, err := curveP256.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 key: %v", err)
	}

	// Generate P-384 key pair
	curveP384 := ecdh.P384()
	privateKeyP384, err := curveP384.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-384 key: %v", err)
	}

	// Generate P-521 key pair
	curveP521 := ecdh.P521()
	privateKeyP521, err := curveP521.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-521 key: %v", err)
	}

	// Store all private keys for potential use
	c.clientPrivateKeyX25519 = privateKeyX25519
	c.clientPrivateKeyP256 = privateKeyP256
	c.clientPrivateKeyP384 = privateKeyP384
	c.clientPrivateKeyP521 = privateKeyP521

	publicKeyBytesX25519 := privateKeyX25519.PublicKey().Bytes()
	publicKeyBytesP256 := privateKeyP256.PublicKey().Bytes()
	publicKeyBytesP384 := privateKeyP384.PublicKey().Bytes()
	publicKeyBytesP521 := privateKeyP521.PublicKey().Bytes()

	c.logger.Debug("Generated key shares",
		zap.Int("x25519_bytes", len(publicKeyBytesX25519)),
		zap.Int("p256_bytes", len(publicKeyBytesP256)),
		zap.Int("p384_bytes", len(publicKeyBytesP384)),
		zap.Int("p521_bytes", len(publicKeyBytesP521)))

	// Build ClientHello message with cipher suites respecting Config
	cipherSuites := c.getCipherSuites()
	if len(cipherSuites) == 0 {
		// If no specific cipher suites configured, build appropriate list based on supported versions
		supportedVersions := c.Config.supportedVersions()
		var allCipherSuites []uint16

		// Add cipher suites for each supported version
		for _, version := range supportedVersions {
			versionCipherSuites := defaultCipherSuites(version)
			allCipherSuites = append(allCipherSuites, versionCipherSuites...)
		}

		// If no versions supported, use sensible defaults
		if len(allCipherSuites) == 0 {
			allCipherSuites = []uint16{
				// TLS 1.3 cipher suites (preferred)
				TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256,
				// TLS 1.2 cipher suites for fallback compatibility
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			}
		}

		cipherSuites = allCipherSuites
	}

	// Get ALPN protocols from Config, default to http/1.1 only if not specified
	// Note: We don't support HTTP/2, so only advertise http/1.1
	alpnProtocols := c.Config.NextProtos
	if len(alpnProtocols) == 0 {
		alpnProtocols = []string{"http/1.1"} // Default to HTTP/1.1 only (no HTTP/2 support)
	}

	hello := &ClientHelloMsg{
		vers:               0x0303, // TLS 1.2 for compatibility
		random:             make([]byte, 32),
		sessionId:          make([]byte, 32),
		cipherSuites:       cipherSuites,
		compressionMethods: []uint8{0},
		serverName:         serverName,
		supportedCurves:    []uint16{X25519, secp256r1, secp384r1, secp521r1}, // Support all major curves
		supportedVersions:  c.Config.supportedVersions(),                      // Use Config-specified versions
		supportedSignatureAlgorithms: []uint16{
			// Modern algorithms (preferred)
			ed25519, // EdDSA
			rsa_pss_rsae_sha256,
			rsa_pss_pss_sha256, // RSA-PSS with PSS OID
			ecdsa_secp256r1_sha256,
			rsa_pss_rsae_sha384,
			rsa_pss_pss_sha384, // RSA-PSS with PSS OID
			ecdsa_secp384r1_sha384,
			rsa_pss_rsae_sha512,
			rsa_pss_pss_sha512, // RSA-PSS with PSS OID
			ecdsa_secp521r1_sha512,
			// Legacy algorithms (for compatibility)
			rsa_pkcs1_sha256,
			rsa_pkcs1_sha384,
			rsa_pkcs1_sha512,
		},
		keyShares: []keyShare{
			{group: X25519, data: publicKeyBytesX25519},
			{group: secp256r1, data: publicKeyBytesP256},
			{group: secp384r1, data: publicKeyBytesP384},
			{group: secp521r1, data: publicKeyBytesP521},
		},
		alpnProtocols: alpnProtocols, // RFC 7301 - Application-Layer Protocol Negotiation
	}

	// Fill random bytes using cryptographically secure randomness
	if _, err := rand.Read(hello.random); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	if _, err := rand.Read(hello.sessionId); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	// Store random for TLS 1.2 compatibility and HelloRetryRequest
	c.clientRandom = make([]byte, len(hello.random))
	copy(c.clientRandom, hello.random)

	// Store original values for potential HelloRetryRequest
	c.originalClientRandom = make([]byte, len(hello.random))
	copy(c.originalClientRandom, hello.random)
	c.originalSessionId = make([]byte, len(hello.sessionId))
	copy(c.originalSessionId, hello.sessionId)

	// Return X25519 key by default (we'll use P256 if server selects it)
	return hello.Marshal(), nil
}

// readHandshakeMessage reads a complete handshake message
func (c *Client) readHandshakeMessage() ([]byte, error) {
	// First check if we have pending handshake data from a coalesced record
	if len(c.pendingHandshakeData) > 0 {
		// Need at least 4 bytes for handshake message header
		if len(c.pendingHandshakeData) < 4 {
			return nil, fmt.Errorf("pending handshake data too short: %d bytes", len(c.pendingHandshakeData))
		}

		// Extract handshake message length from header
		msgLen := int(c.pendingHandshakeData[1])<<16 | int(c.pendingHandshakeData[2])<<8 | int(c.pendingHandshakeData[3])
		totalMsgLen := 4 + msgLen

		if len(c.pendingHandshakeData) < totalMsgLen {
			return nil, fmt.Errorf("pending handshake data incomplete: have %d, need %d", len(c.pendingHandshakeData), totalMsgLen)
		}

		// Extract the message and update pending buffer
		msg := make([]byte, totalMsgLen)
		copy(msg, c.pendingHandshakeData[:totalMsgLen])
		c.pendingHandshakeData = c.pendingHandshakeData[totalMsgLen:]

		c.logger.Debug("Read handshake message from pending buffer",
			zap.Int("msg_bytes", totalMsgLen),
			zap.Int("remaining_pending", len(c.pendingHandshakeData)))

		return msg, nil
	}

	// No pending data, read from connection
	// Read TLS record header
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, fmt.Errorf("failed to read record header: %v", err)
	}

	recordType := header[0]
	recordLength := int(header[3])<<8 | int(header[4])

	if recordType != recordTypeHandshake {
		return nil, fmt.Errorf("expected handshake record, got type %d", recordType)
	}

	// Read the handshake message
	payload := make([]byte, recordLength)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, fmt.Errorf("failed to read handshake payload: %v", err)
	}

	// Check if this record contains multiple handshake messages
	if len(payload) >= 4 {
		msgLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		totalMsgLen := 4 + msgLen
		if len(payload) > totalMsgLen {
			// Store leftover data for subsequent reads
			c.pendingHandshakeData = payload[totalMsgLen:]
			c.logger.Debug("Stored leftover handshake data from record",
				zap.Int("leftover_bytes", len(c.pendingHandshakeData)))
			return payload[:totalMsgLen], nil
		}
	}

	return payload, nil
}

// detectTLSVersionFromData analyzes ServerHello data to determine negotiated TLS version
func (c *Client) detectTLSVersionFromData(serverHello []byte) (uint16, uint16, error) {
	if len(serverHello) < 4 {
		return 0, 0, fmt.Errorf("ServerHello too short")
	}

	if HandshakeType(serverHello[0]) != typeServerHello {
		return 0, 0, fmt.Errorf("invalid message type: expected ServerHello")
	}

	payload := serverHello[4:]
	if len(payload) < 38 { // minimum: version(2) + random(32) + session_id_len(1) + cipher_suite(2) + compression(1)
		return 0, 0, fmt.Errorf("ServerHello payload too short")
	}

	// Parse ServerHello: version(2) + random(32) + session_id_len(1) + session_id + cipher_suite(2) + compression(1)
	offset := 0

	// Skip version (2 bytes)
	offset += 2

	// Skip random (32 bytes) - real ServerHello should not have HRR magic random
	offset += 32

	// Parse session ID
	sessionIDLen := payload[offset]
	offset++
	offset += int(sessionIDLen)

	if len(payload) < offset+2 {
		return 0, 0, fmt.Errorf("ServerHello missing cipher suite")
	}

	// Parse cipher suite
	cipherSuite := uint16(payload[offset])<<8 | uint16(payload[offset+1])

	// Check if this is a TLS 1.3 cipher suite
	if IsTLS13CipherSuite(cipherSuite) {
		return VersionTLS13, cipherSuite, nil
	} else if IsTLS12CipherSuite(cipherSuite) {
		return VersionTLS12, cipherSuite, nil
	}

	return 0, 0, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
}

// detectTLSVersion analyzes the ServerHello to determine negotiated TLS version
func (c *Client) detectTLSVersion(serverHello []byte) (uint16, uint16, error) {
	if len(serverHello) < 4 {
		return 0, 0, fmt.Errorf("ServerHello too short")
	}

	if HandshakeType(serverHello[0]) != typeServerHello {
		return 0, 0, fmt.Errorf("invalid message type: expected ServerHello")
	}

	payload := serverHello[4:]
	if len(payload) < 38 { // minimum: version(2) + random(32) + session_id_len(1) + cipher_suite(2) + compression(1)
		return 0, 0, fmt.Errorf("ServerHello payload too short")
	}

	// Check for HelloRetryRequest (HRR) - special ServerHello with magic random value
	hrrRandom := []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}

	serverRandom := payload[2:34]
	if bytes.Equal(serverRandom, hrrRandom) {
		// This is actually called from detectTLSVersion which doesn't have serverName
		// We need to handle this differently - return a special indicator
		return 0, 0, fmt.Errorf("HELLO_RETRY_REQUEST")
	}

	// Parse ServerHello: version(2) + random(32) + session_id_len(1) + session_id + cipher_suite(2) + compression(1)
	offset := 0

	// Skip version (2 bytes)
	offset += 2

	// Skip random (32 bytes)
	offset += 32

	// Parse session ID
	sessionIDLen := payload[offset]
	offset++
	offset += int(sessionIDLen)

	if len(payload) < offset+2 {
		return 0, 0, fmt.Errorf("ServerHello missing cipher suite")
	}

	// Parse cipher suite
	cipherSuite := uint16(payload[offset])<<8 | uint16(payload[offset+1])

	// Check if this is a TLS 1.3 cipher suite
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256:
		// TLS 1.3 cipher suite - check for supported_versions extension
		// For now, assume TLS 1.3 if we see a TLS 1.3 cipher suite
		return VersionTLS13, cipherSuite, nil
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		// TLS 1.2 AEAD cipher suite
		return VersionTLS12, cipherSuite, nil
	default:
		return 0, 0, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}
}

// continueTLS12Handshake continues with TLS 1.2 handshake after version detection
func (c *Client) continueTLS12Handshake() error {
	// Continue TLS 1.2 handshake from after ServerHello (Certificate, ServerKeyExchange, etc.)
	// Note: TLS 1.2 generates its own ECDH key pair based on the server's selected curve
	return c.continueTLS12HandshakeAfterServerHello()
}

// continueTLS13Handshake continues with TLS 1.3 handshake after version detection
func (c *Client) continueTLS13Handshake(cipherSuite uint16) error {
	// Continue with TLS 1.3 handshake using the existing implementation

	// Add transcripts for TLS 1.3
	c.finishedTranscript = make([]byte, len(c.transcript))
	copy(c.finishedTranscript, c.transcript)

	// Extract the ServerHello from the transcript
	// The transcript contains: ClientHello + ServerHello
	// We need to find the ServerHello which starts after the ClientHello
	clientHelloLen := 0
	if len(c.transcript) >= 4 {
		clientHelloLen = 4 + int(c.transcript[1])<<16 + int(c.transcript[2])<<8 + int(c.transcript[3])
	}

	if len(c.transcript) <= clientHelloLen {
		return fmt.Errorf("transcript too short to contain ServerHello")
	}

	serverHelloData := c.transcript[clientHelloLen:]

	// Parse ServerHello to extract server key share for TLS 1.3
	_, serverPublicKey, err := c.parseServerHello(serverHelloData)
	if err != nil {
		return fmt.Errorf("failed to parse ServerHello for TLS 1.3: %v", err)
	}

	c.logger.Debug("Negotiated TLS 1.3 cipher suite", zap.Uint16("cipher_suite", cipherSuite))

	// Use the correct private key based on which group the server selected
	var selectedPrivateKey *ecdh.PrivateKey
	switch c.selectedKeyGroup {
	case 0x001d: // X25519
		selectedPrivateKey = c.clientPrivateKeyX25519
	case 0x0017: // secp256r1 (P-256)
		selectedPrivateKey = c.clientPrivateKeyP256
	case 0x0018: // secp384r1 (P-384)
		selectedPrivateKey = c.clientPrivateKeyP384
	case 0x0019: // secp521r1 (P-521)
		selectedPrivateKey = c.clientPrivateKeyP521
	default:
		return fmt.Errorf("server selected unsupported key group: 0x%04x", c.selectedKeyGroup)
	}

	if selectedPrivateKey == nil {
		return fmt.Errorf("server selected key group 0x%04x but we don't have the private key", c.selectedKeyGroup)
	}

	// Derive shared secret using ECDH
	sharedSecret, err := selectedPrivateKey.ECDH(serverPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %v", err)
	}

	// c.logger.Debug("Shared secret", zap.Int("bytes", len(sharedSecret)), zap.String("secret", fmt.Sprintf("%x", sharedSecret)))

	// Initialize key schedule with shared secret and current transcript
	c.keySchedule = NewKeySchedule(cipherSuite, sharedSecret, c.transcript)

	// Derive handshake keys
	if err := c.keySchedule.DeriveHandshakeKeys(); err != nil {
		return fmt.Errorf("failed to derive handshake keys: %v", err)
	}

	// Create AEADs for the handshake phase
	c.clientAEAD, err = c.keySchedule.CreateClientHandshakeAEAD()
	if err != nil {
		return fmt.Errorf("failed to create client handshake AEAD: %v", err)
	}
	c.serverAEAD, err = c.keySchedule.CreateServerHandshakeAEAD()
	if err != nil {
		return fmt.Errorf("failed to create server handshake AEAD: %v", err)
	}

	c.logger.Debug("TLS 1.3 handshake keys derived successfully")

	// Process encrypted handshake messages
	if err := c.processEncryptedHandshakeMessages(); err != nil {
		return fmt.Errorf("failed to process encrypted handshake messages: %v", err)
	}

	c.logger.Debug("TLS 1.3 handshake completed successfully")
	return nil
}

func (c *Client) readServerHello() ([]byte, error) {
	var handshakeData []byte
	var handshakeMsgLen int
	firstRecord := true

	// Keep reading TLS records until we have a complete handshake message
	for {
		// Read TLS record header
		header := make([]byte, 5)
		if _, err := io.ReadFull(c.conn, header); err != nil {
			return nil, fmt.Errorf("failed to read record header: %v", err)
		}

		recordType := header[0]
		recordLength := int(header[3])<<8 | int(header[4])

		// Handle non-handshake records
		if recordType != 22 { // handshake
			// Read and consume the record payload to keep stream in sync
			payload := make([]byte, recordLength)
			if _, err := io.ReadFull(c.conn, payload); err != nil {
				return nil, fmt.Errorf("failed to read record payload: %v", err)
			}

			// Handle ChangeCipherSpec (TLS 1.3 middlebox compatibility)
			if recordType == 20 { // ChangeCipherSpec
				c.logger.Debug("Received ChangeCipherSpec (TLS 1.3 compatibility)",
					zap.Int("bytes", recordLength))
				// Skip and continue reading - this is expected in TLS 1.3
				continue
			}

			// Handle alert records
			if recordType == 21 && len(payload) >= 2 { // alert
				alertLevel := payload[0]
				alertDescription := payload[1]
				return nil, fmt.Errorf("received TLS alert: level=%d, description=%d", alertLevel, alertDescription)
			}

			return nil, fmt.Errorf("unexpected record type %d while waiting for ServerHello", recordType)
		}

		// Read the handshake record payload
		recordData := make([]byte, recordLength)
		if _, err := io.ReadFull(c.conn, recordData); err != nil {
			return nil, fmt.Errorf("failed to read handshake record: %v", err)
		}

		// Log the TLS record we received
		c.logger.Debug("Received TLS handshake record",
			zap.Int("record_length", recordLength),
			zap.Int("total_bytes_so_far", len(handshakeData)),
			zap.String("hex_data", fmt.Sprintf("%x", recordData)))

		// Append to our handshake data
		handshakeData = append(handshakeData, recordData...)

		// If this is the first record, parse the handshake message header
		if firstRecord {
			if len(recordData) < 4 {
				return nil, fmt.Errorf("handshake record too short: %d bytes", len(recordData))
			}

			// Verify it's a ServerHello
			if recordData[0] != 2 {
				return nil, fmt.Errorf("expected ServerHello message type 2, got %d", recordData[0])
			}

			// Extract handshake message length
			handshakeMsgLen = int(recordData[1])<<16 | int(recordData[2])<<8 | int(recordData[3])
			firstRecord = false

			c.logger.Debug("ServerHello handshake message",
				zap.Int("msg_length", handshakeMsgLen),
				zap.Int("first_record_bytes", len(recordData)))
		}

		// Check if we have the complete handshake message
		totalNeeded := 4 + handshakeMsgLen // 4 bytes header + payload
		if len(handshakeData) >= totalNeeded {
			c.logger.Debug("Received complete ServerHello",
				zap.Int("total_bytes", len(handshakeData)),
				zap.Int("needed_bytes", totalNeeded))
			// Store any leftover data for subsequent reads (coalesced handshake messages)
			if len(handshakeData) > totalNeeded {
				c.pendingHandshakeData = handshakeData[totalNeeded:]
				c.logger.Debug("Stored leftover handshake data from coalesced record",
					zap.Int("leftover_bytes", len(c.pendingHandshakeData)))
			}
			// Return only the complete handshake message
			return handshakeData[:totalNeeded], nil
		}

		c.logger.Debug("Need more data for complete ServerHello",
			zap.Int("have_bytes", len(handshakeData)),
			zap.Int("need_bytes", totalNeeded))
	}
}

// extractServerRandomTLS12 extracts the server random from a TLS 1.2 ServerHello
func (c *Client) extractServerRandomTLS12(serverHello []byte) error {
	if len(serverHello) < 4 {
		return fmt.Errorf("ServerHello too short")
	}

	if HandshakeType(serverHello[0]) != typeServerHello {
		return fmt.Errorf("invalid message type: expected ServerHello")
	}

	payload := serverHello[4:]
	if len(payload) < 38 { // minimum: version(2) + random(32) + session_id_len(1) + cipher_suite(2) + compression(1)
		return fmt.Errorf("ServerHello payload too short")
	}

	offset := 0

	// Skip version (2 bytes)
	offset += 2

	// Extract server random (32 bytes)
	c.serverRandom = make([]byte, 32)
	copy(c.serverRandom, payload[offset:offset+32])
	offset += 32

	c.logger.Debug("Extracted server random", zap.String("random", fmt.Sprintf("%x", c.serverRandom)))

	// Parse session ID
	sessionIDLen := payload[offset]
	offset += 1 + int(sessionIDLen)

	// Skip cipher suite (2 bytes)
	offset += 2

	// Skip compression method (1 byte)
	offset += 1

	// Parse extensions for Extended Master Secret
	c.extendedMasterSecret = false // Default to false
	c.logger.Debug("TLS 1.2 ServerHello parsing", zap.Int("offset", offset), zap.Int("payload_length", len(payload)))
	if len(payload) > offset+2 {
		extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2

		c.logger.Debug("TLS 1.2 ServerHello has extensions", zap.Int("extensions_length", extensionsLen))

		if len(payload) >= offset+extensionsLen {
			extensionsData := payload[offset : offset+extensionsLen]

			// Check for Extended Master Secret extension
			extOffset := 0
			for extOffset < len(extensionsData) {
				if extOffset+4 > len(extensionsData) {
					break
				}

				extType := uint16(extensionsData[extOffset])<<8 | uint16(extensionsData[extOffset+1])
				extLen := int(extensionsData[extOffset+2])<<8 | int(extensionsData[extOffset+3])
				extOffset += 4

				c.logger.Debug("Found extension", zap.Uint16("type", extType), zap.Uint16("type_hex", extType), zap.Int("length", extLen))

				if extType == extensionExtendedMasterSecret {
					c.extendedMasterSecret = true
					c.logger.Debug("Server supports Extended Master Secret (RFC 7627)")
					break
				}

				extOffset += extLen
			}
		}
	} else {
		c.logger.Debug("TLS 1.2 ServerHello has no extensions")
	}

	return nil
}

func (c *Client) parseServerHello(data []byte) (uint16, *ecdh.PublicKey, error) {
	if len(data) < 40 {
		return 0, nil, fmt.Errorf("ServerHello too short")
	}

	// Parse basic fields
	msgType := data[0]
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	version := uint16(data[4])<<8 | uint16(data[5])
	random := data[6:38]
	sessionIDLen := int(data[38])

	c.logger.Debug("ServerHello parsed",
		zap.Uint8("type", msgType),
		zap.Int("length", msgLen),
		zap.Uint16("version", version),
		zap.Int("session_id_length", sessionIDLen))

	offset := 39 + sessionIDLen
	if offset+2 > len(data) {
		return 0, nil, fmt.Errorf("invalid ServerHello: missing cipher suite")
	}

	cipherSuite := uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	// Skip compression method
	offset += 1

	// Parse extensions
	if offset+2 > len(data) {
		return 0, nil, fmt.Errorf("invalid ServerHello: missing extensions length")
	}

	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	// Validate extensions length
	if offset+extensionsLen > len(data) {
		return 0, nil, fmt.Errorf("invalid ServerHello: extensions length %d exceeds remaining data %d", extensionsLen, len(data)-offset)
	}

	extensionsData := data[offset : offset+extensionsLen]

	// Parse extensions: key_share and ALPN
	serverPublicKey, err := c.parseServerHelloExtensions(extensionsData)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse extensions: %v", err)
	}

	_ = random // Suppress unused variable warning
	return cipherSuite, serverPublicKey, nil
}

// parseServerHelloExtensions parses ServerHello extensions (key_share, ALPN, etc.)
func (c *Client) parseServerHelloExtensions(extensionsData []byte) (*ecdh.PublicKey, error) {
	var serverPublicKey *ecdh.PublicKey
	c.negotiatedProtocol = "" // Reset negotiated ALPN protocol

	offset := 0
	for offset < len(extensionsData) {
		if offset+4 > len(extensionsData) {
			break
		}

		extType := uint16(extensionsData[offset])<<8 | uint16(extensionsData[offset+1])
		extLen := int(extensionsData[offset+2])<<8 | int(extensionsData[offset+3])
		offset += 4

		if offset+extLen > len(extensionsData) {
			break
		}

		extData := extensionsData[offset : offset+extLen]

		switch extType {
		case extensionKeyShare: // 51
			keyShare, err := c.parseKeyShare(extData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse key_share: %v", err)
			}
			serverPublicKey = keyShare
			c.logger.Debug("Parsed key_share extension", zap.Int("length", extLen))

		case extensionALPN: // 16
			// Parse ALPN extension: 2-byte list length + protocols
			if len(extData) < 2 {
				c.logger.Warn("ALPN: Invalid ALPN extension length")
				break
			}
			alpnListLen := int(extData[0])<<8 | int(extData[1])
			if len(extData) < 2+alpnListLen {
				c.logger.Warn("ALPN: ALPN list length exceeds extension data")
				break
			}
			if alpnListLen < 2 {
				c.logger.Warn("ALPN: ALPN list too short")
				break
			}
			// Parse single protocol (server should only return one)
			protoLen := int(extData[2])
			if len(extData) < 3+protoLen {
				c.logger.Warn("ALPN: Protocol length exceeds ALPN data")
				break
			}
			c.negotiatedProtocol = string(extData[3 : 3+protoLen])
			c.logger.Info("ALPN: Server selected protocol", zap.String("protocol", c.negotiatedProtocol))

			// Validate that server's choice was in our offered list
			// Note: buildClientHello may default to http/1.1 if Config.NextProtos is empty
			offeredProtos := c.Config.NextProtos
			if len(offeredProtos) == 0 {
				offeredProtos = []string{"http/1.1"}
			}
			validChoice := slices.Contains(offeredProtos, c.negotiatedProtocol)
			if !validChoice {
				return nil, fmt.Errorf("ALPN: server selected protocol '%s' that we didn't offer", c.negotiatedProtocol)
			}
		}

		offset += extLen
	}

	if serverPublicKey == nil {
		return nil, fmt.Errorf("key_share extension not found")
	}

	return serverPublicKey, nil
}

func (c *Client) parseKeyShareExtension(extensionsData []byte) (*ecdh.PublicKey, error) {
	offset := 0
	for offset < len(extensionsData) {
		if offset+4 > len(extensionsData) {
			break
		}

		extType := uint16(extensionsData[offset])<<8 | uint16(extensionsData[offset+1])
		extLen := int(extensionsData[offset+2])<<8 | int(extensionsData[offset+3])
		offset += 4

		if extType == 51 { // key_share
			if offset+extLen > len(extensionsData) {
				return nil, fmt.Errorf("invalid key_share extension length")
			}

			keyShareData := extensionsData[offset : offset+extLen]
			c.logger.Debug("Found key_share extension",
				zap.Int("extension_length", extLen),
				zap.String("hex_data", fmt.Sprintf("%x", keyShareData)))
			return c.parseKeyShare(keyShareData)
		}

		offset += extLen
	}

	return nil, fmt.Errorf("key_share extension not found")
}

func (c *Client) parseKeyShare(data []byte) (*ecdh.PublicKey, error) {
	if len(data) < 4 {
		c.logger.Error("key_share data too short",
			zap.Int("data_length", len(data)),
			zap.String("hex_data", fmt.Sprintf("%x", data)))
		return nil, fmt.Errorf("key_share data too short")
	}

	group := uint16(data[0])<<8 | uint16(data[1])
	keyLen := int(data[2])<<8 | int(data[3])

	// Store the selected group so we know which private key to use
	c.selectedKeyGroup = group

	// Accept X25519, P-256, P-384, and P-521
	var curve ecdh.Curve
	switch group {
	case 0x001d: // X25519
		curve = ecdh.X25519()
	case 0x0017: // secp256r1 (P-256)
		curve = ecdh.P256()
	case 0x0018: // secp384r1 (P-384)
		curve = ecdh.P384()
	case 0x0019: // secp521r1 (P-521)
		curve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported key share group: 0x%04x", group)
	}

	if len(data) < 4+keyLen {
		return nil, fmt.Errorf("invalid key_share length")
	}

	keyBytes := data[4 : 4+keyLen]
	c.logger.Debug("Server public key",
		zap.Int("bytes", len(keyBytes)),
		zap.Uint16("group", group),
		zap.String("key", fmt.Sprintf("%x", keyBytes)))

	publicKey, err := curve.NewPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	return publicKey, nil
}

func handshakeTypeString(t HandshakeType) string {
	switch t {
	case typeClientHello:
		return "ClientHello"
	case typeServerHello:
		return "ServerHello"
	case typeNewSessionTicket:
		return "NewSessionTicket"
	// TLS 1.2 specific messages
	case typeServerKeyExchange:
		return "ServerKeyExchange"
	case typeClientKeyExchange:
		return "ClientKeyExchange"
	case typeServerHelloDone:
		return "ServerHelloDone"
	case typeCertificateRequest:
		return "CertificateRequest"
	// TLS 1.3 specific messages
	case typeEncryptedExtensions:
		return "EncryptedExtensions"
	// Shared messages
	case typeCertificate:
		return "Certificate"
	case typeCertificateVerify:
		return "CertificateVerify"
	case typeFinished:
		return "Finished"
	default:
		return "Unknown"
	}
}

func (c *Client) processServerCertificate(data []byte) error {
	c.logger.Debug("Processing Server Certificate")
	// data is the entire handshake message, including its 4-byte header.
	payload := data[4:]

	// 1. Parse Certificate Request Context (1-byte length prefix)
	if len(payload) < 1 {
		return fmt.Errorf("payload too short for context length")
	}
	contextLen := int(payload[0])
	if len(payload) < 1+contextLen {
		return fmt.Errorf("payload too short for context body")
	}
	// For server-sent certificates, this should be zero.
	if contextLen != 0 {
		c.logger.Warn("Server sent non-empty certificate request context", zap.Int("bytes", contextLen))
	}
	// Advance payload past the context
	payload = payload[1+contextLen:]

	// 2. Parse Certificate List (3-byte length prefix)
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

	// 3. Parse each CertificateEntry from the list
	var certs []*x509.Certificate
	offset := 0
	for offset < len(listBytes) {
		// Each entry has cert_data and extensions.
		// 3a. Parse cert_data (3-byte length prefix)
		if len(listBytes[offset:]) < 3 {
			return fmt.Errorf("not enough data for certificate entry data length")
		}
		certLen := int(listBytes[offset])<<16 | int(listBytes[offset+1])<<8 | int(listBytes[offset+2])
		offset += 3
		if len(listBytes[offset:]) < certLen {
			return fmt.Errorf("not enough data for certificate body")
		}
		certData := listBytes[offset : offset+certLen]
		offset += certLen

		// 3b. Parse extensions (2-byte length prefix)
		if len(listBytes[offset:]) < 2 {
			return fmt.Errorf("not enough data for extensions length")
		}
		extLen := int(listBytes[offset])<<8 | int(listBytes[offset+1])
		offset += 2
		if len(listBytes[offset:]) < extLen {
			return fmt.Errorf("not enough data for extensions body")
		}
		// We can ignore the extensions themselves for now.
		offset += extLen

		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return fmt.Errorf("server sent no certificates")
	}

	// Store certificates for signature verification
	c.serverCertificates = certs

	// --- Print Server's Common Name and Validate Chain ---
	leafCert := certs[0]
	c.logger.Debug("Received certificates",
		zap.Int("count", len(certs)),
		zap.String("common_name", leafCert.Subject.CommonName))

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

// verifyCertificateVerifyTLS13 verifies the TLS 1.3 CertificateVerify message signature
// RFC 8446 Section 4.4.3: The signature is computed over:
// - 64 spaces (0x20)
// - Context string "TLS 1.3, server CertificateVerify"
// - Single 0x00 byte
// - Transcript hash (all handshake messages up to but not including CertificateVerify)
func (c *Client) verifyCertificateVerifyTLS13(data []byte) error {
	if len(c.serverCertificates) == 0 {
		return fmt.Errorf("no server certificates available for CertificateVerify")
	}

	// Parse CertificateVerify message
	// Format: handshake_type(1) + length(3) + signature_algorithm(2) + signature_length(2) + signature(variable)
	if len(data) < 8 {
		return fmt.Errorf("CertificateVerify message too short: %d bytes", len(data))
	}

	// Skip handshake header (type + length = 4 bytes)
	signatureAlgorithm := uint16(data[4])<<8 | uint16(data[5])
	signatureLength := int(data[6])<<8 | int(data[7])

	if len(data) < 8+signatureLength {
		return fmt.Errorf("CertificateVerify signature truncated: expected %d bytes, got %d", signatureLength, len(data)-8)
	}

	signature := data[8 : 8+signatureLength]

	// Compute transcript hash (everything up to but not including CertificateVerify)
	hasher := c.keySchedule.getHashFunc()()
	hasher.Write(c.finishedTranscript)
	transcriptHash := hasher.Sum(nil)

	// Build the signed content per RFC 8446 Section 4.4.3
	// 64 spaces + context string + 0x00 + transcript hash
	contextString := "TLS 1.3, server CertificateVerify"
	signedContent := make([]byte, 64+len(contextString)+1+len(transcriptHash))
	for i := range 64 {
		signedContent[i] = 0x20 // space
	}
	copy(signedContent[64:], contextString)
	signedContent[64+len(contextString)] = 0x00
	copy(signedContent[64+len(contextString)+1:], transcriptHash)

	serverCert := c.serverCertificates[0]

	// Look up signature algorithm info
	algInfo, supported := supportedSignatureAlgorithms[signatureAlgorithm]
	if !supported {
		return fmt.Errorf("unsupported signature algorithm in CertificateVerify: 0x%04x", signatureAlgorithm)
	}

	c.logger.Debug("Verifying CertificateVerify signature",
		zap.Uint16("signature_algorithm", signatureAlgorithm),
		zap.String("algorithm_name", algInfo.name),
		zap.Int("signature_length", len(signature)),
		zap.Int("transcript_hash_length", len(transcriptHash)))

	// Dispatch to appropriate verification function based on algorithm type
	switch algInfo.algType {
	case sigTypeECDSA:
		return c.verifyECDSASignature(serverCert, signedContent, signature, algInfo.hash)
	case sigTypeRSAPSS:
		return c.verifyRSAPSSSignature(serverCert, signedContent, signature, algInfo.hash)
	case sigTypeRSAPKCS1:
		// Note: RSA PKCS#1 is not allowed in TLS 1.3 CertificateVerify per RFC 8446
		return fmt.Errorf("RSA PKCS#1 v1.5 signatures not allowed in TLS 1.3 CertificateVerify")
	case sigTypeEd25519:
		return c.verifyEd25519Signature(serverCert, signedContent, signature)
	default:
		return fmt.Errorf("unknown signature algorithm type for 0x%04x", signatureAlgorithm)
	}
}

// GetHandshakeKey returns the server handshake key for certificate verification
func (c *Client) GetHandshakeKey() []byte {
	if c.keySchedule == nil {
		return nil
	}
	return c.keySchedule.serverHandshakeKey
}

// GetHandshakeIV returns the server handshake IV for certificate verification
func (c *Client) GetHandshakeIV() []byte {
	if c.keySchedule == nil {
		return nil
	}
	return c.keySchedule.serverHandshakeIV
}

// GetCipherSuite returns the negotiated cipher suite
func (c *Client) GetCipherSuite() uint16 {
	return c.cipherSuite
}

// GetClientApplicationAEAD returns the client application AEAD for split AEAD operations
func (c *Client) GetClientApplicationAEAD() *AEAD {
	return c.clientAEAD
}

// GetServerApplicationAEAD returns the server application AEAD for response decryption
func (c *Client) GetServerApplicationAEAD() *AEAD {
	return c.serverAEAD
}

// GetKeySchedule returns the key schedule for accessing application keys
func (c *Client) GetKeySchedule() *KeySchedule {
	return c.keySchedule
}

// GetNegotiatedVersion returns the negotiated TLS version
func (c *Client) GetNegotiatedVersion() uint16 {
	return c.negotiatedVersion
}

// GetTLS12AEAD returns the TLS 1.2 AEAD context for TEE integration
func (c *Client) GetTLS12AEAD() *TLS12AEADContext {
	return c.tls12AEAD
}

// extractCertificateInfo extracts structured certificate information for verification bundle
func (c *Client) extractCertificateInfo(certs []*x509.Certificate) *teeproto.CertificateInfo {
	if len(certs) == 0 {
		return nil
	}

	leafCert := certs[0]

	var issuerCN string
	if len(certs) > 1 {
		issuerCN = certs[1].Subject.CommonName
	} else {
		issuerCN = leafCert.Issuer.CommonName
	}

	return &teeproto.CertificateInfo{
		CommonName:       leafCert.Subject.CommonName,
		IssuerCommonName: issuerCN,
		NotBeforeUnix:    uint64(leafCert.NotBefore.Unix()),
		NotAfterUnix:     uint64(leafCert.NotAfter.Unix()),
		DnsNames:         leafCert.DNSNames,
	}
}

// GetCertificateInfo returns the stored certificate information
func (c *Client) GetCertificateInfo() *teeproto.CertificateInfo {
	return c.certificateInfo
}

// handleHelloRetryRequestFlow handles the complete HelloRetryRequest flow
func (c *Client) handleHelloRetryRequestFlow(hrrData []byte, serverName string) error {
	c.logger.Info("Processing HelloRetryRequest flow")

	// Parse the HRR to extract the selected key group
	selectedGroup, cookie, err := c.parseHelloRetryRequest(hrrData)
	if err != nil {
		return fmt.Errorf("failed to parse HelloRetryRequest: %v", err)
	}

	c.logger.Debug("HelloRetryRequest parsed",
		zap.Uint16("selected_group", selectedGroup),
		zap.Bool("has_cookie", len(cookie) > 0))

	// Update transcript: transcript = hash(ClientHello1 + HelloRetryRequest)
	if err := c.updateTranscriptForHRR(hrrData); err != nil {
		return fmt.Errorf("failed to update transcript for HRR: %v", err)
	}

	// Build new ClientHello with only the selected key group
	newClientHello, err := c.buildClientHelloForHRR(serverName, selectedGroup, cookie)
	if err != nil {
		return fmt.Errorf("failed to build ClientHello for HRR: %v", err)
	}

	// Send the new ClientHello
	previewLen := min(len(newClientHello), 50)
	c.logger.Debug("Sending updated ClientHello",
		zap.Int("bytes", len(newClientHello)),
		zap.String("hex_preview", fmt.Sprintf("%x", newClientHello[:previewLen])))
	if _, err := c.conn.Write(newClientHello); err != nil {
		return fmt.Errorf("failed to send updated ClientHello: %v", err)
	}

	// Update transcript with new ClientHello (handshake message only, not record header)
	newClientHelloMsg := newClientHello[5:]
	c.transcript = append(c.transcript, newClientHelloMsg...)

	// Read the real ServerHello
	c.logger.Debug("Waiting for real ServerHello after HRR")
	realServerHello, err := c.readServerHello()
	if err != nil {
		return fmt.Errorf("failed to read real ServerHello after HRR: %v", err)
	}
	c.logger.Debug("Received real ServerHello after HRR", zap.Int("bytes", len(realServerHello)))

	c.transcript = append(c.transcript, realServerHello...)

	// Now detect the TLS version from the real ServerHello
	negotiatedVersion, cipherSuite, err := c.detectTLSVersionFromData(realServerHello)
	if err != nil {
		return fmt.Errorf("failed to detect TLS version from real ServerHello: %v", err)
	}

	c.negotiatedVersion = negotiatedVersion
	c.cipherSuite = cipherSuite

	c.logger.Debug("Negotiated TLS version and cipher suite after HRR",
		zap.Uint16("version", negotiatedVersion),
		zap.Uint16("cipher_suite", cipherSuite))

	// Continue with the appropriate handshake implementation
	switch negotiatedVersion {
	case VersionTLS12:
		c.logger.Debug("Proceeding with TLS 1.2 handshake after HRR")
		if err := c.extractServerRandomTLS12(realServerHello); err != nil {
			return fmt.Errorf("failed to extract server random: %v", err)
		}
		return c.continueTLS12Handshake()
	case VersionTLS13:
		c.logger.Debug("Proceeding with TLS 1.3 handshake after HRR")
		return c.continueTLS13Handshake(cipherSuite)
	default:
		return fmt.Errorf("unsupported TLS version: 0x%04x", negotiatedVersion)
	}
}

// parseHelloRetryRequest parses a HelloRetryRequest message
func (c *Client) parseHelloRetryRequest(hrrData []byte) (selectedGroup uint16, cookie []byte, err error) {
	if len(hrrData) < 4 {
		return 0, nil, fmt.Errorf("HelloRetryRequest too short")
	}

	if HandshakeType(hrrData[0]) != typeServerHello {
		return 0, nil, fmt.Errorf("invalid message type: expected ServerHello")
	}

	payload := hrrData[4:]
	if len(payload) < 38 {
		return 0, nil, fmt.Errorf("HelloRetryRequest payload too short")
	}

	// Parse ServerHello structure: version(2) + random(32) + session_id_len(1) + session_id + cipher_suite(2) + compression(1) + extensions_len(2) + extensions
	offset := 0

	// Skip version (2 bytes)
	offset += 2

	// Skip random (32 bytes) - should be HRR magic value
	offset += 32

	// Parse session ID
	sessionIDLen := payload[offset]
	offset++
	offset += int(sessionIDLen)

	// Skip cipher suite (2 bytes)
	offset += 2

	// Skip compression method (1 byte)
	offset += 1

	// Parse extensions
	if len(payload) < offset+2 {
		return 0, nil, fmt.Errorf("HelloRetryRequest missing extensions length")
	}

	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2

	if len(payload) < offset+extensionsLen {
		return 0, nil, fmt.Errorf("HelloRetryRequest extensions length exceeds payload")
	}

	extensionsData := payload[offset : offset+extensionsLen]

	// Parse extensions to find key_share and cookie
	extOffset := 0
	for extOffset < len(extensionsData) {
		if extOffset+4 > len(extensionsData) {
			break
		}

		extType := uint16(extensionsData[extOffset])<<8 | uint16(extensionsData[extOffset+1])
		extLen := int(extensionsData[extOffset+2])<<8 | int(extensionsData[extOffset+3])
		extOffset += 4

		if extOffset+extLen > len(extensionsData) {
			break
		}

		extData := extensionsData[extOffset : extOffset+extLen]

		switch extType {
		case 51: // key_share
			if len(extData) >= 2 {
				selectedGroup = uint16(extData[0])<<8 | uint16(extData[1])
				c.logger.Debug("HelloRetryRequest selected key group", zap.Uint16("group", selectedGroup))
			}
		case 44: // cookie
			cookie = make([]byte, len(extData))
			copy(cookie, extData)
			c.logger.Debug("HelloRetryRequest contains cookie", zap.Int("bytes", len(cookie)))
		}

		extOffset += extLen
	}

	if selectedGroup == 0 {
		return 0, nil, fmt.Errorf("HelloRetryRequest missing key_share extension")
	}

	return selectedGroup, cookie, nil
}

// updateTranscriptForHRR updates the transcript according to HRR rules
func (c *Client) updateTranscriptForHRR(hrrData []byte) error {
	// For HelloRetryRequest, the transcript becomes:
	// Hash(ClientHello1 + HelloRetryRequest) where ClientHello1 is replaced by a synthetic message

	// Create synthetic ClientHello1 message: type(1) + length(3) + Hash(ClientHello1)
	// We need to hash the original ClientHello first
	hashFunc := c.getHashForCipherSuite(c.cipherSuite)
	if hashFunc == nil {
		// Default to SHA256 if cipher suite not known yet
		hashFunc = func() []byte {
			h := sha256.New()
			h.Write(c.transcript)
			return h.Sum(nil)
		}
	}

	clientHelloHash := hashFunc()

	// Create synthetic message: message_hash(254) + length(3) + hash
	syntheticMsg := make([]byte, 4+len(clientHelloHash))
	syntheticMsg[0] = 254 // message_hash type
	putUint24(syntheticMsg[1:4], uint32(len(clientHelloHash)))
	copy(syntheticMsg[4:], clientHelloHash)

	// Replace transcript with synthetic message + HelloRetryRequest
	c.transcript = make([]byte, 0, len(syntheticMsg)+len(hrrData))
	c.transcript = append(c.transcript, syntheticMsg...)
	c.transcript = append(c.transcript, hrrData...)

	c.logger.Debug("Updated transcript for HelloRetryRequest",
		zap.Int("synthetic_msg_bytes", len(syntheticMsg)),
		zap.Int("hrr_bytes", len(hrrData)),
		zap.Int("total_transcript_bytes", len(c.transcript)))

	return nil
}

// buildClientHelloForHRR builds a new ClientHello for HelloRetryRequest with only the selected key group
func (c *Client) buildClientHelloForHRR(serverName string, selectedGroup uint16, cookie []byte) ([]byte, error) {
	c.logger.Debug("Building ClientHello for HelloRetryRequest",
		zap.Uint16("selected_group", selectedGroup),
		zap.Bool("has_cookie", len(cookie) > 0))

	// Generate key pair for the selected group
	var privateKey *ecdh.PrivateKey
	var publicKeyBytes []byte
	var err error

	switch selectedGroup {
	case X25519: // 0x001d = 29
		if c.clientPrivateKeyX25519 != nil {
			// Reuse existing key if available
			privateKey = c.clientPrivateKeyX25519
			publicKeyBytes = privateKey.PublicKey().Bytes()
		} else {
			curve := ecdh.X25519()
			privateKey, err = curve.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("failed to generate X25519 key: %v", err)
			}
			publicKeyBytes = privateKey.PublicKey().Bytes()
			c.clientPrivateKeyX25519 = privateKey
		}
	case secp256r1: // 0x0017 = 23
		if c.clientPrivateKeyP256 != nil {
			// Reuse existing key if available
			privateKey = c.clientPrivateKeyP256
			publicKeyBytes = privateKey.PublicKey().Bytes()
		} else {
			curve := ecdh.P256()
			privateKey, err = curve.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("failed to generate P-256 key: %v", err)
			}
			publicKeyBytes = privateKey.PublicKey().Bytes()
			c.clientPrivateKeyP256 = privateKey
		}
	default:
		return nil, fmt.Errorf("unsupported key group in HelloRetryRequest: 0x%04x", selectedGroup)
	}

	c.selectedKeyGroup = selectedGroup

	// Build ClientHello message with same parameters as original but only selected key share
	cipherSuites := c.getCipherSuites()
	if len(cipherSuites) == 0 {
		cipherSuites = []uint16{TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256}
	}

	hello := &ClientHelloMsg{
		vers:               0x0303, // TLS 1.2 for compatibility
		random:             make([]byte, 32),
		sessionId:          make([]byte, len(c.originalSessionId)),
		cipherSuites:       cipherSuites,
		compressionMethods: []uint8{0},
		serverName:         serverName,
		supportedCurves:    []uint16{X25519, secp256r1, secp384r1, secp521r1}, // Support all major curves
		supportedVersions:  []uint16{0x0304},                                  // TLS 1.3
		supportedSignatureAlgorithms: []uint16{
			// Modern algorithms (preferred)
			ed25519, // EdDSA
			rsa_pss_rsae_sha256,
			rsa_pss_pss_sha256, // RSA-PSS with PSS OID
			ecdsa_secp256r1_sha256,
			rsa_pss_rsae_sha384,
			rsa_pss_pss_sha384, // RSA-PSS with PSS OID
			ecdsa_secp384r1_sha384,
			rsa_pss_rsae_sha512,
			rsa_pss_pss_sha512, // RSA-PSS with PSS OID
			ecdsa_secp521r1_sha512,
			// Legacy algorithms (for compatibility)
			rsa_pkcs1_sha256,
			rsa_pkcs1_sha384,
			rsa_pkcs1_sha512,
		},
		keyShares: []keyShare{
			{group: selectedGroup, data: publicKeyBytes},
		},
		cookie: cookie, // Include cookie if provided
	}

	// Generate new random values (required for second ClientHello)
	if _, err := rand.Read(hello.random); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	// Use the same session ID as the original ClientHello (RFC 8446 requirement)
	if len(c.originalSessionId) == 0 {
		return nil, fmt.Errorf("original session ID not available for HelloRetryRequest")
	}
	copy(hello.sessionId, c.originalSessionId)

	c.logger.Debug("Generated key share for HRR",
		zap.Uint16("group", selectedGroup),
		zap.Int("public_key_bytes", len(publicKeyBytes)))

	return hello.Marshal(), nil
}

// sendEmptyCertificateTLS13 sends an empty Certificate message for TLS 1.3
// RFC 8446 Section 4.4.2: Certificate message format for TLS 1.3
// When server requests client cert but we have none, send empty certificate list
func (c *Client) sendEmptyCertificateTLS13() error {
	c.logger.Info("Sending empty Certificate in response to server's CertificateRequest (TLS 1.3)")

	// TLS 1.3 Certificate message:
	// - Handshake type: 0x0b (Certificate)
	// - Length: 3 bytes (total length of following data)
	// - certificate_request_context length: 1 byte (0 for empty)
	// - certificate_list length: 3 bytes (0 for empty)
	msg := make([]byte, 8)
	msg[0] = 0x0b // typeCertificate
	msg[1] = 0x00 // Length high byte
	msg[2] = 0x00 // Length mid byte
	msg[3] = 0x04 // Length low byte (4 bytes for context len + cert list len)
	msg[4] = 0x00 // Certificate request context length (empty)
	msg[5] = 0x00 // Certificate list length high byte
	msg[6] = 0x00 // Certificate list length mid byte
	msg[7] = 0x00 // Certificate list length low byte (empty list)

	// Add to transcript
	c.finishedTranscript = append(c.finishedTranscript, msg...)

	// Encrypt the Certificate message using the client's HANDSHAKE keys (same as Finished)
	plaintextWithContentType := make([]byte, 0, len(msg)+1)
	plaintextWithContentType = append(plaintextWithContentType, msg...)
	plaintextWithContentType = append(plaintextWithContentType, recordTypeHandshake) // Real content type

	ciphertextLen := len(plaintextWithContentType) + c.clientAEAD.aead.Overhead()
	header := make([]byte, 5)
	header[0] = recordTypeApplicationData // Encrypted handshake messages are sent in application_data records
	header[1] = 0x03                      // Legacy version
	header[2] = 0x03
	header[3] = byte(ciphertextLen >> 8)
	header[4] = byte(ciphertextLen)

	c.logger.Debug("AEAD Encrypt (Empty Certificate)", zap.Uint64("seq", c.clientAEAD.seq))
	ciphertext := c.clientAEAD.Encrypt(plaintextWithContentType, header)

	// Send the encrypted record
	record := append(header, ciphertext...)
	if _, err := c.conn.Write(record); err != nil {
		return fmt.Errorf("failed to write empty Certificate record: %v", err)
	}

	c.logger.Debug("Sent empty Certificate (TLS 1.3)")
	return nil
}

// getHashForCipherSuite returns the hash function for a given cipher suite
func (c *Client) getHashForCipherSuite(cipherSuite uint16) func() []byte {
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256:
		return func() []byte {
			h := sha256.New()
			h.Write(c.transcript)
			return h.Sum(nil)
		}
	case TLS_AES_256_GCM_SHA384:
		return func() []byte {
			h := sha512.New384()
			h.Write(c.transcript)
			return h.Sum(nil)
		}
	default:
		return nil
	}
}
