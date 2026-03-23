package minitls

import (
	"encoding/binary"
	"fmt"
)

// TLS 1.2 Handshake Messages Implementation
// Following RFC 5246 and focusing on ECDHE-AEAD cipher suites

// ServerKeyExchangeMsg represents the TLS 1.2 ServerKeyExchange message
type ServerKeyExchangeMsg struct {
	curveType  uint8
	namedCurve uint16
	publicKey  []byte
	signAlg    uint16
	signature  []byte
}

// ParseServerKeyExchange parses a ServerKeyExchange message
func ParseServerKeyExchange(data []byte) (*ServerKeyExchangeMsg, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ServerKeyExchange message too short: %d bytes", len(data))
	}

	if HandshakeType(data[0]) != typeServerKeyExchange {
		return nil, fmt.Errorf("invalid message type: expected %d, got %d", typeServerKeyExchange, data[0])
	}

	msgLen := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if len(data) < int(4+msgLen) {
		return nil, fmt.Errorf("ServerKeyExchange message length mismatch")
	}

	msg := &ServerKeyExchangeMsg{}
	payload := data[4:]
	offset := 0

	// Parse ECDH server params
	if len(payload) < 4 {
		return nil, fmt.Errorf("ServerKeyExchange payload too short")
	}

	msg.curveType = payload[offset]
	offset++

	msg.namedCurve = binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Parse public key
	pubKeyLen := int(payload[offset])
	offset++

	// Bounds check: ensure payload has enough bytes for public key
	if offset+pubKeyLen > len(payload) {
		return nil, fmt.Errorf("ServerKeyExchange: public key length %d exceeds remaining payload %d", pubKeyLen, len(payload)-offset)
	}

	msg.publicKey = make([]byte, pubKeyLen)
	copy(msg.publicKey, payload[offset:offset+pubKeyLen])
	offset += pubKeyLen

	// Bounds check: ensure payload has enough bytes for signature algorithm (2 bytes) and length (2 bytes)
	if offset+4 > len(payload) {
		return nil, fmt.Errorf("ServerKeyExchange: insufficient bytes for signature header, need 4, have %d", len(payload)-offset)
	}

	// Parse signature algorithm and signature
	msg.signAlg = binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	sigLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// Bounds check: ensure payload has enough bytes for signature
	if offset+sigLen > len(payload) {
		return nil, fmt.Errorf("ServerKeyExchange: signature length %d exceeds remaining payload %d", sigLen, len(payload)-offset)
	}

	msg.signature = make([]byte, sigLen)
	copy(msg.signature, payload[offset:offset+sigLen])

	return msg, nil
}

// GetPublicKey returns the server's ECDHE public key
func (m *ServerKeyExchangeMsg) GetPublicKey() []byte {
	return m.publicKey
}

// GetNamedCurve returns the server's specified curve
func (m *ServerKeyExchangeMsg) GetNamedCurve() uint16 {
	return m.namedCurve
}

// GetSignatureAlgorithm returns the signature algorithm used
func (m *ServerKeyExchangeMsg) GetSignatureAlgorithm() uint16 {
	return m.signAlg
}

// GetSignature returns the signature bytes
func (m *ServerKeyExchangeMsg) GetSignature() []byte {
	return m.signature
}

// GetServerParams returns the server ECDH parameters that were signed
// Format: curve_type (1 byte) + named_curve (2 bytes) + public_key_length (1 byte) + public_key
func (m *ServerKeyExchangeMsg) GetServerParams() []byte {
	params := make([]byte, 0, 4+len(m.publicKey))
	params = append(params, m.curveType)
	params = append(params, byte(m.namedCurve>>8), byte(m.namedCurve))
	params = append(params, byte(len(m.publicKey)))
	params = append(params, m.publicKey...)
	return params
}

// ClientKeyExchangeMsg represents the TLS 1.2 ClientKeyExchange message
type ClientKeyExchangeMsg struct {
	publicKey []byte
}

// NewClientKeyExchange creates a new ClientKeyExchange message
func NewClientKeyExchange(publicKey []byte) *ClientKeyExchangeMsg {
	result := &ClientKeyExchangeMsg{
		publicKey: make([]byte, len(publicKey)),
	}
	copy(result.publicKey, publicKey)
	return result
}

// Marshal serializes the ClientKeyExchange message
func (m *ClientKeyExchangeMsg) Marshal() []byte {
	// RFC 4492: ECDHE ClientKeyExchange format:
	// - 4 bytes: handshake header (type + 3-byte length)
	// - 1 byte: public key length (for X25519, this is 32)
	// - 32 bytes: X25519 public key
	// Total: 37 bytes (not 33!)
	msgLen := 1 + len(m.publicKey)
	totalLen := 4 + msgLen

	msg := make([]byte, totalLen)

	// Handshake message header
	msg[0] = byte(typeClientKeyExchange)
	msg[1] = byte(msgLen >> 16)
	msg[2] = byte(msgLen >> 8)
	msg[3] = byte(msgLen)

	// ECDHE public key encoding (RFC 4492 Section 5.4)
	msg[4] = byte(len(m.publicKey)) // Public key length (32 for X25519)
	copy(msg[5:], m.publicKey)      // 32-byte X25519 public key

	return msg
}

// ServerHelloDoneMsg represents the TLS 1.2 ServerHelloDone message
type ServerHelloDoneMsg struct{}

// ParseServerHelloDone parses a ServerHelloDone message
func ParseServerHelloDone(data []byte) (*ServerHelloDoneMsg, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ServerHelloDone message too short")
	}

	if HandshakeType(data[0]) != typeServerHelloDone {
		return nil, fmt.Errorf("invalid message type")
	}

	return &ServerHelloDoneMsg{}, nil
}

// TLS12FinishedMsg represents the TLS 1.2 Finished message
type TLS12FinishedMsg struct {
	verifyData []byte // 12 bytes for TLS 1.2
}

// NewTLS12Finished creates a new TLS 1.2 Finished message
func NewTLS12Finished(verifyData []byte) (*TLS12FinishedMsg, error) {
	if len(verifyData) != 12 {
		return nil, fmt.Errorf("TLS 1.2 finished message must have 12 bytes of verify data, got %d", len(verifyData))
	}

	msg := &TLS12FinishedMsg{
		verifyData: make([]byte, 12),
	}
	copy(msg.verifyData, verifyData)
	return msg, nil
}

// Marshal serializes the TLS 1.2 Finished message
func (m *TLS12FinishedMsg) Marshal() []byte {
	msg := make([]byte, 16) // 4-byte header + 12-byte verify data

	msg[0] = byte(typeFinished)
	msg[1] = 0
	msg[2] = 0
	msg[3] = 12

	copy(msg[4:], m.verifyData)

	return msg
}

// GetVerifyData returns the verify data from the Finished message
func (m *TLS12FinishedMsg) GetVerifyData() []byte {
	return m.verifyData
}

// ParseTLS12Finished parses a TLS 1.2 Finished message
func ParseTLS12Finished(data []byte) (*TLS12FinishedMsg, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("Finished message too short: %d bytes", len(data))
	}

	if HandshakeType(data[0]) != typeFinished {
		return nil, fmt.Errorf("invalid message type: expected %d, got %d", typeFinished, data[0])
	}

	msgLen := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if msgLen != 12 {
		return nil, fmt.Errorf("TLS 1.2 Finished message should have 12 bytes, got %d", msgLen)
	}

	if len(data) < 16 {
		return nil, fmt.Errorf("Finished message truncated: expected 16 bytes, got %d", len(data))
	}

	msg := &TLS12FinishedMsg{
		verifyData: make([]byte, 12),
	}
	copy(msg.verifyData, data[4:16])

	return msg, nil
}

// ChangeCipherSpecMsg represents the ChangeCipherSpec message
type ChangeCipherSpecMsg struct{}

// Marshal serializes the ChangeCipherSpec message
func (m *ChangeCipherSpecMsg) Marshal() []byte {
	msg := make([]byte, 6)
	msg[0] = recordTypeChangeCipherSpec
	msg[1] = 0x03
	msg[2] = 0x03
	msg[3] = 0x00
	msg[4] = 0x01
	msg[5] = 0x01

	return msg
}
