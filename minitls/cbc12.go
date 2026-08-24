package minitls

// The MAC-then-encrypt padding validation in this file follows the approach
// used by Go's crypto/tls package. Copyright 2009 The Go Authors. Use of the
// relevant code is governed by the BSD-style license in the Go distribution.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math"
	"sync"
)

const (
	tlsRecordHeaderLen       = 5
	tls12MaxPlaintext        = 16384
	tls12MaxCBCRecordPayload = tls12MaxPlaintext + 2048
)

type TLS12CBCRecordMode uint8

const (
	TLS12CBCRecordModeUnspecified TLS12CBCRecordMode = iota
	TLS12CBCRecordModeMACThenEncrypt
	TLS12CBCRecordModeEncryptThenMAC
)

func (m TLS12CBCRecordMode) String() string {
	switch m {
	case TLS12CBCRecordModeMACThenEncrypt:
		return "MAC_THEN_ENCRYPT"
	case TLS12CBCRecordModeEncryptThenMAC:
		return "ENCRYPT_THEN_MAC"
	default:
		return "UNSPECIFIED"
	}
}

// TLS12CBCReadState is the minimum server-to-client record state that TEE_T
// needs. It intentionally contains no client-write traffic secret.
type TLS12CBCReadState struct {
	CipherSuite  uint16
	Mode         TLS12CBCRecordMode
	ReadKey      []byte
	ReadMACKey   []byte
	ReadIV       []byte
	ReadSequence uint64
}

func (s *TLS12CBCReadState) Clone() *TLS12CBCReadState {
	if s == nil {
		return nil
	}
	return &TLS12CBCReadState{
		CipherSuite:  s.CipherSuite,
		Mode:         s.Mode,
		ReadKey:      append([]byte(nil), s.ReadKey...),
		ReadMACKey:   append([]byte(nil), s.ReadMACKey...),
		ReadIV:       append([]byte(nil), s.ReadIV...),
		ReadSequence: s.ReadSequence,
	}
}

// TLS12CBCContext implements the TLS 1.2 AES-CBC record protection needed by
// the handshake and trusted-TEE application-data path.
type TLS12CBCContext struct {
	mu          sync.Mutex
	writeKey    []byte
	writeMACKey []byte
	writeIV     []byte
	readKey     []byte
	readMACKey  []byte
	readIV      []byte
	writeSeq    uint64
	readSeq     uint64
	cipherSuite uint16
	mode        TLS12CBCRecordMode
	random      io.Reader
}

func NewTLS12CBCContext(keys *TLS12CBCKeys, cipherSuite uint16, mode TLS12CBCRecordMode) (*TLS12CBCContext, error) {
	if keys == nil {
		return nil, fmt.Errorf("TLS 1.2 CBC keys are nil")
	}
	ctx := &TLS12CBCContext{
		writeKey:    append([]byte(nil), keys.ClientKey...),
		writeMACKey: append([]byte(nil), keys.ClientMACKey...),
		writeIV:     append([]byte(nil), keys.ClientIV...),
		readKey:     append([]byte(nil), keys.ServerKey...),
		readMACKey:  append([]byte(nil), keys.ServerMACKey...),
		readIV:      append([]byte(nil), keys.ServerIV...),
		cipherSuite: cipherSuite,
		mode:        mode,
		random:      rand.Reader,
	}
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	return ctx, nil
}

func NewTLS12CBCReadContext(state *TLS12CBCReadState) (*TLS12CBCContext, error) {
	if state == nil {
		return nil, fmt.Errorf("TLS 1.2 CBC read state is nil")
	}
	ctx := &TLS12CBCContext{
		readKey:     append([]byte(nil), state.ReadKey...),
		readMACKey:  append([]byte(nil), state.ReadMACKey...),
		readIV:      append([]byte(nil), state.ReadIV...),
		readSeq:     state.ReadSequence,
		cipherSuite: state.CipherSuite,
		mode:        state.Mode,
		random:      rand.Reader,
	}
	if err := ctx.validateRead(); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (ctx *TLS12CBCContext) validate() error {
	if err := ctx.validateRead(); err != nil {
		return err
	}
	info := GetCipherSuiteInfo(ctx.cipherSuite)
	if len(ctx.writeKey) != info.KeySize || len(ctx.writeMACKey) != info.MACSize || len(ctx.writeIV) != info.IVSize {
		return fmt.Errorf("invalid TLS 1.2 CBC write-state lengths")
	}
	return nil
}

func (ctx *TLS12CBCContext) validateRead() error {
	info := GetCipherSuiteInfo(ctx.cipherSuite)
	if info == nil || !info.IsCBC {
		return fmt.Errorf("unsupported TLS 1.2 CBC cipher suite: 0x%04x", ctx.cipherSuite)
	}
	if ctx.mode != TLS12CBCRecordModeMACThenEncrypt && ctx.mode != TLS12CBCRecordModeEncryptThenMAC {
		return fmt.Errorf("invalid TLS 1.2 CBC record mode: %d", ctx.mode)
	}
	if len(ctx.readKey) != info.KeySize || len(ctx.readMACKey) != info.MACSize || len(ctx.readIV) != info.IVSize {
		return fmt.Errorf("invalid TLS 1.2 CBC read-state lengths")
	}
	switch info.MACHash {
	case "SHA1":
		if _, ok := newTLS12CBCSHA1().(constantTimeHash); !ok {
			return fmt.Errorf("TLS 1.2 CBC SHA-1 requires constant-time hash support")
		}
	case "SHA256", "SHA384":
	default:
		return fmt.Errorf("unsupported TLS 1.2 CBC MAC hash %q", info.MACHash)
	}
	return nil
}

func (ctx *TLS12CBCContext) RecordMode() TLS12CBCRecordMode {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.mode
}

func (ctx *TLS12CBCContext) GetWriteSequence() uint64 {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.writeSeq
}

func (ctx *TLS12CBCContext) GetReadSequence() uint64 {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.readSeq
}

// Destroy clears record keys and sequence state. It serializes with record
// operations so no operation can use partially cleared state.
func (ctx *TLS12CBCContext) Destroy() {
	if ctx == nil {
		return
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	clear(ctx.writeKey)
	clear(ctx.writeMACKey)
	clear(ctx.writeIV)
	clear(ctx.readKey)
	clear(ctx.readMACKey)
	clear(ctx.readIV)
	ctx.writeKey = nil
	ctx.writeMACKey = nil
	ctx.writeIV = nil
	ctx.readKey = nil
	ctx.readMACKey = nil
	ctx.readIV = nil
	ctx.writeSeq = 0
	ctx.readSeq = 0
	ctx.cipherSuite = 0
	ctx.mode = TLS12CBCRecordModeUnspecified
}

func (ctx *TLS12CBCContext) ExportReadState() *TLS12CBCReadState {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return (&TLS12CBCReadState{
		CipherSuite:  ctx.cipherSuite,
		Mode:         ctx.mode,
		ReadKey:      ctx.readKey,
		ReadMACKey:   ctx.readMACKey,
		ReadIV:       ctx.readIV,
		ReadSequence: ctx.readSeq,
	}).Clone()
}

// EncryptRecord returns one complete TLS 1.2 record, including its five-byte
// header. Sequence numbers advance only after successful encryption.
func (ctx *TLS12CBCContext) EncryptRecord(contentType byte, plaintext []byte) ([]byte, error) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.writeSeq == math.MaxUint64 {
		return nil, ErrSequenceNumberOverflow
	}
	if len(plaintext) > tls12MaxPlaintext {
		return nil, fmt.Errorf("TLS plaintext length %d exceeds %d", len(plaintext), tls12MaxPlaintext)
	}
	if len(ctx.writeKey) == 0 {
		return nil, fmt.Errorf("TLS 1.2 CBC write state is unavailable")
	}

	block, err := aes.NewCipher(ctx.writeKey)
	if err != nil {
		return nil, fmt.Errorf("create TLS 1.2 CBC write cipher: %w", err)
	}
	explicitIV := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(ctx.random, explicitIV); err != nil {
		return nil, fmt.Errorf("generate TLS 1.2 CBC explicit IV: %w", err)
	}

	var encryptedPlaintext []byte
	if ctx.mode == TLS12CBCRecordModeMACThenEncrypt {
		mac := tls12CBCMAC(ctx.writeMACKey, ctx.cipherSuite, ctx.writeSeq, contentType, len(plaintext), plaintext, nil)
		encryptedPlaintext = make([]byte, 0, len(plaintext)+len(mac)+block.BlockSize())
		encryptedPlaintext = append(encryptedPlaintext, plaintext...)
		encryptedPlaintext = append(encryptedPlaintext, mac...)
	} else {
		encryptedPlaintext = append([]byte(nil), plaintext...)
	}

	encryptedPlaintext = appendTLSPadding(encryptedPlaintext, block.BlockSize())
	ciphertext := make([]byte, len(encryptedPlaintext))
	cipher.NewCBCEncrypter(block, explicitIV).CryptBlocks(ciphertext, encryptedPlaintext)
	encryptedFragment := append(explicitIV, ciphertext...)

	payload := encryptedFragment
	if ctx.mode == TLS12CBCRecordModeEncryptThenMAC {
		mac := tls12CBCMAC(ctx.writeMACKey, ctx.cipherSuite, ctx.writeSeq, contentType, len(encryptedFragment), encryptedFragment, nil)
		payload = append(payload, mac...)
	}
	if len(payload) > tls12MaxCBCRecordPayload {
		return nil, fmt.Errorf("TLS 1.2 CBC record payload is too large")
	}

	record := make([]byte, tlsRecordHeaderLen+len(payload))
	record[0] = contentType
	record[1] = byte(VersionTLS12 >> 8)
	record[2] = byte(VersionTLS12 & 0xff)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[tlsRecordHeaderLen:], payload)
	ctx.writeSeq++
	return record, nil
}

// DecryptRecord authenticates and decrypts one complete TLS 1.2 CBC record.
// Authentication, padding, and public-shape failures all return
// ErrBadRecordMAC and do not advance the read sequence.
func (ctx *TLS12CBCContext) DecryptRecord(header, payload []byte) ([]byte, error) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.readSeq == math.MaxUint64 {
		return nil, ErrSequenceNumberOverflow
	}
	if !validTLS12CBCHeader(header, payload) {
		return nil, ErrBadRecordMAC
	}
	info := GetCipherSuiteInfo(ctx.cipherSuite)
	contentType := header[0]
	encryptedFragment := payload

	if ctx.mode == TLS12CBCRecordModeEncryptThenMAC {
		if len(payload) < info.MACSize {
			return nil, ErrBadRecordMAC
		}
		encryptedFragment = payload[:len(payload)-info.MACSize]
		remoteMAC := payload[len(payload)-info.MACSize:]
		localMAC := tls12CBCMAC(ctx.readMACKey, ctx.cipherSuite, ctx.readSeq, contentType, len(encryptedFragment), encryptedFragment, nil)
		if subtle.ConstantTimeCompare(localMAC, remoteMAC) != 1 {
			return nil, ErrBadRecordMAC
		}
	}

	block, err := aes.NewCipher(ctx.readKey)
	if err != nil {
		return nil, ErrBadRecordMAC
	}
	blockSize := block.BlockSize()
	minimumCiphertext := blockSize
	if ctx.mode == TLS12CBCRecordModeMACThenEncrypt {
		minimumCiphertext = roundUpTLS12(info.MACSize+1, blockSize)
	}
	if len(encryptedFragment) < blockSize+minimumCiphertext || (len(encryptedFragment)-blockSize)%blockSize != 0 {
		return nil, ErrBadRecordMAC
	}

	explicitIV := encryptedFragment[:blockSize]
	plaintextWithPadding := append([]byte(nil), encryptedFragment[blockSize:]...)
	cipher.NewCBCDecrypter(block, explicitIV).CryptBlocks(plaintextWithPadding, plaintextWithPadding)

	paddingToRemove, paddingGood := extractTLS12Padding(plaintextWithPadding)
	if ctx.mode == TLS12CBCRecordModeEncryptThenMAC {
		if paddingGood != 255 || paddingToRemove > len(plaintextWithPadding) {
			return nil, ErrBadRecordMAC
		}
		plaintext := append([]byte(nil), plaintextWithPadding[:len(plaintextWithPadding)-paddingToRemove]...)
		if len(plaintext) > tls12MaxPlaintext {
			return nil, ErrBadRecordMAC
		}
		ctx.readSeq++
		return plaintext, nil
	}

	n := len(plaintextWithPadding) - info.MACSize - paddingToRemove
	n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n)
	if n+info.MACSize > len(plaintextWithPadding) {
		return nil, ErrBadRecordMAC
	}
	remoteMAC := plaintextWithPadding[n : n+info.MACSize]
	localMAC := tls12CBCMAC(ctx.readMACKey, ctx.cipherSuite, ctx.readSeq, contentType, n, plaintextWithPadding[:n], plaintextWithPadding[n+info.MACSize:])
	macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
	if macAndPaddingGood != 1 || n > tls12MaxPlaintext {
		return nil, ErrBadRecordMAC
	}

	plaintext := append([]byte(nil), plaintextWithPadding[:n]...)
	ctx.readSeq++
	return plaintext, nil
}

func validTLS12CBCHeader(header, payload []byte) bool {
	if len(header) != tlsRecordHeaderLen || len(payload) > tls12MaxCBCRecordPayload {
		return false
	}
	if binary.BigEndian.Uint16(header[1:3]) != VersionTLS12 {
		return false
	}
	return int(binary.BigEndian.Uint16(header[3:5])) == len(payload)
}

func appendTLSPadding(in []byte, blockSize int) []byte {
	paddingBytes := blockSize - len(in)%blockSize
	paddingValue := byte(paddingBytes - 1)
	for range paddingBytes {
		in = append(in, paddingValue)
	}
	return in
}

func roundUpTLS12(value, multiple int) int {
	return value + (multiple-value%multiple)%multiple
}

// extractTLS12Padding is constant-time with respect to the padding length and
// contents. It returns the number of bytes to remove and 255 for valid padding.
func extractTLS12Padding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	good = byte(int32(^t) >> 31)
	toCheck := 256
	if toCheck > len(payload) {
		toCheck = len(payload)
	}
	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)
	paddingLen &= good
	return int(paddingLen) + 1, good
}

type constantTimeHash interface {
	hash.Hash
	ConstantTimeSum([]byte) []byte
}

var newTLS12CBCSHA1 = sha1.New

type constantTimeHashWrapper struct{ h constantTimeHash }

func (w *constantTimeHashWrapper) Write(p []byte) (int, error) { return w.h.Write(p) }
func (w *constantTimeHashWrapper) Sum(b []byte) []byte         { return w.h.ConstantTimeSum(b) }
func (w *constantTimeHashWrapper) Reset()                      { w.h.Reset() }
func (w *constantTimeHashWrapper) Size() int                   { return w.h.Size() }
func (w *constantTimeHashWrapper) BlockSize() int              { return w.h.BlockSize() }

func tls12CBCMAC(macKey []byte, cipherSuite uint16, seq uint64, contentType byte, length int, data, extra []byte) []byte {
	info := GetCipherSuiteInfo(cipherSuite)
	var hashFunc func() hash.Hash
	switch info.MACHash {
	case "SHA1":
		hashFunc = func() hash.Hash {
			h := newTLS12CBCSHA1()
			if constantTime, ok := h.(constantTimeHash); ok {
				return &constantTimeHashWrapper{h: constantTime}
			}
			return h
		}
	case "SHA256":
		hashFunc = sha256.New
	case "SHA384":
		hashFunc = sha512.New384
	default:
		panic("unsupported TLS 1.2 CBC MAC hash")
	}

	mac := hmac.New(hashFunc, macKey)
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[:8], seq)
	aad[8] = contentType
	binary.BigEndian.PutUint16(aad[9:11], VersionTLS12)
	binary.BigEndian.PutUint16(aad[11:13], uint16(length))
	_, _ = mac.Write(aad[:])
	_, _ = mac.Write(data)
	result := mac.Sum(nil)
	if extra != nil {
		_, _ = mac.Write(extra)
	}
	return result
}
