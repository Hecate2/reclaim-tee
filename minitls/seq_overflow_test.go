package minitls

import (
	"math"
	"testing"
)

func TestAEADEncryptRejectsAtMaxSeq(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	aead, err := NewAEAD(key, iv, TLS_CHACHA20_POLY1305_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	aead.seq = math.MaxUint64
	_, err = aead.EncryptChecked([]byte("test"), nil)
	if err == nil {
		t.Fatal("expected error at max sequence number")
	}
}

func TestAEADDecryptRejectsAtMaxSeq(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	aead, err := NewAEAD(key, iv, TLS_CHACHA20_POLY1305_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	ct := aead.Encrypt([]byte("test"), nil)
	aead.seq = math.MaxUint64
	_, err = aead.DecryptChecked(ct, nil)
	if err == nil {
		t.Fatal("expected error at max sequence number")
	}
}

func TestSplitAEADEncryptRejectsAtMaxSeq(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	sa := NewSplitAEAD(key, iv, TLS_CHACHA20_POLY1305_SHA256)
	sa.seq = math.MaxUint64
	_, _, err := sa.EncryptWithoutTag([]byte("test"), nil)
	if err == nil {
		t.Fatal("expected error at max sequence number")
	}
}

func TestTLS12ExplicitIVMustMatchReadSeq(t *testing.T) {
	// NewTLS12AEADContext(writeKey, writeIV, readKey, readIV, cipherSuite)
	// AES-128-GCM: 16-byte key, 4-byte IV
	key := make([]byte, 16)
	iv := make([]byte, 4)
	ctx, err := NewTLS12AEADContext(key, iv, key, iv, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello")
	recordHeader := []byte{0x17, 0x03, 0x03, 0x00, byte(len(plaintext))}
	ct, err := ctx.Encrypt(plaintext, recordHeader)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper the explicit IV (first 8 bytes) to be seq=99
	ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7] = 0, 0, 0, 0, 0, 0, 0, 99
	_, err = ctx.Decrypt(ct, recordHeader)
	if err == nil {
		t.Fatal("expected error when explicit IV does not match readSeq")
	}
}
