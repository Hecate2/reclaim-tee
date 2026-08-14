package mpc

import (
	"crypto/aes"
	"crypto/cipher"
)

// fixedAES encrypts independent blocks under the public fixed key used by the
// garbling hash. The amd64 path encrypts two or four blocks in one assembly
// call. Other targets use crypto/aes.
type fixedAES struct {
	fallback    cipher.Block
	roundKeys   [11 * aes.BlockSize]byte
	accelerated bool
}

func newFixedAES(key *[16]byte) (*fixedAES, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	result := &fixedAES{fallback: block}
	configureFixedAES(result, key)
	return result, nil
}

func (a *fixedAES) encrypt2(blocks *[2 * aes.BlockSize]byte) {
	if a.accelerated {
		aes128Encrypt2(&a.roundKeys[0], &blocks[0])
		return
	}
	for off := 0; off < len(blocks); off += aes.BlockSize {
		a.fallback.Encrypt(blocks[off:off+aes.BlockSize], blocks[off:off+aes.BlockSize])
	}
}

func (a *fixedAES) encrypt4(blocks *[4 * aes.BlockSize]byte) {
	if a.accelerated {
		aes128Encrypt4(&a.roundKeys[0], &blocks[0])
		return
	}
	for off := 0; off < len(blocks); off += aes.BlockSize {
		a.fallback.Encrypt(blocks[off:off+aes.BlockSize], blocks[off:off+aes.BlockSize])
	}
}
