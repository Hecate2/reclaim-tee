//go:build amd64 && gc

package mpc

import "golang.org/x/sys/cpu"

func configureFixedAES(a *fixedAES, key *[16]byte) {
	if !cpu.X86.HasAES {
		return
	}
	aes128ExpandKey(&key[0], &a.roundKeys[0])
	a.accelerated = true
}

//go:noescape
func aes128ExpandKey(key, roundKeys *byte)

//go:noescape
func aes128Encrypt2(roundKeys, blocks *byte)

//go:noescape
func aes128Encrypt4(roundKeys, blocks *byte)
