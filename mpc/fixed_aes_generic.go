//go:build !amd64 || !gc

package mpc

func configureFixedAES(_ *fixedAES, _ *[16]byte) {}

func aes128ExpandKey(_, _ *byte) {}

func aes128Encrypt2(_, _ *byte) {}

func aes128Encrypt4(_, _ *byte) {}
