//go:build amd64 && gc

package mpc

import "golang.org/x/sys/cpu"

//go:noescape
func clmul128(a, b, lo, hi *Label)

func gf128Mul(a, b Label) Label {
	if !cpu.X86.HasPCLMULQDQ {
		return gf128MulGeneric(a, b)
	}
	var lo, hi Label
	clmul128(&a, &b, &lo, &hi)
	return reduceGF128(lo, hi)
}
