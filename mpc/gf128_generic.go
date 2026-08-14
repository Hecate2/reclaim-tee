//go:build !amd64 || !gc

package mpc

func gf128Mul(a, b Label) Label {
	return gf128MulGeneric(a, b)
}
