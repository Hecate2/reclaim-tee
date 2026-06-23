package handlers

import (
	"strings"
	"testing"
)

func TestValidateDigestFormat(t *testing.T) {
	sha := "sha256:" + strings.Repeat("a", 64)
	app := "snp-app:" + strings.Repeat("b", 64)
	base256 := "snp-base:" + strings.Repeat("c", 64)
	base384 := "snp-base:" + strings.Repeat("d", 96)

	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid sha256", sha, true},
		{"valid snp app", app, true},
		{"valid snp base sha256", base256, true},
		{"valid snp base sha384", base384, true},
		{"sha256 wrong length", "sha256:" + strings.Repeat("a", 63), false},
		{"snp app wrong length (96 not 64)", "snp-app:" + strings.Repeat("b", 96), false},
		{"snp base wrong length (80)", "snp-base:" + strings.Repeat("c", 80), false},
		{"snp app uppercase hex", "snp-app:" + strings.Repeat("B", 64), false},
		{"unknown prefix", "snp:" + strings.Repeat("a", 64), false},
		{"no prefix", strings.Repeat("a", 64), false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateDigestFormat(c.in)
			if c.ok && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatalf("expected error for %q, got nil", c.in)
			}
		})
	}
}
