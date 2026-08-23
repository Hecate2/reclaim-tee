package main

import (
	"crypto"
	"testing"
)

func TestParsePCRs(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	mrs, err := parsePCRs([]string{"7=" + digest, "11=" + digest}, crypto.SHA256)
	if err != nil {
		t.Fatalf("parsePCRs: %v", err)
	}
	if got, want := joinedPCRIndices(mrs), "7,11"; got != want {
		t.Fatalf("joinedPCRIndices = %q, want %q", got, want)
	}
}

func TestParsePCRsRejectsWrongBankLength(t *testing.T) {
	if _, err := parsePCRs([]string{"7=00"}, crypto.SHA384); err == nil {
		t.Fatal("parsePCRs accepted a one-byte SHA-384 PCR")
	}
}

func TestSecureBootAuthorityRequiresPostSeparatorUse(t *testing.T) {
	valid := secureBootPolicy{
		enabled:                true,
		permittedKeys:          1,
		trustedDBEntries:       1,
		postAuthorities:        1,
		trustedPostAuthorities: 1,
	}
	withoutPostSeparatorUse := valid
	withoutPostSeparatorUse.postAuthorities = 0
	withoutPostSeparatorUse.trustedPostAuthorities = 0
	if secureBootAuthorityOK(withoutPostSeparatorUse) {
		t.Fatal("policy accepted a key that did not authorize a post-separator binary")
	}
	if !secureBootAuthorityOK(valid) {
		t.Fatal("policy rejected a trusted key used after the separator")
	}
}

func TestSecureBootAuthorityRejectsAdditionalBootAuthorization(t *testing.T) {
	base := secureBootPolicy{
		enabled:                true,
		permittedKeys:          1,
		trustedDBEntries:       1,
		postAuthorities:        1,
		trustedPostAuthorities: 1,
	}
	tests := map[string]func(*secureBootPolicy){
		"second db key":        func(p *secureBootPolicy) { p.permittedKeys++ },
		"allowed image hash":   func(p *secureBootPolicy) { p.permittedHashes++ },
		"R revoked in dbx":     func(p *secureBootPolicy) { p.trustedDBXEntries++ },
		"pre-separator signer": func(p *secureBootPolicy) { p.preAuthorities++ },
		"second boot signer": func(p *secureBootPolicy) {
			p.postAuthorities++
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := base
			mutate(&policy)
			if secureBootAuthorityOK(policy) {
				t.Fatal("policy accepted an additional boot authorization path")
			}
		})
	}
}
