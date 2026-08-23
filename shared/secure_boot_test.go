package shared

import "testing"

func TestSecureBootAuthorityPolicy(t *testing.T) {
	valid := secureBootAuthorityPolicy{
		enabled: true, permittedKeys: 1, releaseDBEntries: 1,
		postAuthorities: 1, releasePostAuthorities: 1,
	}
	if !secureBootAuthorityPolicyOK(valid) {
		t.Fatal("valid R-only policy rejected")
	}

	tests := map[string]func(*secureBootAuthorityPolicy){
		"disabled":            func(p *secureBootAuthorityPolicy) { p.enabled = false },
		"additional db key":   func(p *secureBootAuthorityPolicy) { p.permittedKeys = 2 },
		"permitted hash":      func(p *secureBootAuthorityPolicy) { p.permittedHashes = 1 },
		"R absent from db":    func(p *secureBootAuthorityPolicy) { p.releaseDBEntries = 0 },
		"R revoked":           func(p *secureBootAuthorityPolicy) { p.releaseDBXEntries = 1 },
		"pre-boot authority":  func(p *secureBootAuthorityPolicy) { p.preAuthorities = 1 },
		"no executed image":   func(p *secureBootAuthorityPolicy) { p.postAuthorities = 0; p.releasePostAuthorities = 0 },
		"foreign signer used": func(p *secureBootAuthorityPolicy) { p.postAuthorities = 2; p.releasePostAuthorities = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := valid
			mutate(&policy)
			if secureBootAuthorityPolicyOK(policy) {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
