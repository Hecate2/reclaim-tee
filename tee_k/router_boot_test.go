package main

import (
	"strings"
	"testing"
)

func TestTEEKConfig_RouterModeDetection(t *testing.T) {
	cases := []struct {
		name      string
		routerURL string
		want      bool
	}{
		{"empty → not router mode", "", false},
		{"any value → router mode", "https://tee.reclaimprotocol.org", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &TEEKConfig{RouterURL: tc.routerURL}
			if got := c.RouterMode(); got != tc.want {
				t.Fatalf("RouterMode() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateRouterConfig(t *testing.T) {
	base := TEEKConfig{
		RouterURL:               "https://router",
		SelfAddr:                "10.0.0.1:443",
		PeerAddr:                "10.0.0.2:443",
		ExpectedPeerImageDigest: "sha256:abc",
		JWTPublicKey:            "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
		ExpectedJWTIssuer:       "router.reclaimprotocol.org",
		KMSEnclaveDomainKey:     "tk.reclaimprotocol.org",
	}
	if err := validateRouterConfig(&base); err != nil {
		t.Fatalf("full config should validate: %v", err)
	}

	// EXPECTED_PEER_IMAGE_DIGEST and KMS_ENCLAVE_DOMAIN_KEY become required
	// only inside a real enclave (gated by shared.IsEnclaveMode); they are
	// not exercised here because the test environment has no launcher socket.
	// SELF_ADDR is auto-discovered from GCE metadata in startRouterMode
	// when unset, so it's not required by the config validator.
	// EXPECTED_PEER_IMAGE_DIGEST and KMS_ENCLAVE_DOMAIN_KEY are required
	// only inside a real enclave (gated by shared.IsEnclaveMode).
	cases := []struct {
		name   string
		mutate func(*TEEKConfig)
		want   string
	}{
		{"missing PEER_ADDR", func(c *TEEKConfig) { c.PeerAddr = "" }, "PEER_ADDR"},
		{"missing JWT_PUBLIC_KEY", func(c *TEEKConfig) { c.JWTPublicKey = "" }, "JWT_PUBLIC_KEY"},
		{"missing EXPECTED_JWT_ISSUER", func(c *TEEKConfig) { c.ExpectedJWTIssuer = "" }, "EXPECTED_JWT_ISSUER"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			err := validateRouterConfig(&c)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}
