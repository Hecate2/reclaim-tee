package minitls

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// serverHelloWith builds a minimal ServerHello handshake message with the
// given random and cipher suite, enough for the negotiation-time checks.
func serverHelloWith(random []byte, cipherSuite uint16) []byte {
	payload := make([]byte, 0, 42)
	payload = append(payload, 0x03, 0x03)
	payload = append(payload, random...)
	payload = append(payload, 0x00)
	payload = append(payload, byte(cipherSuite>>8), byte(cipherSuite))
	payload = append(payload, 0x00)
	payload = append(payload, 0x00, 0x00)

	msg := []byte{byte(typeServerHello), 0, 0, 0}
	putUint24(msg[1:4], uint32(len(payload)))
	return append(msg, payload...)
}

func randomWithSentinel() []byte {
	r := bytes.Repeat([]byte{0xAA}, 32)
	copy(r[24:], downgradeSentinelTLS12)
	return r
}

func TestParseCipherSuiteRejectsUnknownHex(t *testing.T) {
	if _, err := ParseCipherSuite("dead"); err == nil {
		t.Fatal("expected unknown hex cipher suite to be rejected")
	}
	if _, err := ParseCipherSuite("0xdead"); err == nil {
		t.Fatal("expected unknown 0x-prefixed cipher suite to be rejected")
	}
	if IsValidCipherSuite("dead") {
		t.Fatal("IsValidCipherSuite accepted an unknown suite")
	}

	got, err := ParseCipherSuite("0x1301")
	if err != nil || got != TLS_AES_128_GCM_SHA256 {
		t.Fatalf("known hex suite should parse, got 0x%04x err %v", got, err)
	}
}

func TestCheckNegotiatedRejectsUnofferedSuite(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{})
	c.offeredCipherSuites = []uint16{TLS_AES_128_GCM_SHA256}

	if err := c.checkNegotiated(VersionTLS13, TLS_AES_128_GCM_SHA256); err != nil {
		t.Fatalf("offered suite should be accepted: %v", err)
	}
	if err := c.checkNegotiated(VersionTLS13, TLS_AES_256_GCM_SHA384); err == nil {
		t.Fatal("expected unoffered cipher suite to be rejected")
	}
}

func TestCheckNegotiatedEnforcesConfiguredVersionRange(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{MinVersion: VersionTLS13, MaxVersion: VersionTLS13})

	if err := c.checkNegotiated(VersionTLS13, TLS_AES_128_GCM_SHA256); err != nil {
		t.Fatalf("TLS 1.3 should be accepted when pinned to 1.3: %v", err)
	}
	if err := c.checkNegotiated(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); err == nil {
		t.Fatal("expected TLS 1.2 to be rejected when pinned to 1.3")
	}
}

func TestDowngradeSentinelDetectedWhenTLS13Offered(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{MinVersion: VersionTLS12, MaxVersion: VersionTLS13})
	sh := serverHelloWith(randomWithSentinel(), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	err := c.checkDowngradeSentinel(VersionTLS12, sh)
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected downgrade detection, got %v", err)
	}
}

// A client pinned to TLS 1.2 never offers 1.3, so a 1.3-capable server marking
// the sentinel is expected and must not abort. Cloudflare does exactly this.
func TestDowngradeSentinelIgnoredWhenTLS13NotOffered(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{MinVersion: VersionTLS12, MaxVersion: VersionTLS12})
	sh := serverHelloWith(randomWithSentinel(), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	if err := c.checkDowngradeSentinel(VersionTLS12, sh); err != nil {
		t.Fatalf("sentinel must be ignored when TLS 1.3 was not offered: %v", err)
	}
}

func TestDowngradeSentinelIgnoredForTLS13(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{})
	sh := serverHelloWith(randomWithSentinel(), TLS_AES_128_GCM_SHA256)

	if err := c.checkDowngradeSentinel(VersionTLS13, sh); err != nil {
		t.Fatalf("sentinel check does not apply to TLS 1.3: %v", err)
	}
}

func TestDetectTLSVersionReturnsHRRSentinel(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{})
	sh := serverHelloWith(hrrRandom, TLS_AES_128_GCM_SHA256)

	_, _, err := c.detectTLSVersion(sh)
	if !errors.Is(err, errHelloRetryRequest) {
		t.Fatalf("expected errHelloRetryRequest, got %v", err)
	}
}

func TestSecondHelloRetryRequestRejected(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{})
	sh := serverHelloWith(hrrRandom, TLS_AES_128_GCM_SHA256)

	_, _, err := c.detectTLSVersionFromData(sh)
	if err == nil || !strings.Contains(err.Error(), "second HelloRetryRequest") {
		t.Fatalf("expected second-HRR rejection, got %v", err)
	}
}

func TestBuildClientHelloOffersExtendedMasterSecret(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{})
	hello, err := c.buildClientHello("example.com")
	if err != nil {
		t.Fatalf("buildClientHello: %v", err)
	}

	ems := []byte{byte(extensionExtendedMasterSecret >> 8), byte(extensionExtendedMasterSecret), 0x00, 0x00}
	if !bytes.Contains(hello, ems) {
		t.Fatal("ClientHello does not advertise the Extended Master Secret extension")
	}
	if len(c.offeredCipherSuites) == 0 {
		t.Fatal("offeredCipherSuites not recorded")
	}
}

func TestBuildClientHelloForHRRSupportsAllOfferedGroups(t *testing.T) {
	for _, group := range []uint16{X25519, secp256r1, secp384r1, secp521r1} {
		c := NewClientWithConfig(nil, &Config{})
		if _, err := c.buildClientHello("example.com"); err != nil {
			t.Fatalf("buildClientHello: %v", err)
		}

		hello, err := c.buildClientHelloForHRR("example.com", group, nil)
		if err != nil {
			t.Fatalf("group 0x%04x should be supported after HRR: %v", group, err)
		}
		if !bytes.Contains(hello, []byte("http/1.1")) {
			t.Fatalf("group 0x%04x: CH2 must mirror CH1's ALPN", group)
		}
		if bytes.Equal(c.clientRandom, c.originalClientRandom) {
			t.Fatalf("group 0x%04x: clientRandom must track CH2, not CH1", group)
		}
	}
}
