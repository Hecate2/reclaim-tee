package minitls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func tls12HandshakeRecord(payload []byte) []byte {
	record := []byte{recordTypeHandshake, byte(VersionTLS12 >> 8), byte(VersionTLS12 & 0xff), 0, 0}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	return append(record, payload...)
}

func TestReadHandshakeMessageReassemblesRecordFragments(t *testing.T) {
	first := []byte{byte(typeCertificate), 0, 0, 7, 1, 2, 3, 4, 5, 6, 7}
	second := []byte{byte(typeServerHelloDone), 0, 0, 0}
	records := [][]byte{
		tls12HandshakeRecord(first[:2]),
		tls12HandshakeRecord(first[2:8]),
		tls12HandshakeRecord(append(append([]byte(nil), first[8:]...), second...)),
	}

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	deadline := time.Now().Add(time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		for _, record := range records {
			if _, err := serverConn.Write(record); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	client := NewClientWithConfig(clientConn, &Config{})
	gotFirst, err := client.readHandshakeMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotFirst, first) {
		t.Fatalf("first handshake = %x, want %x", gotFirst, first)
	}
	gotSecond, err := client.readHandshakeMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSecond, second) {
		t.Fatalf("second handshake = %x, want %x", gotSecond, second)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

// serverHelloWith builds a minimal ServerHello handshake message with the
// given random and cipher suite, enough for the negotiation-time checks.
func serverHelloWith(random []byte, cipherSuite uint16) []byte {
	return serverHelloWithExtensions(random, cipherSuite, 0, nil)
}

func serverHelloWithExtensions(random []byte, cipherSuite uint16, compression byte, extensions []byte) []byte {
	payload := make([]byte, 0, 42)
	payload = append(payload, 0x03, 0x03)
	payload = append(payload, random...)
	payload = append(payload, 0x00)
	payload = append(payload, byte(cipherSuite>>8), byte(cipherSuite))
	payload = append(payload, compression)
	payload = append(payload, byte(len(extensions)>>8), byte(len(extensions)))
	payload = append(payload, extensions...)

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
		if !bytes.Equal(c.clientRandom, c.originalClientRandom) {
			t.Fatalf("group 0x%04x: CH2 must preserve CH1 random", group)
		}
	}
}

func TestBuildClientHelloForHRRPreservesEtMVersionsAndCookie(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{
		MinVersion: VersionTLS12, MaxVersion: VersionTLS13,
	})
	if _, err := c.buildClientHello("example.com"); err != nil {
		t.Fatalf("buildClientHello: %v", err)
	}
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}
	hello, err := c.buildClientHelloForHRR("example.com", X25519, cookie)
	if err != nil {
		t.Fatalf("buildClientHelloForHRR: %v", err)
	}
	extensions := parseClientHelloExtensions(t, hello)
	if data, ok := extensions[extensionEncryptThenMAC]; !ok || len(data) != 0 {
		t.Fatalf("CH2 Encrypt-then-MAC extension = %x, present=%v", data, ok)
	}
	wantCookie := append([]byte{0, byte(len(cookie))}, cookie...)
	if !bytes.Equal(extensions[extensionCookie], wantCookie) {
		t.Fatalf("CH2 cookie extension = %x, want %x", extensions[extensionCookie], wantCookie)
	}
	wantVersions := []byte{4, byte(VersionTLS13 >> 8), byte(VersionTLS13 & 0xff), byte(VersionTLS12 >> 8), byte(VersionTLS12 & 0xff)}
	if !bytes.Equal(extensions[extensionSupportedVersions], wantVersions) {
		t.Fatalf("CH2 supported_versions = %x, want %x", extensions[extensionSupportedVersions], wantVersions)
	}
}

func TestDetectTLSVersionRejectsMalformedServerHelloShape(t *testing.T) {
	c := NewClientWithConfig(nil, &Config{})
	valid := serverHelloWith(bytes.Repeat([]byte{0x11}, 32), TLS_AES_128_GCM_SHA256)

	t.Run("legacy version", func(t *testing.T) {
		serverHello := append([]byte(nil), valid...)
		serverHello[4], serverHello[5] = 0x03, 0x02
		if _, _, err := c.detectTLSVersion(serverHello); err == nil || !strings.Contains(err.Error(), "legacy version") {
			t.Fatalf("invalid legacy version result: %v", err)
		}
	})

	t.Run("session ID length", func(t *testing.T) {
		serverHello := append([]byte(nil), valid...)
		serverHello[4+34] = 0xff
		if _, _, err := c.detectTLSVersion(serverHello); err == nil || !strings.Contains(err.Error(), "session ID length") {
			t.Fatalf("invalid session ID length result: %v", err)
		}
	})

	t.Run("compression", func(t *testing.T) {
		serverHello := serverHelloWithExtensions(bytes.Repeat([]byte{0x11}, 32), TLS_AES_128_GCM_SHA256, 1, nil)
		if _, _, err := c.detectTLSVersion(serverHello); err == nil || !strings.Contains(err.Error(), "compression") {
			t.Fatalf("invalid compression result: %v", err)
		}
	})
}

func TestTLS12ServerHelloEncryptThenMACValidation(t *testing.T) {
	etm := []byte{byte(extensionEncryptThenMAC >> 8), byte(extensionEncryptThenMAC), 0, 0}
	random := bytes.Repeat([]byte{0x22}, 32)

	t.Run("negotiated for CBC", func(t *testing.T) {
		c := NewClientWithConfig(nil, &Config{})
		c.offeredEncryptThenMAC = true
		c.cipherSuite = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		serverHello := serverHelloWithExtensions(random, c.cipherSuite, 0, etm)
		if err := c.extractServerRandomTLS12(serverHello); err != nil {
			t.Fatal(err)
		}
		if !c.encryptThenMAC {
			t.Fatal("valid Encrypt-then-MAC selection was not recorded")
		}
	})

	t.Run("not offered", func(t *testing.T) {
		c := NewClientWithConfig(nil, &Config{})
		c.cipherSuite = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		serverHello := serverHelloWithExtensions(random, c.cipherSuite, 0, etm)
		if err := c.extractServerRandomTLS12(serverHello); err == nil {
			t.Fatal("unoffered Encrypt-then-MAC selection was accepted")
		}
	})

	t.Run("non-CBC suite", func(t *testing.T) {
		c := NewClientWithConfig(nil, &Config{})
		c.offeredEncryptThenMAC = true
		c.cipherSuite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		serverHello := serverHelloWithExtensions(random, c.cipherSuite, 0, etm)
		if err := c.extractServerRandomTLS12(serverHello); err == nil || !strings.Contains(err.Error(), "non-CBC") {
			t.Fatalf("non-CBC Encrypt-then-MAC result: %v", err)
		}
	})

	t.Run("duplicate extension", func(t *testing.T) {
		c := NewClientWithConfig(nil, &Config{})
		c.cipherSuite = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		duplicate := []byte{0, 99, 0, 0, 0, 99, 0, 0}
		serverHello := serverHelloWithExtensions(random, c.cipherSuite, 0, duplicate)
		if err := c.extractServerRandomTLS12(serverHello); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate extension result: %v", err)
		}
	})
}

func parseClientHelloExtensions(t *testing.T, record []byte) map[uint16][]byte {
	t.Helper()
	if len(record) < 5 || int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 {
		t.Fatal("invalid ClientHello record")
	}
	message := record[5:]
	if len(message) < 4+2+32+1 || HandshakeType(message[0]) != typeClientHello {
		t.Fatal("invalid ClientHello message")
	}
	offset := 4 + 2 + 32
	sessionIDLen := int(message[offset])
	offset++
	if sessionIDLen > len(message)-offset {
		t.Fatal("invalid ClientHello session ID")
	}
	offset += sessionIDLen
	if len(message)-offset < 2 {
		t.Fatal("missing ClientHello cipher suites")
	}
	suitesLen := int(binary.BigEndian.Uint16(message[offset : offset+2]))
	offset += 2
	if suitesLen > len(message)-offset {
		t.Fatal("invalid ClientHello cipher suites")
	}
	offset += suitesLen
	if len(message)-offset < 1 {
		t.Fatal("missing ClientHello compression methods")
	}
	compressionLen := int(message[offset])
	offset++
	if compressionLen > len(message)-offset {
		t.Fatal("invalid ClientHello compression methods")
	}
	offset += compressionLen
	if len(message)-offset < 2 {
		t.Fatal("missing ClientHello extensions")
	}
	extensionsLen := int(binary.BigEndian.Uint16(message[offset : offset+2]))
	offset += 2
	if extensionsLen != len(message)-offset {
		t.Fatal("invalid ClientHello extensions length")
	}
	result := make(map[uint16][]byte)
	end := offset + extensionsLen
	for offset < end {
		if end-offset < 4 {
			t.Fatal("truncated ClientHello extension")
		}
		extensionType := binary.BigEndian.Uint16(message[offset : offset+2])
		extensionLen := int(binary.BigEndian.Uint16(message[offset+2 : offset+4]))
		offset += 4
		if extensionLen > end-offset {
			t.Fatal("invalid ClientHello extension length")
		}
		if _, duplicate := result[extensionType]; duplicate {
			t.Fatalf("duplicate ClientHello extension %d", extensionType)
		}
		result[extensionType] = append([]byte(nil), message[offset:offset+extensionLen]...)
		offset += extensionLen
	}
	return result
}
