package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestValidateTLS12CBCRequestPlaintextRequiresSingleRecord(t *testing.T) {
	if err := validateTLS12CBCRequestPlaintext(bytes.Repeat([]byte{'a'}, maxTLS12CBCRequestPlaintext)); err != nil {
		t.Fatalf("maximum single-record request rejected: %v", err)
	}
	if err := validateTLS12CBCRequestPlaintext(bytes.Repeat([]byte{'a'}, maxTLS12CBCRequestPlaintext+1)); err == nil {
		t.Fatal("multi-record CBC request was accepted")
	}
}

func TestValidateHTTPRequestFormatRejectsAmbiguousFraming(t *testing.T) {
	teek := &TEEK{logger: shared.NewNopLogger()}
	connection := &shared.RequestConnectionData{Hostname: "example.com", Port: 443}
	valid := "POST /submit HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 4\r\n\r\ndata"

	tests := []struct {
		name    string
		request string
		ranges  []shared.RequestRedactionRange
	}{
		{name: "pipelined request", request: "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "trailing bytes", request: "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\ntrailing"},
		{name: "duplicate content length", request: "POST / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ndata"},
		{name: "transfer encoding", request: "POST / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\ndata"},
		{name: "redacted content length", request: valid, ranges: []shared.RequestRedactionRange{{Start: strings.Index(valid, "Content-Length"), Length: len("Content-Length"), Type: shared.RedactionTypeSensitive}}},
		{name: "redaction crosses request version", request: valid, ranges: []shared.RequestRedactionRange{{Start: strings.Index(valid, "submit"), Length: len("submit HTTP"), Type: shared.RedactionTypeSensitive}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := teek.validateRedactionPositions(test.ranges, len(test.request)); err != nil {
				t.Fatalf("test range invalid: %v", err)
			}
			if err := teek.validateTLS12CBCHTTPRequestFormat([]byte(test.request), test.ranges, connection); err == nil {
				t.Fatal("ambiguous request framing was accepted")
			}
		})
	}
}

func TestStrictCBCRequestChecksDoNotChangeLegacyValidator(t *testing.T) {
	teek := &TEEK{logger: shared.NewNopLogger()}
	connection := &shared.RequestConnectionData{Hostname: "example.com", Port: 443}
	legacyRequest := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

	if err := teek.validateHTTPRequestFormat(legacyRequest, nil, connection); err != nil {
		t.Fatalf("legacy split-AEAD request behavior changed: %v", err)
	}
	if err := teek.validateTLS12CBCHTTPRequestFormat(legacyRequest, nil, connection); err == nil {
		t.Fatal("CBC validator accepted request without explicit Content-Length")
	}
}

func TestPreCBCClientCannotNegotiateCBC(t *testing.T) {
	legacyDefault := &minitls.Config{MinVersion: minitls.VersionTLS12, MaxVersion: minitls.VersionTLS12}
	if err := validateClientCipherCapabilities(legacyDefault, false); err != nil {
		t.Fatalf("legacy AEAD defaults rejected: %v", err)
	}

	forcedCBC := &minitls.Config{CipherSuites: []uint16{minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}
	if err := validateClientCipherCapabilities(forcedCBC, false); err == nil {
		t.Fatal("pre-CBC client was allowed to force a CBC cipher suite")
	}
	if err := validateClientCipherCapabilities(forcedCBC, true); err != nil {
		t.Fatalf("CBC-capable client was rejected: %v", err)
	}
}
