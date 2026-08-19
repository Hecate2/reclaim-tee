package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestValidateHTTPRequestFormatAcceptsSupportedHTTPSPorts(t *testing.T) {
	t.Parallel()

	teek := &TEEK{logger: shared.NewNopLogger()}
	tests := []struct {
		name       string
		hostname   string
		port       int
		hostHeader string
	}{
		{name: "default HTTPS port", hostname: "example.com", port: 443, hostHeader: "example.com"},
		{name: "alternate HTTPS port", hostname: "example.com", port: 8443, hostHeader: "example.com:8443"},
		{name: "alternate HTTPS port IPv6", hostname: "2001:db8::1", port: 8443, hostHeader: "[2001:db8::1]:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", tt.hostHeader))
			connData := &shared.RequestConnectionData{Hostname: tt.hostname, Port: tt.port}
			if err := teek.validateHTTPRequestFormat(request, nil, connData); err != nil {
				t.Fatalf("validateHTTPRequestFormat() error = %v", err)
			}
		})
	}
}

func TestValidateHTTPRequestFormatRejectsUnsupportedHTTPSPort(t *testing.T) {
	t.Parallel()

	teek := &TEEK{logger: shared.NewNopLogger()}
	request := []byte("GET / HTTP/1.1\r\nHost: example.com:9443\r\nConnection: close\r\n\r\n")
	connData := &shared.RequestConnectionData{Hostname: "example.com", Port: 9443}

	err := teek.validateHTTPRequestFormat(request, nil, connData)
	if err == nil {
		t.Fatal("validateHTTPRequestFormat() error = nil, want unsupported port error")
	}
	if !strings.Contains(err.Error(), "443 and 8443") {
		t.Fatalf("validateHTTPRequestFormat() error = %q, want supported-port list", err)
	}
}

func TestValidateHTTPRequestFormatRejectsHostWithoutAlternatePort(t *testing.T) {
	t.Parallel()

	teek := &TEEK{logger: shared.NewNopLogger()}
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	connData := &shared.RequestConnectionData{Hostname: "example.com", Port: 8443}

	err := teek.validateHTTPRequestFormat(request, nil, connData)
	if err == nil {
		t.Fatal("validateHTTPRequestFormat() error = nil, want Host authority mismatch")
	}
	if !strings.Contains(err.Error(), "does not match connection authority") {
		t.Fatalf("validateHTTPRequestFormat() error = %q, want authority mismatch", err)
	}
}
