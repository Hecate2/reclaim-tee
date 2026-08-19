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
	ports := []int{81, 85, 150, 155, 443, 1006, 2095, 2096, 4430, 8079, 8080, 8081, 8084, 8443, 8483, 50001, 50300}

	for _, port := range ports {
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			t.Parallel()

			hostHeader := fmt.Sprintf("example.com:%d", port)
			if port == 443 {
				hostHeader = "example.com"
			}
			request := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader))
			connData := &shared.RequestConnectionData{Hostname: "example.com", Port: port}
			if err := teek.validateHTTPRequestFormat(request, nil, connData); err != nil {
				t.Fatalf("validateHTTPRequestFormat() error = %v", err)
			}
		})
	}
}

func TestValidateHTTPRequestFormatAcceptsAlternateHTTPSPortIPv6(t *testing.T) {
	t.Parallel()

	teek := &TEEK{logger: shared.NewNopLogger()}
	request := []byte("GET / HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\nConnection: close\r\n\r\n")
	connData := &shared.RequestConnectionData{Hostname: "2001:db8::1", Port: 8443}
	if err := teek.validateHTTPRequestFormat(request, nil, connData); err != nil {
		t.Fatalf("validateHTTPRequestFormat() error = %v", err)
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
	for _, want := range []string{"81", "50300", "got port 9443"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("validateHTTPRequestFormat() error = %q, want %q", err, want)
		}
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
