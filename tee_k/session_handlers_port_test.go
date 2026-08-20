package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestValidateHTTPRequestFormatAcceptsAnyValidHTTPSPort(t *testing.T) {
	t.Parallel()

	teek := &TEEK{logger: shared.NewNopLogger()}
	ports := []int{1, 80, 81, 443, 444, 8443, 9443, 50001, 65535}

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

func TestValidateHTTPRequestFormatAcceptsNonDefaultHTTPSPortIPv6(t *testing.T) {
	t.Parallel()

	teek := &TEEK{logger: shared.NewNopLogger()}
	request := []byte("GET / HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\nConnection: close\r\n\r\n")
	connData := &shared.RequestConnectionData{Hostname: "2001:db8::1", Port: 8443}
	if err := teek.validateHTTPRequestFormat(request, nil, connData); err != nil {
		t.Fatalf("validateHTTPRequestFormat() error = %v", err)
	}
}

func TestValidateHTTPRequestFormatRejectsInvalidPortNumber(t *testing.T) {
	t.Parallel()

	teek := &TEEK{logger: shared.NewNopLogger()}
	for _, port := range []int{-1, 0, 65536} {
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			t.Parallel()

			request := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: example.com:%d\r\nConnection: close\r\n\r\n", port))
			connData := &shared.RequestConnectionData{Hostname: "example.com", Port: port}
			err := teek.validateHTTPRequestFormat(request, nil, connData)
			if err == nil {
				t.Fatal("validateHTTPRequestFormat() error = nil, want invalid port error")
			}
			if !strings.Contains(err.Error(), "between 1 and 65535") {
				t.Fatalf("validateHTTPRequestFormat() error = %q, want valid port range", err)
			}
		})
	}
}

func TestValidateHTTPRequestFormatRejectsHostWithoutNonDefaultPort(t *testing.T) {
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
