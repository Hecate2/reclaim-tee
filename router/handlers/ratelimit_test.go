package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func requestWithXFF(xff, remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/allocate", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIPUsesLBVouchedEntry(t *testing.T) {
	cases := []struct {
		name string
		xff  string
		want string
	}{
		{"lb appended pair", "203.0.113.7, 130.211.0.1", "203.0.113.7"},
		{"spoofed prefix ignored", "1.2.3.4, 203.0.113.7, 130.211.0.1", "203.0.113.7"},
		{"multiple spoofed entries ignored", "9.9.9.9, 8.8.8.8, 203.0.113.7, 130.211.0.1", "203.0.113.7"},
		{"ipv6 normalised", "2001:db8::1, 130.211.0.1", "2001:db8::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientIP(requestWithXFF(tc.xff, "130.211.0.1:443")); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPFallsBackWhenNoVouchedEntry(t *testing.T) {
	if got := clientIP(requestWithXFF("", "198.51.100.9:1234")); got != "198.51.100.9" {
		t.Fatalf("no XFF should use RemoteAddr, got %q", got)
	}
	if got := clientIP(requestWithXFF("1.2.3.4", "198.51.100.9:1234")); got != "198.51.100.9" {
		t.Fatalf("single-entry XFF is not LB-vouched, got %q", got)
	}
}

// The bypass this guards: a spoofed leftmost entry used to mint a fresh
// bucket per request, so every request arrived with a full burst.
func TestRateLimiterNotBypassedByRotatingXFFPrefix(t *testing.T) {
	l := newIPRateLimiter(rate.Limit(1), 3, 10*time.Minute, 4096)

	allowed := 0
	for i := range 20 {
		xff := string(rune('a'+i)) + ".example, 203.0.113.7, 130.211.0.1"
		if l.Allow(clientIP(requestWithXFF(xff, "130.211.0.1:443"))) {
			allowed++
		}
	}

	if allowed > 3 {
		t.Fatalf("rotating the spoofable XFF prefix allowed %d requests, want at most the burst of 3", allowed)
	}
}
