package client

import (
	"testing"
)

func TestValidateGeoLocation(t *testing.T) {
	tests := []struct {
		name        string
		geoLocation string
		wantErr     bool
	}{
		{"valid US", "US", false},
		{"valid US lowercase", "us", false},
		{"valid GB", "GB", false},
		{"valid DE", "DE", false},
		{"valid JP", "JP", false},
		{"invalid XX", "XX", true},
		{"invalid ZZ", "ZZ", true},
		{"too short", "U", true},
		{"too long", "USA", true},
		{"empty", "", true},
		{"numbers", "12", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGeoLocation(tt.geoLocation)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGeoLocation(%q) error = %v, wantErr %v", tt.geoLocation, err, tt.wantErr)
			}
		})
	}
}

func TestParseProxyURL(t *testing.T) {
	tests := []struct {
		name         string
		proxyURL     string
		geoLocation  string
		wantScheme   string
		wantHost     string
		wantPort     string
		wantUsername string
		wantPassword string
		wantErr      bool
	}{
		{
			name:         "standard proxy URL with geoLocation",
			proxyURL:     "https://user-country-{{geoLocation}}:password123@proxy.example.io:22225/",
			geoLocation:  "US",
			wantScheme:   "https",
			wantHost:     "proxy.example.io",
			wantPort:     "22225",
			wantUsername: "user-country-us",
			wantPassword: "password123",
			wantErr:      false,
		},
		{
			name:         "https no port uses 443",
			proxyURL:     "https://user-{{geoLocation}}:pass@proxy.example.com/",
			geoLocation:  "GB",
			wantScheme:   "https",
			wantHost:     "proxy.example.com",
			wantPort:     "443",
			wantUsername: "user-gb",
			wantPassword: "pass",
			wantErr:      false,
		},
		{
			name:         "http no port uses default",
			proxyURL:     "http://user-{{geoLocation}}:pass@proxy.example.com/",
			geoLocation:  "GB",
			wantScheme:   "http",
			wantHost:     "proxy.example.com",
			wantPort:     "22225",
			wantUsername: "user-gb",
			wantPassword: "pass",
			wantErr:      false,
		},
		{
			name:        "missing geoLocation placeholder errors",
			proxyURL:    "https://user:pass@proxy.example.com/",
			geoLocation: "US",
			wantErr:     true,
		},
		{
			name:         "geoLocation substitution lowercase",
			proxyURL:     "https://zone-{{geoLocation}}:secret@proxy.io:8080/",
			geoLocation:  "DE",
			wantScheme:   "https",
			wantHost:     "proxy.io",
			wantPort:     "8080",
			wantUsername: "zone-de",
			wantPassword: "secret",
			wantErr:      false,
		},
		{
			name:         "geoLocation in host part",
			proxyURL:     "https://user:pass@proxy-{{geoLocation}}.example.com:8080/",
			geoLocation:  "US",
			wantScheme:   "https",
			wantHost:     "proxy-us.example.com",
			wantPort:     "8080",
			wantUsername: "user",
			wantPassword: "pass",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, host, port, username, password, err := parseProxyURL(tt.proxyURL, tt.geoLocation)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseProxyURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if scheme != tt.wantScheme {
					t.Errorf("scheme = %q, want %q", scheme, tt.wantScheme)
				}
				if host != tt.wantHost {
					t.Errorf("host = %q, want %q", host, tt.wantHost)
				}
				if port != tt.wantPort {
					t.Errorf("port = %q, want %q", port, tt.wantPort)
				}
				if username != tt.wantUsername {
					t.Errorf("username = %q, want %q", username, tt.wantUsername)
				}
				if password != tt.wantPassword {
					t.Errorf("password = %q, want %q", password, tt.wantPassword)
				}
			}
		})
	}
}
