package providers

import (
	"bytes"
	"net/url"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestHostHeaderSerializationPreservesPreCBCWireFormat(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{rawURL: "https://example.com/", want: "example.com"},
		{rawURL: "https://example.com:443/", want: "example.com"},
		{rawURL: "https://example.com:8443/", want: "example.com:8443"},
		{rawURL: "https://[2001:db8::1]/", want: "2001:db8::1"},
		{rawURL: "https://[2001:db8::1]:443/", want: "2001:db8::1"},
		{rawURL: "https://[2001:db8::1]:8443/", want: "[2001:db8::1]:8443"},
	}

	for _, test := range tests {
		t.Run(test.rawURL, func(t *testing.T) {
			u, err := url.Parse(test.rawURL)
			if err != nil {
				t.Fatal(err)
			}
			if got := getHostHeaderString(u); got != test.want {
				t.Fatalf("getHostHeaderString() = %q, want pre-CBC wire value %q", got, test.want)
			}
		})
	}
}

func TestCreateRequestPreservesPreCBCDefaultPortIPv6HostHeader(t *testing.T) {
	for _, rawURL := range []string{
		"https://[2001:db8::1]/",
		"https://[2001:db8::1]:443/",
	} {
		t.Run(rawURL, func(t *testing.T) {
			request, err := CreateRequest(
				&HTTPProviderSecretParams{AuthorisationHeader: "Bearer fixed"},
				&HTTPProviderParams{URL: rawURL, Method: "GET"},
			)
			if err != nil {
				t.Fatal(err)
			}
			wantPrefix := []byte("GET / HTTP/1.1\r\nHost: 2001:db8::1\r\nConnection: close\r\n")
			if !bytes.HasPrefix(request.Data, wantPrefix) {
				t.Fatalf("request no longer matches pre-CBC wire prefix: %q", request.Data)
			}
		})
	}
}

func TestCreateRequestSecretURLRangesMatchSerializedRequest(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "explicit default port", url: "https://example.com:443/api?token={{secret}}"},
		{name: "default port IPv6", url: "https://[2001:db8::1]:443/api?token={{secret}}"},
		{name: "escaped path prefix", url: "https://example.com/a%2Fb/api?token={{secret}}"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const secretValue = "ABCDEFGH"
			params := HTTPProviderParams{URL: test.url, Method: "GET"}
			secret := HTTPProviderSecretParams{
				AuthorisationHeader: "Bearer fixed",
				ParamValues:         map[string]string{"secret": secretValue},
			}

			request, err := CreateRequest(&secret, &params)
			if err != nil {
				t.Fatalf("CreateRequest() error = %v", err)
			}

			matched := false
			masked := bytes.Clone(request.Data)
			for _, redaction := range request.Redactions {
				end := redaction.Start + redaction.Length
				if redaction.Start < 0 || end > len(request.Data) {
					t.Fatalf("redaction [%d:%d] is outside request of length %d", redaction.Start, end, len(request.Data))
				}
				if bytes.Equal(request.Data[redaction.Start:end], []byte(secretValue)) {
					matched = true
				}
				for i := redaction.Start; i < end; i++ {
					masked[i] = '*'
				}
			}
			if !matched {
				t.Fatalf("no redaction points at the serialized secret in request %q", request.Data)
			}
			if bytes.Contains(masked, []byte(secretValue)) {
				t.Fatalf("serialized secret remains outside redaction ranges: %q", masked)
			}
		})
	}
}

func TestGetResponseRedactionsHideChunkExtensionsAndTrailers(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1;auth=SECRET\r\nA\r\n0\r\nX-Secret: TOKEN\r\n\r\n")
	params := HTTPProviderParams{
		URL:                "https://example.com/",
		Method:             "GET",
		ResponseRedactions: []ResponseRedaction{{Regex: "A"}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: true}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "chunk-metadata-privacy")
	if err != nil {
		t.Fatalf("GetResponseRedactions() error = %v", err)
	}
	masked := bytes.Clone(response)
	for _, redaction := range redactions {
		for i := redaction.Start; i < redaction.Start+redaction.Length; i++ {
			masked[i] = '*'
		}
	}
	if bytes.Contains(masked, []byte("SECRET")) {
		t.Fatalf("chunk extension value was revealed: %q", masked)
	}
	if bytes.Contains(masked, []byte("TOKEN")) {
		t.Fatalf("chunk trailer value was revealed: %q", masked)
	}
	if !bytes.Contains(masked, []byte("1;")) || !bytes.Contains(masked, []byte("\r\nA\r\n0\r\n")) {
		t.Fatalf("required chunk size and delimiter framing was redacted: %q", masked)
	}
}

func TestTLS12CBCRevealsHeaderSyntaxButNotHiddenValues(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Secret: TOKEN\r\nContent-Length: 1\r\n\r\nA")
	params := HTTPProviderParams{
		URL:                "https://example.com/",
		Method:             "GET",
		ResponseRedactions: []ResponseRedaction{{Regex: "A"}},
	}
	legacyCtx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}
	cbcCtx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: true}

	legacyRedactions, err := GetResponseRedactions(response, &params, &legacyCtx, "legacy-header-syntax")
	if err != nil {
		t.Fatal(err)
	}
	legacyMasked := applyResponseRedactions(response, legacyRedactions)
	if bytes.Contains(legacyMasked, []byte("X-Secret")) {
		t.Fatalf("pre-CBC header-name redaction behavior changed: %q", legacyMasked)
	}

	cbcRedactions, err := GetResponseRedactions(response, &params, &cbcCtx, "cbc-header-syntax")
	if err != nil {
		t.Fatal(err)
	}
	cbcMasked := applyResponseRedactions(response, cbcRedactions)
	if !bytes.Contains(cbcMasked, []byte("X-Secret: *****\r\n")) {
		t.Fatalf("CBC header syntax is unavailable to verifier: %q", cbcMasked)
	}
	if bytes.Contains(cbcMasked, []byte("TOKEN")) {
		t.Fatalf("CBC hidden header value was revealed: %q", cbcMasked)
	}
}

func TestGetResponseRedactionsAllowHashedCaptureAtChunkBoundary(t *testing.T) {
	response := chunkedResponse("text/plain", []byte("prefix="), []byte("secret"))
	hash := "oprf-mpc"
	params := HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		ResponseRedactions: []ResponseRedaction{{
			Regex: "prefix=(?<value>secret)",
			Hash:  &hash,
		}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: true}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "oprf-chunk-boundary")
	if err != nil {
		t.Fatalf("GetResponseRedactions() error = %v", err)
	}
	for _, redaction := range redactions {
		if redaction.Hash != hash {
			continue
		}
		got := response[redaction.Start : redaction.Start+redaction.Length]
		if !bytes.Equal(got, []byte("secret")) {
			t.Fatalf("hashed range points at %q, want secret", got)
		}
		return
	}
	t.Fatal("hashed capture redaction not found")
}

func TestPreCBCProviderBehaviorRemainsLegacyCompatible(t *testing.T) {
	params := HTTPProviderParams{
		URL:                "https://example.com/",
		Method:             "GET",
		ResponseRedactions: []ResponseRedaction{{Regex: "A"}},
	}
	legacyCtx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}
	cbcCtx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: true}

	t.Run("chunk metadata remains legacy-visible", func(t *testing.T) {
		response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1;auth=SECRET\r\nA\r\n0\r\nX-Secret: TOKEN\r\n\r\n")

		legacyRedactions, err := GetResponseRedactions(response, &params, &legacyCtx, "legacy-chunk-metadata")
		if err != nil {
			t.Fatalf("legacy GetResponseRedactions() error = %v", err)
		}
		legacyMasked := applyResponseRedactions(response, legacyRedactions)
		if !bytes.Contains(legacyMasked, []byte("SECRET")) || !bytes.Contains(legacyMasked, []byte("TOKEN")) {
			t.Fatalf("legacy chunk metadata behavior changed: %q", legacyMasked)
		}

		cbcRedactions, err := GetResponseRedactions(response, &params, &cbcCtx, "cbc-chunk-metadata")
		if err != nil {
			t.Fatalf("CBC GetResponseRedactions() error = %v", err)
		}
		cbcMasked := applyResponseRedactions(response, cbcRedactions)
		if bytes.Contains(cbcMasked, []byte("SECRET")) || bytes.Contains(cbcMasked, []byte("TOKEN")) {
			t.Fatalf("CBC chunk metadata was revealed: %q", cbcMasked)
		}
	})

	malformedResponses := []struct {
		name     string
		response []byte
	}{
		{
			name:     "missing terminal zero chunk",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n"),
		},
		{
			name:     "missing final trailer terminator",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n"),
		},
		{
			name:     "bytes after terminal chunk",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\nextra"),
		},
		{
			name:     "empty chunk size line",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n\r\n1\r\nA\r\n0\r\n\r\n"),
		},
		{
			name:     "signed chunk size",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n+1\r\nA\r\n0\r\n\r\n"),
		},
		{
			name:     "bytes after content length",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nAextra"),
		},
		{
			name:     "duplicate content length",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nA"),
		},
		{
			name:     "transfer encoding with content length",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nContent-Length: 11\r\n\r\n1\r\nA\r\n0\r\n\r\n"),
		},
	}

	for _, test := range malformedResponses {
		t.Run(test.name, func(t *testing.T) {
			if _, err := GetResponseRedactions(test.response, &params, &legacyCtx, "legacy-framing"); err != nil {
				t.Fatalf("legacy framing behavior changed: %v", err)
			}
			if _, err := GetResponseRedactions(test.response, &params, &cbcCtx, "cbc-framing"); err == nil {
				t.Fatal("CBC strict framing accepted incomplete or ambiguous response")
			}
		})
	}
}

func TestTLS12CBCStrictChunkTrailerCompletion(t *testing.T) {
	validResponses := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\nX-Trailer: value\r\n\r\n"),
	}
	for i, response := range validResponses {
		if _, err := parseHTTPResponseBytesWithFraming(response, true); err != nil {
			t.Fatalf("valid strict chunked response %d rejected: %v", i, err)
		}
	}

	invalidResponses := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\nX-Trailer: value\r\n"),
	}
	for i, response := range invalidResponses {
		if _, err := parseHTTPResponseBytesWithFraming(response, true); err == nil {
			t.Fatalf("incomplete strict chunked response %d was accepted", i)
		}
	}
}

func applyResponseRedactions(response []byte, redactions []shared.ResponseRedactionRange) []byte {
	masked := bytes.Clone(response)
	for _, redaction := range redactions {
		for i := redaction.Start; i < redaction.Start+redaction.Length; i++ {
			masked[i] = '*'
		}
	}
	return masked
}
