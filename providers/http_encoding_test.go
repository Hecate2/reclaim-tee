package providers

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestGetResponseRedactionsPreservesRawOffsetsForInvalidUTF8(t *testing.T) {
	body := append([]byte("<html><body><p>"), 0xf1)
	body = append(body, []byte(`<span>ASCII TARGET</span></p></body></html>`)...)

	response := responseWithBody(body, "text/html; charset=ISO-8859-1")

	params := HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		ResponseRedactions: []ResponseRedaction{{
			XPath: "//span",
			Regex: "ASCII TARGET",
		}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(
		response,
		&params,
		&ctx,
		"iso-8859-1-regression",
	)
	if err != nil {
		t.Fatalf("XPath/regex unexpectedly failed: %v", err)
	}

	reconstructed := reconstructRedactedResponse(t, response, redactions)

	if !bytes.Contains(reconstructed, []byte("ASCII TARGET")) {
		t.Fatalf(
			"XPath/regex matched, but the generated ranges did not reveal the exact raw value: %q",
			reconstructed,
		)
	}
}

func TestGetResponseRedactionsKeepsAllSelectorOffsetsByteAligned(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		contentType string
		redaction   ResponseRedaction
		want        []byte
	}{
		{
			name:        "regex only after invalid byte",
			body:        append([]byte("<p>before\xf1</p>"), []byte(`<span>ASCII TARGET</span>`)...),
			contentType: "text/html; charset=ISO-8859-1",
			redaction:   ResponseRedaction{Regex: "ASCII TARGET"},
			want:        []byte("ASCII TARGET"),
		},
		{
			name:        "xpath only after multiple invalid bytes",
			body:        append([]byte("<p>\xf1middle\xe9</p>"), []byte(`<span>ASCII TARGET</span>`)...),
			contentType: "text/html; charset=ISO-8859-1",
			redaction:   ResponseRedaction{XPath: "//span"},
			want:        []byte("ASCII TARGET"),
		},
		{
			name:        "xpath jsonpath and regex after invalid byte",
			body:        append([]byte("<p>before\xf1</p>"), []byte(`<script>{"value":"ASCII TARGET"}</script>`)...),
			contentType: "text/html; charset=ISO-8859-1",
			redaction: ResponseRedaction{
				XPath:    "//script",
				JSONPath: "$.value",
				Regex:    "ASCII TARGET",
			},
			want: []byte("ASCII TARGET"),
		},
		{
			name:        "invalid byte after selection",
			body:        append([]byte(`<span>ASCII TARGET</span><p>after`), 0xf1),
			contentType: "text/html; charset=ISO-8859-1",
			redaction:   ResponseRedaction{XPath: "//span", Regex: "ASCII TARGET"},
			want:        []byte("ASCII TARGET"),
		},
		{
			name:        "valid UTF-8 before selection",
			body:        []byte(`<p>Señor</p><span>ASCII TARGET</span>`),
			contentType: "text/html; charset=UTF-8",
			redaction:   ResponseRedaction{XPath: "//span", Regex: "ASCII TARGET"},
			want:        []byte("ASCII TARGET"),
		},
		{
			name:        "charset-aware xpath keeps raw range",
			body:        []byte{'<', 's', 'p', 'a', 'n', '>', 'S', 'e', 0xf1, 'o', 'r', '<', '/', 's', 'p', 'a', 'n', '>'},
			contentType: "text/html; charset=ISO-8859-1",
			redaction:   ResponseRedaction{XPath: "//span[text()='Señor']"},
			want:        []byte{'S', 'e', 0xf1, 'o', 'r'},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := responseWithBody(test.body, test.contentType)
			params := HTTPProviderParams{
				URL:                "https://example.com/",
				Method:             "GET",
				ResponseRedactions: []ResponseRedaction{test.redaction},
			}
			ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

			redactions, err := GetResponseRedactions(response, &params, &ctx, test.name)
			if err != nil {
				t.Fatalf("GetResponseRedactions() error = %v", err)
			}

			reconstructed := reconstructRedactedResponse(t, response, redactions)
			if !bytes.Contains(reconstructed, test.want) {
				t.Fatalf("revealed response does not contain raw target %q: %q", test.want, reconstructed)
			}
		})
	}
}

func TestGetResponseRedactionsKeepsHashedRegexGroupByteAligned(t *testing.T) {
	body := append([]byte("<p>before\xf1</p>"), []byte(`<span>ASCII TARGET</span>`)...)
	response := responseWithBody(body, "text/html; charset=ISO-8859-1")
	hash := "oprf"
	params := HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		ResponseRedactions: []ResponseRedaction{{
			Regex: `<span>(?<secret>ASCII TARGET)</span>`,
			Hash:  &hash,
		}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "hashed-regex-offset-regression")
	if err != nil {
		t.Fatalf("GetResponseRedactions() error = %v", err)
	}

	for _, redaction := range redactions {
		if redaction.Hash != hash {
			continue
		}
		got := response[redaction.Start : redaction.Start+redaction.Length]
		if !bytes.Equal(got, []byte("ASCII TARGET")) {
			t.Fatalf("hashed range points at %q, want %q", got, "ASCII TARGET")
		}
		return
	}
	t.Fatal("hashed regex range not found")
}

func TestGetResponseRedactionsKeepsChunkedRegexOffsetsByteAligned(t *testing.T) {
	firstChunk := []byte("<p>before\xf1</p><span>ASCII ")
	secondChunk := []byte("TARGET</span>")
	response := chunkedResponse(
		"text/html; charset=ISO-8859-1",
		firstChunk,
		secondChunk,
	)
	params := HTTPProviderParams{
		URL:                "https://example.com/",
		Method:             "GET",
		ResponseRedactions: []ResponseRedaction{{Regex: "ASCII TARGET"}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "chunked-regex-offset-regression")
	if err != nil {
		t.Fatalf("GetResponseRedactions() error = %v", err)
	}

	reconstructed := reconstructRedactedResponse(t, response, redactions)
	parsed, err := parseHTTPResponseBytes(response)
	if err != nil {
		t.Fatalf("parse original chunked response: %v", err)
	}
	var dechunked []byte
	for _, chunk := range parsed.Chunks {
		dechunked = append(dechunked, reconstructed[chunk.Start:chunk.Start+chunk.Length]...)
	}
	if !bytes.Contains(dechunked, []byte("ASCII TARGET")) {
		t.Fatalf("dechunked reveal does not contain target: %q", dechunked)
	}
}

func responseWithBody(body []byte, contentType string) []byte {
	response := fmt.Appendf(
		nil,
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
		contentType,
		len(body),
	)
	return append(response, body...)
}

func chunkedResponse(contentType string, chunks ...[]byte) []byte {
	response := fmt.Appendf(
		nil,
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\n\r\n",
		contentType,
	)
	for _, chunk := range chunks {
		response = fmt.Appendf(response, "%x\r\n", len(chunk))
		response = append(response, chunk...)
		response = append(response, '\r', '\n')
	}
	return append(response, '0', '\r', '\n', '\r', '\n')
}

func reconstructRedactedResponse(t *testing.T, response []byte, redactions []shared.ResponseRedactionRange) []byte {
	t.Helper()

	reconstructed := bytes.Clone(response)
	for _, redaction := range redactions {
		start := redaction.Start
		end := redaction.Start + redaction.Length
		if start < 0 || end > len(reconstructed) || end < start {
			t.Fatalf("invalid redaction range [%d:%d]", start, end)
		}
		for i := start; i < end; i++ {
			reconstructed[i] = '*'
		}
	}
	return reconstructed
}
