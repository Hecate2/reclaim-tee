package providers

import (
	"bytes"
	"testing"
)

func TestGetResponseRedactionsMatchesNonASCIIRegexOnlyAgainstDecodedBody(t *testing.T) {
	body := []byte{'<', 's', 'p', 'a', 'n', '>', 'S', 'e', 0xf1, 'o', 'r', '<', '/', 's', 'p', 'a', 'n', '>'}
	response := responseWithBody(body, "text/html; charset=ISO-8859-1")
	params := HTTPProviderParams{
		URL:                "https://example.com/",
		Method:             "GET",
		ResponseRedactions: []ResponseRedaction{{Regex: "Señor"}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "iso-regex-only")
	if err != nil {
		t.Fatalf("non-ASCII regex-only redaction should match the charset-decoded body: %v", err)
	}

	reconstructed := reconstructRedactedResponse(t, response, redactions)
	wantRaw := []byte{'S', 'e', 0xf1, 'o', 'r'}
	if !bytes.Contains(reconstructed, wantRaw) {
		t.Fatalf("revealed response does not contain the exact raw ISO-8859-1 target %x: %x", wantRaw, reconstructed)
	}
}

func TestGetResponseRedactionsMatchesNonASCIINestedRegexAgainstDecodedXPathNode(t *testing.T) {
	body := []byte{'<', 's', 'p', 'a', 'n', '>', 'S', 'e', 0xf1, 'o', 'r', '<', '/', 's', 'p', 'a', 'n', '>'}
	response := responseWithBody(body, "text/html; charset=ISO-8859-1")
	params := HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		ResponseRedactions: []ResponseRedaction{{
			XPath: "//span",
			Regex: "Señor",
		}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "iso-xpath-regex")
	if err != nil {
		t.Fatalf("non-ASCII nested regex should match the charset-decoded XPath node: %v", err)
	}

	reconstructed := reconstructRedactedResponse(t, response, redactions)
	wantRaw := []byte{'S', 'e', 0xf1, 'o', 'r'}
	if !bytes.Contains(reconstructed, wantRaw) {
		t.Fatalf("revealed response does not contain the exact raw ISO-8859-1 target %x: %x", wantRaw, reconstructed)
	}
}

func TestGetResponseRedactionsMatchesNonASCIINestedRegexAgainstDecodedMarkup(t *testing.T) {
	body := []byte{'<', 's', 'p', 'a', 'n', ' ', 't', 'i', 't', 'l', 'e', '=', '"', 'S', 'e', 0xf1, 'o', 'r', '"', '>', 'v', 'a', 'l', 'u', 'e', '<', '/', 's', 'p', 'a', 'n', '>'}
	response := responseWithBody(body, "text/html; charset=ISO-8859-1")
	params := HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		ResponseRedactions: []ResponseRedaction{{
			XPath: "//span",
			Regex: `title="Señor"`,
		}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "iso-xpath-markup-regex")
	if err != nil {
		t.Fatalf("nested regex should match decoded element markup: %v", err)
	}

	reconstructed := reconstructRedactedResponse(t, response, redactions)
	wantRaw := []byte{'t', 'i', 't', 'l', 'e', '=', '"', 'S', 'e', 0xf1, 'o', 'r', '"'}
	if !bytes.Contains(reconstructed, wantRaw) {
		t.Fatalf("revealed response does not contain the exact raw attribute %x: %x", wantRaw, reconstructed)
	}
}

func TestGetResponseRedactionsMapsNonASCIIRegexNamedGroupToRawBytes(t *testing.T) {
	body := []byte{'<', 's', 'p', 'a', 'n', '>', 'p', 'r', 'e', 'f', 'i', 'x', ' ', 'S', 'e', 0xf1, 'o', 'r', ' ', 's', 'u', 'f', 'f', 'i', 'x', '<', '/', 's', 'p', 'a', 'n', '>'}
	response := responseWithBody(body, "text/html; charset=ISO-8859-1")
	hash := "oprf"
	params := HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		ResponseRedactions: []ResponseRedaction{{
			Regex: `<span>prefix (?<secret>Señor) suffix</span>`,
			Hash:  &hash,
		}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "iso-regex-named-group")
	if err != nil {
		t.Fatalf("non-ASCII named regex group should match decoded body: %v", err)
	}

	wantRaw := []byte{'S', 'e', 0xf1, 'o', 'r'}
	for _, redaction := range redactions {
		if redaction.Hash != hash {
			continue
		}
		got := response[redaction.Start : redaction.Start+redaction.Length]
		if !bytes.Equal(got, wantRaw) {
			t.Fatalf("hashed range points at %x, want raw group %x", got, wantRaw)
		}
		return
	}
	t.Fatal("hashed regex range not found")
}

func TestGetResponseRedactionsMapsChunkedNonASCIIRegexToRawBytes(t *testing.T) {
	firstChunk := []byte("<span>Se")
	secondChunk := []byte{0xf1, 'o', 'r', '<', '/', 's', 'p', 'a', 'n', '>'}
	response := chunkedResponse(
		"text/html; charset=ISO-8859-1",
		firstChunk,
		secondChunk,
	)
	params := HTTPProviderParams{
		URL:                "https://example.com/",
		Method:             "GET",
		ResponseRedactions: []ResponseRedaction{{Regex: "Señor"}},
	}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}

	redactions, err := GetResponseRedactions(response, &params, &ctx, "iso-chunked-regex")
	if err != nil {
		t.Fatalf("chunked non-ASCII regex should match decoded body: %v", err)
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
	wantRaw := []byte{'S', 'e', 0xf1, 'o', 'r'}
	if !bytes.Contains(dechunked, wantRaw) {
		t.Fatalf("dechunked reveal does not contain raw target %x: %x", wantRaw, dechunked)
	}
}
