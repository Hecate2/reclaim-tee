package providers

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// clientReservedHeaders are request headers the client sets itself; a provider
// or secret config must not override them (lowercased for case-insensitive match).
var clientReservedHeaders = map[string]struct{}{
	"host":            {},
	"connection":      {},
	"content-length":  {},
	"accept-encoding": {},
}

// CreateRequest builds the HTTP/1.1 request bytes and redaction ranges
func CreateRequest(secret *HTTPProviderSecretParams, params *HTTPProviderParams) (CreateRequestResult, error) {
	if params == nil {
		return CreateRequestResult{}, fmt.Errorf("provider params are required")
	}
	if secret == nil {
		return CreateRequestResult{}, fmt.Errorf("secret params are required")
	}

	// Add special TEE log for provider operations
	logger.Info("🔐 TEE: Creating HTTP request for provider",
		zap.String("url", params.URL),
		zap.String("method", params.Method),
		zap.String("source", "TEE-PROVIDERS"),
	)
	logger.Info("Starting CreateRequest", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.String("url", params.URL), zap.String("method", params.Method))

	if secret.CookieStr == "" && secret.AuthorisationHeader == "" && len(secret.Headers) == 0 {
		logger.Error("auth parameters are not set", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"))
		return CreateRequestResult{}, fmt.Errorf("auth parameters are not set")
	}

	logger.Debug("Secret params provided", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Bool("cookie", secret.CookieStr != ""), zap.Bool("auth", secret.AuthorisationHeader != ""), zap.Int("headers", len(secret.Headers)))

	pubHeaders := map[string]string{}
	maps.Copy(pubHeaders, params.Headers)

	// Build secret headers list in TS order: Cookie, Authorization, then any extra secret headers
	secHeadersList := []string{}
	if secret.CookieStr != "" {
		secHeadersList = append(secHeadersList, fmt.Sprintf("Cookie: %s", secret.CookieStr))
	}
	if secret.AuthorisationHeader != "" {
		secHeadersList = append(secHeadersList, fmt.Sprintf("Authorization: %s", secret.AuthorisationHeader))
	}
	for k, v := range secret.Headers {
		secHeadersList = append(secHeadersList, fmt.Sprintf("%s: %s", k, v))
	}

	// Default UA if not provided anywhere
	hasUA := false
	for k := range pubHeaders {
		if equalsFoldUserAgent(k) {
			hasUA = true
			break
		}
	}
	if !hasUA {
		for _, line := range secHeadersList {
			if len(line) >= len("User-Agent:") && equalsFoldUserAgent(line[:len("User-Agent:")]) {
				hasUA = true
				break
			}
		}
	}
	if !hasUA {
		pubHeaders["User-Agent"] = DEFAULT_USER_AGENT
	}

	// A config header duplicating one the client sets is appended after ours and
	// a server may honor it as an override; reject instead of sending a conflict.
	for _, h := range []struct {
		src map[string]string
		lbl string
	}{{pubHeaders, "provider"}, {secret.Headers, "secret"}} {
		for k := range h.src {
			if _, reserved := clientReservedHeaders[strings.ToLower(strings.TrimSpace(k))]; reserved {
				logger.Error("reserved header overridden by config", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.String("header", k), zap.String("source", h.lbl))
				return CreateRequestResult{}, fmt.Errorf("%s header %q overrides a client-managed header (Host/Connection/Content-Length/Accept-Encoding); remove it from the provider config", h.lbl, k)
			}
		}
	}

	logger.Info("Step 1/5: Substituting template parameters", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("step", 1), zap.Int("total", 5))
	sp, err := substituteParamValues(params, secret, false)
	if err != nil {
		return CreateRequestResult{}, fmt.Errorf("failed to substitute provider parameters: %w", err)
	}
	p := sp.NewParams
	logger.Debug("Parameter substitution complete", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("extracted_values", len(sp.ExtractedValues)))

	logger.Info("Step 2/5: Parsing URL and building request line", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("step", 2), zap.Int("total", 5))
	u, err := url.Parse(p.URL)
	if err != nil {
		logger.Error("invalid url", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Error(err))
		return CreateRequestResult{}, fmt.Errorf("invalid url: %w", err)
	}
	logger.Debug("Parsed URL", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.String("level", "verbose"), zap.String("host", u.Host), zap.String("path", u.Path))
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := u.RawQuery
	reqTarget := path
	if query != "" {
		reqTarget = reqTarget + "?" + query
	}
	reqLine := fmt.Sprintf("%s %s HTTP/1.1", p.Method, reqTarget)
	logger.Debug("Built request line", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.String("request_line", reqLine))

	logger.Info("Step 3/5: Building request body and headers", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("step", 3), zap.Int("total", 5))
	bodyBytes := strToUint8Array(p.Body)
	contentLength := len(bodyBytes)
	logger.Debug("Body length", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("body_bytes", contentLength))

	pubHeadersList := buildHeadersList(pubHeaders)
	hostHeader := getHostHeaderString(u)
	logger.Debug("Host header and public headers", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.String("level", "verbose"), zap.String("host_header", hostHeader), zap.Int("public_headers", len(pubHeadersList)))
	lines := []string{
		reqLine,
		// `Host` and `Connection: close` must be the first two headers after
		// the request line, in this exact order. The attestor enforces this
		// regex-strict to prevent HTTP request smuggling via pipelining
		// (OVE-20260504-0001, attestor-core PR #79).
		fmt.Sprintf("Host: %s", hostHeader),
		"Connection: close",
		fmt.Sprintf("Content-Length: %d", contentLength),
		"Accept-Encoding: identity",
	}
	lines = append(lines, pubHeadersList...)
	lines = append(lines, secHeadersList...)
	lines = append(lines, "\r\n")
	logger.Info("Step 4/5: Assembling final request", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("step", 4), zap.Int("total", 5))
	headersStr := joinCRLF(lines)
	headerBytes := []byte(headersStr)
	data := append(headerBytes, bodyBytes...)

	logger.Info("Step 5/5: Computing redaction ranges", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("step", 5), zap.Int("total", 5))
	// redactions: hide all secret headers block
	redactions := []shared.RequestRedactionRange{}
	if len(secHeadersList) > 0 {
		secHeadersStr := joinCRLF(secHeadersList)
		idx := bytes.Index(data, []byte(secHeadersStr))
		if idx >= 0 {
			redactions = append(redactions, shared.RequestRedactionRange{Start: idx, Length: len(secHeadersStr), Type: "sensitive"})
		}
	}
	// hidden body parts
	for _, hb := range sp.HiddenBodyParts {
		if hb.Length > 0 {
			redactions = append(redactions, shared.RequestRedactionRange{Start: len(headerBytes) + hb.Index, Length: hb.Length, Type: "sensitive"})
		}
	}
	// hidden URL parts
	for _, hu := range sp.HiddenURLParts {
		if hu.Length > 0 {
			redactions = append(redactions, shared.RequestRedactionRange{Start: hu.Index, Length: hu.Length, Type: "sensitive"})
		}
	}
	sort.Slice(redactions, func(i, j int) bool {
		return redactions[i].Start+redactions[i].Length < redactions[j].Start+redactions[j].Length
	})

	logger.Debug("Created redaction ranges", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.Int("redaction_ranges", len(redactions)))
	logger.Debug("Request headers", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"), zap.String("headers", string(headerBytes)))

	logger.Info("Request created successfully", zap.String("component", "HTTP"), zap.String("operation", "CreateRequest"))
	return CreateRequestResult{Data: data, Redactions: redactions}, nil
}

// GetResponseRedactions computes redaction ranges for an HTTP response based on responseRedactions in params
func GetResponseRedactions(response []byte, rawParams *HTTPProviderParams, ctx *ProviderCtx, requestId string) ([]shared.ResponseRedactionRange, error) {
	if rawParams == nil {
		return nil, fmt.Errorf("provider params are required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("provider context is required")
	}

	// Create a local logger with requestId if provided
	logger.Info("Starting GetResponseRedactions",
		zap.String("component", "HTTP"),
		zap.String("operation", "GetResponseRedactions"),
		zap.Int("response_size", len(response)),
		zap.Int("redaction_rules", len(rawParams.ResponseRedactions)),
		zap.String("requestId", requestId))

	logger.Info("Step 1/4: Parsing HTTP response", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("step", 1), zap.Int("total", 4))
	res, err := parseHTTPResponseBytes(response)
	if err != nil {
		logger.Error("Failed to parse response", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Error(err))
		return nil, err
	}
	logger.Info("Parsed HTTP response content type", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.String("requestId", requestId), zap.String("content_type", res.Headers["content-type"]))

	if len(rawParams.ResponseRedactions) == 0 {
		logger.Info("No redaction rules specified, returning empty redactions", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"))
		return []shared.ResponseRedactionRange{}, nil
	}

	if res.StatusCode/100 != 2 {
		logger.Error("Non-2xx status code", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("status_code", res.StatusCode), zap.String("status_message", res.StatusMessage))
		return nil, fmt.Errorf("expected status 2xx, got %d (%s)", res.StatusCode, res.StatusMessage)
	}

	logger.Info("Step 2/4: Substituting parameters in redaction rules", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("step", 2), zap.Int("total", 4))
	// substitute placeholders in params (ignoreMissing = true)
	sp, err := substituteParamValues(rawParams, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to substitute provider parameters: %w", err)
	}
	params := sp.NewParams
	logger.Debug("Parameter substitution complete for redaction rules", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"))

	logger.Info("Step 3/4: Identifying response structure and reveals", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("step", 3), zap.Int("total", 4))
	headerEndIndex := res.StatusLineEndIndex
	bodyStartIdx := res.BodyStartIndex
	if bodyStartIdx < 4 {
		logger.Error("Failed to find response body", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("body_start_idx", bodyStartIdx))
		return nil, errors.New("Failed to find response body")
	}

	revealFraming := shouldRevealChunkFraming(ctx)

	reveals := []shared.ResponseRedactionRange{{Start: 0, Length: headerEndIndex}}

	// CRLF boundary: only verify and reveal when client supports it
	if shouldRevealCrlf(ctx) {
		if res.HeaderEndIdx < 0 || res.HeaderEndIdx+4 > len(response) {
			return nil, fmt.Errorf("Failed to find header/body separator at index %d", res.HeaderEndIdx)
		}
		if !bytes.Equal(response[res.HeaderEndIdx:res.HeaderEndIdx+4], []byte("\r\n\r\n")) {
			return nil, fmt.Errorf("Failed to find header/body separator at index %d", res.HeaderEndIdx)
		}
	}

	// always reveal the double CRLF which separates headers from body (mirror TS)
	reveals = append(reveals, shared.ResponseRedactionRange{Start: res.HeaderEndIdx, Length: 4})

	// reveal Date header if present
	if rng, ok := res.HeaderLowerToRanges["date"]; ok && rng.Start+rng.Length > rng.Start {
		reveals = append(reveals, rng)
	}

	// reveal content-type so the verifier can decode the response body charset
	if rng, ok := res.HeaderLowerToRanges["content-type"]; ok && rng.Length > 0 {
		reveals = append(reveals, rng)
	}

	// reveal transfer-encoding header so the verifier can dechunk the body
	if revealFraming {
		if rng, ok := res.HeaderLowerToRanges["transfer-encoding"]; ok && rng.Length > 0 {
			reveals = append(reveals, rng)
		}
	}

	logger.Info("Step 4/4: Processing redaction requests", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("step", 4), zap.Int("total", 4))
	bodyCharset := responseBodyCharset(res.Headers["content-type"])
	body, err := decodeResponseBody(res.Body, bodyCharset)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}
	redactions := []shared.ResponseRedactionRange{}

	for i, rs := range params.ResponseRedactions {

		proc, err := processRedactionRequest(&body, &rs, bodyStartIdx, res.Chunks, revealFraming)
		if err != nil {
			logger.Error("Redaction failed", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("redaction_index", i+1), zap.Error(err))
			return nil, err
		}

		for _, item := range proc {
			reveals = append(reveals, item.Reveal)
			redactions = append(redactions, item.Redactions...)
		}
	}

	// reveal all chunk framing (size lines + terminator) so the verifier can
	// dechunk; chunk data stays redacted unless a redaction reveals it
	if revealFraming && len(res.Chunks) > 0 {
		prev := res.HeaderEndIdx + 4
		for _, chunk := range res.Chunks {
			if chunk.Start > prev {
				reveals = append(reveals, shared.ResponseRedactionRange{Start: prev, Length: chunk.Start - prev})
			}
			prev = chunk.Start + chunk.Length
		}
		if len(response) > prev {
			reveals = append(reveals, shared.ResponseRedactionRange{Start: prev, Length: len(response) - prev})
		}
	}

	if revealFraming {
		// reveals can overlap (a redaction reveal spanning chunk framing), so
		// redact the complement of their union
		sort.Slice(reveals, func(i, j int) bool { return reveals[i].Start < reveals[j].Start })
		if len(reveals) > 1 {
			currentIndex := 0
			for _, r := range reveals {
				if currentIndex < r.Start {
					redactions = append(redactions, shared.ResponseRedactionRange{Start: currentIndex, Length: r.Start - currentIndex})
				}
				if end := r.Start + r.Length; end > currentIndex {
					currentIndex = end
				}
			}
			if currentIndex < len(response) {
				redactions = append(redactions, shared.ResponseRedactionRange{Start: currentIndex, Length: len(response) - currentIndex})
			}
		}
	} else {
		sort.Slice(reveals, func(i, j int) bool { return reveals[i].Start+reveals[i].Length < reveals[j].Start+reveals[j].Length })

		if len(reveals) > 1 {
			currentIndex := 0
			for i, r := range reveals {
				if currentIndex < r.Start {
					redactions = append(redactions, shared.ResponseRedactionRange{Start: currentIndex, Length: r.Start - currentIndex})
				}
				currentIndex = r.Start + r.Length

				// legacy: extend the final chunked reveal to EOF to match old TS
				if len(res.Chunks) > 0 && i == len(reveals)-1 {
					lastChunk := res.Chunks[len(res.Chunks)-1]
					lastChunkEnd := lastChunk.Start + lastChunk.Length
					if currentIndex == lastChunkEnd && currentIndex < len(response) {
						currentIndex = len(response)
					}
				}
			}
			endIndex := len(response)
			if currentIndex < endIndex {
				redactions = append(redactions, shared.ResponseRedactionRange{Start: currentIndex, Length: endIndex - currentIndex})
			}
		}
	}

	for _, reveal := range reveals {
		if reveal.Hash != "" {
			redactions = append(redactions, reveal)
		}
	}

	sort.Slice(redactions, func(i, j int) bool {
		return redactions[i].Start+redactions[i].Length < redactions[j].Start+redactions[j].Length
	})

	logger.Info("Response redaction complete", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("reveals", len(reveals)), zap.Int("redactions", len(redactions)))
	logger.Debug("Total redacted bytes", zap.String("component", "HTTP"), zap.String("operation", "GetResponseRedactions"), zap.Int("total_redacted_bytes", func() int {
		total := 0
		for _, r := range redactions {
			total += r.Length
		}
		return total
	}()))

	return redactions, nil
}

func responseBodyCharset(contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return params["charset"]
}

func GetHostPort(params *HTTPProviderParams, secretParams *HTTPProviderSecretParams) (string, int, error) {
	if params == nil {
		return "", -1, fmt.Errorf("provider params are required")
	}

	logger.Info("Starting GetHostPort", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.String("url", params.URL))

	urlStr, err := getURL(params, secretParams)
	if err != nil {
		logger.Error("Failed to get URL", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.Error(err))
		return "", -1, err
	}
	logger.Debug("Processed URL", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.String("level", "verbose"), zap.String("url", urlStr))

	u, err := url.Parse(urlStr)
	if err != nil {
		logger.Error("URL parsing failed", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.Error(err))
		return "", -1, fmt.Errorf("url is incorrect: %w", err)
	}

	if u.Host == "" {
		logger.Error("No host found in URL", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"))
		return "", -1, fmt.Errorf("url is incorrect: no host found")
	}

	// Only support HTTPS
	if u.Scheme != "https" {
		logger.Error("Non-HTTPS scheme not supported", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.String("scheme", u.Scheme))
		return "", -1, fmt.Errorf("only HTTPS URLs are supported, got: %s", u.Scheme)
	}
	logger.Debug("HTTPS URL validated, extracting host/port", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.String("host", u.Host))

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		if _, ok := errors.AsType[*net.AddrError](err); ok {
			// No port specified, use HTTPS default
			logger.Debug("No explicit port, using default HTTPS port", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"))
			logger.Info("Resolved host and port", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.String("host", u.Host), zap.Int("port", DEFAULT_HTTPS_PORT))
			return u.Host, DEFAULT_HTTPS_PORT, nil
		}
		logger.Error("Failed to split host:port", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.Error(err))
		return "", -1, fmt.Errorf("url is incorrect: %w", err)
	}

	intPort, err := strconv.Atoi(port)
	if err != nil {
		logger.Error("Invalid port number", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.String("port", port))
		return "", -1, fmt.Errorf("url is incorrect: invalid port %q: %w", port, err)
	}

	logger.Info("Resolved host and port", zap.String("component", "HTTP"), zap.String("operation", "GetHostPort"), zap.String("host", host), zap.Int("port", intPort))
	return host, intPort, nil
}
