package providers

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

const DEFAULT_USER_AGENT = "reclaim-attestor"
const DEFAULT_HTTPS_PORT = 443

func equalsFoldUserAgent(s string) bool { return strings.EqualFold(s, "user-agent") }

func buildHeadersList(h map[string]string) []string {
	if len(h) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := make([]string, 0, len(keys))
	for _, k := range keys {
		res = append(res, fmt.Sprintf("%s: %s", k, h[k]))
	}
	return res
}

func getHostHeaderString(u *url.URL) string {
	port := u.Port()
	if port != "" && port != strconv.Itoa(DEFAULT_HTTPS_PORT) {
		return u.Host
	}
	return u.Hostname()
}

func joinCRLF(lines []string) string { return strings.Join(lines, "\r\n") }

// Template substitution with offsets, mirroring TS logic
var paramsRegex = regexp.MustCompile(`{{([^{}]+)}}`)

type hiddenPart struct {
	Index  int
	Length int
}

type substituteResult struct {
	NewParams       HTTPProviderParams
	ExtractedValues map[string]string
	HiddenBodyParts []hiddenPart
	HiddenURLParts  []hiddenPart
}

func substituteParamValues(current *HTTPProviderParams, secret *HTTPProviderSecretParams, ignoreMissing bool) (substituteResult, error) {
	if current == nil {
		return substituteResult{}, fmt.Errorf("provider params are required")
	}

	logger.Info("Starting substituteParamValues", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.String("url", current.URL), zap.Bool("ignore_missing", ignoreMissing))

	// deep copy via json
	var params HTTPProviderParams
	b, err := json.Marshal(*current)
	if err != nil {
		return substituteResult{}, fmt.Errorf("failed to copy provider params: %w", err)
	}
	if err := json.Unmarshal(b, &params); err != nil {
		return substituteResult{}, fmt.Errorf("failed to copy provider params: %w", err)
	}
	logger.Debug("Parameters deep copied via JSON", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"))

	extracted := map[string]string{}

	// URL
	hiddenURL := []hiddenPart{}
	urlParams, err := extractAndReplaceTemplateValues(params.URL, &params, secret, ignoreMissing)
	if err != nil {
		return substituteResult{}, fmt.Errorf("url: %w", err)
	}
	if urlParams.NewParam != "" || len(urlParams.ExtractedValues) > 0 {
		logger.Debug("URL substitution complete", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.Int("extracted_values", len(urlParams.ExtractedValues)), zap.Int("hidden_parts", len(urlParams.HiddenParts)))
		params.URL = urlParams.NewParam
		maps.Copy(extracted, urlParams.ExtractedValues)
		if len(urlParams.HiddenParts) > 0 {
			host := getHostHeaderString(mustParseURL(params.URL))
			offset := len("https://"+host) - len(current.Method) - 1 // space after method
			for _, hp := range urlParams.HiddenParts {
				hiddenURL = append(hiddenURL, hiddenPart{Index: hp.Index - offset, Length: hp.Length})
			}
			logger.Debug("URL has hidden parts", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.String("level", "verbose"), zap.Int("hidden_parts", len(hiddenURL)))
		}
	}

	// Body
	hiddenBody := []hiddenPart{}
	if params.Body != nil {
		bodyStr := uint8ArrayToStr(normalizeBodyToBytes(params.Body))
		br, err := extractAndReplaceTemplateValues(bodyStr, &params, secret, ignoreMissing)
		if err != nil {
			return substituteResult{}, fmt.Errorf("body: %w", err)
		}
		if br.NewParam != "" || len(br.ExtractedValues) > 0 {
			logger.Debug("Body substitution complete", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.Int("extracted_values", len(br.ExtractedValues)), zap.Int("hidden_parts", len(br.HiddenParts)))
			params.Body = br.NewParam
			maps.Copy(extracted, br.ExtractedValues)
			hiddenBody = br.HiddenParts
		}
	} else {
		logger.Debug("No body to process", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"))
	}

	// Geo
	geoParams, err := extractAndReplaceTemplateValues(params.GeoLocation, &params, secret, ignoreMissing)
	if err != nil {
		return substituteResult{}, fmt.Errorf("geoLocation: %w", err)
	}
	if geoParams.NewParam != "" || len(geoParams.ExtractedValues) > 0 {
		logger.Debug("GeoLocation substitution complete", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.Int("extracted_values", len(geoParams.ExtractedValues)))
		params.GeoLocation = geoParams.NewParam
		maps.Copy(extracted, geoParams.ExtractedValues)
	}

	if params.ResponseRedactions != nil {
		for i := range params.ResponseRedactions {
			if params.ResponseRedactions[i].Regex != "" {
				regexParams, err := extractAndReplaceTemplateValues(params.ResponseRedactions[i].Regex, &params, secret, ignoreMissing)
				if err != nil {
					return substituteResult{}, fmt.Errorf("responseRedactions[%d].regex: %w", i, err)
				}
				params.ResponseRedactions[i].Regex = regexParams.NewParam
				logger.Debug("Redaction regex substituted", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.String("level", "verbose"), zap.Int("redaction_index", i+1))
			}

			if params.ResponseRedactions[i].XPath != "" {
				xpathParams, err := extractAndReplaceTemplateValues(params.ResponseRedactions[i].XPath, &params, secret, ignoreMissing)
				if err != nil {
					return substituteResult{}, fmt.Errorf("responseRedactions[%d].xPath: %w", i, err)
				}
				params.ResponseRedactions[i].XPath = xpathParams.NewParam
				logger.Debug("Redaction XPath substituted", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.String("level", "verbose"), zap.Int("redaction_index", i+1))
			}

			if params.ResponseRedactions[i].JSONPath != "" {
				jsonPathParams, err := extractAndReplaceTemplateValues(params.ResponseRedactions[i].JSONPath, &params, secret, ignoreMissing)
				if err != nil {
					return substituteResult{}, fmt.Errorf("responseRedactions[%d].jsonPath: %w", i, err)
				}
				params.ResponseRedactions[i].JSONPath = jsonPathParams.NewParam
				logger.Debug("Redaction JSONPath substituted", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.String("level", "verbose"), zap.Int("redaction_index", i+1))
			}
		}
	}

	if params.ResponseMatches != nil {
		for i := range params.ResponseMatches {
			if params.ResponseMatches[i].Value != "" {
				matchParams, err := extractAndReplaceTemplateValues(params.ResponseMatches[i].Value, &params, secret, ignoreMissing)
				if err != nil {
					return substituteResult{}, fmt.Errorf("responseMatches[%d].value: %w", i, err)
				}
				params.ResponseMatches[i].Value = matchParams.NewParam
				maps.Copy(extracted, matchParams.ExtractedValues)
				logger.Debug("Match value substituted", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.String("level", "verbose"), zap.Int("match_index", i+1), zap.Int("extracted_values", len(matchParams.ExtractedValues)))
			}
		}
	}

	result := substituteResult{NewParams: params, ExtractedValues: extracted, HiddenBodyParts: hiddenBody, HiddenURLParts: hiddenURL}
	logger.Info("Parameter substitution complete", zap.String("component", "Utils"), zap.String("operation", "substituteParamValues"), zap.Int("total_extracted_values", len(extracted)), zap.Int("hidden_body_parts", len(hiddenBody)), zap.Int("hidden_url_parts", len(hiddenURL)))
	return result, nil
}

func strToUint8Array(body any) []byte {
	switch b := body.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	case nil:
		return []byte("")
	default:
		return []byte("") // or return nil/error if you prefer
	}
}

func uint8ArrayToStr(b []byte) string { return string(bytes.ToValidUTF8(b, []byte("�"))) }

func normalizeBodyToBytes(body any) []byte {
	switch b := body.(type) {
	case string:
		return []byte(b)
	case []byte:
		return b
	case nil:
		return nil
	default:
		return nil

	}
}

type replacedParams struct {
	NewParam        string
	ExtractedValues map[string]string
	HiddenParts     []hiddenPart
}

func extractAndReplaceTemplateValues(param string, params *HTTPProviderParams, secret *HTTPProviderSecretParams, ignoreMissing bool) (replacedParams, error) {
	if param == "" {
		logger.Debug("Empty parameter, returning as-is", zap.String("component", "Utils"), zap.String("operation", "extractAndReplaceTemplateValues"), zap.String("level", "verbose"))
		return replacedParams{NewParam: "", ExtractedValues: map[string]string{}, HiddenParts: nil}, nil
	}
	matches := paramsRegex.FindAllStringSubmatchIndex(param, -1)
	if len(matches) == 0 {
		logger.Debug("No template patterns found", zap.String("component", "Utils"), zap.String("operation", "extractAndReplaceTemplateValues"), zap.String("level", "verbose"))
		return replacedParams{NewParam: param, ExtractedValues: map[string]string{}, HiddenParts: nil}, nil
	}
	logger.Debug("Found template patterns", zap.String("component", "Utils"), zap.String("operation", "extractAndReplaceTemplateValues"), zap.Int("pattern_count", len(matches)))

	extracted := map[string]string{}
	hidden := []hiddenPart{}
	var b strings.Builder
	last := 0
	totalOffset := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		nameStart, nameEnd := m[2], m[3]
		pn := param[nameStart:nameEnd]
		// write text before match
		b.WriteString(param[last:start])

		if params.ParamValues != nil {
			if val, ok := params.ParamValues[pn]; ok {
				extracted[pn] = val
				b.WriteString(val)
				totalOffset += len(val) - (end - start)
				last = end
				logger.Debug("Found public param", zap.String("component", "Utils"), zap.String("operation", "extractAndReplaceTemplateValues"), zap.String("level", "verbose"), zap.String("param_name", pn), zap.String("param_value", val))
				continue
			}
		}

		if secret != nil {
			if secret.ParamValues != nil {
				if val, ok := secret.ParamValues[pn]; ok {
					hidden = append(hidden, hiddenPart{Index: start + totalOffset, Length: len(val)})
					b.WriteString(val)
					totalOffset += len(val) - (end - start)
					last = end
					continue
				}
			}
		}

		if ignoreMissing {
			logger.Warn("Parameter not found, keeping template as-is", zap.String("component", "Utils"), zap.String("operation", "extractAndReplaceTemplateValues"), zap.String("param_name", pn))
			b.WriteString(param[start:end])
			last = end
			continue
		}

		logger.Error("Parameter not found in public or secret values", zap.String("component", "Utils"), zap.String("operation", "extractAndReplaceTemplateValues"), zap.String("param_name", pn))
		return replacedParams{}, fmt.Errorf("parameter %q not found in paramValues or secretParams.paramValues", pn)
	}
	// tail
	b.WriteString(param[last:])

	result := replacedParams{NewParam: b.String(), ExtractedValues: extracted, HiddenParts: hidden}
	logger.Debug("Template processing complete", zap.String("component", "Utils"), zap.String("operation", "extractAndReplaceTemplateValues"), zap.Int("extracted_values", len(extracted)), zap.Int("hidden_parts", len(hidden)))
	return result, nil
}

func mustParseURL(s string) *url.URL { u, _ := url.Parse(s); return u }

// getURL mirrors the TypeScript getURL function - only processes URL string with parameter substitution
func getURL(params *HTTPProviderParams, secretParams *HTTPProviderSecretParams) (string, error) {
	urlStr := params.URL
	if urlStr == "" {
		return "", fmt.Errorf("url is required")
	}

	// Extract parameter names from URL (mirror TS paramsRegex behavior)
	paramNames := make(map[string]bool)
	re := regexp.MustCompile(`\{\{([^{}]+)}}`)
	matches := re.FindAllStringSubmatch(urlStr, -1)
	for _, match := range matches {
		if len(match) > 1 {
			paramNames[match[1]] = true
		}
	}

	// Substitute parameters in URL only
	for paramName := range paramNames {
		placeholder := fmt.Sprintf("{{%s}}", paramName)
		var value string
		var found bool

		// Check public params first
		if params.ParamValues != nil {
			if val, exists := params.ParamValues[paramName]; exists {
				value = val
				found = true
			}
		}

		// Check secret params if not found in public
		if !found && secretParams != nil && secretParams.ParamValues != nil {
			if val, exists := secretParams.ParamValues[paramName]; exists {
				value = val
				found = true
			}
		}

		if !found {
			return "", fmt.Errorf("parameter \"%s\" value not found in templateParams", paramName)
		}

		urlStr = strings.ReplaceAll(urlStr, placeholder, value)
	}

	return urlStr, nil
}
