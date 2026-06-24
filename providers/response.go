package providers

import (
	"encoding/base64"
	"fmt"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"regexp"

	"go.uber.org/zap"
)

// internal structure mirroring the TS parseHttpResponse return

// RedactionItem mirrors TS: an item with a reveal and accompanying redactions
type RedactionItem struct {
	Reveal     shared.ResponseRedactionRange
	Redactions []shared.ResponseRedactionRange
}

// makeRegex mirrors the TS makeRegex: enable dotAll and case-insensitive, and
// convert JS-style named groups (?<name>...) to Go/RE2-style (?P<name>...)
func makeRegex(str string) (*regexp.Regexp, error) {
	converted := convertJsNamedGroupsToGo(str)
	return regexp.Compile("(?si)" + converted)
}

var jsNamedGroupPattern = regexp.MustCompile(`\(\?<([A-Za-z][A-Za-z0-9_]*)>`)

func convertJsNamedGroupsToGo(s string) string {
	// Replace `(?<name>` with `(?P<name>`
	return jsNamedGroupPattern.ReplaceAllString(s, `(?P<$1>`)
}

// processRedactionRequest implements TS semantics for XPath/JSONPath/Regex and hashed groups
func processRedactionRequest(
	body string,
	rs *ResponseRedaction,
	bodyStartIdx int,
	resChunks []shared.ResponseRedactionRange,
	revealFraming bool,
) ([]RedactionItem, error) {
	logger.Info("Starting processRedactionRequest", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.String("xpath", rs.XPath), zap.String("json_path", rs.JSONPath), zap.String("regex", rs.Regex))
	items := []RedactionItem{}

	// 1) XPath branch
	if rs.XPath != "" {
		contentsOnly := rs.JSONPath != ""

		locs, err := ExtractHTMLElementsIndexes(body, rs.XPath, contentsOnly)
		if err != nil {
			logger.Error("XPath extraction failed", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.Error(err))
			return nil, err
		}
		for _, ix := range locs {
			startAbs := ix.Start
			endAbs := ix.End

			if rs.JSONPath != "" {
				// run JSONPath within element
				elem := body[startAbs:endAbs]
				jlocs, err := ExtractJSONValueIndexes([]byte(elem), rs.JSONPath)
				if err != nil {
					logger.Error("JSONPath within XPath failed", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.Error(err))
					return nil, err
				}
				for j, jsonLoc := range jlocs {
					jStartAbs := startAbs + jsonLoc.Start
					jEndAbs := startAbs + jsonLoc.End
					logger.Debug("Applying regex to JSON value", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.String("level", "verbose"), zap.Int("json_value_index", j+1), zap.Int("start", jStartAbs), zap.Int("end", jEndAbs))
					proc, err := applyRegexWindow(body, *rs, jStartAbs, jEndAbs, bodyStartIdx, resChunks, revealFraming)
					if err != nil {
						logger.Error("Regex application failed", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.Error(err))
						return nil, err
					}
					items = append(items, proc...)
				}
				continue
			}
			proc, err := applyRegexWindow(body, *rs, startAbs, endAbs, bodyStartIdx, resChunks, revealFraming)
			if err != nil {
				logger.Error("Regex application failed", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.Error(err))
				return nil, err
			}
			items = append(items, proc...)
		}
		return items, nil
	}

	// 2) JSONPath-only branch
	if rs.JSONPath != "" {

		locs, err := ExtractJSONValueIndexes([]byte(body), rs.JSONPath)
		if err != nil {
			logger.Error("JSONPath extraction failed", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.Error(err))
			return nil, err
		}

		for _, jsonLoc := range locs {
			startAbs := jsonLoc.Start
			endAbs := jsonLoc.End

			proc, err := applyRegexWindow(body, *rs, startAbs, endAbs, bodyStartIdx, resChunks, revealFraming)
			if err != nil {
				logger.Error("Regex application failed", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.Error(err))
				return nil, err
			}
			items = append(items, proc...)
		}
		return items, nil
	}

	// 3) Regex-only branch
	if rs.Regex != "" {

		proc, err := applyRegexWindow(body, *rs, 0, len(body), bodyStartIdx, resChunks, revealFraming)
		if err != nil {
			logger.Error("Regex processing failed", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"), zap.Error(err))
			return nil, err
		}
		return proc, nil
	}

	logger.Error("No valid extraction method specified", zap.String("component", "Response"), zap.String("operation", "processRedactionRequest"))
	return nil, fmt.Errorf("Expected either xPath, jsonPath or regex for redaction")
}

// convertResponsePosToAbsolutePos converts a position within the response body to absolute position in the full response,
// accounting for chunked transfer encoding. This implementation exactly matches TypeScript behavior.
func convertResponsePosToAbsolutePos(pos int, bodyStartIdx int, chunks []shared.ResponseRedactionRange) int {
	if len(chunks) > 0 {

		chunkBodyStart := 0
		for _, ch := range chunks {
			chunkSize := ch.Length

			// Handle boundary positions exactly like TypeScript
			if pos >= chunkBodyStart && pos < (chunkBodyStart+chunkSize) {
				logger.Debug("Position maps to chunk", zap.String("component", "Response"), zap.String("operation", "convertResponsePosToAbsolutePos"), zap.String("level", "verbose"), zap.Int("position", pos), zap.Int("chunk_body_start", chunkBodyStart), zap.Int("absolute_pos", pos-chunkBodyStart+ch.Start))
				return pos - chunkBodyStart + ch.Start
			}
			// Handle positions exactly at chunk boundary (go to next chunk)
			if pos == (chunkBodyStart + chunkSize) {
				logger.Debug("Position at chunk boundary", zap.String("component", "Response"), zap.String("operation", "convertResponsePosToAbsolutePos"), zap.String("level", "verbose"), zap.Int("position", pos), zap.Int("chunk_end", ch.Start+ch.Length))
				return ch.Start + ch.Length
			}

			chunkBodyStart += chunkSize
		}

		logger.Error("Position out of range for chunks", zap.String("component", "Response"), zap.String("operation", "convertResponsePosToAbsolutePos"), zap.Int("position", pos), zap.Int("chunk_count", len(chunks)))
		return -1 // Match TypeScript error handling pattern
	}
	return bodyStartIdx + pos
}

// getRedactionsForChunkHeaders returns redaction ranges for chunk headers between chunk bodies if a reveal spans across them.
func getRedactionsForChunkHeaders(from, to int, chunks []shared.ResponseRedactionRange) []shared.ResponseRedactionRange {
	res := []shared.ResponseRedactionRange{}
	if len(chunks) == 0 {
		return res
	}
	for i := 1; i < len(chunks); i++ {
		ch := chunks[i]
		if ch.Start > from && ch.Start < to {
			previousEnd := chunks[i-1].Start + chunks[i-1].Length
			res = append(res, shared.ResponseRedactionRange{Start: previousEnd, Length: ch.Start - previousEnd})
		}
	}
	return res
}

// parseHTTPResponseBytes parses an HTTP/1.1 response and returns structural metadata and chunk ranges.
// This function now uses the new streaming parser internally but provides the same interface.
func parseHTTPResponseBytes(data []byte) (*HTTPParsedResponse, error) {
	logger.Info("Starting parseHTTPResponseBytes", zap.String("component", "Response"), zap.String("operation", "parseHTTPResponseBytes"), zap.Int("data_size", len(data)))

	// Use the new streaming parser for complete HTTP/1.1 compliance
	parser := NewHTTPResponseParser()

	// Process all data at once
	if err := parser.OnChunk(data); err != nil {
		logger.Error("Failed to process response data", zap.String("component", "Response"), zap.String("operation", "parseHTTPResponseBytes"), zap.Error(err))
		return nil, err
	}

	// Signal end of stream
	if err := parser.StreamEnded(); err != nil {
		logger.Error("Failed to finalize response", zap.String("component", "Response"), zap.String("operation", "parseHTTPResponseBytes"), zap.Error(err))
		return nil, err
	}

	return parser.Response, nil
}

// IndexRange represents a start and end position in a document
type IndexRange struct {
	Start int
	End   int
}

// applyRegexWindow encapsulates the regex application and hashing semantics
// over a [startAbs, endAbs) window in the response body, mirroring TS behavior.
func applyRegexWindow(
	body string,
	rs ResponseRedaction,
	startAbs int,
	endAbs int,
	bodyStartIdx int,
	resChunks []shared.ResponseRedactionRange,
	revealFraming bool,
) ([]RedactionItem, error) {
	items := []RedactionItem{}

	// Helper to add a reveal for [startAbs, endAbs)
	addRange := func(sAbs, eAbs int) {
		if sAbs < 0 || eAbs <= sAbs {
			return
		}
		reveal := getReveal(sAbs, eAbs-sAbs, bodyStartIdx, resChunks, "")
		// new clients leave chunk framing revealed (verifier dechunks); older
		// clients redact framing inside a reveal that spans chunks
		var reds []shared.ResponseRedactionRange
		if !revealFraming {
			reds = getRedactionsForChunkHeaders(reveal.Start, reveal.Start+reveal.Length, resChunks)
		}
		items = append(items, RedactionItem{Reveal: reveal, Redactions: reds})
	}

	segment := body[startAbs:endAbs]
	if rs.Regex == "" {
		addRange(startAbs, endAbs)
		return items, nil
	}

	re, err := makeRegex(rs.Regex)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp %q: %w", rs.Regex, err)
	}

	if rs.Hash == nil {
		loc := re.FindStringIndex(segment)
		if loc == nil {
			enc := base64.StdEncoding.EncodeToString([]byte(segment))
			return nil, fmt.Errorf("regexp %s does not match found element '%s'", rs.Regex, enc)
		}
		matchStart := startAbs + loc[0]
		matchEnd := startAbs + loc[1]
		addRange(matchStart, matchEnd)
		return items, nil
	}

	// Hash semantics with exactly one named capture group
	smi := re.FindStringSubmatchIndex(segment)
	if smi == nil {
		enc := base64.StdEncoding.EncodeToString([]byte(segment))
		return nil, fmt.Errorf("regexp %s does not match found element '%s'", rs.Regex, enc)
	}
	names := re.SubexpNames()
	totalNamed := 0
	grpFromRel, grpToRel := -1, -1
	fullFromRel := smi[0]
	fullToRel := smi[1]
	for gi, name := range names {
		if gi == 0 {
			continue
		}
		from := smi[2*gi]
		to := smi[2*gi+1]
		if name != "" && from >= 0 && to >= 0 {
			totalNamed++
			grpFromRel, grpToRel = from, to
		}
	}
	if totalNamed != 1 {
		return nil, fmt.Errorf("exactly one named capture group is needed per hashed redaction")
	}
	fullFrom := startAbs + fullFromRel
	fullTo := startAbs + fullToRel
	grpFrom := startAbs + grpFromRel
	grpTo := startAbs + grpToRel

	// pre-group (unhashed)
	if grpFrom > fullFrom {
		addRange(fullFrom, grpFrom)
	}
	// group (hashed) — must not span chunks
	reveal := getReveal(grpFrom, grpTo-grpFrom, bodyStartIdx, resChunks, *rs.Hash)
	chunkReds := getRedactionsForChunkHeaders(reveal.Start, reveal.Start+reveal.Length, resChunks)
	if len(chunkReds) > 0 {
		return nil, fmt.Errorf("hash redactions cannot be performed if the redacted string is split between 2 or more HTTP chunks")
	}
	items = append(items, RedactionItem{Reveal: reveal, Redactions: chunkReds})

	// post-group (unhashed)
	if grpTo < fullTo {
		addRange(grpTo, fullTo)
	}

	return items, nil
}

func getReveal(startIdx, length, bodyStartIdx int, resChunks []shared.ResponseRedactionRange, hash string) shared.ResponseRedactionRange {
	from := convertResponsePosToAbsolutePos(startIdx, bodyStartIdx, resChunks)
	to := convertResponsePosToAbsolutePos(startIdx+length, bodyStartIdx, resChunks)

	return shared.ResponseRedactionRange{
		Start:  from,
		Length: to - from,
		Hash:   hash,
	}
}
