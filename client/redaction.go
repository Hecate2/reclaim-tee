package client

import (
	"fmt"
	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"slices"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// analyzeResponseRedaction is the main entry point for response redaction analysis
func (c *Client) analyzeResponseRedaction() (shared.ResponseRedactionSpec, error) {
	// Step 1: Analyze TLS records and build mappings
	tlsAnalysis := c.analyzeTLSRecords(c.getSortedSequenceNumbers())

	// Step 2: Process HTTP content redactions if present
	httpRedactions, err := c.analyzeHTTPContent(tlsAnalysis.HTTPMappings, tlsAnalysis.AllHTTPContent)
	if err != nil {
		return shared.ResponseRedactionSpec{}, fmt.Errorf("failed to analyze HTTP content: %w", err)
	}

	// Step 3: Combine all redaction ranges
	responseRedactionRanges := append(tlsAnalysis.ProtocolRedactions, httpRedactions...)

	// Step 4: Consolidate and finalize
	spec := c.finalizeRedactionSpec(responseRedactionRanges)

	// Calculate total response size in TLS stream coordinates (matching redaction ranges)
	totalResponseBytes := 0
	for _, parsed := range c.parsedResponseBySeq {
		if parsed != nil {
			// Use TLS stream length to match TEE_T's consolidated stream coordinates
			if minitls.IsTLS13CipherSuite(c.cipherSuite) {
				totalResponseBytes += parsed.OriginalLen - 1 // TLS 1.3: strips last byte from encrypted data
			} else {
				totalResponseBytes += parsed.OriginalLen // TLS 1.2: no inner plaintext structure
			}
		}
	}

	// Calculate total redacted bytes from consolidated ranges (also in TLS stream coordinates)
	totalRedactedBytes := 0
	for _, r := range spec.Ranges {
		totalRedactedBytes += r.Length
	}

	// Calculate revealed bytes (now both values use same TLS stream coordinate system)
	revealedBytes := totalResponseBytes - totalRedactedBytes

	// Log statistics - single line with revealed bytes and OPRF redaction count
	logFields := []zap.Field{
		zap.Int("revealed_bytes", revealedBytes),
		zap.Int("oprf_redactions", len(c.oprfRedactionRanges)),
	}
	if c.requestId != "" {
		logFields = append(logFields, zap.String("requestId", c.requestId))
	}
	c.logger.Info("Response redaction analysis complete", logFields...)

	return spec, nil
}

// getSortedSequenceNumbers returns sequence numbers in sorted order
func (c *Client) getSortedSequenceNumbers() []uint64 {
	seqNums := make([]uint64, 0, len(c.parsedResponseBySeq))
	for seqNum := range c.parsedResponseBySeq {
		seqNums = append(seqNums, seqNum)
	}
	slices.Sort(seqNums)
	return seqNums
}

// analyzeTLSRecords processes all TLS records and categorizes them
func (c *Client) analyzeTLSRecords(seqNums []uint64) *TLSAnalysisResult {
	result := &TLSAnalysisResult{
		ProtocolRedactions: make([]shared.ResponseRedactionRange, 0),
		HTTPMappings:       make([]TLSToHTTPMapping, 0),
		AllHTTPContent:     make([]byte, 0),
	}

	// Debug logging (commented out for production)
	// c.logger.Info("[REDACTION DEBUG] Starting TLS record analysis",
	// 	zap.Int("total_sequences", len(seqNums)),
	// 	zap.Uint64s("sequence_numbers", seqNums))

	for _, seqNum := range seqNums {
		c.processSingleTLSRecord(seqNum, result)
	}

	// Debug logging (commented out for production)
	// totalOriginalLen := 0
	// totalActualContentLen := 0
	// totalPaddingBytes := 0
	// for _, seqNum := range seqNums {
	// 	parsed := c.parsedResponseBySeq[seqNum]
	// 	if parsed != nil {
	// 		totalOriginalLen += parsed.OriginalLen
	// 		totalActualContentLen += len(parsed.ActualContent)
	// 		paddingBytes := parsed.OriginalLen - len(parsed.ActualContent) - 1 // -1 for content type
	// 		if paddingBytes < 0 {
	// 			paddingBytes = 0
	// 		}
	// 		totalPaddingBytes += paddingBytes
	// 	}
	// }
	//
	// c.logger.Info("📊 TLS Record Analysis Summary",
	// 	zap.Int("total_sequences", len(seqNums)),
	// 	zap.Int("total_original_len", totalOriginalLen),
	// 	zap.Int("total_actual_content_len", totalActualContentLen),
	// 	zap.Int("total_tls_stream_offset", result.TotalTLSOffset),
	// 	zap.Int("total_padding_bytes", totalPaddingBytes),
	// 	zap.Int("total_content_type_bytes", len(seqNums)),
	// 	zap.Int("http_content_bytes", len(result.AllHTTPContent)))

	// Store mappings for OPRF use
	c.httpToTlsMapping = result.HTTPMappings

	return result
}

// processSingleTLSRecord processes one TLS record based on its content type
func (c *Client) processSingleTLSRecord(seqNum uint64, result *TLSAnalysisResult) {
	parsed := c.parsedResponseBySeq[seqNum]
	if parsed == nil {
		c.terminateConnectionWithError("No parsed data found for sequence", fmt.Errorf("invalid sequence number %d", seqNum))
		return
	}

	// Verify ciphertext exists
	ciphertext, exists := c.ciphertextBySeq[seqNum]
	if !exists {
		c.terminateConnectionWithError("No ciphertext found for sequence", fmt.Errorf("invalid sequence number %d", seqNum))
		return
	}

	// TEE_T's consolidated stream format depends on TLS version:
	// - TLS 1.3: strips last byte from encrypted data (OriginalLen - 1)
	//   Note: Structure is [content][type][padding], last byte is end of padding
	// - TLS 1.2: keeps full encrypted data (OriginalLen)
	var tlsStreamLength int
	if minitls.IsTLS13CipherSuite(c.cipherSuite) {
		tlsStreamLength = parsed.OriginalLen - 1 // TLS 1.3: strip last byte
	} else {
		tlsStreamLength = parsed.OriginalLen // TLS 1.2: no stripping
	}

	if len(ciphertext) != tlsStreamLength {
		panic(fmt.Sprintf("ciphertext length (%d) does not match TEE_T stream length (%d) for cipher %x",
			len(ciphertext), tlsStreamLength, c.cipherSuite))
	}

	actualLength := len(parsed.ActualContent)
	// ciphertextLength := len(ciphertext)

	// Debug logging (commented out for production)
	// c.logger.Info("[REDACTION DEBUG] Processing TLS record",
	// 	zap.Uint64("seq_num", seqNum),
	// 	zap.Int("total_offset_BEFORE", result.TotalTLSOffset),
	// 	zap.Uint8("content_type", parsed.ContentType),
	// 	zap.Int("actual_content_length", actualLength),
	// 	zap.Int("ciphertext_length", len(ciphertext)),
	// 	zap.Int("original_length", parsed.OriginalLen),
	// 	zap.Int("tls_stream_length", tlsStreamLength))

	switch parsed.ContentType {
	case minitls.RecordTypeApplicationData:
		// Create mapping for this segment
		mapping := TLSToHTTPMapping{
			SeqNum:     seqNum,
			HTTPPos:    len(result.AllHTTPContent),
			TLSPos:     result.TotalTLSOffset,
			Length:     actualLength, // HTTP content length (for mapping)
			Ciphertext: ciphertext,
		}

		result.HTTPMappings = append(result.HTTPMappings, mapping)
		result.AllHTTPContent = append(result.AllHTTPContent, parsed.ActualContent...)
	default:
		// Redact everything except app data
		// Use tlsStreamLength to match TEE_T's consolidated stream
		result.ProtocolRedactions = append(result.ProtocolRedactions,
			shared.ResponseRedactionRange{
				Start:  result.TotalTLSOffset,
				Length: tlsStreamLength,
			})
	}

	// oldOffset := result.TotalTLSOffset
	// Increment by tlsStreamLength to match TEE_T's consolidated stream
	result.TotalTLSOffset += tlsStreamLength
	// Debug logging (commented out for production)
	// c.logger.Info("[REDACTION DEBUG] Incremented offset",
	// 	zap.Int("old_offset", oldOffset),
	// 	zap.Int("increment_by", tlsStreamLength),
	// 	zap.Int("new_offset", result.TotalTLSOffset))
}

// analyzeHTTPContent analyzes HTTP content and returns redaction ranges
func (c *Client) analyzeHTTPContent(mappings []TLSToHTTPMapping, httpContent []byte) ([]shared.ResponseRedactionRange, error) {
	if len(httpContent) == 0 || len(mappings) == 0 {
		return nil, nil
	}
	// Parse HTTP response
	httpResponse := c.parseHTTPResponse(httpContent)
	c.lastResponseData = httpResponse

	// Get automatic redactions from provider if configured
	httpRedactions, err := c.getAutomaticHTTPRedactions(httpResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to get automatic HTTP redactions: %w", err)
	}

	// Convert HTTP positions to TLS positions
	return c.mapHTTPToTLSRedactions(httpRedactions, mappings), nil
}

// getAutomaticHTTPRedactions gets provider-specific redactions
func (c *Client) getAutomaticHTTPRedactions(httpResponse *HTTPResponse) ([]shared.ResponseRedactionRange, error) {
	if len(c.lastRedactionRanges) == 0 {
		c.logger.Info("Getting automatic response redactions", zap.Int("response_bytes", len(httpResponse.FullResponse)))

		ranges, err := c.getResponseRedactions(httpResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to get response redactions: %w", err)
		}

		c.logger.Info("Automatic response redactions generated",
			zap.Int("redaction_ranges", len(ranges)))
		c.lastRedactionRanges = ranges
	} else {
		c.logger.Info("Response redactions already generated",
			zap.Int("cached_ranges", len(c.lastRedactionRanges)))
	}

	return c.lastRedactionRanges, nil
}

// mapHTTPToTLSRedactions converts HTTP position ranges to TLS stream positions
func (c *Client) mapHTTPToTLSRedactions(httpRanges []shared.ResponseRedactionRange, mappings []TLSToHTTPMapping) []shared.ResponseRedactionRange {
	tlsRanges := make([]shared.ResponseRedactionRange, 0)

	for _, httpRange := range httpRanges {
		tlsPositions := c.findTLSPositions(httpRange.Start, httpRange.Length, mappings)
		tlsRanges = append(tlsRanges, tlsPositions...)
	}

	return tlsRanges
}

// findTLSPositions converts an HTTP range to TLS positions
func (c *Client) findTLSPositions(httpStart int, httpLength int, mappings []TLSToHTTPMapping) []shared.ResponseRedactionRange {
	ranges := make([]shared.ResponseRedactionRange, 0)
	httpEnd := httpStart + httpLength

	for _, mapping := range mappings {
		mappingHTTPEnd := mapping.HTTPPos + mapping.Length

		// Check if this mapping overlaps with the HTTP range
		if mapping.HTTPPos < httpEnd && mappingHTTPEnd > httpStart {
			// Calculate the overlap
			overlapStart := max(mapping.HTTPPos, httpStart)
			overlapEnd := min(mappingHTTPEnd, httpEnd)

			// Convert to TLS positions
			tlsStart := mapping.TLSPos + (overlapStart - mapping.HTTPPos)
			tlsLength := overlapEnd - overlapStart

			ranges = append(ranges, shared.ResponseRedactionRange{
				Start:  tlsStart,
				Length: tlsLength,
			})
		}
	}

	return ranges
}

// finalizeRedactionSpec consolidates ranges and creates the final spec
func (c *Client) finalizeRedactionSpec(ranges []shared.ResponseRedactionRange) shared.ResponseRedactionSpec {
	// Log individual ranges if needed (debug)
	c.logRedactionRanges("Pre-consolidation", ranges)

	// Consolidate overlapping ranges
	consolidated := shared.ConsolidateResponseRedactionRanges(ranges)

	c.logger.Info("[REDACTION] Final redaction spec generated",
		zap.Int("original_count", len(ranges)),
		zap.Int("consolidated_count", len(consolidated)))

	return shared.ResponseRedactionSpec{
		Ranges: consolidated,
	}
}

// logRedactionRanges logs redaction ranges for debugging
func (c *Client) logRedactionRanges(context string, ranges []shared.ResponseRedactionRange) {
	for i, r := range ranges {
		c.logger.Debug(fmt.Sprintf("[REDACTION] %s range", context),
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("length", r.Length),
			zap.Int("end", r.Start+r.Length-1))
	}
}

// applyRedactionRangesToContent applies redaction ranges to a content segment
func (c *Client) applyRedactionRangesToContent(content []byte, baseOffset int, ranges []shared.ResponseRedactionRange) []byte {
	result := make([]byte, len(content))
	copy(result, content)

	// Apply each redaction range that overlaps with this content
	for _, r := range ranges {
		rangeStart := r.Start
		rangeEnd := r.Start + r.Length
		contentStart := baseOffset
		contentEnd := baseOffset + len(content)

		// Check for overlap
		overlapStart := max(rangeStart, contentStart)
		overlapEnd := min(rangeEnd, contentEnd)

		if overlapStart < overlapEnd {
			// Apply redaction (replace with asterisks)
			localStart := overlapStart - contentStart
			localEnd := overlapEnd - contentStart
			for i := localStart; i < localEnd; i++ {
				result[i] = '*'
			}
		}
	}

	return result
}

// logRedactedResponseWithAsterisks reconstructs the full response and logs it with redacted parts as asterisks
func (c *Client) logRedactedResponseWithAsterisks(ranges []shared.ResponseRedactionRange) {
	// Debug logging disabled for production - uncomment if needed for debugging
	// Get sorted sequence numbers
	// seqNums := c.getSortedSequenceNumbers()

	// Reconstruct full TLS stream
	// var fullTLSStream []byte
	// totalOffset := 0

	// c.logger.Info("=== RECONSTRUCTING FULL TLS STREAM ===")

	// for _, seqNum := range seqNums {
	// 	parsed := c.parsedResponseBySeq[seqNum]
	// 	if parsed == nil {
	// 		continue
	// 	}

	// 	c.logger.Info("TLS Record",
	// 		zap.Uint64("seq_num", seqNum),
	// 		zap.Int("offset", totalOffset),
	// 		zap.Int("length", len(parsed.ActualContent)),
	// 		zap.Uint8("content_type", parsed.ContentType))

	// 	fullTLSStream = append(fullTLSStream, parsed.ActualContent...)
	// 	totalOffset += len(parsed.ActualContent)
	// }

	// c.logger.Info("Full TLS stream reconstructed",
	// 	zap.Int("total_bytes", len(fullTLSStream)))

	// Apply redactions (replace with asterisks)
	// redactedStream := c.applyRedactionRangesToContent(fullTLSStream, 0, ranges)

	// Log statistics
	// totalRedacted := 0
	// for _, r := range ranges {
	// 	totalRedacted += r.Length
	// }
	// totalRevealed := len(fullTLSStream) - totalRedacted

	// c.logger.Info("=== REDACTION STATISTICS ===",
	// 	zap.Int("total_bytes", len(fullTLSStream)),
	// 	zap.Int("redacted_bytes", totalRedacted),
	// 	zap.Int("revealed_bytes", totalRevealed),
	// 	zap.Int("num_ranges", len(ranges)))

	// Log each range
	// for i, r := range ranges {
	// 	c.logger.Info("Redaction Range",
	// 		zap.Int("index", i),
	// 		zap.Int("start", r.Start),
	// 		zap.Int("length", r.Length),
	// 		zap.Int("end", r.Start+r.Length))
	// }

	// Log the full redacted response (convert to string for readability)
	// c.logger.Info("=== FULL REDACTED RESPONSE (asterisks show redacted parts) ===")
	// c.logger.Info(string(redactedStream))
	// c.logger.Info("=== END REDACTED RESPONSE ===")
}

// sendRedactionSpec sends redaction specification to TEE_K
func (c *Client) sendRedactionSpec() error {
	c.logger.Info("🚀 [REDACTION] Generating and sending redaction specification to TEE_K")

	// Analyze response content to identify redaction ranges
	redactionSpec, err := c.analyzeResponseRedaction()
	if err != nil {
		c.terminateConnectionWithError("Failed to analyze response redaction", err)
		return fmt.Errorf("failed to analyze response redaction: %w", err)
	}

	// Log the full redacted response for debugging
	c.logRedactedResponseWithAsterisks(redactionSpec.Ranges)

	// Send redaction spec to TEE_K using protobuf envelope
	if c.wsConn == nil {
		return fmt.Errorf("no websocket connection to TEE_K")
	}

	// IMPORTANT: Send MPC OPRF ranges BEFORE redaction spec
	// This allows TEEs to set OPRF state before processing redaction,
	// preventing premature signature sending
	mpcRanges := c.buildOPRFMPCRanges()
	if len(mpcRanges) > 0 {
		if err := c.sendOPRFRangesToBothTEEs(mpcRanges); err != nil {
			return fmt.Errorf("send MPC OPRF ranges: %w", err)
		}
		c.logger.Info("Sent MPC OPRF ranges to both TEEs", zap.Int("count", len(mpcRanges)))
	} else {
		// Send empty submission so TEEs know to skip OPRF
		if err := c.sendOPRFRangesToBothTEEs(nil); err != nil {
			return fmt.Errorf("send empty MPC OPRF ranges: %w", err)
		}
	}

	// Map ranges
	pr := make([]*teeproto.ResponseRedactionRange, 0, len(redactionSpec.Ranges))
	for _, r := range redactionSpec.Ranges {
		pr = append(pr, &teeproto.ResponseRedactionRange{Start: int32(r.Start), Length: int32(r.Length)})
	}

	env := &teeproto.Envelope{SessionId: c.sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_ResponseRedactionSpec{ResponseRedactionSpec: &teeproto.ResponseRedactionSpec{Ranges: pr}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal redaction spec envelope: %v", err)
	}
	if err := c.wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("failed to send redaction spec: %v", err)
	}

	c.logger.Info("Sent redaction specification to TEE_K", zap.Int("consolidated_ranges", len(redactionSpec.Ranges)))

	c.advanceToPhase(PhaseReceivingRedacted)

	c.logger.Info("Entering redacted receiving phase - waiting for TEE_K to send 'finished' to TEE_T")
	return nil
}

// buildOPRFMPCRanges converts HTTP response redaction ranges with hash="oprf-mpc" to TLS positions
// Also stores the HTTP <-> TLS position mappings for later use in ParamValue replacement
func (c *Client) buildOPRFMPCRanges() []*teeproto.OPRFRangeSpec {
	var ranges []*teeproto.OPRFRangeSpec
	c.oprfMpcRangeMappings = nil // Reset mappings

	// Sort HTTP starts for deterministic ordering (map iteration is random)
	// This ensures OPRF outputs match the same order as our mappings
	httpStarts := make([]int, 0, len(c.oprfMpcRedactionRanges))
	for httpStart := range c.oprfMpcRedactionRanges {
		httpStarts = append(httpStarts, httpStart)
	}
	slices.Sort(httpStarts)

	// Iterate in sorted order for deterministic TLS range ordering
	for _, httpStart := range httpStarts {
		httpLength := c.oprfMpcRedactionRanges[httpStart]
		httpEnd := httpStart + httpLength - 1

		// Convert HTTP range to TLS stream positions
		tlsStart, err := c.httpPositionToTlsPosition(httpStart)
		if err != nil {
			c.logger.Error("Failed to convert HTTP start position to TLS",
				zap.Int("http_start", httpStart),
				zap.Error(err))
			continue
		}
		tlsEnd, err := c.httpPositionToTlsPosition(httpEnd)
		if err != nil {
			c.logger.Error("Failed to convert HTTP end position to TLS",
				zap.Int("http_end", httpEnd),
				zap.Error(err))
			continue
		}
		tlsEnd++ // Include the end byte

		// Validate length fits in single OPRF (max 64 bytes)
		tlsLength := tlsEnd - tlsStart
		if tlsLength > 64 {
			c.logger.Error("MPC OPRF range too long",
				zap.Int("tls_length", tlsLength),
				zap.Int("max", 64))
			continue
		}
		if tlsLength <= 0 {
			c.logger.Error("Invalid MPC OPRF range",
				zap.Int("tls_start", tlsStart),
				zap.Int("tls_end", tlsEnd))
			continue
		}

		// Store mapping for later use in ParamValue replacement
		c.oprfMpcRangeMappings = append(c.oprfMpcRangeMappings, OPRFMPCRangeMapping{
			HTTPStart:  httpStart,
			HTTPLength: httpLength,
			TLSStart:   tlsStart,
			TLSLength:  tlsLength,
		})

		ranges = append(ranges, &teeproto.OPRFRangeSpec{
			TlsStart:  int32(tlsStart),
			TlsLength: int32(tlsLength),
		})
	}

	return ranges
}
