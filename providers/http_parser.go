package providers

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// HTTPResponseParser represents a streaming HTTP/1.1 response parser
// that can handle partial data, Content-Length, chunked encoding, and connection-close responses
type HTTPResponseParser struct {
	// Response data being constructed
	Response *HTTPParsedResponse

	// Parser state
	remainingBodyBytes int64 // -1 means read until stream ends, 0 means no more body, >0 means exact count
	isChunked          bool  // true if using chunked transfer encoding
	chunkNeedsCRLF     bool
	finalChunkSeen     bool
	strictFraming      bool
	remaining          []byte // buffer for incomplete data
	currentByteIdx     int    // current position in the complete response stream

	// State flags
	headersComplete bool
	complete        bool
	streamEnded     bool
}

// HTTPParsedResponse represents a parsed HTTP response with all metadata
type HTTPParsedResponse struct {
	StatusCode          int
	StatusMessage       string
	StatusLineEndIndex  int
	HeaderEndIdx        int
	BodyStartIndex      int
	Body                []byte
	HeaderLowerToRanges map[string]shared.ResponseRedactionRange
	HeaderFraming       []shared.ResponseRedactionRange // header names, delimiters, and CRLFs
	Headers             map[string]string               // header values for processing
	Chunked             bool
	Chunks              []shared.ResponseRedactionRange // for chunked responses
	ChunkFraming        []shared.ResponseRedactionRange // safe chunk-size and CRLF ranges

	// Completeness tracking
	HeadersComplete bool
	Complete        bool
}

// NewHTTPResponseParser creates a new streaming HTTP response parser
func NewHTTPResponseParser() *HTTPResponseParser {
	return newHTTPResponseParser(false)
}

func newHTTPResponseParser(strictFraming bool) *HTTPResponseParser {
	logger.Info("Starting NewHTTPResponseParser", zap.String("component", "Parser"), zap.String("operation", "NewHTTPResponseParser"), zap.String("description", "Creating streaming parser"))

	return &HTTPResponseParser{
		Response: &HTTPParsedResponse{
			StatusCode:          0,
			StatusMessage:       "",
			StatusLineEndIndex:  -1,
			HeaderEndIdx:        -1,
			BodyStartIndex:      -1,
			Body:                []byte{},
			HeaderLowerToRanges: make(map[string]shared.ResponseRedactionRange),
			HeaderFraming:       []shared.ResponseRedactionRange{},
			Headers:             make(map[string]string),
			Chunked:             false,
			Chunks:              []shared.ResponseRedactionRange{},
			ChunkFraming:        []shared.ResponseRedactionRange{},
			HeadersComplete:     false,
			Complete:            false,
		},
		remainingBodyBytes: 0,
		isChunked:          false,
		strictFraming:      strictFraming,
		remaining:          []byte{},
		currentByteIdx:     0,
		headersComplete:    false,
		complete:           false,
		streamEnded:        false,
	}
}

// OnChunk processes a new chunk of response data
// This method can be called multiple times as data arrives
func (p *HTTPResponseParser) OnChunk(data []byte) error {

	if p.complete {
		logger.Error("Received data after response was marked complete", zap.String("component", "Parser"), zap.String("operation", "OnChunk"))
		return errors.New("got more data after response was complete")
	}

	// Concatenate with remaining data from previous chunks
	p.remaining = append(p.remaining, data...)

	// Process headers if not complete
	if !p.headersComplete {
		if err := p.processHeaders(); err != nil {
			return err
		}
	}

	// Process body if headers are complete
	if p.headersComplete {
		if err := p.processBody(); err != nil {
			return err
		}
	}

	return nil
}

// StreamEnded indicates that no more data will arrive
// This validates the response completeness and finalizes parsing
func (p *HTTPResponseParser) StreamEnded() error {
	logger.Info("Starting StreamEnded", zap.String("component", "Parser"), zap.String("operation", "StreamEnded"), zap.String("description", "Finalizing response parsing"))

	p.streamEnded = true

	// Validate response completeness
	if !p.headersComplete {
		logger.Error("Stream ended before headers were complete", zap.String("component", "Parser"), zap.String("operation", "StreamEnded"))
		return errors.New("stream ended before headers were complete")
	}

	// Check if we're missing expected body data.
	if p.remainingBodyBytes > 0 {
		logger.Error("Stream ended with body bytes still expected", zap.String("component", "Parser"), zap.String("operation", "StreamEnded"), zap.Int64("remaining_body_bytes", p.remainingBodyBytes))
		return errors.New("stream ended before all body bytes were received")
	}
	if p.strictFraming && p.isChunked {
		if p.chunkNeedsCRLF {
			return errors.New("stream ended before chunk data CRLF")
		}
		if !p.finalChunkSeen {
			return errors.New("stream ended before terminal zero chunk")
		}
		if !p.complete {
			return errors.New("stream ended before final chunk trailer terminator")
		}
	}

	// Handle remaining data based on response type
	if len(p.remaining) > 0 {
		if p.remainingBodyBytes == -1 {
			// Stream-until-close: consume all remaining data as body
			p.Response.Body = append(p.Response.Body, p.remaining...)
			p.currentByteIdx += len(p.remaining)
			p.remaining = []byte{}
		} else if p.isChunked {
			if p.strictFraming {
				return errors.New("received trailing bytes after chunked response")
			}
			// Chunked: consume trailing data (trailer headers, final CRLF) to match TypeScript behavior
			logger.Debug("Consuming remaining bytes as chunked trailer to match TypeScript", zap.String("component", "Parser"), zap.String("operation", "StreamEnded"), zap.Int("remaining_bytes", len(p.remaining)))
			p.currentByteIdx += len(p.remaining) // CRITICAL FIX: advance position like TypeScript
			p.remaining = []byte{}
		} else if p.strictFraming {
			return errors.New("received trailing bytes after Content-Length body")
		} else {
			logger.Debug("Ignoring extra bytes after Content-Length body", zap.String("component", "Parser"), zap.String("operation", "StreamEnded"), zap.Int("extra_bytes", len(p.remaining)))
			p.remaining = []byte{}
		}
	}

	p.complete = true
	p.Response.Complete = true

	logger.Info("Response parsing completed", zap.String("component", "Parser"), zap.String("operation", "StreamEnded"), zap.Int("status_code", p.Response.StatusCode), zap.Int("body_bytes", len(p.Response.Body)), zap.Int("chunks", len(p.Response.Chunks)))

	return nil
}

// processHeaders processes HTTP headers from the buffer
func (p *HTTPResponseParser) processHeaders() error {

	for {
		line, found := p.getLine()
		if !found {
			logger.Debug("Need more data to complete header line", zap.String("component", "Parser"), zap.String("operation", "processHeaders"), zap.String("level", "verbose"))
			break // Need more data
		}

		// First line is status line
		if p.Response.StatusCode == 0 {
			if err := p.parseStatusLine(line); err != nil {
				return err
			}
			continue
		}

		// Empty line signals end of headers
		if line == "" {
			return p.finishHeaders()
		}

		// Parse header line
		if err := p.parseHeaderLine(line); err != nil {
			return err
		}
	}

	return nil
}

// parseStatusLine parses the HTTP status line
func (p *HTTPResponseParser) parseStatusLine(line string) error {
	logger.Debug("Parsing status line", zap.String("component", "Parser"), zap.String("operation", "parseStatusLine"), zap.String("level", "verbose"), zap.String("line", line))

	// Parse HTTP/1.1 200 OK format
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		logger.Error("Invalid status line format", zap.String("component", "Parser"), zap.String("operation", "parseStatusLine"))
		return fmt.Errorf("invalid HTTP status line: %s", line)
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		logger.Error("Invalid status code", zap.String("component", "Parser"), zap.String("operation", "parseStatusLine"), zap.String("status_code", parts[1]))
		return fmt.Errorf("invalid status code %s: %w", parts[1], err)
	}

	p.Response.StatusCode = statusCode
	if len(parts) >= 3 {
		p.Response.StatusMessage = parts[2]
	}
	p.Response.StatusLineEndIndex = p.currentByteIdx - 2 // subtract CRLF

	logger.Debug("Parsed status", zap.String("component", "Parser"), zap.String("operation", "parseStatusLine"), zap.Int("status_code", p.Response.StatusCode), zap.String("status_message", p.Response.StatusMessage))
	return nil
}

// parseHeaderLine parses a single HTTP header line
func (p *HTTPResponseParser) parseHeaderLine(line string) error {
	var before, after string
	var separator, valueStart int
	if p.strictFraming {
		separator = strings.IndexByte(line, ':')
		if separator <= 0 {
			logger.Warn("Header line missing colon separator", zap.String("component", "Parser"), zap.String("operation", "parseHeaderLine"), zap.String("line", line))
			return errors.New("invalid HTTP response header line")
		}
		before = line[:separator]
		if !validHTTPResponseHeaderName(before) {
			return errors.New("invalid HTTP response header name")
		}
		valueStart = separator + 1
		for valueStart < len(line) && (line[valueStart] == ' ' || line[valueStart] == '\t') {
			valueStart++
		}
		after = line[valueStart:]
	} else {
		var ok bool
		before, after, ok = strings.Cut(line, ": ")
		if !ok {
			logger.Warn("Header line missing colon separator", zap.String("component", "Parser"), zap.String("operation", "parseHeaderLine"), zap.String("line", line))
			return nil // Preserve legacy behavior: skip malformed headers.
		}
		separator = len(before)
		valueStart = separator + 2
	}

	key := strings.ToLower(before)
	value := after
	if p.strictFraming && (key == "content-length" || key == "transfer-encoding") {
		if _, exists := p.Response.Headers[key]; exists {
			return fmt.Errorf("duplicate HTTP response framing header %q", key)
		}
	}

	// Store header value for processing
	p.Response.Headers[key] = value

	// Store header with range information
	lineStart := p.currentByteIdx - len(line) - 2 // subtract line + CRLF
	p.Response.HeaderLowerToRanges[key] = shared.ResponseRedactionRange{
		Start:  lineStart,
		Length: len(line),
	}
	if p.strictFraming {
		p.Response.HeaderFraming = append(p.Response.HeaderFraming,
			shared.ResponseRedactionRange{Start: lineStart, Length: valueStart},
			shared.ResponseRedactionRange{Start: lineStart + len(line), Length: 2},
		)
	}

	logger.Debug("Header parsed", zap.String("component", "Parser"), zap.String("operation", "parseHeaderLine"), zap.String("level", "verbose"), zap.String("key", key), zap.String("value", value), zap.Int("start", lineStart), zap.Int("end", lineStart+len(line)))
	return nil
}

// finishHeaders completes header processing and sets up body parsing
func (p *HTTPResponseParser) finishHeaders() error {

	p.headersComplete = true
	p.Response.HeadersComplete = true
	p.Response.HeaderEndIdx = p.currentByteIdx - 4 // subtract double CRLF
	p.Response.BodyStartIndex = p.currentByteIdx

	// Determine body reading strategy
	transferEncoding := p.Response.Headers["transfer-encoding"]
	contentLength := p.Response.Headers["content-length"]
	if p.strictFraming && transferEncoding != "" && contentLength != "" {
		return errors.New("HTTP response contains both Transfer-Encoding and Content-Length")
	}
	isChunked := strings.Contains(strings.ToLower(transferEncoding), "chunked")
	if p.strictFraming && transferEncoding != "" {
		codings := strings.Split(strings.ToLower(transferEncoding), ",")
		isChunked = false
		for index, coding := range codings {
			coding = strings.TrimSpace(coding)
			if coding == "" {
				return errors.New("HTTP response contains an invalid Transfer-Encoding")
			}
			if coding == "chunked" {
				if index != len(codings)-1 {
					return errors.New("HTTP response contains invalid Transfer-Encoding order")
				}
				isChunked = true
			}
		}
	}

	if isChunked {
		// Chunked transfer encoding
		p.isChunked = true
		p.Response.Chunked = true
		p.remainingBodyBytes = 0
	} else if contentLength != "" {
		// Fixed content length
		if p.strictFraming {
			for _, char := range []byte(contentLength) {
				if char < '0' || char > '9' {
					return fmt.Errorf("invalid Content-Length %s", contentLength)
				}
			}
		}
		length, err := strconv.ParseInt(contentLength, 10, 64)
		if err != nil {
			logger.Error("Invalid Content-Length", zap.String("component", "Parser"), zap.String("operation", "finishHeaders"), zap.String("content_length", contentLength))
			return fmt.Errorf("invalid Content-Length %s: %w", contentLength, err)
		}

		// Security check: Content-Length must be non-negative
		if length < 0 {
			logger.Error("Negative Content-Length not allowed", zap.String("component", "Parser"), zap.String("operation", "finishHeaders"), zap.Int64("length", length))
			return fmt.Errorf("invalid Content-Length %s: negative values not allowed", contentLength)
		}

		p.remainingBodyBytes = length

		// Handle zero-length body
		if length == 0 {
			p.complete = true
			p.Response.Complete = true
		}
	} else {
		// Read until connection closes
		p.remainingBodyBytes = -1
	}

	return nil
}

func validHTTPResponseHeaderName(name string) bool {
	for i := range len(name) {
		char := name[i]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return name != ""
}

// processBody processes the HTTP response body
func (p *HTTPResponseParser) processBody() error {
	if p.complete {
		return nil
	}

	if p.isChunked {
		return p.processChunkedBody()
	} else {
		return p.processFixedBody()
	}
}

// processFixedBody processes body with known or unknown length
func (p *HTTPResponseParser) processFixedBody() error {
	if p.remainingBodyBytes == 0 {
		// No more body expected
		if !p.complete {
			p.complete = true
			p.Response.Complete = true
		}
		return nil
	}

	if len(p.remaining) == 0 {
		return nil // Need more data
	}

	var bytesToCopy int

	if p.remainingBodyBytes == -1 {
		// Read all available bytes (stream-until-close)
		bytesToCopy = len(p.remaining)
	} else {
		// Read up to remaining body bytes
		bytesToCopy = int(min(p.remainingBodyBytes, int64(len(p.remaining))))
		p.remainingBodyBytes -= int64(bytesToCopy)
	}

	// Copy data to body
	p.Response.Body = append(p.Response.Body, p.remaining[:bytesToCopy]...)
	p.remaining = p.remaining[bytesToCopy:]
	p.currentByteIdx += bytesToCopy

	// Check if fixed-length body is complete
	if p.remainingBodyBytes == 0 {
		p.complete = true
		p.Response.Complete = true
	}

	return nil
}

// processChunkedBody processes chunked transfer encoding
func (p *HTTPResponseParser) processChunkedBody() error {

	for {
		if p.finalChunkSeen {
			line, found := p.getLine()
			if !found {
				break
			}
			p.recordChunkFraming(p.currentByteIdx-2, 2)
			if line == "" {
				p.complete = true
				p.Response.Complete = true
				break
			}
			continue
		}

		if p.chunkNeedsCRLF {
			if len(p.remaining) < 2 {
				break
			}
			if !bytes.Equal(p.remaining[:2], []byte("\r\n")) {
				logger.Error("Missing chunk trailing CRLF", zap.String("component", "Parser"), zap.String("operation", "processChunkedBody"))
				return errors.New("invalid chunk: missing CRLF after data")
			}
			p.recordChunkFraming(p.currentByteIdx, 2)
			p.remaining = p.remaining[2:]
			p.currentByteIdx += 2
			p.chunkNeedsCRLF = false
			continue
		}

		if p.remainingBodyBytes > 0 {
			// Read chunk data
			bytesToRead := int(min(p.remainingBodyBytes, int64(len(p.remaining))))
			if bytesToRead == 0 {
				break // Need more data
			}

			// Add chunk data to body
			p.Response.Body = append(p.Response.Body, p.remaining[:bytesToRead]...)
			p.remaining = p.remaining[bytesToRead:]
			p.currentByteIdx += bytesToRead
			p.remainingBodyBytes -= int64(bytesToRead)

			if p.remainingBodyBytes > 0 {
				break // Still need more chunk data
			}

			p.chunkNeedsCRLF = true
			continue
		}

		// Read next chunk size
		line, found := p.getLine()
		if !found {
			break // Need more data
		}

		if line == "" {
			if p.strictFraming {
				return errors.New("invalid chunk: empty size line")
			}
			continue // Skip empty lines
		}

		// Parse chunk size (handle extensions)
		sizeStr := line
		if before, _, ok := strings.Cut(line, ";"); ok {
			sizeStr = before
		}
		sizeStr = strings.TrimSpace(sizeStr)
		if p.strictFraming && !validChunkSize(sizeStr) {
			return errors.New("invalid chunk size")
		}

		chunkSize, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			logger.Error("Invalid chunk size", zap.String("component", "Parser"), zap.String("operation", "processChunkedBody"), zap.String("chunk_size", sizeStr))
			return fmt.Errorf("invalid chunk size %s: %w", sizeStr, err)
		}
		lineStart := p.currentByteIdx - len(line) - 2
		sizeOffset := strings.Index(line, sizeStr)
		if sizeOffset < 0 {
			return errors.New("invalid chunk size position")
		}
		if extensionOffset := strings.IndexByte(line, ';'); extensionOffset >= 0 {
			// Reveal through the extension delimiter so the verifier can
			// distinguish valid hidden extension data from malformed size syntax.
			p.recordChunkFraming(lineStart, extensionOffset+1)
		} else {
			p.recordChunkFraming(lineStart, len(line))
		}
		p.recordChunkFraming(p.currentByteIdx-2, 2)

		if chunkSize == 0 {
			p.finalChunkSeen = true
			continue
		}

		// Record chunk range (absolute positions in complete response)
		chunkStart := p.currentByteIdx
		p.Response.Chunks = append(p.Response.Chunks, shared.ResponseRedactionRange{
			Start:  chunkStart,
			Length: int(chunkSize),
		})

		p.remainingBodyBytes = chunkSize
	}

	return nil
}

func validChunkSize(size string) bool {
	if size == "" {
		return false
	}
	for i := range len(size) {
		char := size[i]
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') {
			continue
		}
		return false
	}
	return true
}

func (p *HTTPResponseParser) recordChunkFraming(start, length int) {
	if length <= 0 {
		return
	}
	p.Response.ChunkFraming = append(p.Response.ChunkFraming, shared.ResponseRedactionRange{
		Start: start, Length: length,
	})
}

// getLine extracts a CRLF-terminated line from the buffer
func (p *HTTPResponseParser) getLine() (string, bool) {
	crlfIdx := bytes.Index(p.remaining, []byte("\r\n"))
	if crlfIdx == -1 {
		return "", false // Line not complete
	}

	line := string(p.remaining[:crlfIdx])
	p.remaining = p.remaining[crlfIdx+2:] // Skip CRLF
	p.currentByteIdx += crlfIdx + 2

	return line, true
}
