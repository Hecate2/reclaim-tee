package client

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

func (c *Client) createRedactedRequest(httpRequest []byte) (shared.RedactedRequestData, shared.RedactionStreamsData, error) {
	c.logger.Info("Creating redacted request",
		zap.Int("request_data_length", len(c.requestData)),
		zap.Int("http_request_length", len(httpRequest)))

	if len(c.requestData) > 0 {
		c.logger.Info("Using stored request data")
		httpRequest = c.requestData
	} else if len(httpRequest) == 0 {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("no request data provided")
	} else {
		c.logger.Info("Using provided HTTP request")
	}

	c.logger.Debug("Original request details",
		zap.Int("length", len(httpRequest)),
		zap.String("target_host", c.targetHost),
		zap.Int("host_length", len(c.targetHost)))

	c.logger.Debug("Complete HTTP request before redaction",
		zap.String("request", string(httpRequest)),
		zap.Int("total_length", len(httpRequest)))

	ranges := c.requestRedactionRanges
	if len(ranges) == 0 {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("no redaction ranges provided - library requires explicit redaction ranges")
	}

	c.logger.Info("Redaction configuration",
		zap.Int("ranges_count", len(ranges)))
	for i, r := range ranges {
		c.logger.Debug("Redaction range",
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("end", r.Start+r.Length),
			zap.String("type", r.Type))
	}

	if err := c.validateRedactionRanges(ranges, len(httpRequest)); err != nil {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("invalid redaction ranges: %v", err)
	}

	streams, keys, err := c.generateRedactionStreams(ranges)
	if err != nil {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("failed to generate redaction streams: %v", err)
	}

	redactedRequest := c.applyRedaction(httpRequest, ranges, streams)

	prettyReq := append([]byte(nil), redactedRequest...)
	for _, r := range ranges {
		end := r.Start + r.Length
		if r.Start < 0 || end > len(prettyReq) {
			continue
		}
		for i := r.Start; i < end; i++ {
			prettyReq[i] = '*'
		}
	}

	c.logger.Debug("Non-sensitive parts (unchanged)")
	lines := strings.Split(string(httpRequest), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "Host: ") ||
			strings.HasPrefix(line, "Connection: ") || line == "" {
			c.logger.Debug("Non-sensitive line", zap.String("line", line))
		}
	}

	commitments := c.computeCommitments(streams, keys)

	var proofStreams [][]byte
	var proofKeys [][]byte
	for idx, r := range ranges {
		if r.Type == shared.RedactionTypeSensitiveProof {
			proofStreams = append(proofStreams, streams[idx])
			proofKeys = append(proofKeys, keys[idx])
		}
	}

	if len(proofStreams) > 0 {
		totalStreamLen := 0
		for _, stream := range proofStreams {
			totalStreamLen += len(stream)
		}
		c.proofStream = make([]byte, totalStreamLen)
		offset := 0
		for _, stream := range proofStreams {
			copy(c.proofStream[offset:], stream)
			offset += len(stream)
		}
		c.proofKey = proofKeys[0]

		c.logger.Info("R_SP streams concatenated",
			zap.Int("r_sp_ranges", len(proofStreams)),
			zap.Int("total_proof_stream_length", len(c.proofStream)),
			zap.Int("proof_key_length", len(c.proofKey)))
	}

	c.logger.Info("Redaction summary",
		zap.Int("original_length", len(httpRequest)),
		zap.Int("redacted_length", len(redactedRequest)),
		zap.Int("redaction_ranges", len(ranges)))

	c.redactedRequestPlain = redactedRequest
	c.requestRedactionRanges = ranges

	return shared.RedactedRequestData{
			RedactedRequest: redactedRequest,
			Commitments:     commitments,
			RedactionRanges: ranges,
		}, shared.RedactionStreamsData{
			Streams:        streams,
			CommitmentKeys: keys,
		}, nil
}

func (c *Client) generateRedactionStreams(ranges []shared.RequestRedactionRange) ([][]byte, [][]byte, error) {
	streams := make([][]byte, len(ranges))
	keys := make([][]byte, len(ranges))
	for i, r := range ranges {
		stream := make([]byte, r.Length)
		if _, err := rand.Read(stream); err != nil {
			return nil, nil, fmt.Errorf("failed to generate stream %d: %v", i, err)
		}
		streams[i] = stream
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, nil, fmt.Errorf("failed to generate key %d: %v", i, err)
		}
		keys[i] = key
	}
	return streams, keys, nil
}

func (c *Client) applyRedaction(request []byte, ranges []shared.RequestRedactionRange, streams [][]byte) []byte {
	redacted := make([]byte, len(request))
	copy(redacted, request)
	for i, r := range ranges {
		if i >= len(streams) {
			continue
		}
		for j := 0; j < r.Length && r.Start+j < len(redacted); j++ {
			redacted[r.Start+j] ^= streams[i][j]
		}
	}
	return redacted
}

func (c *Client) computeCommitments(streams, keys [][]byte) [][]byte {
	commitments := make([][]byte, len(streams))
	for i := 0; i < len(streams) && i < len(keys); i++ {
		h := hmac.New(sha256.New, keys[i])
		h.Write(streams[i])
		commitments[i] = h.Sum(nil)
	}
	return commitments
}

func (c *Client) validateRedactionRanges(ranges []shared.RequestRedactionRange, requestLen int) error {
	for _, r := range ranges {
		if r.Start < 0 || r.Length < 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("invalid redaction range: start=%d, length=%d, requestLen=%d", r.Start, r.Length, requestLen)
		}
	}
	return nil
}

func (c *Client) parseHTTPResponse(data []byte) *HTTPResponse {
	dataStr := string(data)
	lines := strings.Split(dataStr, "\r\n")
	response := &HTTPResponse{
		StatusCode:   200,
		Headers:      make(map[string]string),
		Body:         data,
		FullResponse: data,
	}
	if len(lines) > 0 && strings.HasPrefix(lines[0], "HTTP/") {
		parts := strings.Split(lines[0], " ")
		if len(parts) >= 2 {
			var code int
			if _, err := fmt.Sscanf(parts[1], "%d", &code); err == nil {
				response.StatusCode = code
			}
		}
	}
	bodyStart := 0
	for i, line := range lines {
		if line == "" {
			bodyStart = i + 1
			break
		}
		if i > 0 {
			if colonIdx := strings.Index(line, ":"); colonIdx != -1 {
				key := strings.TrimSpace(line[:colonIdx])
				value := strings.TrimSpace(line[colonIdx+1:])
				response.Headers[key] = value

			}
		}
	}
	if bodyStart < len(lines) {
		bodyLines := lines[bodyStart:]
		response.Body = []byte(strings.Join(bodyLines, "\r\n"))
	} else {
		response.Body = []byte("")
	}
	return response
}
