package client

import (
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"google.golang.org/protobuf/proto"
)

func (c *Client) buildProtocolResult() (*ProtocolResult, error) {
	transcripts, _ := c.buildTranscriptResults()
	validation, _ := c.buildValidationResults()
	response, _ := c.buildResponseResults()
	success := transcripts.BothReceived && transcripts.BothSignaturesValid && response.ResponseReceived
	var errorMessage string
	if !success {
		if !transcripts.BothReceived {
			errorMessage = "Not all transcripts received"
		} else if !transcripts.BothSignaturesValid {
			errorMessage = "Transcript signature validation failed"
		} else if !response.ResponseReceived {
			errorMessage = "Response processing failed"
		}
	}
	return &ProtocolResult{SessionID: c.sessionID, StartTime: c.protocolStartTime, CompletionTime: time.Now(), Success: success, ErrorMessage: errorMessage, RequestTarget: c.targetHost, RequestPort: c.targetPort, RequestRedactions: nil, Transcripts: *transcripts, Validation: *validation, Response: *response}, nil
}

func (c *Client) buildTranscriptResults() (*TranscriptResults, error) {
	c.protocolStateMutex.RLock()
	var teekSignedMessage, teetSignedMessage *teeproto.SignedMessage
	if c.teekSignedMessage != nil {
		teekSignedMessage = proto.Clone(c.teekSignedMessage).(*teeproto.SignedMessage)
	}
	if c.teetSignedMessage != nil {
		teetSignedMessage = proto.Clone(c.teetSignedMessage).(*teeproto.SignedMessage)
	}
	teekReceived := c.teeKTranscriptReceived
	teetReceived := c.teeTTranscriptReceived
	teekValid := c.teeKSignatureValid
	teetValid := c.teeTSignatureValid
	c.protocolStateMutex.RUnlock()

	var teekTranscript, teetTranscript *SignedTranscriptData
	if teekSignedMessage != nil {
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(teekSignedMessage.GetBody(), &kPayload); err == nil {
			// Use consolidated keystream from SignedMessage
			consolidatedKeystream := kPayload.GetConsolidatedResponseKeystream()
			var data [][]byte
			if len(consolidatedKeystream) > 0 {
				data = append(data, append([]byte(nil), consolidatedKeystream...)) // Consolidated keystream for verification
			}
			teekTranscript = &SignedTranscriptData{Data: data, Signature: append([]byte(nil), teekSignedMessage.GetSignature()...), EthAddress: extractEthAddressFromSignedMessage(teekSignedMessage)}
		}
	}
	if teetSignedMessage != nil {
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(teetSignedMessage.GetBody(), &tPayload); err == nil {
			// Use consolidated ciphertext from SignedMessage
			consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()
			var data [][]byte
			if len(consolidatedCiphertext) > 0 {
				data = append(data, append([]byte(nil), consolidatedCiphertext...)) // Consolidated ciphertext for verification
			}
			teetTranscript = &SignedTranscriptData{Data: data, Signature: append([]byte(nil), teetSignedMessage.GetSignature()...), EthAddress: extractEthAddressFromSignedMessage(teetSignedMessage)}
		}
	}
	bothReceived := teekReceived && teetReceived
	bothValid := bothReceived && teekValid && teetValid
	return &TranscriptResults{TEEK: teekTranscript, TEET: teetTranscript, BothReceived: bothReceived, BothSignaturesValid: bothValid}, nil
}

func (c *Client) buildValidationResults() (*ValidationResults, error) {
	transcriptValidation := c.buildTranscriptValidationResults()
	allValid := transcriptValidation.OverallValid
	var summary string
	if allValid {
		summary = "All validations passed successfully"
	} else {
		summary = "Some validations failed"
	}
	return &ValidationResults{TranscriptValidation: *transcriptValidation, AllValidationsPassed: allValid, ValidationSummary: summary}, nil
}

func (c *Client) buildResponseResults() (*ResponseResults, error) {
	c.responseContentMutex.Lock()
	batchedSuccess := c.responseProcessingSuccessful
	batchedDataSize := c.reconstructedResponseSize
	httpResponse := cloneHTTPResponse(c.lastResponseData)
	hasRedactions := len(c.lastRedactionRanges) > 0
	c.responseContentMutex.Unlock()

	var responseTimestamp time.Time
	if batchedSuccess {
		responseTimestamp = time.Now()
	}
	finalDataSize := batchedDataSize
	return &ResponseResults{HTTPResponse: httpResponse, ResponseReceived: batchedSuccess, CallbackExecuted: batchedSuccess || hasRedactions, DecryptionSuccessful: batchedSuccess || (finalDataSize > 0), DecryptedDataSize: finalDataSize, ResponseTimestamp: responseTimestamp}, nil
}

func cloneHTTPResponse(source *HTTPResponse) *HTTPResponse {
	if source == nil {
		return nil
	}
	clone := *source
	if source.Headers != nil {
		clone.Headers = make(map[string]string, len(source.Headers))
		for key, value := range source.Headers {
			clone.Headers[key] = value
		}
	}
	clone.Body = cloneBytesPreservingNil(source.Body)
	clone.FullResponse = cloneBytesPreservingNil(source.FullResponse)
	return &clone
}

func cloneBytesPreservingNil(source []byte) []byte {
	if source == nil {
		return nil
	}
	clone := make([]byte, len(source))
	copy(clone, source)
	return clone
}

func (c *Client) buildTranscriptValidationResults() *TranscriptValidationResults {
	c.protocolStateMutex.RLock()
	teekReceived := c.teeKTranscriptReceived
	teetReceived := c.teeTTranscriptReceived
	teekValid := c.teeKSignatureValid
	teetValid := c.teeTSignatureValid
	c.protocolStateMutex.RUnlock()
	return &TranscriptValidationResults{ClientCapturedData: 0, ClientCapturedBytes: 0, TEEKValidation: TranscriptDataValidation{DataReceived: boolToCount(teekReceived), DataMatched: boolToCount(teekValid), ValidationPassed: teekValid}, TEETValidation: TranscriptDataValidation{DataReceived: boolToCount(teetReceived), DataMatched: boolToCount(teetValid), ValidationPassed: teetValid}, OverallValid: teekReceived && teetReceived && teekValid && teetValid, Summary: "Transcript validation based on signed body, session, attested identity, and signature verification"}
}

func boolToCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
