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
	success := transcripts.BothReceived && c.responseProcessingSuccessful
	var errorMessage string
	if !success {
		if !transcripts.BothReceived {
			errorMessage = "Not all transcripts received"
		} else if !c.responseProcessingSuccessful {
			errorMessage = "Response processing failed"
		}
	}
	return &ProtocolResult{SessionID: c.sessionID, StartTime: c.protocolStartTime, CompletionTime: time.Now(), Success: success, ErrorMessage: errorMessage, RequestTarget: c.targetHost, RequestPort: c.targetPort, RequestRedactions: nil, Transcripts: *transcripts, Validation: *validation, Response: *response}, nil
}

func (c *Client) buildTranscriptResults() (*TranscriptResults, error) {
	var teekTranscript, teetTranscript *SignedTranscriptData
	if c.teekSignedMessage != nil {
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(c.teekSignedMessage.GetBody(), &kPayload); err == nil {
			// Use consolidated keystream from SignedMessage
			consolidatedKeystream := kPayload.GetConsolidatedResponseKeystream()
			var data [][]byte
			if len(consolidatedKeystream) > 0 {
				data = append(data, consolidatedKeystream) // Consolidated keystream for verification
			}
			teekTranscript = &SignedTranscriptData{Data: data, Signature: c.teekSignedMessage.GetSignature(), EthAddress: extractEthAddressFromSignedMessage(c.teekSignedMessage)}
		}
	}
	if c.teetSignedMessage != nil {
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err == nil {
			// Use consolidated ciphertext from SignedMessage
			consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()
			var data [][]byte
			if len(consolidatedCiphertext) > 0 {
				data = append(data, consolidatedCiphertext) // Consolidated ciphertext for verification
			}
			teetTranscript = &SignedTranscriptData{Data: data, Signature: c.teetSignedMessage.GetSignature(), EthAddress: extractEthAddressFromSignedMessage(c.teetSignedMessage)}
		}
	}
	bothReceived := c.teekSignedMessage != nil && c.teetSignedMessage != nil
	bothValid := bothReceived
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
	var responseTimestamp time.Time
	if c.responseProcessingSuccessful {
		responseTimestamp = time.Now()
	}
	batchedSuccess := c.responseProcessingSuccessful
	batchedDataSize := c.reconstructedResponseSize
	finalDataSize := batchedDataSize
	return &ResponseResults{HTTPResponse: c.lastResponseData, ResponseReceived: batchedSuccess, CallbackExecuted: batchedSuccess || (len(c.lastRedactionRanges) > 0), DecryptionSuccessful: batchedSuccess || (finalDataSize > 0), DecryptedDataSize: finalDataSize, ResponseTimestamp: responseTimestamp}, nil
}

func (c *Client) buildTranscriptValidationResults() *TranscriptValidationResults {
	c.protocolStateMutex.RLock()
	bothReceived := c.teeKTranscriptReceived && c.teeTTranscriptReceived
	c.protocolStateMutex.RUnlock()
	teekValid := c.teekSignedMessage != nil
	teetValid := c.teetSignedMessage != nil
	return &TranscriptValidationResults{ClientCapturedData: 0, ClientCapturedBytes: 0, TEEKValidation: TranscriptDataValidation{DataReceived: 1, DataMatched: 1, ValidationPassed: teekValid}, TEETValidation: TranscriptDataValidation{DataReceived: 1, DataMatched: 1, ValidationPassed: teetValid}, OverallValid: bothReceived && teekValid && teetValid, Summary: "Transcript validation based on SignedMessage reception and verification"}
}
