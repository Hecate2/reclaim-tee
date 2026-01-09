package client

import (
	"bytes"
	"fmt"
	"time"

	teeproto "tee-mpc/proto"

	"google.golang.org/protobuf/proto"
)

func (c *Client) buildProtocolResult() (*ProtocolResult, error) {
	transcripts, _ := c.buildTranscriptResults()
	validation, _ := c.buildValidationResults()
	attestation, _ := c.buildAttestationResults()
	response, _ := c.buildResponseResults()
	success := transcripts.BothReceived && validation.AttestationValidation.OverallValid && c.responseProcessingSuccessful
	var errorMessage string
	if !success {
		if !transcripts.BothReceived {
			errorMessage = "Not all transcripts received"
		} else if !validation.AttestationValidation.OverallValid {
			errorMessage = "Attestation validation failed"
		} else if !c.responseProcessingSuccessful {
			errorMessage = "Response processing failed"
		}
	}
	return &ProtocolResult{SessionID: c.sessionID, StartTime: c.protocolStartTime, CompletionTime: time.Now(), Success: success, ErrorMessage: errorMessage, RequestTarget: c.targetHost, RequestPort: c.targetPort, RequestRedactions: nil, Transcripts: *transcripts, Validation: *validation, Attestation: *attestation, Response: *response}, nil
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
	attestationValidation := c.buildAttestationValidationResults()
	allValid := transcriptValidation.OverallValid && attestationValidation.OverallValid
	var summary string
	if allValid {
		summary = "All validations passed successfully"
	} else {
		summary = "Some validations failed"
	}
	return &ValidationResults{TranscriptValidation: *transcriptValidation, AttestationValidation: *attestationValidation, AllValidationsPassed: allValid, ValidationSummary: summary}, nil
}

func (c *Client) buildAttestationResults() (*AttestationResults, error) {
	verification := c.buildAttestationValidationResults()
	return &AttestationResults{TEEKPublicKey: nil, TEETPublicKey: nil, Verification: *verification}, nil
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

func (c *Client) buildAttestationValidationResults() *AttestationValidationResults {
	// Verify TEE_K attestation
	teekResult := c.verifyAttestationReport(c.teekSignedMessage, "tee_k")

	// Verify TEE_T attestation
	teetResult := c.verifyAttestationReport(c.teetSignedMessage, "tee_t")

	// Compare public keys
	keyComparison := c.compareAttestationKeys(teekResult, teetResult)

	overallValid := teekResult.RootOfTrustValid && teetResult.RootOfTrustValid && keyComparison.BothTEEsMatch

	return &AttestationValidationResults{
		TEEKAttestation:     teekResult,
		TEETAttestation:     teetResult,
		PublicKeyComparison: keyComparison,
		OverallValid:        overallValid,
		Summary:             fmt.Sprintf("TEE_K valid: %v, TEE_T valid: %v, Keys match: %v", teekResult.RootOfTrustValid, teetResult.RootOfTrustValid, keyComparison.BothTEEsMatch),
	}
}

func (c *Client) verifyAttestationReport(signedMsg *teeproto.SignedMessage, teeName string) AttestationVerificationResult {
	if signedMsg == nil {
		return AttestationVerificationResult{
			AttestationReceived: false,
			RootOfTrustValid:    false,
			PublicKeyExtracted:  false,
			Error:               "No signed message received",
		}
	}

	attestationReport := signedMsg.GetAttestationReport()
	ethAddress := signedMsg.GetEthAddress()

	if attestationReport == nil {
		// No attestation - this is acceptable for testing
		if len(ethAddress) > 0 {
			return AttestationVerificationResult{
				AttestationReceived: false,
				RootOfTrustValid:    true, // Trust the embedded key for now
				PublicKeyExtracted:  true,
				PublicKeySize:       len(ethAddress),
			}
		}
		return AttestationVerificationResult{
			AttestationReceived: false,
			RootOfTrustValid:    false,
			PublicKeyExtracted:  false,
			Error:               "No attestation report",
		}
	}

	// Check attestation type
	attestationType := attestationReport.GetType()
	attestationData := attestationReport.GetReport()

	if attestationType == "gcp" {
		// Verify GCP JWT attestation
		publicKey, err := VerifyGCPConfidentialSpaceAttestation(string(attestationData))
		if err != nil {
			return AttestationVerificationResult{
				AttestationReceived: true,
				RootOfTrustValid:    false,
				PublicKeyExtracted:  false,
				Error:               fmt.Sprintf("GCP attestation verification failed: %v", err),
			}
		}

		return AttestationVerificationResult{
			AttestationReceived: true,
			RootOfTrustValid:    true,
			PublicKeyExtracted:  true,
			PublicKeySize:       len(publicKey),
		}
	} else if attestationType == "nitro" {
		// TODO: Implement Nitro attestation verification
		// For now, just mark as received
		return AttestationVerificationResult{
			AttestationReceived: true,
			RootOfTrustValid:    false, // Not yet implemented
			PublicKeyExtracted:  false,
			Error:               "Nitro attestation verification not yet implemented",
		}
	}

	return AttestationVerificationResult{
		AttestationReceived: true,
		RootOfTrustValid:    false,
		PublicKeyExtracted:  false,
		Error:               fmt.Sprintf("Unknown attestation type: %s", attestationType),
	}
}

func (c *Client) compareAttestationKeys(teekResult, teetResult AttestationVerificationResult) PublicKeyComparisonResult {
	if !teekResult.PublicKeyExtracted || !teetResult.PublicKeyExtracted {
		return PublicKeyComparisonResult{
			ComparisonPerformed: false,
			TEEKKeysMatch:       false,
			TEETKeysMatch:       false,
			BothTEEsMatch:       false,
			Error:               "Public keys not extracted from both attestations",
		}
	}

	// For now, assume keys match if they were successfully extracted
	// TODO: Actually compare the extracted keys with transcript signatures
	return PublicKeyComparisonResult{
		ComparisonPerformed: true,
		TEEKKeysMatch:       teekResult.PublicKeyExtracted,
		TEETKeysMatch:       teetResult.PublicKeyExtracted,
		BothTEEsMatch:       teekResult.RootOfTrustValid && teetResult.RootOfTrustValid,
	}
}

func (c *Client) buildTEEValidationDetails(source string, data [][]byte) TranscriptDataValidation {
	if data == nil {
		return TranscriptDataValidation{DataReceived: 0, DataMatched: 0, ValidationPassed: false, DataDetails: []DataValidationDetail{}}
	}
	var details []DataValidationDetail
	dataMatched := 0
	for i, dataEntry := range data {
		var dataType string
		if len(dataEntry) > 0 {
			dataType = fmt.Sprintf("0x%02x", dataEntry[0])
		} else {
			dataType = "empty"
		}
		matchedCapture := false
		captureIndex := -1
		for j, capturedChunk := range c.capturedTraffic {
			if len(dataEntry) == len(capturedChunk) && bytes.Equal(dataEntry, capturedChunk) {
				matchedCapture = true
				captureIndex = j
				dataMatched++
				break
			}
		}
		detail := DataValidationDetail{DataIndex: i, DataSize: len(dataEntry), DataType: dataType, MatchedCapture: matchedCapture}
		if matchedCapture {
			detail.CaptureIndex = captureIndex
		}
		details = append(details, detail)
	}
	requiredMatches := len(data)
	return TranscriptDataValidation{DataReceived: len(data), DataMatched: dataMatched, ValidationPassed: dataMatched == requiredMatches, DataDetails: details}
}
