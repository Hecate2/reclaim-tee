package client

import (
	"time"
)

// ProtocolResult contains the complete results of the TEE+MPC protocol execution
type ProtocolResult struct {
	// Protocol execution metadata
	SessionID      string    `json:"session_id"`
	StartTime      time.Time `json:"start_time"`
	CompletionTime time.Time `json:"completion_time"`
	Success        bool      `json:"success"`
	ErrorMessage   string    `json:"error_message,omitempty"`

	// Request information
	RequestTarget     string          `json:"request_target"`
	RequestPort       int             `json:"request_port"`
	RequestRedactions []RedactionSpec `json:"request_redactions"`

	// Transcript data
	Transcripts TranscriptResults `json:"transcripts"`

	// Validation results
	Validation ValidationResults `json:"validation"`

	// Response data
	Response ResponseResults `json:"response"`
}

// TranscriptResults contains the signed transcripts from both TEE_K and TEE_T
type TranscriptResults struct {
	TEEK *SignedTranscriptData `json:"tee_k"`
	TEET *SignedTranscriptData `json:"tee_t"`

	// Summary information
	BothReceived        bool `json:"both_received"`
	BothSignaturesValid bool `json:"both_signatures_valid"`
}

// SignedTranscriptData represents a signed transcript in the results
type SignedTranscriptData struct {
	Data       [][]byte `json:"data"`        // Consolidated streams (keystream/ciphertext)
	Signature  []byte   `json:"signature"`   // Comprehensive cryptographic signature
	EthAddress []byte   `json:"eth_address"` // ETH address (20 bytes)
}

// ValidationResults contains the results of transcript validation
type ValidationResults struct {
	TranscriptValidation TranscriptValidationResults `json:"transcript_validation"`
	// Overall validation status
	AllValidationsPassed bool   `json:"all_validations_passed"`
	ValidationSummary    string `json:"validation_summary"`
}

// TranscriptValidationResults contains validation of transcripts against captured traffic
type TranscriptValidationResults struct {
	ClientCapturedData  int `json:"client_captured_data"`
	ClientCapturedBytes int `json:"client_captured_bytes"`

	TEEKValidation TranscriptDataValidation `json:"tee_k_validation"`
	TEETValidation TranscriptDataValidation `json:"tee_t_validation"`

	OverallValid bool   `json:"overall_valid"`
	Summary      string `json:"summary"`
}

// TranscriptDataValidation contains validation results for one TEE's transcript
type TranscriptDataValidation struct {
	DataReceived     int  `json:"data_received"`
	DataMatched      int  `json:"data_matched"`
	ValidationPassed bool `json:"validation_passed"`

	// Detailed data information
	DataDetails []DataValidationDetail `json:"data_details"`
}

// DataValidationDetail contains validation details for a single data entry
type DataValidationDetail struct {
	DataIndex      int    `json:"data_index"`
	DataSize       int    `json:"data_size"`
	DataType       string `json:"data_type"` // hex representation of first byte
	MatchedCapture bool   `json:"matched_capture"`
	CaptureIndex   int    `json:"capture_index,omitempty"` // If matched, which capture index
}

// ResponseResults contains the HTTP response data and proof claims
type ResponseResults struct {
	HTTPResponse *HTTPResponse `json:"http_response,omitempty"`
	// Response processing metadata
	ResponseReceived  bool      `json:"response_received"`
	CallbackExecuted  bool      `json:"callback_executed"`
	CallbackError     string    `json:"callback_error,omitempty"`
	ResponseTimestamp time.Time `json:"response_timestamp"`

	// Decryption information
	DecryptionSuccessful bool `json:"decryption_successful"`
	DecryptedDataSize    int  `json:"decrypted_data_size"`
}
