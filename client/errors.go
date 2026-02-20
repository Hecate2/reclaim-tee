package client

import (
	"fmt"
)

// ReclaimError is the base error type for all library errors
type ReclaimError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Cause   error  `json:"cause,omitempty"`
}

// Error implements the error interface
func (e *ReclaimError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap implements the error unwrapping interface
func (e *ReclaimError) Unwrap() error {
	return e.Cause
}

// ConnectionError represents connection-related errors
type ConnectionError struct {
	*ReclaimError
	Target string `json:"target"` // Which service failed (TEE_K, TEE_T, etc.)
}

// NewConnectionError creates a new connection error
func NewConnectionError(target string, cause error) *ConnectionError {
	return &ConnectionError{
		ReclaimError: &ReclaimError{
			Type:    "connection_error",
			Message: fmt.Sprintf("Failed to connect to %s", target),
			Cause:   cause,
		},
		Target: target,
	}
}

// AttestationError represents attestation verification errors
type AttestationError struct {
	*ReclaimError
}

// NewAttestationError creates a new attestation error
func NewAttestationError(cause error) *AttestationError {
	return &AttestationError{
		ReclaimError: &ReclaimError{
			Type:    "attestation_error",
			Message: "Failed to verify TEE attestation",
			Cause:   cause,
		},
	}
}

// ProtocolError represents protocol-related errors
type ProtocolError struct {
	*ReclaimError
	Phase string `json:"phase"` // Which protocol phase failed
}

// RedactionError represents redaction-related errors
type RedactionError struct {
	*ReclaimError
	RedactionType string `json:"redaction_type"` // "request" or "response"
}

// ConfigurationError represents configuration-related errors
type ConfigurationError struct {
	*ReclaimError
	Field string `json:"field"` // Which configuration field is invalid
}

// ValidationError represents validation errors
type ValidationError struct {
	*ReclaimError
	Field string `json:"field"` // Field that failed validation
	Value any    `json:"value"` // Invalid value
}
