package minitls

import (
	"errors"
	"fmt"
)

// ErrBadRecordMAC is deliberately shared by all CBC authentication, padding,
// and public ciphertext-shape failures. Callers must terminate the session
// without exposing a more specific error.
var ErrBadRecordMAC = errors.New("tls: bad record MAC")

// CertErrorType represents different types of certificate validation errors
type CertErrorType int

const (
	CertErrorInvalidChain CertErrorType = iota
	CertErrorSystemRoots
	CertErrorVerification
	CertErrorHostnameMismatch
	CertErrorExpired
	CertErrorUntrustedRoot
)

// CertificateError represents a structured certificate validation error
// that can be properly propagated through TEE_K -> TEE_T -> Client
type CertificateError struct {
	Type    CertErrorType
	Message string
	Err     error // Underlying error if any
}

func (e *CertificateError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *CertificateError) Unwrap() error {
	return e.Err
}

// AlertLevel returns the TLS alert level for this error
func (e *CertificateError) AlertLevel() uint8 {
	return alertLevelFatal
}

// AlertDescription returns the appropriate TLS alert for this error
func (e *CertificateError) AlertDescription() uint8 {
	switch e.Type {
	case CertErrorInvalidChain, CertErrorVerification:
		return alertBadCertificate
	case CertErrorHostnameMismatch:
		return alertBadCertificate
	case CertErrorExpired:
		return alertCertificateExpired
	case CertErrorUntrustedRoot:
		return alertUnknownCA
	case CertErrorSystemRoots:
		return alertInternalError
	default:
		return alertBadCertificate
	}
}
