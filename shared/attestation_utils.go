//go:build !mobile

package shared

import (
	"bytes"
	"crypto/tls"
	"fmt"

	teeproto "tee-mpc/proto"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
	"github.com/gorilla/websocket"
)

// extractTLSCertFromWebSocket extracts the peer TLS certificate from a WebSocket connection
func ExtractTLSCertFromWebSocket(conn *websocket.Conn) ([]byte, error) {
	underlying := conn.NetConn()

	tlsConn, ok := underlying.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a TLS connection")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}

	return state.PeerCertificates[0].Raw, nil
}

// ExtractPCR0FromAttestation extracts PCR0 from platform-specific attestation as string
func ExtractPCR0FromAttestation(attestation *teeproto.AttestationReport, logger *Logger) (string, error) {
	switch attestation.Type {
	case "nitro":
		return extractPCR0FromNitro(attestation.Report)
	case "gcp":
		return ExtractImageDigestFromGCPAttestation(attestation.Report, logger)
	default:
		return "", fmt.Errorf("unknown attestation type: %s", attestation.Type)
	}
}

// extractPCR0FromNitro parses AWS Nitro attestation document and extracts PCR0 as hex string
func extractPCR0FromNitro(doc []byte) (string, error) {
	// Parse Nitro attestation document using Anjuna library
	sr, err := verifier.NewSignedAttestationReport(bytes.NewReader(doc))
	if err != nil {
		return "", fmt.Errorf("failed to parse nitro attestation document: %v", err)
	}

	// Validate the attestation document signature
	if err := verifier.Validate(sr, nil); err != nil {
		return "", fmt.Errorf("nitro attestation validation failed: %v", err)
	}

	// Extract PCR0 from the PCRs map
	pcr0 := sr.Document.PCRs[0]
	if pcr0 == nil {
		return "", fmt.Errorf("PCR0 not found in attestation document")
	}

	// Return as hex string for simple string comparison
	return fmt.Sprintf("%x", pcr0), nil
}

// ExtractUserDataFromNitroAttestation extracts userData from AWS Nitro attestation document
func ExtractUserDataFromNitroAttestation(doc []byte) (string, error) {
	// Parse Nitro attestation document using Anjuna library
	sr, err := verifier.NewSignedAttestationReport(bytes.NewReader(doc))
	if err != nil {
		return "", fmt.Errorf("failed to parse nitro attestation document: %v", err)
	}

	// Validate the attestation document signature
	if err := verifier.Validate(sr, nil); err != nil {
		return "", fmt.Errorf("nitro attestation validation failed: %v", err)
	}

	// Extract UserData
	return string(sr.Document.UserData), nil
}

// ExtractUserDataFromGCPAttestation extracts userData from GCP Confidential Space attestation token
func ExtractUserDataFromGCPAttestation(token []byte, logger *Logger) (string, error) {
	// Validate JWT signature and extract userData from eat_nonce claim
	userData, err := ValidateGCPAttestationAndExtractUserData(token, logger)
	if err != nil {
		return "", fmt.Errorf("GCP attestation validation failed: %v", err)
	}
	return userData, nil
}
