//go:build !mobile

package proofverifier

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"google.golang.org/protobuf/proto"
)

// collapseAsterisks reduces consecutive asterisks to a maximum of 100 followed by "..." if more exist
func collapseAsterisks(data string) string {
	if len(data) == 0 {
		return data
	}

	var result strings.Builder
	asteriskCount := 0

	for _, char := range data {
		if char == '*' {
			asteriskCount++
		} else {
			// We hit a non-asterisk character
			if asteriskCount > 0 {
				if asteriskCount <= AsteriskCollapseThreshold {
					// Threshold or fewer asterisks, show them all
					result.WriteString(strings.Repeat("*", asteriskCount))
				} else {
					// More than threshold asterisks, show collapsed pattern
					result.WriteString(CollapsedAsteriskPattern)
				}
				asteriskCount = 0
			}
			result.WriteRune(char)
		}
	}

	// Handle trailing asterisks
	if asteriskCount > 0 {
		if asteriskCount <= AsteriskCollapseThreshold {
			result.WriteString(strings.Repeat("*", asteriskCount))
		} else {
			result.WriteString(CollapsedAsteriskPattern)
		}
	}

	return result.String()
}

// replaceOPRFRanges replaces redacted ranges with OPRF outputs
func replaceOPRFRanges(content []byte, oprfVerifications []*teeproto.OPRFVerificationData, oprfRanges map[int]int) []byte {
	if oprfVerifications == nil || len(oprfVerifications) == 0 {
		return content
	}

	result := make([]byte, len(content))
	copy(result, content)

	// Sort OPRF ranges by position to match OPRF verification order
	var sortedPositions []int
	for pos := range oprfRanges {
		sortedPositions = append(sortedPositions, pos)
	}
	sort.Ints(sortedPositions)

	// Replace with OPRF outputs - they're in the same sorted order
	for i, oprfData := range oprfVerifications {
		if i >= len(sortedPositions) {
			break
		}
		httpPos := sortedPositions[i]
		httpLength := oprfRanges[httpPos]

		// Extract OPRF output from public signals (InputVerifyParams structure)
		var verifyParams struct {
			PublicSignals json.RawMessage `json:"publicSignals"`
		}

		if err := json.Unmarshal(oprfData.PublicSignalsJson, &verifyParams); err == nil && verifyParams.PublicSignals != nil {
			// Parse the public signals (InputTOPRFParams)
			var publicSignals struct {
				TOPRF struct {
					Output []byte `json:"output"`
				} `json:"toprf"`
			}

			if err := json.Unmarshal(verifyParams.PublicSignals, &publicSignals); err == nil && len(publicSignals.TOPRF.Output) > 0 {
				// Convert OPRF output to base64
				oprfBase64 := base64.StdEncoding.EncodeToString(publicSignals.TOPRF.Output)

				if httpPos >= 0 && httpPos+httpLength <= len(result) {
					// Adjust OPRF base64 to match the location length
					adjustedOPRF := oprfBase64
					if len(oprfBase64) > httpLength {
						adjustedOPRF = oprfBase64[:httpLength]
					} else if len(oprfBase64) < httpLength {
						// Repeat the base64 string to match target length
						repeated := strings.Repeat(oprfBase64, (httpLength/len(oprfBase64))+1)
						adjustedOPRF = repeated[:httpLength]
					}

					// Replace with OPRF output
					oprfBytes := []byte(adjustedOPRF)
					copy(result[httpPos:httpPos+httpLength], oprfBytes)

					fmt.Printf("[Verifier] Replaced hashed range at position %d (length %d) with OPRF output: %s\n",
						httpPos, httpLength, adjustedOPRF)
				}
			}
		}
	}

	return result
}

// replaceRandomGarbageWithAsterisks replaces random garbage in redacted plaintext with asterisks
func replaceRandomGarbageWithAsterisks(content []byte, ranges []shared.ResponseRedactionRange, oprfRanges map[int]int) []byte {
	result := make([]byte, len(content))
	copy(result, content)

	// Apply each redaction range to replace random garbage with asterisks
	for _, r := range ranges {
		rangeStart := r.Start
		rangeEnd := r.Start + r.Length

		// Check bounds
		if rangeStart < 0 || rangeEnd > len(content) {
			continue // Skip invalid ranges
		}

		// Replace random garbage with asterisks, but skip bytes that are in hashed ranges
		for i := rangeStart; i < rangeEnd; i++ {
			// Check if this specific byte position is within any OPRF range
			inOPRFRange := false
			for oprfStart, oprfLength := range oprfRanges {
				oprfEnd := oprfStart + oprfLength
				if i >= oprfStart && i < oprfEnd {
					inOPRFRange = true
					break
				}
			}

			// Only replace with asterisk if not in an OPRF range
			if !inOPRFRange {
				result[i] = '*'
			}
		}
	}

	return result
}

// // ValidateBundleWithOPRFRanges performs verification with optional OPRF ranges for replacement.
// // oprfRanges is a map from range start position to length.
// func ValidateBundleWithOPRFRanges(bundleData []byte, oprfRanges map[int]int) error {
// 	fmt.Printf("[Verifier] Validating verification bundle (%d bytes)\n", len(bundleData))
//
// 	var bundlePB teeproto.VerificationBundle
// 	if err := proto.Unmarshal(bundleData, &bundlePB); err != nil {
// 		return fmt.Errorf("failed to decode bundle protobuf: %v", err)
// 	}
//
// 	// --- SECURITY: Validate required data is present ---
// 	if bundlePB.TeekSigned == nil {
// 		return fmt.Errorf("SECURITY ERROR: missing TEE_K signed message - verification bundle incomplete")
// 	}
// 	if bundlePB.TeetSigned == nil {
// 		return fmt.Errorf("SECURITY ERROR: missing TEE_T signed message - verification bundle incomplete")
// 	}
//
// 	// --- Signed message verification ---
// 	if err := verifySignedMessage(bundlePB.TeekSigned, "TEE_K"); err != nil {
// 		return fmt.Errorf("TEE_K signed message invalid: %v", err)
// 	}
// 	if err := verifySignedMessage(bundlePB.TeetSigned, "TEE_T"); err != nil {
// 		return fmt.Errorf("TEE_T signed message invalid: %v", err)
// 	}
//
// 	fmt.Println("[Verifier] Comprehensive signature verification successful")
//
// 	// --- Timestamp validation ---
// 	if err := validateTimestamps(bundlePB.TeekSigned, bundlePB.TeetSigned); err != nil {
// 		return fmt.Errorf("timestamp validation failed: %v", err)
// 	}
//
// 	fmt.Println("[Verifier] Timestamp validation successful")
//
// 	// Work directly with protobuf format - no legacy conversion needed!
//
// 	if bundlePB.TeekSigned == nil {
// 		// SECURITY: Missing proof components compromise verification integrity
// 		return fmt.Errorf("critical security failure: TEE_K transcript missing - cannot perform proof stream application")
// 	}
//
// 	// --- Extract payloads ---
// 	var kPayload teeproto.KOutputPayload
// 	if err := proto.Unmarshal(bundlePB.TeekSigned.GetBody(), &kPayload); err != nil {
// 		return fmt.Errorf("failed to unmarshal TEE_K payload: %v", err)
// 	}
//
// 	var tPayload teeproto.TOutputPayload
// 	if err := proto.Unmarshal(bundlePB.TeetSigned.GetBody(), &tPayload); err != nil {
// 		return fmt.Errorf("failed to unmarshal TEE_T payload: %v", err)
// 	}
//
// 	// --- SIMPLIFIED RESPONSE RECONSTRUCTION ---
// 	consolidatedKeystream := kPayload.GetConsolidatedResponseKeystream()
// 	consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()
//
// 	if len(consolidatedKeystream) != len(consolidatedCiphertext) {
// 		return fmt.Errorf("response keystream/ciphertext length mismatch: %d vs %d",
// 			len(consolidatedKeystream), len(consolidatedCiphertext))
// 	}
//
// 	// Direct XOR - NO PACKET PARSING FOR RESPONSE!
// 	reconstructedResponse := make([]byte, len(consolidatedCiphertext))
// 	for i := range consolidatedCiphertext {
// 		reconstructedResponse[i] = consolidatedCiphertext[i] ^ consolidatedKeystream[i]
// 	}
//
// 	fmt.Printf("[Verifier] Reconstructed %d response bytes via direct XOR\n", len(reconstructedResponse))
//
// 	// --- Apply hashed range replacements first (before asterisks) ---
//
// 	if bundlePB.OprfVerifications != nil && len(bundlePB.OprfVerifications) > 0 && oprfRanges != nil {
// 		reconstructedResponse = replaceOPRFRanges(reconstructedResponse, bundlePB.OprfVerifications, oprfRanges)
// 		fmt.Printf("[Verifier] Applied %d OPRF range replacements\n", len(bundlePB.OprfVerifications))
// 	}
//
// 	// --- Apply response redactions (UNCHANGED) ---
// 	if len(kPayload.GetResponseRedactionRanges()) > 0 {
// 		var respRanges []shared.ResponseRedactionRange
// 		for i, rr := range kPayload.GetResponseRedactionRanges() {
// 			respRanges = append(respRanges, shared.ResponseRedactionRange{
// 				Start:  int(rr.GetStart()),
// 				Length: int(rr.GetLength()),
// 			})
// 			fmt.Printf("[Verifier] 📋 Range from TEE_K [%d]: start=%d, length=%d, end=%d\n",
// 				i, int(rr.GetStart()), int(rr.GetLength()), int(rr.GetStart())+int(rr.GetLength())-1)
// 		}
// 		consolidatedRanges := shared.ConsolidateResponseRedactionRanges(respRanges)
// 		fmt.Printf("[Verifier] 🔧 Consolidated %d ranges into %d ranges\n", len(respRanges), len(consolidatedRanges))
//
// 		for i, r := range consolidatedRanges {
// 			fmt.Printf("[Verifier] 📋 Consolidated range [%d]: start=%d, length=%d, end=%d\n",
// 				i, r.Start, r.Length, r.Start+r.Length-1)
// 		}
//
// 		fmt.Printf("[Verifier] 🔧 Applying asterisk replacement to %d byte response\n", len(reconstructedResponse))
// 		reconstructedResponse = replaceRandomGarbageWithAsterisks(reconstructedResponse, consolidatedRanges, oprfRanges)
// 		fmt.Printf("[Verifier] ✅ Applied %d response redaction ranges\n", len(consolidatedRanges))
// 	} else {
// 		fmt.Printf("[Verifier] ❌ No redaction ranges found in TEE_K payload\n")
// 	}
//
// 	// --- Display response ---
// 	fmt.Println("[Verifier] Reconstructed response:\n---\n" + collapseAsterisks(string(reconstructedResponse)) + "\n---")
//
// 	// --- Request reconstruction using TEE_T-signed proof streams ---
// 	if len(tPayload.GetRequestProofStreams()) > 0 {
// 		fmt.Printf("[Verifier] Found %d R_SP proof streams signed by TEE_T ✅\n", len(tPayload.GetRequestProofStreams()))
//
// 		redactedRequest := kPayload.GetRedactedRequest()
// 		redactionRanges := kPayload.GetRequestRedactionRanges()
//
// 		if len(redactedRequest) > 0 {
// 			// Create a copy of the redacted request to apply proof streams
// 			revealedRequest := make([]byte, len(redactedRequest))
// 			copy(revealedRequest, redactedRequest)
//
// 			// Apply proof streams ONLY to sensitive_proof ranges
// 			proofStreamIndex := 0
//
// 			for _, r := range redactionRanges {
// 				if r.GetType() == "sensitive_proof" {
// 					if proofStreamIndex >= len(tPayload.GetRequestProofStreams()) {
// 						return fmt.Errorf("insufficient TEE_T-signed proof streams for sensitive_proof range")
// 					}
//
// 					proofStream := tPayload.GetRequestProofStreams()[proofStreamIndex]
// 					start := int(r.GetStart())
// 					length := int(r.GetLength())
//
// 					if start+length > len(revealedRequest) {
// 						return fmt.Errorf("proof range [%d:%d] exceeds request length %d", start, start+length, len(revealedRequest))
// 					}
//
// 					if length != len(proofStream) {
// 						return fmt.Errorf("proof stream length mismatch: range needs %d bytes, stream has %d", length, len(proofStream))
// 					}
//
// 					// Apply XOR to reveal original sensitive_proof data
// 					for i := 0; i < length; i++ {
// 						revealedRequest[start+i] ^= proofStream[i]
// 					}
//
// 					fmt.Printf("[Verifier] ✅ Revealed sensitive_proof range [%d:%d] using TEE_T-signed stream\n", start, start+length)
// 					proofStreamIndex++
// 				}
// 			}
//
// 			fmt.Printf("[Verifier] Reconstructed request with TEE_T-signed proof streams:\n---\n%s\n---\n", string(revealedRequest))
// 		}
// 	} else {
// 		fmt.Println("[Verifier] No R_SP proof streams - only R_S verification available (sensitive data remains redacted)")
// 	}
//
// 	// --- Display certificate info ---
// 	// SECURITY: Extract certificate info from signed TEE_K payload, not unsigned bundle field
// 	certInfo := kPayload.GetCertificateInfo()
// 	if certInfo != nil {
// 		fmt.Printf("[Verifier] Certificate: %s (issued by %s)\n",
// 			certInfo.GetCommonName(), certInfo.GetIssuerCommonName())
// 		fmt.Printf("[Verifier] Valid: %s to %s\n",
// 			time.Unix(int64(certInfo.GetNotBeforeUnix()), 0).Format(time.RFC3339),
// 			time.Unix(int64(certInfo.GetNotAfterUnix()), 0).Format(time.RFC3339))
// 	}
//
// 	// --- Verify redaction ranges authenticity ---
// 	if len(kPayload.GetRequestRedactionRanges()) > 0 {
// 		fmt.Printf("[Verifier] Redaction ranges verified ✅ (TEE_K signed %d request and %d response ranges)\n", len(kPayload.GetRequestRedactionRanges()), len(kPayload.GetResponseRedactionRanges()))
// 	}
//
// 	fmt.Println("[Verifier] Verification complete – success 🥳")
// 	return nil
// }

// verifyAttestationReportETH verifies a protobuf AttestationReport and extracts the ETH address
func verifyAttestationReportETH(report *teeproto.AttestationReport, expectedSource string) (shared.Address, error) {
	switch report.Type {
	case "gcp":
		// For GCP, we need to extract the ETH address from the attestation token
		// This is a placeholder - GCP attestation ETH address extraction needs specific implementation
		return shared.Address{}, fmt.Errorf("GCP ETH address extraction not yet implemented for protobuf format")

	default:
		return shared.Address{}, fmt.Errorf("unsupported attestation type: %s", report.Type)
	}
}

// verifySignedMessage verifies a protobuf SignedMessage
func verifySignedMessage(signedMsg *teeproto.SignedMessage, source string) error {
	if signedMsg == nil {
		return fmt.Errorf("SECURITY ERROR: %s signed message is nil", source)
	}

	fmt.Printf("[Verifier] Verifying %s signed message (body type: %v)\n", source, signedMsg.GetBodyType())

	// SECURITY: Strict validation of required fields
	if len(signedMsg.GetSignature()) == 0 {
		return fmt.Errorf("SECURITY ERROR: %s missing signature - cannot verify authenticity", source)
	}
	if len(signedMsg.GetBody()) == 0 {
		return fmt.Errorf("SECURITY ERROR: %s missing body - no data to verify", source)
	}

	// Validate body type
	expectedBodyType := teeproto.BodyType_BODY_TYPE_K_OUTPUT
	if source == "TEE_T" {
		expectedBodyType = teeproto.BodyType_BODY_TYPE_T_OUTPUT
	}
	if signedMsg.GetBodyType() != expectedBodyType {
		return fmt.Errorf("SECURITY ERROR: %s wrong body type, expected %v got %v", source, expectedBodyType, signedMsg.GetBodyType())
	}

	// Extract ETH address - either from AttestationReport (enclave mode) or PublicKey field (standalone mode)
	var ethAddress shared.Address
	var err error

	if signedMsg.GetAttestationReport() != nil {
		// Enclave mode: extract ETH address from attestation report
		attestationReport := signedMsg.GetAttestationReport()
		fmt.Printf("[Verifier] Verifying %s attestation report (type: %s)\n", source, attestationReport.GetType())

		// Verify attestation and extract ETH address
		ethAddress, err = verifyAttestationReportETH(attestationReport, source)
		if err != nil {
			return fmt.Errorf("SECURITY ERROR: %s attestation verification failed: %v", source, err)
		}
		fmt.Printf("[Verifier] %s attestation verification SUCCESS, extracted ETH address: %s\n", source, ethAddress.Hex())
	} else if len(signedMsg.GetEthAddress()) > 0 {
		// Standalone mode: use ETH address
		ethAddress = shared.HexToAddress(string(signedMsg.GetEthAddress()))
		fmt.Printf("[Verifier] Using %s standalone mode ETH address: %s\n", source, ethAddress.Hex())
	} else {
		return fmt.Errorf("SECURITY ERROR: %s missing both attestation report and public key", source)
	}

	if err := shared.VerifySignatureWithETH(signedMsg.GetBody(), signedMsg.GetSignature(), ethAddress); err != nil {
		return fmt.Errorf("SECURITY ERROR: %s cryptographic signature verification FAILED: %v", source, err)
	}

	fmt.Printf("[Verifier] ✅ %s cryptographic signature verification PASSED (verified %d bytes exactly as signed)\n",
		source, len(signedMsg.GetBody()))

	// Only after signature verification succeeds, validate that the body can be parsed
	switch signedMsg.GetBodyType() {
	case teeproto.BodyType_BODY_TYPE_K_OUTPUT:
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(signedMsg.GetBody(), &kPayload); err != nil {
			return fmt.Errorf("SECURITY ERROR: %s body parsing failed after signature verification: %v", source, err)
		}
		fmt.Printf("[Verifier] %s body content validated: redacted_request=%d bytes, ranges=%d, consolidated_keystream=%d bytes\n",
			source, len(kPayload.GetRedactedRequest()), len(kPayload.GetRequestRedactionRanges()),
			len(kPayload.GetConsolidatedResponseKeystream()))
	case teeproto.BodyType_BODY_TYPE_T_OUTPUT:
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(signedMsg.GetBody(), &tPayload); err != nil {
			return fmt.Errorf("SECURITY ERROR: %s body parsing failed after signature verification: %v", source, err)
		}
		fmt.Printf("[Verifier] %s body content validated: consolidated_ciphertext=%d bytes\n", source, len(tPayload.GetConsolidatedResponseCiphertext()))
	}

	return nil
}

// validateTimestamps checks that both TEE timestamps are within acceptable ranges
// Requirements:
// 1. TEE_K and TEE_T timestamps must be within 5 seconds of each other
// 2. Neither timestamp can be older than 10 minutes in the past
// NOTE: Timestamps are now extracted from the SIGNED payloads, not the wrapper
func validateTimestamps(teekSigned, teetSigned *teeproto.SignedMessage) error {
	// Extract TEE_K timestamp from signed KOutputPayload
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(teekSigned.GetBody(), &kPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_K payload for timestamp: %v", err)
	}
	teekTimestamp := kPayload.GetTimestampMs()

	// Extract TEE_T timestamp from signed TOutputPayload
	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(teetSigned.GetBody(), &tPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_T payload for timestamp: %v", err)
	}
	teetTimestamp := tPayload.GetTimestampMs()

	now := time.Now().UnixMilli()

	// Check if timestamps are present
	if teekTimestamp == 0 {
		return fmt.Errorf("TEE_K timestamp missing or invalid in signed payload")
	}
	if teetTimestamp == 0 {
		return fmt.Errorf("TEE_T timestamp missing or invalid in signed payload")
	}

	// Check that neither timestamp is older than 10 minutes
	maxAgeMs := int64(10 * 60 * 1000) // 10 minutes in milliseconds
	if now-int64(teekTimestamp) > maxAgeMs {
		return fmt.Errorf("TEE_K timestamp too old: %d minutes ago", (now-int64(teekTimestamp))/60000)
	}
	if now-int64(teetTimestamp) > maxAgeMs {
		return fmt.Errorf("TEE_T timestamp too old: %d minutes ago", (now-int64(teetTimestamp))/60000)
	}

	// Check that TEE_K and TEE_T timestamps are within 5 seconds of each other
	timeDiffMs := int64(teekTimestamp) - int64(teetTimestamp)
	if timeDiffMs < 0 {
		timeDiffMs = -timeDiffMs
	}
	maxDiffMs := int64(5 * 1000) // 5 seconds in milliseconds
	if timeDiffMs > maxDiffMs {
		return fmt.Errorf("TEE_K and TEE_T timestamps differ by %d seconds (max allowed: 5 seconds)", timeDiffMs/1000)
	}

	fmt.Printf("[Verifier] Timestamp validation passed (SIGNED timestamps):\n")
	fmt.Printf("  TEE_K: %s\n", time.UnixMilli(int64(teekTimestamp)).UTC().Format("2006-01-02 15:04:05.000 UTC"))
	fmt.Printf("  TEE_T: %s\n", time.UnixMilli(int64(teetTimestamp)).UTC().Format("2006-01-02 15:04:05.000 UTC"))
	fmt.Printf("  Time difference: %d ms\n", timeDiffMs)

	return nil
}
