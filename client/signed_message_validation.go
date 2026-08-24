package client

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func (c *Client) validateTEEKSignedMessage(envelopeSession string, signed *teeproto.SignedMessage) (*teeproto.KOutputPayload, error) {
	if err := c.validateSignedMessageEnvelope("tee_k", teeproto.BodyType_BODY_TYPE_K_OUTPUT, envelopeSession, signed); err != nil {
		return nil, err
	}
	var body teeproto.KOutputPayload
	if err := proto.Unmarshal(signed.GetBody(), &body); err != nil {
		return nil, fmt.Errorf("unmarshal TEE_K signed body: %w", err)
	}
	if err := c.validateSignedSession(envelopeSession, body.GetSessionId()); err != nil {
		return nil, err
	}
	if err := c.validateSignedMessageSignature("tee_k", signed, body.GetAttestationType()); err != nil {
		return nil, err
	}
	if err := c.validateTEEKTLS12CBCContract(&body, signed); err != nil {
		return nil, err
	}
	return &body, nil
}

func (c *Client) acceptTEEKSignedMessage(envelopeSession string, signed *teeproto.SignedMessage) error {
	body, err := c.validateTEEKSignedMessage(envelopeSession, signed)
	if err != nil {
		return err
	}
	c.protocolStateMutex.Lock()
	defer c.protocolStateMutex.Unlock()
	if c.teekSignedMessage != nil {
		return fmt.Errorf("duplicate signed message")
	}
	c.teekSignedMessage = proto.Clone(signed).(*teeproto.SignedMessage)
	c.responseKeystream = append([]byte(nil), body.GetConsolidatedResponseKeystream()...)
	c.teeKSignatureValid = true
	c.teeKTranscriptReceived = true
	return nil
}

func (c *Client) validateTEETSignedMessage(envelopeSession string, signed *teeproto.SignedMessage) (*teeproto.TOutputPayload, error) {
	if err := c.validateSignedMessageEnvelope("tee_t", teeproto.BodyType_BODY_TYPE_T_OUTPUT, envelopeSession, signed); err != nil {
		return nil, err
	}
	var body teeproto.TOutputPayload
	if err := proto.Unmarshal(signed.GetBody(), &body); err != nil {
		return nil, fmt.Errorf("unmarshal TEE_T signed body: %w", err)
	}
	if err := c.validateSignedSession(envelopeSession, body.GetSessionId()); err != nil {
		return nil, err
	}
	if err := c.validateSignedMessageSignature("tee_t", signed, body.GetAttestationType()); err != nil {
		return nil, err
	}
	if err := c.validateTEETTLS12CBCContract(&body, signed); err != nil {
		return nil, err
	}
	return &body, nil
}

func (c *Client) validateTEEKTLS12CBCContract(body *teeproto.KOutputPayload, signed *teeproto.SignedMessage) error {
	isCBC := minitls.IsTLS12CBCCipherSuite(c.cipherSuite)
	if !isCBC {
		if body.GetTls12Cbc() != nil {
			return fmt.Errorf("TEE_K CBC output present for non-CBC session")
		}
		return nil
	}
	cbc := body.GetTls12Cbc()
	if cbc == nil {
		return fmt.Errorf("TEE_K signed body is missing TLS 1.2 CBC output")
	}
	if len(body.GetRedactedRequest()) != 0 || len(body.GetRequestRedactionRanges()) != 0 ||
		len(body.GetConsolidatedResponseKeystream()) != 0 || len(body.GetResponseRedactionRanges()) != 0 {
		return fmt.Errorf("TEE_K TLS 1.2 CBC output mixes legacy AEAD fields")
	}
	if len(signed.GetResponsePackets()) != 0 || len(signed.GetServerAppKey()) != 0 || signed.GetCipherSuite() != 0 {
		return fmt.Errorf("TEE_K TLS 1.2 CBC output exposes legacy unsigned TLS metadata")
	}

	c.cbcMutex.Lock()
	binding := c.cbcBinding
	requestDigest := append([]byte(nil), c.cbcRequestDigest...)
	c.cbcMutex.Unlock()
	if binding == nil || !proto.Equal(binding, cbc.GetBinding()) {
		return fmt.Errorf("TEE_K TLS 1.2 CBC session binding mismatch")
	}
	if len(requestDigest) != 32 || !bytes.Equal(requestDigest, cbc.GetRequestRecordsSha256()) {
		return fmt.Errorf("TEE_K TLS 1.2 CBC request record digest mismatch")
	}
	signedRanges := cbc.GetRequestRedactionRanges()
	if len(signedRanges) != len(c.requestRedactionRanges) {
		return fmt.Errorf("TEE_K TLS 1.2 CBC request redaction range count mismatch")
	}
	for i, item := range c.requestRedactionRanges {
		if signedRanges[i] == nil || signedRanges[i].GetStart() != int32(item.Start) ||
			signedRanges[i].GetLength() != int32(item.Length) || signedRanges[i].GetType() != item.Type {
			return fmt.Errorf("TEE_K TLS 1.2 CBC request redaction range %d mismatch", i)
		}
	}
	redacted := cbc.GetAuthenticatedRedactedRequest()
	if len(redacted) != len(c.requestData) {
		return fmt.Errorf("TEE_K authenticated redacted request length is %d, want %d", len(redacted), len(c.requestData))
	}
	mask := make([]bool, len(c.requestData))
	for i, item := range c.requestRedactionRanges {
		if item.Start < 0 || item.Length <= 0 || item.Start > len(mask) || item.Length > len(mask)-item.Start {
			return fmt.Errorf("local request redaction range %d is invalid", i)
		}
		switch item.Type {
		case shared.RedactionTypeSensitive:
			for j := item.Start; j < item.Start+item.Length; j++ {
				mask[j] = true
			}
		case shared.RedactionTypeSensitiveProof:
		default:
			return fmt.Errorf("local request redaction range %d has invalid type", i)
		}
	}
	for i := range redacted {
		if !mask[i] && redacted[i] != c.requestData[i] {
			return fmt.Errorf("TEE_K authenticated redacted request differs outside sensitive ranges")
		}
	}
	return nil
}

func (c *Client) validateTEETTLS12CBCContract(body *teeproto.TOutputPayload, signed *teeproto.SignedMessage) error {
	isCBC := minitls.IsTLS12CBCCipherSuite(c.cipherSuite)
	if !isCBC {
		if body.GetTls12Cbc() != nil {
			return fmt.Errorf("TEE_T CBC output present for non-CBC session")
		}
		return nil
	}
	cbc := body.GetTls12Cbc()
	if cbc == nil {
		return fmt.Errorf("TEE_T signed body is missing TLS 1.2 CBC output")
	}
	if len(body.GetConsolidatedResponseCiphertext()) != 0 || len(body.GetRequestProofStreams()) != 0 {
		return fmt.Errorf("TEE_T TLS 1.2 CBC output mixes legacy AEAD fields")
	}
	if len(signed.GetResponsePackets()) != 0 || len(signed.GetServerAppKey()) != 0 || signed.GetCipherSuite() != 0 {
		return fmt.Errorf("TEE_T TLS 1.2 CBC output exposes legacy unsigned TLS metadata")
	}

	c.cbcMutex.Lock()
	binding := c.cbcBinding
	responseDigest := append([]byte(nil), c.cbcResponseDigest...)
	lengths := append([]uint32(nil), c.cbcResponsePlaintextLengths...)
	ranges := append([]shared.ResponseRedactionRange(nil), c.cbcResponseRedactionRanges...)
	c.cbcMutex.Unlock()
	if binding == nil || !proto.Equal(binding, cbc.GetBinding()) {
		return fmt.Errorf("TEE_T TLS 1.2 CBC session binding mismatch")
	}
	if len(responseDigest) != 32 || !bytes.Equal(responseDigest, cbc.GetResponseRecordsSha256()) {
		return fmt.Errorf("TEE_T TLS 1.2 CBC response record digest mismatch")
	}
	if !slices.Equal(lengths, cbc.GetPlaintextRecordLengths()) {
		return fmt.Errorf("TEE_T TLS 1.2 CBC plaintext record lengths mismatch")
	}
	signedRanges := cbc.GetResponseRedactionRanges()
	if len(signedRanges) != len(ranges) {
		return fmt.Errorf("TEE_T TLS 1.2 CBC response redaction range count mismatch")
	}
	for i, item := range ranges {
		if signedRanges[i] == nil || signedRanges[i].GetStart() != int32(item.Start) || signedRanges[i].GetLength() != int32(item.Length) {
			return fmt.Errorf("TEE_T TLS 1.2 CBC response redaction range %d mismatch", i)
		}
	}

	c.responseContentMutex.Lock()
	seqNums := make([]uint64, 0, len(c.parsedResponseBySeq))
	for seq := range c.parsedResponseBySeq {
		seqNums = append(seqNums, seq)
	}
	slices.Sort(seqNums)
	var authenticatedResponse []byte
	for _, seq := range seqNums {
		parsed := c.parsedResponseBySeq[seq]
		if parsed != nil && parsed.ContentType == minitls.RecordTypeApplicationData {
			authenticatedResponse = append(authenticatedResponse, parsed.ActualContent...)
		}
	}
	c.responseContentMutex.Unlock()
	redacted := cbc.GetAuthenticatedRedactedResponse()
	if len(redacted) != len(authenticatedResponse) {
		return fmt.Errorf("TEE_T authenticated redacted response length is %d, want %d", len(redacted), len(authenticatedResponse))
	}
	mask := make([]bool, len(redacted))
	for i, item := range ranges {
		if item.Start < 0 || item.Length <= 0 || item.Start > len(mask) || item.Length > len(mask)-item.Start {
			return fmt.Errorf("local response redaction range %d is invalid", i)
		}
		for j := item.Start; j < item.Start+item.Length; j++ {
			mask[j] = true
		}
	}
	for i := range redacted {
		if !mask[i] && redacted[i] != authenticatedResponse[i] {
			return fmt.Errorf("TEE_T authenticated redacted response differs outside redaction ranges")
		}
	}
	return nil
}

func (c *Client) acceptTEETSignedMessage(envelopeSession string, signed *teeproto.SignedMessage) error {
	body, err := c.validateTEETSignedMessage(envelopeSession, signed)
	if err != nil {
		return err
	}
	c.protocolStateMutex.Lock()
	defer c.protocolStateMutex.Unlock()
	if c.teetSignedMessage != nil {
		return fmt.Errorf("duplicate signed message")
	}
	c.teetSignedMessage = proto.Clone(signed).(*teeproto.SignedMessage)
	c.consolidatedResponseCiphertext = append([]byte(nil), body.GetConsolidatedResponseCiphertext()...)
	c.teeTSignatureValid = true
	c.teeTTranscriptReceived = true
	return nil
}

func (c *Client) validateSignedMessageEnvelope(role string, expectedType teeproto.BodyType, envelopeSession string, signed *teeproto.SignedMessage) error {
	if signed == nil {
		return fmt.Errorf("%s signed message is nil", role)
	}
	if signed.GetBodyType() != expectedType {
		return fmt.Errorf("%s signed message has body type %s, expected %s", role, signed.GetBodyType(), expectedType)
	}
	if len(signed.GetBody()) == 0 {
		return fmt.Errorf("%s signed message body is empty", role)
	}

	if envelopeSession == "" {
		return fmt.Errorf("%s signed message envelope has empty session ID", role)
	}
	return nil
}

func (c *Client) validateSignedMessageSignature(role string, signed *teeproto.SignedMessage, signedAttestationType string) error {
	address, err := c.signedMessageAddress(role, signed, signedAttestationType)
	if err != nil {
		return err
	}
	if err := shared.VerifyEthSignature(signed.GetBody(), signed.GetSignature(), address); err != nil {
		return fmt.Errorf("%s signed message signature: %w", role, err)
	}
	return nil
}

func (c *Client) validateSignedSession(envelopeSession, bodySession string) error {
	c.sessionMutex.RLock()
	wantSession := c.sessionID
	c.sessionMutex.RUnlock()
	if wantSession == "" {
		return fmt.Errorf("signed message received before session establishment")
	}
	if envelopeSession != wantSession {
		return fmt.Errorf("signed message envelope session mismatch: got %q, want %q", envelopeSession, wantSession)
	}
	if bodySession != wantSession {
		return fmt.Errorf("signed message body session mismatch: got %q, want %q", bodySession, wantSession)
	}
	return nil
}

func (c *Client) signedMessageAddress(role string, signed *teeproto.SignedMessage, signedAttestationType string) (shared.Address, error) {
	report := signed.GetAttestationReport()
	if report == nil {
		if c.resolveClientMode() != ModeStandalone {
			return shared.Address{}, fmt.Errorf("%s signed message requires verified attestation outside standalone mode", role)
		}
		if signedAttestationType != "" && signedAttestationType != "standalone" {
			return shared.Address{}, fmt.Errorf("%s signed body claims attestation type %q without a report", role, signedAttestationType)
		}
		return standaloneSignedMessageAddress(role, signed.GetEthAddress())
	}
	if len(signed.GetEthAddress()) != 0 {
		return shared.Address{}, fmt.Errorf("%s signed message contains both attestation and standalone address", role)
	}
	if len(report.GetReport()) == 0 {
		return shared.Address{}, fmt.Errorf("%s signed message attestation is empty", role)
	}
	if signedAttestationType == "" {
		// Bundles created before the signed generation marker use the report's
		// outer type. This fallback can be removed after that migration closes.
		signedAttestationType = report.GetType()
	}

	switch signedAttestationType {
	case "gcp":
		if report.GetType() != "gcp" {
			return shared.Address{}, fmt.Errorf("%s signed body claims GCP but report type is %q", role, report.GetType())
		}
		if err := c.validateGCPAttestation(report.GetReport()); err != nil {
			return shared.Address{}, fmt.Errorf("validate %s GCP attestation: %w", role, err)
		}
		return verifiedSigningAddress(role, func(prefix string) (string, error) {
			if c.findGCPNonce != nil {
				return c.findGCPNonce(report.GetReport(), prefix)
			}
			return shared.FindNonceValue(report.GetReport(), prefix)
		})
	case "sev-snp":
		if report.GetType() != "sev-snp" {
			return shared.Address{}, fmt.Errorf("%s signed body claims SEV-SNP but report type is %q", role, report.GetType())
		}
		nonces, err := c.validateSEVAttestation(report.GetReport())
		if err != nil {
			return shared.Address{}, fmt.Errorf("validate %s SEV-SNP attestation: %w", role, err)
		}
		return verifiedSigningAddress(role, func(prefix string) (string, error) {
			return shared.FindNonceInList(nonces, prefix)
		})
	case "secure-boot":
		if report.GetType() != "sev-snp" && report.GetType() != "secure-boot" {
			return shared.Address{}, fmt.Errorf("%s signed body claims Secure Boot but report type is %q", role, report.GetType())
		}
		nonces, err := c.validateSecureBootAttestation(report.GetReport())
		if err != nil {
			return shared.Address{}, fmt.Errorf("validate %s Secure Boot attestation: %w", role, err)
		}
		return verifiedSigningAddress(role, func(prefix string) (string, error) {
			return shared.FindNonceInList(nonces, prefix)
		})
	default:
		return shared.Address{}, fmt.Errorf("unsupported %s signed attestation type %q", role, signedAttestationType)
	}

}

func (c *Client) validateGCPAttestation(raw []byte) error {
	if c.verifyGCPAttestation != nil {
		return c.verifyGCPAttestation(raw)
	}
	attestor, err := shared.NewGoogleAttestor()
	if err != nil {
		return fmt.Errorf("create GCP attestor: %w", err)
	}
	return attestor.Validate(raw, c.logger)
}

func (c *Client) validateSEVAttestation(raw []byte) ([]string, error) {
	if c.verifySEVAttestation != nil {
		return c.verifySEVAttestation(raw)
	}
	nonces, _, _, err := shared.VerifyCombinedSEVSNPNonceAttestation(raw)
	return nonces, err
}

func (c *Client) validateSecureBootAttestation(raw []byte) ([]string, error) {
	if c.verifySEVAttestation != nil {
		return c.verifySEVAttestation(raw)
	}
	nonces, _, _, err := shared.VerifyCompatibleSecureBootNonceAttestation(raw)
	return nonces, err
}

// verifiedSigningAddress is called only after the provider-specific report has
// been cryptographically verified. It owns the common role-prefix binding and
// canonical Ethereum address validation for both attestation providers.
func verifiedSigningAddress(role string, findNonce func(string) (string, error)) (shared.Address, error) {
	addressHex, err := findNonce(role + "_public_key:")
	if err != nil {
		return shared.Address{}, fmt.Errorf("find %s signing identity: %w", role, err)
	}
	if !shared.IsHexAddress(addressHex) {
		return shared.Address{}, fmt.Errorf("%s attestation contains invalid signing address", role)
	}
	return shared.HexToAddress(addressHex), nil
}

func standaloneSignedMessageAddress(role string, encoded []byte) (shared.Address, error) {
	// Current standalone TEEs send the canonical 0x-prefixed ASCII form. Keep
	// accepting the documented legacy 20-byte representation as well.
	if len(encoded) == len(shared.Address{}) {
		return shared.BytesToAddress(encoded), nil
	}
	if shared.IsHexAddress(string(encoded)) {
		return shared.HexToAddress(string(encoded)), nil
	}
	return shared.Address{}, fmt.Errorf("%s signed message has invalid standalone address", role)
}
