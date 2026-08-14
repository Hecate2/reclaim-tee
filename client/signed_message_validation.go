package client

import (
	"fmt"

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
	if err := c.validateSignedMessageSignature("tee_k", signed); err != nil {
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
	if err := c.validateSignedMessageSignature("tee_t", signed); err != nil {
		return nil, err
	}
	return &body, nil
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

func (c *Client) validateSignedMessageSignature(role string, signed *teeproto.SignedMessage) error {
	address, err := c.signedMessageAddress(role, signed)
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

func (c *Client) signedMessageAddress(role string, signed *teeproto.SignedMessage) (shared.Address, error) {
	report := signed.GetAttestationReport()
	if report == nil {
		if c.resolveClientMode() != ModeStandalone {
			return shared.Address{}, fmt.Errorf("%s signed message requires verified attestation outside standalone mode", role)
		}
		return standaloneSignedMessageAddress(role, signed.GetEthAddress())
	}
	if len(signed.GetEthAddress()) != 0 {
		return shared.Address{}, fmt.Errorf("%s signed message contains both attestation and standalone address", role)
	}
	if len(report.GetReport()) == 0 {
		return shared.Address{}, fmt.Errorf("%s signed message attestation is empty", role)
	}

	switch report.GetType() {
	case "gcp":
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
		nonces, err := c.validateSEVAttestation(report.GetReport())
		if err != nil {
			return shared.Address{}, fmt.Errorf("validate %s SEV-SNP attestation: %w", role, err)
		}
		return verifiedSigningAddress(role, func(prefix string) (string, error) {
			return shared.FindNonceInList(nonces, prefix)
		})
	default:
		return shared.Address{}, fmt.Errorf("unsupported %s attestation type %q", role, report.GetType())
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
