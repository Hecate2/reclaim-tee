package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// addToTranscript safely adds data with explicit type to the session's transcript.
func (t *TEEK) addToTranscript(sessionID string, data []byte, dataType string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session for transcript")
		return err
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Copy buffer to avoid unexpected mutation
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	session.TranscriptData = append(session.TranscriptData, dataCopy)
	session.TranscriptDataTypes = append(session.TranscriptDataTypes, dataType)

	t.logger.WithSession(sessionID).Debug("Added data to transcript",
		zap.Int("bytes", len(data)),
		zap.String("type", dataType),
		zap.Int("total_data", len(session.TranscriptData)))

	return nil
}

func (t *TEEK) generateComprehensiveSignatureForIdentity(identity *teekSessionIdentity) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	teekState, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return err
	}
	return t.generateComprehensiveSignatureForSession(identity.session, teekState, func(env *teeproto.Envelope) error {
		if err := identity.ensureCurrent(); err != nil {
			return err
		}
		if t.finalSignatureWrite != nil {
			return t.finalSignatureWrite(identity.session, env)
		}
		return t.routeToClientForSession(identity.session, env)
	})
}

func (t *TEEK) generateComprehensiveSignatureForSession(session *shared.Session, teekState *TEEKSessionState, route func(*teeproto.Envelope) error) error {
	sessionID := session.ID
	t.logger.WithSession(sessionID).Debug("Generating comprehensive signature")

	// Snapshot the signing keypair together with its attestation. Both rotate
	// on every refresh, so they must be read as one consistent epoch — the
	// bundle is signed by keyPair and carries attestationReport, which binds
	// keyPair's ETH address.
	keyPair, attestationReport, err := t.signingEpoch(sessionID)
	if err != nil {
		return fmt.Errorf("get signing epoch: %v", err)
	}
	if keyPair == nil {
		return fmt.Errorf("no signing key pair available")
	}

	// Get transcript data
	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Get redacted streams
	session.StreamsMutex.Lock()
	defer session.StreamsMutex.Unlock()

	// SIMPLIFIED: Only extract request metadata, no TLS packet processing
	var requestMetadata *shared.RequestMetadata

	for i, data := range session.TranscriptData {
		dataType := ""
		if i < len(session.TranscriptDataTypes) {
			dataType = session.TranscriptDataTypes[i]
		}

		switch dataType {
		case shared.TranscriptDataTypeHTTPRequestRedacted:
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			requestMetadata.RedactedRequest = data
		case "redaction_ranges":
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			// Unmarshal the redaction ranges from protobuf
			ranges, err := shared.UnmarshalRequestRedactionRangesProtobuf(data)
			if err != nil {
				t.logger.WithSession(sessionID).Error("Failed to unmarshal redaction ranges from transcript", zap.Error(err))
			} else {
				requestMetadata.RedactionRanges = ranges
				t.logger.WithSession(sessionID).Debug("Loaded redaction ranges from transcript", zap.Int("ranges", len(ranges)))
			}
			// TLS packet data not included in transcript - using structured data instead
		}
	}

	// Get ETH address for this key pair
	ethAddress := keyPair.GetEthAddress()

	timestampMs := time.Now().UnixMilli()
	signedAttestationType := ""
	if t.ratls != nil {
		signedAttestationType = attestationReportType()
	}
	kPayload := &teeproto.KOutputPayload{
		SessionId:       sessionID,           // Bind to session for cross-TEE verification
		TimestampMs:     uint64(timestampMs), // Include signed timestamp
		AttestationType: signedAttestationType,
	}
	if requestMetadata != nil {
		kPayload.RedactedRequest = requestMetadata.RedactedRequest
		for _, r := range requestMetadata.RedactionRanges {
			kPayload.RequestRedactionRanges = append(kPayload.RequestRedactionRanges, &teeproto.RequestRedactionRange{Start: int32(r.Start), Length: int32(r.Length), Type: r.Type})
		}
	}
	// Use consolidated keystream from session for SignedMessage
	kPayload.ConsolidatedResponseKeystream = session.ConsolidatedResponseKeystream

	// Include certificate info in signed payload
	kPayload.CertificateInfo = session.CertificateInfo
	if session.ResponseState != nil && len(session.ResponseState.ResponseRedactionRanges) > 0 {
		for _, rr := range session.ResponseState.ResponseRedactionRanges {
			kPayload.ResponseRedactionRanges = append(kPayload.ResponseRedactionRanges, &teeproto.ResponseRedactionRange{Start: int32(rr.Start), Length: int32(rr.Length)})
		}
		t.logger.WithSession(sessionID).Debug("Included response redaction ranges in signed payload", zap.Int("ranges", len(session.ResponseState.ResponseRedactionRanges)))
	}

	// Include OPRF outputs in signed payload
	if teekState != nil {
		oprfOutputs := t.buildOPRFOutputsForSigning(teekState)
		if len(oprfOutputs) > 0 {
			kPayload.OprfOutputs = oprfOutputs
			t.logger.WithSession(sessionID).Debug("Included OPRF outputs in signed payload", zap.Int("count", len(oprfOutputs)))
		}
	}

	// Create protobuf body and sign it directly
	marshalOutput := t.finalSignatureMarshal
	if marshalOutput == nil {
		marshalOutput = func(payload *teeproto.KOutputPayload) ([]byte, error) {
			return proto.Marshal(payload)
		}
	}
	body, err := marshalOutput(kPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal KOutputPayload: %v", err)
	}

	// Sign the exact protobuf body bytes
	signOutput := t.finalSignatureSign
	if signOutput == nil {
		signOutput = func(pair *shared.SigningKeyPair, data []byte) ([]byte, error) {
			return pair.SignData(data)
		}
	}
	comprehensiveSignature, err := signOutput(keyPair, body)
	if err != nil {
		return fmt.Errorf("failed to generate comprehensive signature: %v", err)
	}

	t.logger.WithSession(sessionID).Debug("Generated comprehensive signature over protobuf body",
		zap.Int("body_bytes", len(body)),
		zap.Int("signature_bytes", len(comprehensiveSignature)))

	// Attestation report (router mode) was snapshotted with keyPair above so the
	// two stay in the same epoch; standalone uses the ETH address instead.
	var publicKeyForStandalone []byte
	if t.ratls != nil {
		if attestationReport == nil {
			return fmt.Errorf("no attestation available for SignedMessage")
		}
		t.logger.WithSession(sessionID).Debug("Including attestation report in SignedMessage")
	} else {
		publicKeyForStandalone = []byte(ethAddress.String())
		t.logger.WithSession(sessionID).Debug("Including ETH address in SignedMessage (standalone mode)")
	}

	// Collect TLS packet metadata for client-side decryption
	var responsePackets []*teeproto.TLSPacketInfo
	var serverAppKey []byte
	var cipherSuite uint32

	// Get TLS state for packet metadata
	tlsState := teekState
	if tlsState != nil && tlsState.TLSClient != nil {
		tlsClient := tlsState.TLSClient
		cipherSuite = uint32(tlsClient.GetCipherSuite())

		// Get server application key based on cipher suite
		if minitls.IsTLS13CipherSuite(uint16(cipherSuite)) {
			// TLS 1.3: Get from key schedule
			if keySchedule := tlsClient.GetKeySchedule(); keySchedule != nil {
				serverAppKey = keySchedule.GetServerApplicationKey()
			}
		} else {
			// TLS 1.2: Get from TLS 1.2 AEAD
			if tls12AEAD := tlsClient.GetTLS12AEAD(); tls12AEAD != nil {
				serverAppKey = tls12AEAD.GetReadKey()
			}
		}

		// Build packet metadata from response state
		if session.ResponseState != nil {
			session.ResponseState.ResponsesMutex.Lock()

			// Sort sequence numbers for deterministic ordering
			var seqNums []uint64
			for seqNum := range session.ResponseState.ResponseLengthBySeq {
				seqNums = append(seqNums, seqNum)
			}
			slices.Sort(seqNums)

			// Track position in consolidated keystream
			currentPosition := uint32(0)

			for _, seqNum := range seqNums {
				length := session.ResponseState.ResponseLengthBySeq[seqNum]

				if minitls.IsTLS13CipherSuite(uint16(cipherSuite)) {
					length-- // !!! Remove content type byte
				}

				// Get the stored nonce for this sequence number
				nonce := session.ResponseState.NonceBySeq[seqNum]

				// t.logger.WithSession(sessionID).Info("Retrieved nonce for transcript",
				//	zap.Uint64("seq_num", seqNum),
				//	zap.Uint32("position", currentPosition),
				//	zap.Int("length", length),
				//	zap.Binary("nonce", nonce),
				//	zap.Bool("nonce_exists", nonce != nil))

				if nonce != nil {
					packetInfo := &teeproto.TLSPacketInfo{
						SeqNum:   seqNum,
						Position: currentPosition,
						Length:   uint32(length),
						Nonce:    nonce,
					}
					responsePackets = append(responsePackets, packetInfo)
				} else {
					t.logger.WithSession(sessionID).Warn("No nonce found for sequence", zap.Uint64("seq_num", seqNum))
				}

				// Update position for next packet
				currentPosition += uint32(length)
			}

			session.ResponseState.ResponsesMutex.Unlock()

			t.logger.WithSession(sessionID).Debug("Prepared TLS packet metadata",
				zap.Int("packet_count", len(responsePackets)),
				zap.Uint32("cipher_suite", cipherSuite))
		}
	} else {
		t.logger.WithSession(sessionID).Warn("Could not retrieve TLS state for packet metadata")
	}

	// Send the signed message to client (timestamp is now inside signed body)
	signedMsg := &teeproto.SignedMessage{
		BodyType:          teeproto.BodyType_BODY_TYPE_K_OUTPUT,
		Body:              body,
		EthAddress:        publicKeyForStandalone,
		Signature:         comprehensiveSignature,
		AttestationReport: attestationReport,
		// Additional metadata (not signed)
		ResponsePackets: responsePackets,
		ServerAppKey:    serverAppKey,
		CipherSuite:     cipherSuite,
	}

	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: timestampMs,
		Payload: &teeproto.Envelope_SignedMessage{SignedMessage: signedMsg},
	}
	if err := route(env); err != nil {
		return fmt.Errorf("failed to send signed message to client: %v", err)
	}

	t.logger.WithSession(sessionID).Debug("Sent SignedMessage (KOutput) to client")

	return nil
}
