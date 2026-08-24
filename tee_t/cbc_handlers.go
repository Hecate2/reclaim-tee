package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func tls12CBCModeFromProto(mode teeproto.TLS12CBCRecordMode) (minitls.TLS12CBCRecordMode, error) {
	switch mode {
	case teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_MAC_THEN_ENCRYPT:
		return minitls.TLS12CBCRecordModeMACThenEncrypt, nil
	case teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_ENCRYPT_THEN_MAC:
		return minitls.TLS12CBCRecordModeEncryptThenMAC, nil
	default:
		return minitls.TLS12CBCRecordModeUnspecified, fmt.Errorf("unsupported TLS 1.2 CBC record mode: %d", mode)
	}
}

func (t *TEET) handleTLS12CBCReadState(identity *teetSessionIdentity, message *teeproto.TLS12CBCReadState) error {
	if identity == nil || identity.session == nil || message == nil {
		return fmt.Errorf("invalid TLS 1.2 CBC read-state message")
	}
	state, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return err
	}
	if !state.CBCReadStateReceived.CompareAndSwap(false, true) {
		err := fmt.Errorf("duplicate TLS 1.2 CBC read-state message")
		_ = t.sendTLS12CBCReadStateAck(identity.session, message.GetBinding(), err)
		return err
	}

	binding := message.GetBinding()
	if binding == nil || binding.GetContractVersion() != 1 || len(binding.GetSessionBinding()) != 32 {
		err := fmt.Errorf("invalid TLS 1.2 CBC session binding")
		_ = t.sendTLS12CBCReadStateAck(identity.session, binding, err)
		return err
	}
	cipherSuite := uint16(binding.GetCipherSuite())
	if !minitls.IsTLS12CBCCipherSuite(cipherSuite) {
		err := fmt.Errorf("unsupported TLS 1.2 CBC cipher suite 0x%04x", cipherSuite)
		_ = t.sendTLS12CBCReadStateAck(identity.session, binding, err)
		return err
	}
	mode, err := tls12CBCModeFromProto(binding.GetRecordMode())
	if err != nil {
		_ = t.sendTLS12CBCReadStateAck(identity.session, binding, err)
		return err
	}
	if message.GetReadSequence() != 1 {
		err := fmt.Errorf("TLS 1.2 CBC read sequence is %d, want 1", message.GetReadSequence())
		_ = t.sendTLS12CBCReadStateAck(identity.session, binding, err)
		return err
	}
	readContext, err := minitls.NewTLS12CBCReadContext(&minitls.TLS12CBCReadState{
		CipherSuite:  cipherSuite,
		Mode:         mode,
		ReadKey:      message.GetReadKey(),
		ReadMACKey:   message.GetReadMacKey(),
		ReadIV:       message.GetReadIv(),
		ReadSequence: message.GetReadSequence(),
	})
	if err != nil {
		_ = t.sendTLS12CBCReadStateAck(identity.session, binding, err)
		return err
	}
	state.cbcMu.Lock()
	state.CBCBinding = proto.Clone(binding).(*teeproto.TLS12CBCSessionBinding)
	state.CBCReadContext = readContext
	state.CipherSuite = cipherSuite
	state.cbcMu.Unlock()
	return t.sendTLS12CBCReadStateAck(identity.session, binding, nil)
}

func (t *TEET) sendTLS12CBCReadStateAck(session *shared.Session, binding *teeproto.TLS12CBCSessionBinding, stateErr error) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	ack := &teeproto.TLS12CBCReadStateAck{Success: stateErr == nil}
	if binding != nil {
		ack.SessionBinding = append([]byte(nil), binding.GetSessionBinding()...)
	}
	if stateErr != nil {
		ack.ErrorMessage = stateErr.Error()
	}
	return t.routeToTEEKForSession(session, &teeproto.Envelope{
		SessionId:   session.ID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Tls12CbcReadStateAck{
			Tls12CbcReadStateAck: ack,
		},
	})
}

type authenticatedTLS12CBCBatch struct {
	readContext      *minitls.TLS12CBCContext
	records          []*teeproto.TLSRecord
	fragments        []*teeproto.AuthenticatedCBCResponse_Fragment
	response         []byte
	plaintextLengths []uint32
	closeNotify      bool
}

func authenticateTLS12CBCResponseBatch(readContext *minitls.TLS12CBCContext, batch *teeproto.BatchedTLSRecords) (*authenticatedTLS12CBCBatch, error) {
	if readContext == nil || batch == nil {
		return nil, fmt.Errorf("TLS 1.2 CBC response state or batch is nil")
	}
	records := batch.GetRecords()
	if len(records) == 0 || len(records) > shared.MaxEncryptedFragments {
		return nil, fmt.Errorf("invalid TLS 1.2 CBC response record count: %d", len(records))
	}
	batchContext, err := minitls.NewTLS12CBCReadContext(readContext.ExportReadState())
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			batchContext.Destroy()
		}
	}()
	result := &authenticatedTLS12CBCBatch{
		readContext: batchContext,
		records:     make([]*teeproto.TLSRecord, 0, len(records)),
		fragments:   make([]*teeproto.AuthenticatedCBCResponse_Fragment, 0, len(records)),
	}
	for i, record := range records {
		if record == nil {
			return nil, fmt.Errorf("nil TLS 1.2 CBC response record at index %d", i)
		}
		if result.closeNotify {
			return nil, fmt.Errorf("TLS record follows close_notify")
		}
		seq := batchContext.GetReadSequence()
		header := record.GetHeader()
		contentType := byte(0)
		if len(header) != 0 {
			contentType = header[0]
		}
		plaintext, err := batchContext.DecryptRecord(header, record.GetPayload())
		if err != nil {
			return nil, fmt.Errorf("TLS 1.2 CBC response authentication failed: %w", err)
		}
		if contentType != minitls.RecordTypeApplicationData && contentType != minitls.RecordTypeAlert {
			return nil, fmt.Errorf("unsupported authenticated post-handshake TLS record type %d", contentType)
		}
		result.records = append(result.records, &teeproto.TLSRecord{
			Header: append([]byte(nil), header...), Payload: append([]byte(nil), record.GetPayload()...), SeqNum: seq,
		})
		result.fragments = append(result.fragments, &teeproto.AuthenticatedCBCResponse_Fragment{
			SeqNum: seq, RecordType: uint32(contentType), Plaintext: append([]byte(nil), plaintext...),
		})
		switch contentType {
		case minitls.RecordTypeApplicationData:
			result.response = append(result.response, plaintext...)
			result.plaintextLengths = append(result.plaintextLengths, uint32(len(plaintext)))
		case minitls.RecordTypeAlert:
			if len(plaintext) != 2 {
				return nil, fmt.Errorf("invalid TLS 1.2 alert length %d", len(plaintext))
			}
			if plaintext[1] == 0 {
				result.closeNotify = true
			}
		}
	}
	if len(result.response) == 0 {
		return nil, fmt.Errorf("TLS 1.2 CBC response contains no application data")
	}
	committed = true
	return result, nil
}

func (t *TEET) handleTLS12CBCResponseRecords(identity *teetSessionIdentity, batch *teeproto.BatchedTLSRecords) error {
	if identity == nil || identity.session == nil || batch == nil {
		return fmt.Errorf("invalid TLS 1.2 CBC response batch")
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	state, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return t.rejectTLS12CBCResponse(identity, err)
	}
	state.cbcMu.Lock()
	if state.CBCBinding == nil || state.CBCReadContext == nil {
		state.cbcMu.Unlock()
		return t.rejectTLS12CBCResponse(identity, fmt.Errorf("TLS 1.2 CBC read state is unavailable"))
	}
	if !state.ResponseBatchReceived.CompareAndSwap(false, true) {
		state.cbcMu.Unlock()
		return t.rejectTLS12CBCResponse(identity, fmt.Errorf("multiple TLS 1.2 CBC response batches received"))
	}
	// Decrypt into a temporary context and publish nothing until the entire
	// terminal batch authenticates. The sequence numbers in the client message
	// are diagnostic only; TEE_T assigns them from its trusted read state.
	authenticated, err := authenticateTLS12CBCResponseBatch(state.CBCReadContext, batch)
	if err != nil {
		state.cbcMu.Unlock()
		return t.rejectTLS12CBCResponse(identity, err)
	}
	digest, err := shared.TLS12CBCRecordDigest(shared.TLS12CBCResponseDigestDomain, authenticated.records)
	if err != nil {
		state.cbcMu.Unlock()
		return t.rejectTLS12CBCResponse(identity, err)
	}

	previousReadContext := state.CBCReadContext
	state.CBCReadContext = authenticated.readContext
	state.CBCAuthenticatedResponse = append([]byte(nil), authenticated.response...)
	state.ConsolidatedResponseCiphertext = append([]byte(nil), authenticated.response...)
	state.CBCResponseDigest = digest
	state.CBCPlaintextRecordLengths = authenticated.plaintextLengths
	state.cbcMu.Unlock()
	previousReadContext.Destroy()

	ready := &teeproto.Envelope{
		SessionId: identity.session.ID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_CiphertextReady{
			CiphertextReady: &teeproto.CiphertextReady{TotalLength: int32(len(authenticated.response))},
		},
	}
	if err := t.routeToTEEKForSession(identity.session, ready); err != nil {
		return t.rejectTLS12CBCResponse(identity, fmt.Errorf("notify TEE_K of authenticated CBC response: %w", err))
	}
	responseEnvelope := &teeproto.Envelope{
		SessionId: identity.session.ID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_AuthenticatedCbcResponse{
			AuthenticatedCbcResponse: &teeproto.AuthenticatedCBCResponse{
				Fragments: authenticated.fragments, CloseNotify: authenticated.closeNotify,
			},
		},
	}
	if err := t.routeToClientForSession(identity.session, responseEnvelope); err != nil {
		return t.rejectTLS12CBCResponse(identity, fmt.Errorf("send authenticated CBC response to client: %w", err))
	}
	return nil
}

func (t *TEET) rejectTLS12CBCResponse(identity *teetSessionIdentity, err error) error {
	if identity != nil {
		t.terminateSessionWithErrorForIdentity(identity, shared.ReasonProtocolViolation, err, "TLS 1.2 CBC response rejected")
	}
	return err
}

func (t *TEET) handleTLS12CBCResponseRedactionSpec(identity *teetSessionIdentity, spec *teeproto.ResponseRedactionSpec) error {
	if identity == nil || identity.session == nil || spec == nil {
		return fmt.Errorf("invalid TLS 1.2 CBC response redaction specification")
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	state, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return err
	}
	state.cbcMu.Lock()
	if state.CBCBinding == nil || len(state.CBCAuthenticatedResponse) == 0 || len(state.CBCResponseDigest) != 32 {
		state.cbcMu.Unlock()
		return fmt.Errorf("TLS 1.2 CBC authenticated response is unavailable")
	}
	authenticatedResponse := append([]byte(nil), state.CBCAuthenticatedResponse...)
	state.cbcMu.Unlock()
	if !state.CBCRedactionSpecReceived.CompareAndSwap(false, true) {
		return fmt.Errorf("multiple TLS 1.2 CBC response redaction specifications received")
	}
	ranges := spec.GetRanges()
	if len(ranges) > shared.MaxResponseRedactionRanges {
		return fmt.Errorf("too many TLS 1.2 CBC response redaction ranges: %d", len(ranges))
	}
	responseLength := len(authenticatedResponse)
	for i, item := range ranges {
		if item == nil {
			return fmt.Errorf("nil TLS 1.2 CBC response redaction range at index %d", i)
		}
		start, length := int(item.GetStart()), int(item.GetLength())
		if start < 0 || length <= 0 || start > responseLength || length > responseLength-start {
			return fmt.Errorf("TLS 1.2 CBC response redaction range %d is out of bounds", i)
		}
		for j := i + 1; j < len(ranges); j++ {
			other := ranges[j]
			if other == nil {
				return fmt.Errorf("nil TLS 1.2 CBC response redaction range at index %d", j)
			}
			otherStart, otherLength := int(other.GetStart()), int(other.GetLength())
			if start < otherStart+otherLength && otherStart < start+length {
				return fmt.Errorf("TLS 1.2 CBC response redaction ranges %d and %d overlap", i, j)
			}
		}
	}

	redacted := append([]byte(nil), authenticatedResponse...)
	storedRanges := make([]*teeproto.ResponseRedactionRange, 0, len(ranges))
	for _, item := range ranges {
		start, length := int(item.GetStart()), int(item.GetLength())
		if _, err := rand.Read(redacted[start : start+length]); err != nil {
			return fmt.Errorf("redact authenticated TLS 1.2 CBC response: %w", err)
		}
		storedRanges = append(storedRanges, &teeproto.ResponseRedactionRange{Start: item.GetStart(), Length: item.GetLength()})
	}
	state.cbcMu.Lock()
	state.CBCAuthenticatedRedactedResponse = redacted
	state.CBCResponseRedactionRanges = storedRanges
	state.cbcMu.Unlock()
	identity.session.FinishedStateMutex.Lock()
	identity.session.TEEKFinished = true
	identity.session.FinishedStateMutex.Unlock()
	return t.checkFinishedCondition(identity)
}
