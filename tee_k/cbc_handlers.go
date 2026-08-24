package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

const maxTLS12CBCRequestPlaintext = 16384

func validateTLS12CBCRequestPlaintext(request []byte) error {
	if len(request) == 0 || len(request) > maxTLS12CBCRequestPlaintext {
		return fmt.Errorf("invalid TLS 1.2 CBC HTTP request length: %d", len(request))
	}
	return nil
}

const tls12CBCReadStateAckTimeout = 5 * time.Second

func tls12CBCModeToProto(mode minitls.TLS12CBCRecordMode) (teeproto.TLS12CBCRecordMode, error) {
	switch mode {
	case minitls.TLS12CBCRecordModeMACThenEncrypt:
		return teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_MAC_THEN_ENCRYPT, nil
	case minitls.TLS12CBCRecordModeEncryptThenMAC:
		return teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_ENCRYPT_THEN_MAC, nil
	default:
		return teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_UNSPECIFIED, fmt.Errorf("unsupported TLS 1.2 CBC record mode: %d", mode)
	}
}

func (t *TEEK) handOffTLS12CBCReadState(sessionID string, state *TEEKSessionState) (*teeproto.TLS12CBCSessionBinding, error) {
	if state == nil || state.TLSClient == nil {
		return nil, fmt.Errorf("TLS 1.2 CBC session state is unavailable")
	}
	ctx := state.TLSClient.GetTLS12CBC()
	if ctx == nil {
		return nil, fmt.Errorf("TLS 1.2 CBC context is unavailable")
	}
	readState := ctx.ExportReadState()
	if readState.ReadSequence != 1 {
		return nil, fmt.Errorf("TLS 1.2 CBC server read sequence is %d after handshake, want 1", readState.ReadSequence)
	}
	mode, err := tls12CBCModeToProto(readState.Mode)
	if err != nil {
		return nil, err
	}
	bindingBytes := make([]byte, 32)
	if _, err := rand.Read(bindingBytes); err != nil {
		return nil, fmt.Errorf("generate TLS 1.2 CBC session binding: %w", err)
	}
	binding := &teeproto.TLS12CBCSessionBinding{
		ContractVersion:      1,
		CipherSuite:          uint32(readState.CipherSuite),
		RecordMode:           mode,
		ExtendedMasterSecret: state.TLSClient.TLS12ExtendedMasterSecret(),
		SessionBinding:       bindingBytes,
	}
	state.cbcMu.Lock()
	state.CBCBinding = proto.Clone(binding).(*teeproto.TLS12CBCSessionBinding)
	state.CBCReadStateAck = make(chan error, 1)
	ackChannel := state.CBCReadStateAck
	state.cbcMu.Unlock()

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Tls12CbcReadState{
			Tls12CbcReadState: &teeproto.TLS12CBCReadState{
				Binding:      binding,
				ReadKey:      readState.ReadKey,
				ReadMacKey:   readState.ReadMACKey,
				ReadIv:       readState.ReadIV,
				ReadSequence: readState.ReadSequence,
			},
		},
	}
	if err := t.sendEnvelopeToTEET(sessionID, env); err != nil {
		return nil, fmt.Errorf("send TLS 1.2 CBC read state to TEE_T: %w", err)
	}

	select {
	case err := <-ackChannel:
		if err != nil {
			return nil, err
		}
		return binding, nil
	case <-time.After(tls12CBCReadStateAckTimeout):
		return nil, fmt.Errorf("timeout waiting for TLS 1.2 CBC read-state acknowledgment")
	}
}

func (t *TEEK) handleTLS12CBCReadStateAck(identity *teekSessionIdentity, ack *teeproto.TLS12CBCReadStateAck) error {
	if identity == nil || identity.session == nil || ack == nil {
		return fmt.Errorf("invalid TLS 1.2 CBC read-state acknowledgment")
	}
	state, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return err
	}
	state.cbcMu.Lock()
	if state.CBCBinding == nil || state.CBCReadStateAck == nil {
		state.cbcMu.Unlock()
		return fmt.Errorf("unexpected TLS 1.2 CBC read-state acknowledgment")
	}
	binding := proto.Clone(state.CBCBinding).(*teeproto.TLS12CBCSessionBinding)
	ackChannel := state.CBCReadStateAck
	state.cbcMu.Unlock()
	if !state.CBCReadStateAcked.CompareAndSwap(false, true) {
		return fmt.Errorf("duplicate TLS 1.2 CBC read-state acknowledgment")
	}
	var ackErr error
	if !bytes.Equal(ack.GetSessionBinding(), binding.GetSessionBinding()) {
		ackErr = fmt.Errorf("TLS 1.2 CBC read-state acknowledgment binding mismatch")
	} else if !ack.GetSuccess() {
		ackErr = fmt.Errorf("TEE_T rejected TLS 1.2 CBC read state: %s", ack.GetErrorMessage())
	}
	ackChannel <- ackErr
	return ackErr
}

func isTLS12CBCSession(state *TEEKSessionState) bool {
	if state == nil {
		return false
	}
	state.cbcMu.Lock()
	defer state.cbcMu.Unlock()
	return validateTLS12CBCBinding(state.CBCBinding) == nil
}

func validateTLS12CBCBinding(binding *teeproto.TLS12CBCSessionBinding) error {
	if binding == nil || binding.GetContractVersion() != 1 || len(binding.GetSessionBinding()) != 32 {
		return fmt.Errorf("invalid TLS 1.2 CBC session binding")
	}
	if !minitls.IsTLS12CBCCipherSuite(uint16(binding.GetCipherSuite())) {
		return fmt.Errorf("binding contains unsupported TLS 1.2 CBC cipher suite")
	}
	return nil
}

func (t *TEEK) handleTLS12CBCRequest(sessionID string, request *teeproto.TLS12CBCRequest) error {
	if request == nil {
		return fmt.Errorf("TLS 1.2 CBC request is nil")
	}
	state, err := t.getSessionTLSState(sessionID)
	if err != nil {
		return err
	}
	if !isTLS12CBCSession(state) || !state.HandshakeComplete || state.TLSClient == nil || state.TLSClient.GetTLS12CBC() == nil {
		return fmt.Errorf("TLS 1.2 CBC request received outside a completed CBC session")
	}
	if !state.CBCRequestReceived.CompareAndSwap(false, true) {
		return fmt.Errorf("multiple TLS 1.2 CBC requests received")
	}
	fullRequest := request.GetFullRequest()
	if err := validateTLS12CBCRequestPlaintext(fullRequest); err != nil {
		return err
	}
	if len(request.GetRedactionRanges()) > shared.MaxRedactionRanges {
		return fmt.Errorf("too many TLS 1.2 CBC request redaction ranges")
	}
	ranges := make([]shared.RequestRedactionRange, 0, len(request.GetRedactionRanges()))
	for _, item := range request.GetRedactionRanges() {
		if item == nil {
			return fmt.Errorf("nil TLS 1.2 CBC request redaction range")
		}
		ranges = append(ranges, shared.RequestRedactionRange{
			Start: int(item.GetStart()), Length: int(item.GetLength()), Type: item.GetType(),
		})
	}
	if err := t.validateRedactionPositions(ranges, len(fullRequest)); err != nil {
		return err
	}
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return err
	}
	if err := t.validateTLS12CBCHTTPRequestFormat(fullRequest, ranges, session.ConnectionData); err != nil {
		return err
	}

	authenticatedRedactedRequest := append([]byte(nil), fullRequest...)
	for _, item := range ranges {
		if item.Type == shared.RedactionTypeSensitive {
			if _, err := rand.Read(authenticatedRedactedRequest[item.Start : item.Start+item.Length]); err != nil {
				return fmt.Errorf("redact TLS 1.2 CBC request: %w", err)
			}
		}
	}

	ctx := state.TLSClient.GetTLS12CBC()
	seq := ctx.GetWriteSequence()
	record, err := ctx.EncryptRecord(minitls.RecordTypeApplicationData, fullRequest)
	if err != nil {
		return fmt.Errorf("encrypt TLS 1.2 CBC request record: %w", err)
	}
	records := []*teeproto.TLSRecord{{
		Header: append([]byte(nil), record[:5]...), Payload: append([]byte(nil), record[5:]...), SeqNum: seq,
	}}
	if len(records) > shared.MaxEncryptedFragments {
		return fmt.Errorf("TLS 1.2 CBC request has too many records")
	}
	digest, err := shared.TLS12CBCRecordDigest(shared.TLS12CBCRequestDigestDomain, records)
	if err != nil {
		return err
	}
	state.cbcMu.Lock()
	state.CBCAuthenticatedRedactedRequest = authenticatedRedactedRequest
	state.CBCRequestDigest = digest
	state.CBCRequestRedactionRanges = make([]*teeproto.RequestRedactionRange, 0, len(ranges))
	for _, item := range ranges {
		state.CBCRequestRedactionRanges = append(state.CBCRequestRedactionRanges, &teeproto.RequestRedactionRange{
			Start: int32(item.Start), Length: int32(item.Length), Type: item.Type,
		})
	}
	state.cbcMu.Unlock()

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedTlsRecords{
			BatchedTlsRecords: &teeproto.BatchedTLSRecords{Records: records},
		},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
		return fmt.Errorf("send TLS 1.2 CBC request records to client: %w", err)
	}
	return nil
}

func (t *TEEK) processTLS12CBCResponseRedactionSpec(sessionID string, state *TEEKSessionState) error {
	if !isTLS12CBCSession(state) || !state.CBCCiphertextReady.Load() {
		return nil
	}
	spec := state.getCBCResponseRedactionSpec()
	if spec == nil {
		return nil
	}
	state.LockOPRF()
	responseLength := len(state.ConsolidatedKeystream)
	state.UnlockOPRF()
	if responseLength == 0 {
		return fmt.Errorf("authenticated TLS 1.2 CBC response length is unavailable")
	}
	for i, item := range spec.Ranges {
		if item.Start < 0 || item.Length <= 0 || item.Start > responseLength || item.Length > responseLength-item.Start {
			return fmt.Errorf("TLS 1.2 CBC response redaction range %d is out of bounds", i)
		}
	}
	if !state.CBCRedactionForwarded.CompareAndSwap(false, true) {
		return nil
	}

	ranges := make([]*teeproto.ResponseRedactionRange, 0, len(spec.Ranges))
	for _, item := range spec.Ranges {
		ranges = append(ranges, &teeproto.ResponseRedactionRange{Start: int32(item.Start), Length: int32(item.Length)})
	}
	if err := t.sendEnvelopeToTEET(sessionID, &teeproto.Envelope{
		SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_ResponseRedactionSpec{
			ResponseRedactionSpec: &teeproto.ResponseRedactionSpec{Ranges: ranges},
		},
	}); err != nil {
		return fmt.Errorf("forward TLS 1.2 CBC response redaction specification to TEE_T: %w", err)
	}
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return err
	}
	session.StreamsMutex.Lock()
	session.RedactionProcessingComplete = true
	session.StreamsMutex.Unlock()
	return t.checkAndSendSignatureIfReady(sessionID)
}
