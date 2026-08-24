package main

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func TestSnapshotCBCResponseForOPRFIsConcurrentSafe(t *testing.T) {
	state := &TEETSessionState{
		CBCBinding:               &teeproto.TLS12CBCSessionBinding{ContractVersion: 1},
		CBCAuthenticatedResponse: []byte("initial response"),
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			state.cbcMu.Lock()
			state.CBCAuthenticatedResponse = bytes.Repeat([]byte{byte(i)}, 32)
			state.cbcMu.Unlock()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			response, isCBC := state.snapshotCBCResponseForOPRF()
			if !isCBC || len(response) == 0 {
				t.Errorf("CBC snapshot unavailable: isCBC=%v len=%d", isCBC, len(response))
				return
			}
		}
	}()
	close(start)
	workers.Wait()
}

func TestTLS12CBCTOutputUsesOnlyExplicitContractFields(t *testing.T) {
	const sessionID = "cbc-t-output"
	manager := NewTEETSessionManager()
	if err := manager.RegisterSession(sessionID); err != nil {
		t.Fatal(err)
	}
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	_, readContext := newCBCResponseTestContexts(t, minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, minitls.TLS12CBCRecordModeMACThenEncrypt)
	state := &TEETSessionState{
		session: session,
		CBCBinding: &teeproto.TLS12CBCSessionBinding{
			ContractVersion: 1, CipherSuite: minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			RecordMode:     teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_MAC_THEN_ENCRYPT,
			SessionBinding: make([]byte, 32),
		},
		CBCReadContext: readContext, CBCAuthenticatedResponse: []byte("response"),
		CBCAuthenticatedRedactedResponse: []byte("responXX"), CBCResponseDigest: make([]byte, 32),
		CBCResponseRedactionRanges:     []*teeproto.ResponseRedactionRange{{Start: 6, Length: 2}},
		CBCPlaintextRecordLengths:      []uint32{8},
		ConsolidatedResponseCiphertext: []byte("legacy ciphertext"),
		RequestProofStreams:            [][]byte{[]byte("legacy proof")},
	}
	manager.SetTEETSessionState(sessionID, state)
	session.TEEKFinished = true
	clientConn, _, outbound := newKOS2ReceiverControlWebSocket(t)
	session.ClientConn = clientConn
	keyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	teet := &TEET{sessionManager: manager, logger: shared.NewNopLogger(), signingKeyPair: keyPair}
	if err := teet.checkFinishedCondition(&teetSessionIdentity{session: session}); err != nil {
		t.Fatal(err)
	}

	var wire []byte
	select {
	case wire = <-outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for T CBC signed output")
	}
	var env teeproto.Envelope
	if err := proto.Unmarshal(wire, &env); err != nil {
		t.Fatal(err)
	}
	var payload teeproto.TOutputPayload
	if err := proto.Unmarshal(env.GetSignedMessage().GetBody(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.GetTls12Cbc() == nil {
		t.Fatal("T CBC output is missing explicit contract")
	}
	if len(payload.GetConsolidatedResponseCiphertext()) != 0 || len(payload.GetRequestProofStreams()) != 0 {
		t.Fatal("T CBC output included legacy AEAD fields")
	}
}

func newCBCResponseTestContexts(t *testing.T, suite uint16, mode minitls.TLS12CBCRecordMode) (*minitls.TLS12CBCContext, *minitls.TLS12CBCContext) {
	t.Helper()
	info := minitls.GetCipherSuiteInfo(suite)
	if info == nil {
		t.Fatalf("missing cipher suite info for 0x%04x", suite)
	}
	keys := &minitls.TLS12CBCKeys{
		ClientKey: make([]byte, info.KeySize), ClientMACKey: make([]byte, info.MACSize), ClientIV: make([]byte, info.IVSize),
		ServerKey: make([]byte, info.KeySize), ServerMACKey: make([]byte, info.MACSize), ServerIV: make([]byte, info.IVSize),
	}
	for i := range keys.ClientKey {
		keys.ClientKey[i] = byte(i + 1)
	}
	for i := range keys.ClientMACKey {
		keys.ClientMACKey[i] = byte(i + 33)
	}
	writer, err := minitls.NewTLS12CBCContext(keys, suite, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.EncryptRecord(minitls.RecordTypeHandshake, []byte("finished")); err != nil {
		t.Fatal(err)
	}
	reader, err := minitls.NewTLS12CBCReadContext(&minitls.TLS12CBCReadState{
		CipherSuite: suite, Mode: mode, ReadKey: keys.ClientKey, ReadMACKey: keys.ClientMACKey,
		ReadIV: keys.ClientIV, ReadSequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return writer, reader
}

func encryptCBCResponseTestRecord(t *testing.T, writer *minitls.TLS12CBCContext, recordType byte, plaintext []byte, claimedSeq uint64) *teeproto.TLSRecord {
	t.Helper()
	record, err := writer.EncryptRecord(recordType, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return &teeproto.TLSRecord{Header: append([]byte(nil), record[:5]...), Payload: append([]byte(nil), record[5:]...), SeqNum: claimedSeq}
}

func TestAuthenticateTLS12CBCResponseBatchMtEAndEtM(t *testing.T) {
	tests := []struct {
		name  string
		suite uint16
		mode  minitls.TLS12CBCRecordMode
	}{
		{name: "mte_sha1", suite: minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, mode: minitls.TLS12CBCRecordModeMACThenEncrypt},
		{name: "etm_sha256", suite: minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, mode: minitls.TLS12CBCRecordModeEncryptThenMAC},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer, reader := newCBCResponseTestContexts(t, tt.suite, tt.mode)
			batch := &teeproto.BatchedTLSRecords{Records: []*teeproto.TLSRecord{
				encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeApplicationData, []byte("HTTP/1.1 200 OK\r\n\r\nbody"), 900),
				encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeAlert, []byte{1, 0}, 901),
			}}
			result, err := authenticateTLS12CBCResponseBatch(reader, batch)
			if err != nil {
				t.Fatal(err)
			}
			if string(result.response) != "HTTP/1.1 200 OK\r\n\r\nbody" || !result.closeNotify {
				t.Fatalf("unexpected authenticated result: response=%q close_notify=%v", result.response, result.closeNotify)
			}
			if len(result.fragments) != 2 || result.fragments[0].GetSeqNum() != 1 || result.fragments[1].GetSeqNum() != 2 {
				t.Fatalf("TEE_T did not assign authoritative sequences: %+v", result.fragments)
			}
			if len(result.plaintextLengths) != 1 || result.plaintextLengths[0] != uint32(len(result.response)) {
				t.Fatalf("unexpected plaintext lengths: %v", result.plaintextLengths)
			}
			if reader.GetReadSequence() != 1 || result.readContext.GetReadSequence() != 3 {
				t.Fatalf("read-state publication changed before commit: original=%d batch=%d", reader.GetReadSequence(), result.readContext.GetReadSequence())
			}
		})
	}
}

func TestAuthenticateTLS12CBCResponseBatchRejectsTamperWithoutPartialResult(t *testing.T) {
	for _, mode := range []minitls.TLS12CBCRecordMode{minitls.TLS12CBCRecordModeMACThenEncrypt, minitls.TLS12CBCRecordModeEncryptThenMAC} {
		writer, reader := newCBCResponseTestContexts(t, minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, mode)
		first := encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeApplicationData, []byte("first"), 1)
		second := encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeApplicationData, []byte("second"), 2)
		second.Payload[len(second.Payload)-1] ^= 1
		result, err := authenticateTLS12CBCResponseBatch(reader, &teeproto.BatchedTLSRecords{Records: []*teeproto.TLSRecord{first, second}})
		if result != nil || !errors.Is(err, minitls.ErrBadRecordMAC) {
			t.Fatalf("mode %s: result=%v err=%v", mode, result, err)
		}
		if reader.GetReadSequence() != 1 {
			t.Fatalf("mode %s: failed batch advanced published read sequence to %d", mode, reader.GetReadSequence())
		}
	}
}

func TestAuthenticateTLS12CBCResponseBatchRejectsRecordsAfterCloseNotify(t *testing.T) {
	writer, reader := newCBCResponseTestContexts(t, minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, minitls.TLS12CBCRecordModeMACThenEncrypt)
	batch := &teeproto.BatchedTLSRecords{Records: []*teeproto.TLSRecord{
		encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeApplicationData, []byte("response"), 1),
		encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeAlert, []byte{1, 0}, 2),
		encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeApplicationData, []byte("trailing"), 3),
	}}
	if result, err := authenticateTLS12CBCResponseBatch(reader, batch); err == nil || result != nil {
		t.Fatalf("record after close_notify accepted: result=%v err=%v", result, err)
	}
}

func TestAuthenticateTLS12CBCResponseBatchAllowsWarningAlert(t *testing.T) {
	writer, reader := newCBCResponseTestContexts(t, minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, minitls.TLS12CBCRecordModeMACThenEncrypt)
	batch := &teeproto.BatchedTLSRecords{Records: []*teeproto.TLSRecord{
		encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeAlert, []byte{1, 100}, 1),
		encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeApplicationData, []byte("response"), 2),
	}}
	result, err := authenticateTLS12CBCResponseBatch(reader, batch)
	if err != nil {
		t.Fatal(err)
	}
	if result.closeNotify || string(result.response) != "response" || len(result.fragments) != 2 {
		t.Fatalf("unexpected warning-alert result: response=%q close_notify=%v fragments=%d", result.response, result.closeNotify, len(result.fragments))
	}
}

func TestAuthenticateTLS12CBCResponseBatchRejectsMalformedAlert(t *testing.T) {
	writer, reader := newCBCResponseTestContexts(t, minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, minitls.TLS12CBCRecordModeMACThenEncrypt)
	batch := &teeproto.BatchedTLSRecords{Records: []*teeproto.TLSRecord{
		encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeApplicationData, []byte("response"), 1),
		encryptCBCResponseTestRecord(t, writer, minitls.RecordTypeAlert, []byte{1}, 2),
	}}
	if result, err := authenticateTLS12CBCResponseBatch(reader, batch); err == nil || result != nil {
		t.Fatalf("malformed alert accepted: result=%v err=%v", result, err)
	}
}
