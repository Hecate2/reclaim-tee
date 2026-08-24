package client

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func testCBCBinding() *teeproto.TLS12CBCSessionBinding {
	return &teeproto.TLS12CBCSessionBinding{
		ContractVersion: 1, CipherSuite: minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		RecordMode:           teeproto.TLS12CBCRecordMode_TLS12_CBC_RECORD_MODE_MAC_THEN_ENCRYPT,
		ExtendedMasterSecret: true, SessionBinding: make([]byte, 32),
	}
}

func signCBCContractBody(t *testing.T, pair *shared.SigningKeyPair, bodyType teeproto.BodyType, body []byte) *teeproto.SignedMessage {
	t.Helper()
	signature, err := pair.SignData(body)
	if err != nil {
		t.Fatal(err)
	}
	return &teeproto.SignedMessage{BodyType: bodyType, Body: body, Signature: signature, EthAddress: []byte(pair.GetEthAddress().Hex())}
}

func newCBCContractClient(session string) *Client {
	c := clientWithSession(session)
	c.cipherSuite = minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	c.cbcBinding = testCBCBinding()
	return c
}

func TestTLS12CBCSignedContractsAcceptExplicitFields(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := newCBCContractClient("cbc-contract")
	c.requestData = []byte("abcSECRETxyz")
	c.requestRedactionRanges = []shared.RequestRedactionRange{{Start: 3, Length: 6, Type: shared.RedactionTypeSensitive}}
	c.cbcRequestDigest = make([]byte, 32)

	kBody, err := proto.Marshal(&teeproto.KOutputPayload{
		SessionId: "cbc-contract",
		Tls12Cbc: &teeproto.TLS12CBCKOutput{
			Binding: c.cbcBinding, AuthenticatedRedactedRequest: []byte("abcXXXXXXxyz"), RequestRecordsSha256: make([]byte, 32),
			RequestRedactionRanges: []*teeproto.RequestRedactionRange{{Start: 3, Length: 6, Type: shared.RedactionTypeSensitive}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.validateTEEKSignedMessage("cbc-contract", signCBCContractBody(t, pair, teeproto.BodyType_BODY_TYPE_K_OUTPUT, kBody)); err != nil {
		t.Fatalf("valid K CBC contract rejected: %v", err)
	}

	response := []byte("HTTP/1.1 200 OK\r\n\r\nbodySECRET")
	redactedResponse := append([]byte(nil), response...)
	redactedResponse[len(redactedResponse)-6] = 'X'
	redactedResponse[len(redactedResponse)-5] = 'X'
	redactedResponse[len(redactedResponse)-4] = 'X'
	redactedResponse[len(redactedResponse)-3] = 'X'
	redactedResponse[len(redactedResponse)-2] = 'X'
	redactedResponse[len(redactedResponse)-1] = 'X'
	c.parsedResponseBySeq[1] = &TLSResponseData{ActualContent: response, ContentType: minitls.RecordTypeApplicationData, OriginalLen: len(response)}
	c.cbcResponseDigest = make([]byte, 32)
	c.cbcResponsePlaintextLengths = []uint32{uint32(len(response))}
	c.cbcResponseRedactionRanges = []shared.ResponseRedactionRange{{Start: len(response) - 6, Length: 6}}
	tBody, err := proto.Marshal(&teeproto.TOutputPayload{
		SessionId: "cbc-contract",
		Tls12Cbc: &teeproto.TLS12CBCTOutput{
			Binding: c.cbcBinding, AuthenticatedRedactedResponse: redactedResponse, ResponseRecordsSha256: make([]byte, 32),
			ResponseRedactionRanges: []*teeproto.ResponseRedactionRange{{Start: int32(len(response) - 6), Length: 6}},
			PlaintextRecordLengths:  []uint32{uint32(len(response))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.validateTEETSignedMessage("cbc-contract", signCBCContractBody(t, pair, teeproto.BodyType_BODY_TYPE_T_OUTPUT, tBody)); err != nil {
		t.Fatalf("valid T CBC contract rejected: %v", err)
	}

	var payload teeproto.TOutputPayload
	if err := proto.Unmarshal(tBody, &payload); err != nil {
		t.Fatal(err)
	}
	payload.Tls12Cbc.CloseNotify = true
	tampered, err := proto.Marshal(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.validateTEETSignedMessage("cbc-contract", signCBCContractBody(t, pair, teeproto.BodyType_BODY_TYPE_T_OUTPUT, tampered)); err == nil {
		t.Fatal("signed close_notify mismatch was accepted")
	}
}

func TestTLS12CBCSignedContractsRejectLegacyMixAndCleartextChanges(t *testing.T) {
	pair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newKMessage := func(c *Client, payload *teeproto.KOutputPayload) *teeproto.SignedMessage {
		body, marshalErr := proto.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return signCBCContractBody(t, pair, teeproto.BodyType_BODY_TYPE_K_OUTPUT, body)
	}

	t.Run("legacy field", func(t *testing.T) {
		c := newCBCContractClient("cbc-mix")
		c.requestData = []byte("request")
		c.cbcRequestDigest = make([]byte, 32)
		payload := &teeproto.KOutputPayload{
			SessionId: "cbc-mix", ConsolidatedResponseKeystream: []byte{1},
			Tls12Cbc: &teeproto.TLS12CBCKOutput{Binding: c.cbcBinding, AuthenticatedRedactedRequest: []byte("request"), RequestRecordsSha256: make([]byte, 32)},
		}
		_, err := c.validateTEEKSignedMessage("cbc-mix", newKMessage(c, payload))
		if err == nil || !strings.Contains(err.Error(), "mixes legacy") {
			t.Fatalf("legacy/CBC field mix result=%v", err)
		}
	})

	t.Run("outside redaction", func(t *testing.T) {
		c := newCBCContractClient("cbc-clear")
		c.requestData = []byte("abcSECRETxyz")
		c.requestRedactionRanges = []shared.RequestRedactionRange{{Start: 3, Length: 6, Type: shared.RedactionTypeSensitive}}
		c.cbcRequestDigest = make([]byte, 32)
		payload := &teeproto.KOutputPayload{
			SessionId: "cbc-clear",
			Tls12Cbc: &teeproto.TLS12CBCKOutput{
				Binding: c.cbcBinding, AuthenticatedRedactedRequest: []byte("zbcXXXXXXxyz"), RequestRecordsSha256: make([]byte, 32),
				RequestRedactionRanges: []*teeproto.RequestRedactionRange{{Start: 3, Length: 6, Type: shared.RedactionTypeSensitive}},
			},
		}
		_, err := c.validateTEEKSignedMessage("cbc-clear", newKMessage(c, payload))
		if err == nil || !strings.Contains(err.Error(), "outside sensitive") {
			t.Fatalf("cleartext mutation result=%v", err)
		}
	})

	t.Run("redaction range mismatch", func(t *testing.T) {
		c := newCBCContractClient("cbc-range")
		c.requestData = []byte("abcSECRETxyz")
		c.requestRedactionRanges = []shared.RequestRedactionRange{{Start: 3, Length: 6, Type: shared.RedactionTypeSensitive}}
		c.cbcRequestDigest = make([]byte, 32)
		payload := &teeproto.KOutputPayload{
			SessionId: "cbc-range",
			Tls12Cbc: &teeproto.TLS12CBCKOutput{
				Binding: c.cbcBinding, AuthenticatedRedactedRequest: []byte("abcXXXXXXxyz"), RequestRecordsSha256: make([]byte, 32),
				RequestRedactionRanges: []*teeproto.RequestRedactionRange{{Start: 4, Length: 6, Type: shared.RedactionTypeSensitive}},
			},
		}
		_, err := c.validateTEEKSignedMessage("cbc-range", newKMessage(c, payload))
		if err == nil || !strings.Contains(err.Error(), "redaction range 0 mismatch") {
			t.Fatalf("redaction range mutation result=%v", err)
		}
	})
}

func TestTLS12CBCAuthenticatedResponseFailurePublishesNothing(t *testing.T) {
	c := newCBCContractClient("cbc-no-partial")
	response := &teeproto.AuthenticatedCBCResponse{Fragments: []*teeproto.AuthenticatedCBCResponse_Fragment{
		{SeqNum: 1, RecordType: minitls.RecordTypeApplicationData, Plaintext: []byte("HTTP/1.1 200 OK\r\n\r\nbody")},
		{SeqNum: 2, RecordType: 99, Plaintext: []byte("invalid")},
	}}
	if err := c.handleAuthenticatedTLS12CBCResponse("cbc-no-partial", response); err == nil {
		t.Fatal("invalid authenticated response was accepted")
	}
	if len(c.parsedResponseBySeq) != 0 || len(c.ciphertextBySeq) != 0 || len(c.cbcResponsePlaintextLengths) != 0 {
		t.Fatal("failed authenticated response published partial plaintext state")
	}
}

func TestTLS12CBCAuthenticatedResponseRejectsFatalAlertWithoutPublishing(t *testing.T) {
	c := newCBCContractClient("cbc-fatal-alert")
	response := &teeproto.AuthenticatedCBCResponse{Fragments: []*teeproto.AuthenticatedCBCResponse_Fragment{
		{SeqNum: 1, RecordType: minitls.RecordTypeApplicationData, Plaintext: []byte("HTTP/1.1 200 OK\r\n\r\nbody")},
		{SeqNum: 2, RecordType: minitls.RecordTypeAlert, Plaintext: []byte{2, 40}},
	}}
	err := c.handleAuthenticatedTLS12CBCResponse("cbc-fatal-alert", response)
	if err == nil || !strings.Contains(err.Error(), "handshake_failure") {
		t.Fatalf("fatal alert result: %v", err)
	}
	if len(c.parsedResponseBySeq) != 0 || len(c.ciphertextBySeq) != 0 || len(c.cbcResponsePlaintextLengths) != 0 {
		t.Fatal("fatal alert published partial plaintext state")
	}
}

func TestTLS12CBCRedactionCoordinatesExcludeAuthenticatedAlerts(t *testing.T) {
	c := newCBCContractClient("cbc-redaction-alert")
	first := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
	second := []byte("hello")
	alert := []byte{1, 0}
	c.parsedResponseBySeq[1] = &TLSResponseData{
		ActualContent: first, ContentType: minitls.RecordTypeApplicationData, OriginalLen: len(first),
	}
	c.parsedResponseBySeq[2] = &TLSResponseData{
		ActualContent: second, ContentType: minitls.RecordTypeApplicationData, OriginalLen: len(second),
	}
	c.parsedResponseBySeq[3] = &TLSResponseData{
		ActualContent: alert, ContentType: minitls.RecordTypeAlert, OriginalLen: len(alert),
	}
	c.ciphertextBySeq[1] = append([]byte(nil), first...)
	c.ciphertextBySeq[2] = append([]byte(nil), second...)
	c.ciphertextBySeq[3] = append([]byte(nil), alert...)

	analysis, err := c.analyzeTLSRecords([]uint64{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	wantResponseLength := len(first) + len(second)
	if analysis.TotalTLSOffset != wantResponseLength {
		t.Fatalf("CBC response coordinate length = %d, want %d", analysis.TotalTLSOffset, wantResponseLength)
	}
	if len(analysis.ProtocolRedactions) != 0 {
		t.Fatalf("CBC alert produced out-of-band response redactions: %+v", analysis.ProtocolRedactions)
	}
	if len(analysis.HTTPMappings) != 2 || analysis.HTTPMappings[1].TLSPos != len(first) {
		t.Fatalf("CBC application-data mappings are not contiguous: %+v", analysis.HTTPMappings)
	}
}

func TestPreCBCRedactionCoordinatesStillIncludeProtocolRecords(t *testing.T) {
	c := newCBCContractClient("legacy-redaction-alert")
	c.cipherSuite = minitls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	appData := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	alert := []byte{1, 0}
	c.parsedResponseBySeq[1] = &TLSResponseData{
		ActualContent: appData, ContentType: minitls.RecordTypeApplicationData, OriginalLen: len(appData),
	}
	c.parsedResponseBySeq[2] = &TLSResponseData{
		ActualContent: alert, ContentType: minitls.RecordTypeAlert, OriginalLen: len(alert),
	}
	c.ciphertextBySeq[1] = append([]byte(nil), appData...)
	c.ciphertextBySeq[2] = append([]byte(nil), alert...)

	analysis, err := c.analyzeTLSRecords([]uint64{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.TotalTLSOffset != len(appData)+len(alert) {
		t.Fatalf("pre-CBC coordinate length = %d, want %d", analysis.TotalTLSOffset, len(appData)+len(alert))
	}
	if len(analysis.ProtocolRedactions) != 1 || analysis.ProtocolRedactions[0].Start != len(appData) ||
		analysis.ProtocolRedactions[0].Length != len(alert) {
		t.Fatalf("pre-CBC protocol redactions changed: %+v", analysis.ProtocolRedactions)
	}
}

func TestTLS12CBCVerificationBundleRejectsLegacyTOPRF(t *testing.T) {
	c := newCBCContractClient("cbc-toprf")
	c.oprfRedactionRanges = map[int]int{0: 1}
	if _, err := c.BuildVerificationBundleData(nil, nil); err == nil || !strings.Contains(err.Error(), "legacy ZK TOPRF") {
		t.Fatalf("legacy TOPRF result: %v", err)
	}
}

func TestTLS12CBCRequestRecordsAreForwardedExactly(t *testing.T) {
	c := newCBCContractClient("cbc-forward")
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	c.tcpConn = clientConn
	records := []*teeproto.TLSRecord{
		{Header: []byte{minitls.RecordTypeApplicationData, 3, 3, 0, 3}, Payload: []byte{1, 2, 3}, SeqNum: 1},
		{Header: []byte{minitls.RecordTypeApplicationData, 3, 3, 0, 2}, Payload: []byte{4, 5}, SeqNum: 2},
	}
	want := []byte{minitls.RecordTypeApplicationData, 3, 3, 0, 3, 1, 2, 3, minitls.RecordTypeApplicationData, 3, 3, 0, 2, 4, 5}
	result := make(chan error, 1)
	go func() {
		result <- c.handleBatchedTLS12CBCRequest("cbc-forward", &teeproto.BatchedTLSRecords{Records: records})
	}()
	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("forwarded records = %x, want %x", got, want)
	}
	if !c.httpRequestSent.Load() || len(c.cbcRequestDigest) != 32 {
		t.Fatal("successful CBC request forwarding did not publish completion state")
	}
}
