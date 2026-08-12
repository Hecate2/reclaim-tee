package client

import (
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestDetectModeHandlesShortURLs(t *testing.T) {
	tests := []struct {
		name    string
		teekURL string
		teetURL string
		want    ClientMode
	}{
		{name: "empty", want: ModeStandalone},
		{name: "short TEE_K URL", teekURL: "w", want: ModeStandalone},
		{name: "short TEE_T URL", teetURL: "ws", want: ModeStandalone},
		{name: "secure TEE_K URL", teekURL: "wss://tee-k.example", want: ModeEnclave},
		{name: "secure TEE_T URL", teetURL: "wss://tee-t.example", want: ModeEnclave},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectMode(tt.teekURL, tt.teetURL); got != tt.want {
				t.Fatalf("detectMode(%q, %q) = %v, want %v", tt.teekURL, tt.teetURL, got, tt.want)
			}
		})
	}
}

func TestExecuteCompleteProtocolRejectsNilProviderData(t *testing.T) {
	c := NewClient("")

	_, err := c.ExecuteCompleteProtocol(nil)
	if err == nil || !strings.Contains(err.Error(), "provider data is required") {
		t.Fatalf("expected provider data error, got %v", err)
	}
}

func TestGenerateAutomaticRequestDataReturnsMissingParamError(t *testing.T) {
	c := NewClient("")
	c.providerParams = &providers.HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		ResponseMatches: []providers.ResponseMatch{
			{Type: "contains", Value: `"first_name":"{{firstname}}"`},
		},
	}
	c.providerSecretParams = &providers.HTTPProviderSecretParams{
		AuthorisationHeader: "test",
	}

	err := c.generateAutomaticRequestData()
	if err == nil {
		t.Fatal("expected a missing response-match param error")
	}
	if !strings.Contains(err.Error(), "responseMatches[0].value") ||
		!strings.Contains(err.Error(), `parameter "firstname" not found`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnalyzeTLSRecordsReturnsErrorOnCiphertextLengthMismatch(t *testing.T) {
	c := NewClient("")
	c.cipherSuite = minitls.TLS_AES_128_GCM_SHA256
	c.parsedResponseBySeq[0] = &TLSResponseData{
		OriginalLen: 5,
		ContentType: minitls.RecordTypeApplicationData,
	}
	c.ciphertextBySeq[0] = make([]byte, 3)

	_, err := c.analyzeTLSRecords([]uint64{0})
	if err == nil {
		t.Fatal("expected a ciphertext length mismatch error")
	}
	if !strings.Contains(err.Error(), "ciphertext length (3) does not match TEE_T stream length (4)") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnalyzeTLSRecordsReturnsErrorForMissingRecordData(t *testing.T) {
	tests := []struct {
		name       string
		initialize func(*Client)
		want       string
	}{
		{
			name:       "parsed response",
			initialize: func(*Client) {},
			want:       "no parsed data found for sequence 7",
		},
		{
			name: "ciphertext",
			initialize: func(c *Client) {
				c.parsedResponseBySeq[7] = &TLSResponseData{OriginalLen: 1}
			},
			want: "no ciphertext found for sequence 7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient("")
			tt.initialize(c)

			_, err := c.analyzeTLSRecords([]uint64{7})
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestHandleBatchedDecryptionStreamsRejectsEmptyTLS13Record(t *testing.T) {
	c := NewClient("")
	c.cipherSuite = minitls.TLS_AES_128_GCM_SHA256
	c.ciphertextBySeq[0] = []byte{}
	msg := &shared.Message{
		Data: shared.BatchedDecryptionStreamData{
			DecryptionStreams: []shared.ResponseDecryptionStreamData{
				{SeqNum: 0, DecryptionStream: []byte{}},
			},
		},
	}

	c.handleBatchedDecryptionStreams(msg)

	err := <-c.WaitForCompletion()
	if err == nil {
		t.Fatal("expected an invalid decryption stream error")
	}
	if !strings.Contains(err.Error(), "invalid TEE_T stream length -1") {
		t.Fatalf("unexpected error: %v", err)
	}
}
