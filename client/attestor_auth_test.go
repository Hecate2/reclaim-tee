package client

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// sdkJSONAuthRequest is the payload the Reclaim in-app SDK sends on its native
// TEE path. It is captured from the shape built in the SDK's
// attestor/claim/request.dart, which base64-encodes
// {data: <AuthenticatedUserData>, signature: <base64 bytes>} for the
// gnarkTEENative operation type.
//
// This fixture is the point of the test: a round trip through protobuf alone
// would pass no matter what, because the bug is at the cross-language boundary.
const sdkJSONAuthRequest = `{"data":{"id":"user-1","createdAt":1739880000,` +
	`"expiresAt":1739880600,"hostWhitelist":["api.example.com"]},` +
	`"signature":"TUVVQ0lRRA=="}`

func newAuthTestClient(t *testing.T) *Client {
	t.Helper()
	return &Client{logger: &shared.Logger{Logger: zap.NewNop()}}
}

func TestSetAttestorAuthRequestAcceptsSDKJSON(t *testing.T) {
	c := newAuthTestClient(t)

	if err := c.setAttestorAuthRequest(base64.StdEncoding.EncodeToString([]byte(sdkJSONAuthRequest))); err != nil {
		t.Fatalf("setAttestorAuthRequest: %v", err)
	}

	got := c.attestorAuthRequest
	if got == nil {
		t.Fatal("expected an auth request to be stored")
	}
	if id := got.GetData().GetId(); id != "user-1" {
		t.Errorf("id = %q, want user-1", id)
	}
	if created := got.GetData().GetCreatedAt(); created != 1739880000 {
		t.Errorf("createdAt = %d, want 1739880000", created)
	}
	// The expiry is the field worth guarding: a lenient decoder that ignored
	// unknown names would leave it zero and grant a request that never expires.
	if expires := got.GetData().GetExpiresAt(); expires != 1739880600 {
		t.Errorf("expiresAt = %d, want 1739880600", expires)
	}
	if hosts := got.GetData().GetHostWhitelist(); len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Errorf("hostWhitelist = %v", hosts)
	}
	// signature is bytes in the proto and base64 in the JSON.
	if sig := string(got.GetSignature()); sig != "MEUCIQD" {
		t.Errorf("signature = %q, want MEUCIQD", sig)
	}
}

func TestSetAttestorAuthRequestAcceptsProtobuf(t *testing.T) {
	// The pre-existing encoding must keep working unchanged.
	original := &teeproto.AuthenticationRequest{
		Data: &teeproto.AuthenticatedUserData{
			Id:            "user-1",
			CreatedAt:     1739880000,
			ExpiresAt:     1739880600,
			HostWhitelist: []string{"api.example.com"},
		},
		Signature: []byte("MEUCIQD"),
	}
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	c := newAuthTestClient(t)
	if err := c.setAttestorAuthRequest(base64.StdEncoding.EncodeToString(wire)); err != nil {
		t.Fatalf("setAttestorAuthRequest: %v", err)
	}
	if !proto.Equal(c.attestorAuthRequest, original) {
		t.Errorf("round trip changed the request: %v", c.attestorAuthRequest)
	}
}

func TestBothEncodingsProduceTheSameRequest(t *testing.T) {
	// The two encodings are two spellings of one message, so a client that
	// sends either must end up authenticated identically.
	fromJSON := newAuthTestClient(t)
	if err := fromJSON.setAttestorAuthRequest(base64.StdEncoding.EncodeToString([]byte(sdkJSONAuthRequest))); err != nil {
		t.Fatalf("JSON form: %v", err)
	}

	wire, err := proto.Marshal(fromJSON.attestorAuthRequest)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	fromProto := newAuthTestClient(t)
	if err := fromProto.setAttestorAuthRequest(base64.StdEncoding.EncodeToString(wire)); err != nil {
		t.Fatalf("protobuf form: %v", err)
	}

	if !proto.Equal(fromJSON.attestorAuthRequest, fromProto.attestorAuthRequest) {
		t.Error("the two encodings decoded to different requests")
	}
}

func TestSetAttestorAuthRequestEmptyClears(t *testing.T) {
	c := newAuthTestClient(t)
	c.attestorAuthRequest = &teeproto.AuthenticationRequest{}

	if err := c.setAttestorAuthRequest(""); err != nil {
		t.Fatalf("setAttestorAuthRequest(\"\"): %v", err)
	}
	if c.attestorAuthRequest != nil {
		t.Error("empty input should clear the stored request")
	}
}

func TestSetAttestorAuthRequestRejectsUnknownJSONFields(t *testing.T) {
	// Strict parsing on purpose. A decoder that skipped unknown fields would
	// accept a misspelled expiry and store a request with no expiry at all.
	bad := `{"data":{"id":"user-1","expiresAtS":1739880600},"signature":"TUVVQ0lRRA=="}`

	c := newAuthTestClient(t)
	err := c.setAttestorAuthRequest(base64.StdEncoding.EncodeToString([]byte(bad)))
	if err == nil {
		t.Fatal("expected an unknown field to be rejected")
	}
	if !strings.Contains(err.Error(), "expiresAtS") {
		t.Errorf("expected the error to name the offending field, got: %v", err)
	}
	if c.attestorAuthRequest != nil {
		t.Error("a rejected request must not be stored")
	}
}

func TestSetAttestorAuthRequestErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"not base64", "not base64!!", "base64-decode"},
		{"base64 of neither encoding", base64.StdEncoding.EncodeToString([]byte("hello there")), "unmarshal"},
		{"malformed JSON", base64.StdEncoding.EncodeToString([]byte(`{"data":`)), "JSON auth request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newAuthTestClient(t)
			err := c.setAttestorAuthRequest(tc.input)
			if err == nil {
				t.Fatalf("expected an error for %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestJSONDetectionToleratesLeadingWhitespace(t *testing.T) {
	c := newAuthTestClient(t)
	padded := "\n  " + sdkJSONAuthRequest

	if err := c.setAttestorAuthRequest(base64.StdEncoding.EncodeToString([]byte(padded))); err != nil {
		t.Fatalf("setAttestorAuthRequest: %v", err)
	}
	if got := c.attestorAuthRequest.GetData().GetExpiresAt(); got != 1739880600 {
		t.Errorf("expiresAt = %d", got)
	}
}

// TestProtobufIsNeverDetectedAsJSON guards the encoding sniff.
//
// Every AuthenticationRequest begins with 0x0a, which is also a newline, so a
// naive leading-byte check has to survive whitespace trimming. This walks a
// wide spread of real messages and asserts none is routed to the JSON decoder.
func TestProtobufIsNeverDetectedAsJSON(t *testing.T) {
	for i := range 2000 {
		msg := &teeproto.AuthenticationRequest{
			Data: &teeproto.AuthenticatedUserData{
				Id:            strings.Repeat("u", i%40),
				CreatedAt:     uint32(i * 7919),
				ExpiresAt:     uint32(i * 104729),
				HostWhitelist: []string{strings.Repeat("h", i%30) + ".example.com"},
			},
			Signature: bytes.Repeat([]byte{byte(i)}, i%64),
		}
		wire, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("proto.Marshal: %v", err)
		}

		c := newAuthTestClient(t)
		if err := c.setAttestorAuthRequest(base64.StdEncoding.EncodeToString(wire)); err != nil {
			t.Fatalf("i=%d: protobuf rejected: %v (first bytes % x)", i, err, wire[:min(8, len(wire))])
		}
		if !proto.Equal(c.attestorAuthRequest, msg) {
			t.Fatalf("i=%d: decoded to a different message", i)
		}
	}
}
