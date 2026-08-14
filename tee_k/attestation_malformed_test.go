package main

import (
	"strings"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
)

func TestVerifyTEETAttestationRejectsMalformedNestedMessages(t *testing.T) {
	tests := []struct {
		name string
		env  *teeproto.Envelope
		want string
	}{
		{
			name: "nil error data",
			env:  &teeproto.Envelope{Payload: &teeproto.Envelope_Error{}},
			want: "missing error data",
		},
		{
			name: "nil response",
			env:  &teeproto.Envelope{Payload: &teeproto.Envelope_TeetAttestation{}},
			want: "missing response",
		},
		{
			name: "nil report",
			env: &teeproto.Envelope{Payload: &teeproto.Envelope_TeetAttestation{
				TeetAttestation: &teeproto.TEETAttestationResponse{},
			}},
			want: "missing report",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := teetAttestationReportFromEnvelope(test.env)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verification error = %v, want %q", err, test.want)
			}
		})
	}
}
