package main

import (
	"strings"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestVerifyTEEKAttestationRejectsMissingNestedMessages(t *testing.T) {
	teet := &TEET{logger: shared.NewNopLogger()}
	tests := []struct {
		name string
		req  *teeproto.TEEKAttestationRequest
		want string
	}{
		{name: "nil request", want: "missing request"},
		{name: "nil report", req: &teeproto.TEEKAttestationRequest{}, want: "missing report"},
		{
			name: "unknown report type",
			req: &teeproto.TEEKAttestationRequest{AttestationReport: &teeproto.AttestationReport{
				Type: "future-unrecognized-type", Report: []byte("not a GCP token"),
			}},
			want: "unsupported attestation type",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := teet.verifyTEEKAttestation(test.req, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verification error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTEEKAttestationEnvelopeRejectsMalformedNestedMessages(t *testing.T) {
	tests := []struct {
		name string
		env  *teeproto.Envelope
		want string
	}{
		{name: "nil envelope", want: "missing envelope"},
		{
			name: "nil error data",
			env:  &teeproto.Envelope{Payload: &teeproto.Envelope_Error{}},
			want: "missing error data",
		},
		{
			name: "nil request",
			env:  &teeproto.Envelope{Payload: &teeproto.Envelope_TeekAttestation{}},
			want: "missing request",
		},
		{
			name: "nil report",
			env: &teeproto.Envelope{Payload: &teeproto.Envelope_TeekAttestation{
				TeekAttestation: &teeproto.TEEKAttestationRequest{},
			}},
			want: "missing report",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := teekAttestationRequestFromEnvelope(test.env)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("envelope error = %v, want %q", err, test.want)
			}
		})
	}
}
