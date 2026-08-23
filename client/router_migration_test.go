package client

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestAllocatePairAdvertisesMigrationAttestations(t *testing.T) {
	var got struct {
		ClientNonce string   `json:"client_nonce"`
		Accepts     []string `json:"accepts"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.UnmarshalRead(r.Body, &got); err != nil {
			t.Errorf("decode allocation request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pair_id":"p","teek_addr":"k","teet_addr":"t","jwt":"j"}`))
	}))
	defer server.Close()

	if _, err := AllocatePair(server.URL, "nonce"); err != nil {
		t.Fatalf("AllocatePair: %v", err)
	}
	if got.ClientNonce != "nonce" {
		t.Fatalf("client nonce = %q, want nonce", got.ClientNonce)
	}
	for _, attType := range []string{"cs", "sev-snp", "secure-boot"} {
		if !slices.Contains(got.Accepts, attType) {
			t.Fatalf("accepts = %v, missing %q", got.Accepts, attType)
		}
	}
}

func TestClientBuildVersionSecureBoot(t *testing.T) {
	if ClientBuildVersion != "secure-boot" {
		t.Fatalf("ClientBuildVersion = %q, want secure-boot", ClientBuildVersion)
	}
}
