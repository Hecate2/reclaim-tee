package main

import (
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
)

func TestRequireServeKeys(t *testing.T) {
	// A real Accounts value stands in for "billing configured"; nil is the
	// "no balance file" case serve mode must refuse.
	accounts, _, err := hub.OpenAccounts(t.TempDir()+"/accounts.json", map[string]uint64{"t": 1})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	cases := []struct {
		name      string
		serveAddr string
		agentKeys string
		relayKey  string
		accounts  *hub.Accounts
		maxJob    uint64
		wantErr   string
	}{
		{name: "cli one-shot mode needs nothing"},
		{name: "serve mode requires agent keys", serveAddr: ":18085", relayKey: "r", accounts: accounts, maxJob: 1,
			wantErr: "agent-keys"},
		{name: "serve mode requires relay key", serveAddr: ":18085", agentKeys: "p=k", accounts: accounts, maxJob: 1,
			wantErr: "relay-key"},
		{name: "serve mode requires the balance file", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r", maxJob: 1,
			wantErr: "-accounts"},
		{name: "serve mode requires a per-job ceiling", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r", accounts: accounts,
			wantErr: "max-job-micros"},
		{name: "serve mode fully configured", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r", accounts: accounts, maxJob: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireServeKeys(tc.serveAddr, tc.agentKeys, tc.relayKey, tc.accounts, tc.maxJob)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("requireServeKeys(%q, %q, %q) = %v, want nil", tc.serveAddr, tc.agentKeys, tc.relayKey, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("requireServeKeys(%q, %q, %q) = %v, want error containing %q",
					tc.serveAddr, tc.agentKeys, tc.relayKey, err, tc.wantErr)
			}
		})
	}
}
