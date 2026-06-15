package auth

import (
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

func newTestAllowlist(t *testing.T, seed []string) *Allowlist {
	t.Helper()
	a, err := NewAllowlist(t.Context(), store.NewMemoryStore(), seed, zap.NewNop())
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	t.Cleanup(a.Stop)
	return a
}

func TestAllowlist(t *testing.T) {
	a := newTestAllowlist(t, []string{"sha256:aaa", "sha256:bbb"})
	if !a.Contains("sha256:aaa") {
		t.Fatal("expected aaa to be allowed")
	}
	if !a.Contains("sha256:bbb") {
		t.Fatal("expected bbb to be allowed")
	}
	if a.Contains("sha256:ccc") {
		t.Fatal("ccc should not be allowed")
	}
	if a.Contains("") {
		t.Fatal("empty digest should not be allowed")
	}
}

func TestAllowlist_AddRemove(t *testing.T) {
	a := newTestAllowlist(t, nil)
	if a.Contains("sha256:zzz") {
		t.Fatal("empty allowlist should reject")
	}
	if err := a.Add(t.Context(), "sha256:zzz"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !a.Contains("sha256:zzz") {
		t.Fatal("zzz should be allowed after Add")
	}
	if err := a.Remove(t.Context(), "sha256:zzz"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if a.Contains("sha256:zzz") {
		t.Fatal("zzz should not be allowed after Remove")
	}
}

func TestAllowlist_SeedOnlyWhenStoreEmpty(t *testing.T) {
	st := store.NewMemoryStore()
	if err := st.AddDigest(t.Context(), "sha256:pre-existing"); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	// Seed should be IGNORED because the store already has data — the
	// admin-API source of truth wins over the env-var seed once anything
	// has been written.
	a, err := NewAllowlist(t.Context(), st, []string{"sha256:seed-only"}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	defer a.Stop()
	if !a.Contains("sha256:pre-existing") {
		t.Fatal("store contents should win")
	}
	if a.Contains("sha256:seed-only") {
		t.Fatal("seed should not overwrite non-empty store")
	}
}
