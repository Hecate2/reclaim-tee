package hub

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

const (
	testHold = 2_000_000 // the per-job ceiling every test here holds against
	testBill = 1_000_000 // what the default test rate card bills per job
)

func openTestAccounts(t *testing.T, seeds map[string]uint64) (*Accounts, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	acc, _, err := OpenAccounts(path, seeds)
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	return acc, path
}

func TestAccountsSeedOnlyOnFirstCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	acc, fresh, err := OpenAccounts(path, map[string]uint64{"alice": 100})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	if !fresh {
		t.Fatalf("a first create must report fresh")
	}
	if got := acc.Available("alice"); got != 100 {
		t.Fatalf("available = %d, want 100", got)
	}
	again, fresh, err := OpenAccounts(path, map[string]uint64{"alice": 100})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if fresh {
		t.Fatalf("an existing file must not report fresh: re-seeding would refund a drained tenant")
	}
	if got := again.Available("alice"); got != 100 {
		t.Fatalf("available after reopen = %d, want 100 (the seed must not be re-applied)", got)
	}
}

func TestHoldGatesOnBalance(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	if err := acc.Hold("nobody", testHold); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("unfunded tenant hold err = %v, want ErrInsufficientFunds", err)
	}
	if acc.Available("nobody") != 0 {
		t.Fatalf("a refused hold must not create state for the tenant")
	}
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold within balance: %v", err)
	}
	if err := acc.Hold("alice", 1); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("second hold with the balance fully held err = %v, want ErrInsufficientFunds", err)
	}
	acc.ReleaseHold("alice", testHold)
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold after release: %v", err)
	}
}

func TestSettleConvertsHoldToCharge(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle("alice", testHold, testBill); err != nil {
		t.Fatalf("settle: %v", err)
	}
	// balance 3M - 1M = 2M, nothing held: a new job must admit again.
	if got := acc.Available("alice"); got != 2*testBill {
		t.Fatalf("available after settle = %d, want %d", got, 2*testBill)
	}
	if err := acc.Settle("alice", testHold, testHold+1); err == nil {
		t.Fatalf("a price above the hold is a Hub bug and must be refused")
	}
	if got := acc.Available("alice"); got != 2*testBill {
		t.Fatalf("a refused settle must not move money: available = %d", got)
	}
}

func TestChargeBillsAfterRelease(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	acc.ReleaseHold("alice", testHold)
	if err := acc.Charge("alice", testBill); err != nil {
		t.Fatalf("charge after release: %v", err)
	}
	if got := acc.Available("alice"); got != testHold-testBill {
		t.Fatalf("available after charge = %d, want %d", got, testHold-testBill)
	}
	if err := acc.Charge("alice", testHold); err == nil {
		t.Fatalf("a charge beyond the balance is a bug and must be refused, not booked negative")
	}
}

func TestAccountsPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	acc, _, err := OpenAccounts(path, map[string]uint64{"alice": 3 * testBill})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle("alice", testHold, testBill); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}

	again, _, err := OpenAccounts(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// The settle is on disk; the open hold is not — its job died with the
	// process, and replaying it would freeze the money forever.
	if got := again.Available("alice"); got != 2*testBill {
		t.Fatalf("available after reopen = %d, want %d (settle persisted, hold forgotten)", got, 2*testBill)
	}
}

func TestBrokenAccountsRefuseNewHolds(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	// Point the file at a directory: every write fails, which is what a full
	// disk or an IO error does to persistLocked.
	acc.path = t.TempDir()
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle("alice", testHold, testBill); err == nil {
		t.Fatalf("a settle that cannot persist must fail")
	}
	if err := acc.Hold("alice", testHold); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("hold after persistence failure err = %v, want ErrAccountsBroken", err)
	}
}

func TestAccountsRequireCeiling(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)
	_, err := New(Config{
		TEE:      &ScriptedTEE{},
		Rates:    ratesTable(map[string]RateCard{}),
		Store:    NewReceiptStore(t.TempDir()),
		Verify:   acceptAll,
		Accounts: acc,
	})
	if !errors.Is(err, ErrAccountsNeedCeiling) {
		t.Fatalf("accounts without MaxJobMicros err = %v, want ErrAccountsNeedCeiling", err)
	}
}

// --- end to end: no money, no service --------------------------------------

func TestPrepaidBalanceGatesDispatch(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"rich": 2 * testHold})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		return Result{Receipt: makeReceipt(uint64(call), nil, func(r *proof.Receipt) {
			r.Provider = spec.Provider
		})}, nil
	}}
	h := mustHub(t, Config{TEE: fake, Accounts: acc, MaxJobMicros: testHold})

	run := func(tenant string) error {
		_, err := h.Execute(context.Background(), tenant, "m", testSpec(testProvider, "m"), nil, nil)
		return err
	}

	if err := run("nobody"); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("unfunded tenant err = %v, want ErrInsufficientFunds", err)
	}
	if err := run("rich"); err != nil {
		t.Fatalf("funded tenant: %v", err)
	}
	if err := run("rich"); err != nil {
		t.Fatalf("second job within balance: %v", err)
	}
	if err := run("rich"); err != nil {
		t.Fatalf("third job still backed by a full hold: %v", err)
	}
	if got := acc.Available("rich"); got != testHold-testBill {
		t.Fatalf("available after three jobs = %d, want %d", got, testHold-testBill)
	}
	// The remaining balance no longer backs one hold: the next job cannot be
	// admitted, so it is refused before dispatch.
	if err := run("rich"); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("drained tenant err = %v, want ErrInsufficientFunds", err)
	}
	if got := acc.Available("rich"); got != testHold-testBill {
		t.Fatalf("a refused job must not move money: available = %d", got)
	}
}

func TestJobSpendSettleAndReleaseAreOnce(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testHold})
	h := mustHub(t, Config{TEE: &ScriptedTEE{}, Accounts: acc, MaxJobMicros: testHold})

	spend, err := h.beginJob("alice")
	if err != nil {
		t.Fatalf("beginJob: %v", err)
	}
	if got := acc.Available("alice"); got != 2*testHold {
		t.Fatalf("available under hold = %d, want %d", got, 2*testHold)
	}
	// The normal request shape: settle, then the deferred release. The hold
	// is consumed once, the slot returns, the balance drops once.
	spend.settle(testBill)
	spend.release()
	spend.release()
	if got := acc.Available("alice"); got != 3*testHold-testBill {
		t.Fatalf("available after settle+release = %d, want %d", got, 3*testHold-testBill)
	}

	// The watchdog shape: release fires first (hold returned), the charge is
	// still due afterwards.
	spend2, err := h.beginJob("alice")
	if err != nil {
		t.Fatalf("beginJob: %v", err)
	}
	spend2.release()
	if got := acc.Available("alice"); got != 3*testHold-testBill {
		t.Fatalf("release must return the hold in full: available = %d", got)
	}
	spend2.settle(testBill)
	if got := acc.Available("alice"); got != 3*testHold-2*testBill {
		t.Fatalf("charge after release must bill: available = %d, want %d", got, 3*testHold-2*testBill)
	}
	if h.flight.active("alice") != 0 {
		t.Fatalf("both spends released: the in-flight table must be empty")
	}
}
