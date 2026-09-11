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
	if err := acc.Settle("alice", testHold, testBill, testProvider, testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	// balance 3M - 1M = 2M, nothing held: a new job must admit again.
	if got := acc.Available("alice"); got != 2*testBill {
		t.Fatalf("available after settle = %d, want %d", got, 2*testBill)
	}
	if err := acc.Settle("alice", testHold, testHold+1, testProvider, testHold+1, 0); err == nil {
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
	if err := acc.Charge("alice", testBill, testProvider, testBill, 0); err != nil {
		t.Fatalf("charge after release: %v", err)
	}
	if got := acc.Available("alice"); got != testHold-testBill {
		t.Fatalf("available after charge = %d, want %d", got, testHold-testBill)
	}
	if err := acc.Charge("alice", testHold, testProvider, testHold, 0); err == nil {
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
	if err := acc.Settle("alice", testHold, testBill, testProvider, testBill, 0); err != nil {
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
	if err := acc.Settle("alice", testHold, testBill, testProvider, testBill, 0); err == nil {
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
	// The seller side is credited by the same settlement that bills the buyer:
	// three settled jobs, three times the provider's price.
	if got := acc.SellerBalance(testProvider); got != 3*testBill {
		t.Fatalf("seller balance across three settled jobs = %d, want %d", got, 3*testBill)
	}
	if got := acc.PlatformBalance(); got != 0 {
		t.Fatalf("platform balance with no commission configured = %d, want 0", got)
	}
}

// --- seller and platform money ---------------------------------------------

// testProviderFee is the seller's share of a testBill job; the rest is the
// Hub's commission. It is deliberately not a round half so a mix-up between
// the two accounts shows up as an exact-number failure.
const testProviderFee = 800_000

func TestSettleCreditsSellerAndPlatform(t *testing.T) {
	acc, path := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	commission := uint64(testBill - testProviderFee)
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle("alice", testHold, testBill, testProvider, testProviderFee, commission); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if got := acc.SellerBalance(testProvider); got != testProviderFee {
		t.Fatalf("seller balance = %d, want %d", got, testProviderFee)
	}
	if got := acc.PlatformBalance(); got != commission {
		t.Fatalf("platform balance = %d, want %d", got, commission)
	}

	// The money must be on disk, not just in memory: reopening is what turns
	// "we recorded it" into "we still owe it" after a restart.
	again, _, err := OpenAccounts(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := again.SellerBalance(testProvider); got != testProviderFee {
		t.Fatalf("seller balance after reopen = %d, want %d", got, testProviderFee)
	}
	if got := again.PlatformBalance(); got != commission {
		t.Fatalf("platform balance after reopen = %d, want %d", got, commission)
	}

	// The reopen established a fresh conservation baseline; a further
	// settlement has to clear it as well.
	if err := again.Hold("alice", testHold); err != nil {
		t.Fatalf("hold after reopen: %v", err)
	}
	if err := again.Settle("alice", testHold, testBill, testProvider, testProviderFee, commission); err != nil {
		t.Fatalf("settle after reopen: %v", err)
	}
	if got := again.SellerBalance(testProvider); got != 2*testProviderFee {
		t.Fatalf("seller balance after a second settlement = %d, want %d", got, 2*testProviderFee)
	}
}

func TestChargeCreditsSellerAndPlatform(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	acc.ReleaseHold("alice", testHold)
	if err := acc.Charge("alice", testBill, testProvider, testProviderFee, testBill-testProviderFee); err != nil {
		t.Fatalf("charge after release: %v", err)
	}
	if got := acc.SellerBalance(testProvider); got != testProviderFee {
		t.Fatalf("seller balance = %d, want %d", got, testProviderFee)
	}
	if got := acc.PlatformBalance(); got != testBill-testProviderFee {
		t.Fatalf("platform balance = %d, want %d", got, testBill-testProviderFee)
	}
}

func TestSettleRejectsASplitThatDoesNotAddUp(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	// seller + commission > buyer: booking this would create money out of
	// nothing, so the whole settlement must be refused.
	if err := acc.Settle("alice", testHold, testBill, testProvider, testBill, 1); err == nil {
		t.Fatalf("a split that does not add up must be refused")
	}
	if got := acc.SellerBalance(testProvider); got != 0 {
		t.Fatalf("seller balance after a refused split = %d, want 0", got)
	}
	if got := acc.PlatformBalance(); got != 0 {
		t.Fatalf("platform balance after a refused split = %d, want 0", got)
	}
	// The hold is still active (nothing settled), so 3M seeded minus the 2M
	// hold leaves exactly one job's worth available.
	if got := acc.Available("alice"); got != testBill {
		t.Fatalf("available after a refused split = %d, want %d", got, testBill)
	}
	if err := acc.Hold("alice", testHold); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("hold after a refused split err = %v, want ErrAccountsBroken", err)
	}
}

func TestSettleRejectsAnEmptyProvider(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle("alice", testHold, testBill, "", testBill, 0); err == nil {
		t.Fatalf("a settlement with no provider to credit must be refused")
	}
}

func TestSellerPayablesAccumulatePerProvider(t *testing.T) {
	// Four jobs' worth: each admission needs a full hold available, so the
	// starting balance has to outlast the charges themselves.
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 4 * testBill})

	for i := 0; i < 2; i++ {
		if err := acc.Hold("alice", testHold); err != nil {
			t.Fatalf("hold %d: %v", i, err)
		}
		if err := acc.Settle("alice", testHold, testBill, "cheap", testBill, 0); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle("alice", testHold, testBill, "dear", testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if got := acc.SellerBalance("cheap"); got != 2*testBill {
		t.Fatalf("cheap seller balance = %d, want %d", got, 2*testBill)
	}
	if got := acc.SellerBalance("dear"); got != testBill {
		t.Fatalf("dear seller balance = %d, want %d", got, testBill)
	}
	if got := acc.SellerBalance("unknown"); got != 0 {
		t.Fatalf("an unknown provider has no payable, got %d", got)
	}
}

func TestSettleRefusesANonConservingLedger(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})
	if err := acc.Hold("alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}

	// Simulate a write path that credited a seller without a matching buyer
	// charge: the next settlement must notice that the ledger total moved and
	// fail closed rather than keep booking over books that no longer add up.
	acc.mu.Lock()
	acc.sellers[testProvider] = 1
	acc.mu.Unlock()

	if err := acc.Settle("alice", testHold, testBill, testProvider, testBill, 0); err == nil {
		t.Fatalf("a settlement over a non-conserving ledger must be refused")
	}
	if err := acc.Hold("alice", testHold); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("hold after a conservation failure err = %v, want ErrAccountsBroken", err)
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
	spend.settle(testProvider, testBill, testBill, 0)
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
	spend2.settle(testProvider, testBill, testBill, 0)
	if got := acc.Available("alice"); got != 3*testHold-2*testBill {
		t.Fatalf("charge after release must bill: available = %d, want %d", got, 3*testHold-2*testBill)
	}
	if h.flight.active("alice") != 0 {
		t.Fatalf("both spends released: the in-flight table must be empty")
	}
}
