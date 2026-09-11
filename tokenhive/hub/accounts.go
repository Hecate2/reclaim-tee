package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrInsufficientFunds means the tenant's prepaid balance cannot cover the
// hold another job needs. Like the quota it is refused before dispatch, so
// the provider is never asked to spend a credential on a job the buyer
// cannot pay for.
var ErrInsufficientFunds = errors.New("tenant prepaid balance exhausted")

// ErrAccountsNeedCeiling means Accounts was configured without MaxJobMicros.
// The prepaid hold is sized by the per-job ceiling: a job is admitted only
// when the tenant's available balance covers it, and nothing else bounds what
// one job can bill. Without a ceiling there is no hold to take, so enabling
// accounts without one is a construction error, not a runtime surprise.
var ErrAccountsNeedCeiling = errors.New("accounts enabled without MaxJobMicros: the prepaid hold needs a per-job ceiling")

// ErrAccountsBroken means the balance file could not be written the last time
// money moved. The in-memory balances are then ahead of the disk, so
// accounting refuses every new hold until the process is restarted against a
// fixed file — fail-closed, the same shape as the serve-mode key
// requirements. Settles already in flight still book in memory (their holds
// must go somewhere), which is exactly the gap the refusal bounds.
var ErrAccountsBroken = errors.New("balance persistence failed; refusing new jobs until restart")

// accountsFile is the on-disk shape of the balance ledger.
//
// All three roles live in one document so that a settlement writes the buyer's
// charge, the seller's credit and the Hub's commission in a single atomic
// rewrite. There is no ordering in which a buyer can be debited while the
// matching seller/platform credit is lost: a crash loses the whole settlement
// (detectable, because the receipt is already stored) or none of it.
type accountsFile struct {
	Tenants  map[string]uint64 `json:"tenants"`
	Sellers  map[string]uint64 `json:"sellers,omitempty"`
	Platform uint64            `json:"platform,omitempty"`
}

// Accounts is the Hub's durable balance ledger. It keeps every role the money
// system has: one prepaid balance per buyer (tenant), the amount owed to each
// seller (provider), and the Hub's own accumulated commission.
//
// Buyer debt is impossible by construction. Every job takes a hold of exactly
// MaxJobMicros before dispatch (available = balance - held must cover it), a
// settled buyer bill is capped at MaxJobMicros (ErrJobPriceExceeded), and
// settle converts the hold into the charge, so balance >= held*hold always
// holds and a settle can never push the balance below zero. A tenant with no
// money — or less money than one hold — is refused before a provider is ever
// asked to spend a credential.
//
// Seller and platform money moves only as the mirror image of a buyer charge:
// the split is validated to add up (seller + commission == buyer) before any
// balance changes, so a settlement can neither create nor destroy money.
//
// Persistence shape: a single JSON file rewritten atomically (temporary file,
// fsync, rename, fsync of the directory) on every settled mutation. Holds and
// releases are deliberately not persisted: a hold exists only while its job
// runs, jobs do not survive a process restart, and replaying stale holds
// would freeze money for jobs that no longer exist. Seller payables and the
// platform balance are settled state, so they ride along with the buyer charge
// that created them. The file therefore reads back as exactly the settled
// state, and the only crash window is a settlement whose file write never
// landed — the receipt is already in the provider's store, so the gap is
// detectable there, the same direction as every other "executed but unbilled"
// path.
type Accounts struct {
	path string

	mu       sync.Mutex
	balance  map[string]uint64 // buyer prepaid balances, by tenant
	held     map[string]uint64 // buyer holds (memory only: a hold dies with its job)
	sellers  map[string]uint64 // seller payables, by provider
	platform uint64            // the Hub's cumulative commission

	// total is the ledger's conserved quantity: every buyer balance, every
	// seller payable and the platform balance. It moves only when external
	// money enters (the first-boot seed today, a real deposit later), because a
	// settlement is a pure transfer between accounts. Re-derived on load and
	// re-checked after each settlement, it is what turns "a write path forgot
	// one side" from silent money creation into a refused, fail-closed job.
	total uint64

	broken bool
}

// OpenAccounts loads the balance file at path, creating it with the given
// seed balances when it does not exist yet. The seeds apply only on that
// first creation: re-applying them on every start would silently refund a
// drained tenant. An existing file is the truth; the caller learns whether it
// was fresh so it can explain ignored seeds. A malformed seed (empty tenant,
// zero amount) is a startup failure rather than a silently unfunded tenant.
func OpenAccounts(path string, seeds map[string]uint64) (*Accounts, bool, error) {
	a := &Accounts{
		path:    path,
		balance: make(map[string]uint64),
		held:    make(map[string]uint64),
		sellers: make(map[string]uint64),
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		for tenant, micros := range seeds {
			if tenant == "" {
				return nil, false, fmt.Errorf("accounts seed with empty tenant name")
			}
			if micros == 0 {
				return nil, false, fmt.Errorf("accounts seed for tenant %q is zero, which would fund nothing", tenant)
			}
			a.balance[tenant] = micros
		}
		total, err := a.ledgerTotalLocked()
		if err != nil {
			return nil, false, err
		}
		a.total = total
		if err := a.persistLocked(); err != nil {
			return nil, false, err
		}
		return a, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	var doc accountsFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("parse balance file %s: %w", path, err)
	}
	if doc.Tenants != nil {
		a.balance = doc.Tenants
	}
	if doc.Sellers != nil {
		a.sellers = doc.Sellers
	}
	a.platform = doc.Platform
	total, err := a.ledgerTotalLocked()
	if err != nil {
		return nil, false, fmt.Errorf("balance file %s: %w", path, err)
	}
	a.total = total
	return a, false, nil
}

// Hold reserves amount for one job: the tenant's available balance must cover
// it, and a tenant with no file presence has a zero balance and is refused
// without ever creating an entry. Refusing creates no state, so tenant names
// an attacker invents cannot grow the tables.
func (a *Accounts) Hold(tenant string, amount uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.broken {
		return ErrAccountsBroken
	}
	balance, held := a.balance[tenant], a.held[tenant]
	if held > balance || balance-held < amount {
		return fmt.Errorf("%w: tenant %q has %d available, needs %d", ErrInsufficientFunds, tenant, balance-held, amount)
	}
	a.held[tenant] = held + amount
	return nil
}

// Settle converts an active hold into the buyer's actual charge and credits the
// seller and the platform in the same atomic rewrite: the hold leaves the held
// pool, the buyer bill leaves the buyer balance, and the seller's price plus
// the Hub's commission land on their accounts. The three movements are one
// persisted state, so no crash can debit a buyer without paying the seller.
//
// price above hold is a Hub bug (the per-job ceiling is what sized the hold)
// and is refused rather than booked, as is a split that does not add up
// (seller + commission != buyer) — a settlement must be exactly zero-sum.
func (a *Accounts) Settle(tenant string, hold, buyer uint64, provider string, seller, commission uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := validSplit(provider, buyer, seller, commission); err != nil {
		a.broken = true
		return err
	}
	if buyer > hold {
		a.broken = true
		return fmt.Errorf("settle for tenant %q: buyer %d exceeds hold %d", tenant, buyer, hold)
	}
	if a.held[tenant] < hold {
		a.broken = true
		return fmt.Errorf("settle for tenant %q: held %d does not cover hold %d", tenant, a.held[tenant], hold)
	}
	if a.balance[tenant] < buyer {
		a.broken = true
		return fmt.Errorf("settle for tenant %q: balance %d cannot cover buyer %d", tenant, a.balance[tenant], buyer)
	}
	sellerBalance, platform, err := addCredits(a.sellers[provider], seller, a.platform, commission)
	if err != nil {
		a.broken = true
		return fmt.Errorf("settle for provider %q: %w", provider, err)
	}
	a.held[tenant] -= hold
	a.balance[tenant] -= buyer
	a.sellers[provider] = sellerBalance
	a.platform = platform
	if err := a.checkConservationLocked(); err != nil {
		a.broken = true
		return err
	}
	if err := a.persistLocked(); err != nil {
		a.broken = true
		return err
	}
	return nil
}

// Charge bills a buyer whose hold is already gone — the one ordering a
// watchdog-closed session can produce: the connection close releases the hold
// before the truncated receipt is priced, and the charge is still due. The
// seller and platform are credited exactly as in Settle. The debt-safety
// argument is unchanged (the hold backed this job at admission and every
// competing hold backs its own), and a balance that cannot cover the price is
// a bug, refused and marked broken rather than booked negative.
func (a *Accounts) Charge(tenant string, buyer uint64, provider string, seller, commission uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := validSplit(provider, buyer, seller, commission); err != nil {
		a.broken = true
		return err
	}
	if a.balance[tenant] < buyer {
		a.broken = true
		return fmt.Errorf("charge for tenant %q: balance %d cannot cover buyer %d", tenant, a.balance[tenant], buyer)
	}
	sellerBalance, platform, err := addCredits(a.sellers[provider], seller, a.platform, commission)
	if err != nil {
		a.broken = true
		return fmt.Errorf("charge for provider %q: %w", provider, err)
	}
	a.balance[tenant] -= buyer
	a.sellers[provider] = sellerBalance
	a.platform = platform
	if err := a.checkConservationLocked(); err != nil {
		a.broken = true
		return err
	}
	if err := a.persistLocked(); err != nil {
		a.broken = true
		return err
	}
	return nil
}

// ReleaseHold returns an unspent hold. It exists only in memory, so nothing
// is persisted.
func (a *Accounts) ReleaseHold(tenant string, hold uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch h := a.held[tenant]; {
	case h <= hold:
		delete(a.held, tenant)
	default:
		a.held[tenant] = h - hold
	}
}

// Available reports what the tenant can still spend: balance minus holds.
// It exists for tests and operators; enforcement reads the same numbers
// under the same lock inside Hold.
func (a *Accounts) Available(tenant string) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	balance, held := a.balance[tenant], a.held[tenant]
	if held >= balance {
		return 0
	}
	return balance - held
}

// SellerBalance reports what the Hub owes one provider: every settled charge
// that provider earned, accumulated since the file was created.
func (a *Accounts) SellerBalance(provider string) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.sellers[provider]
}

// PlatformBalance reports the Hub's own cumulative commission.
func (a *Accounts) PlatformBalance() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.platform
}

// validSplit checks that a settlement is exactly zero-sum across the three
// roles and that there is a provider to credit. A mismatch is a Hub bug (the
// buyer bill is built as charged + commission), so it must refuse the whole
// settlement rather than move money that does not reconcile.
func validSplit(provider string, buyer, seller, commission uint64) error {
	if provider == "" {
		return errors.New("settlement with an empty provider: the seller credit would have no account")
	}
	total, ok := addChecked(seller, commission)
	if !ok {
		return fmt.Errorf("settlement split overflows: seller %d + commission %d", seller, commission)
	}
	if total != buyer {
		return fmt.Errorf("settlement split does not add up: seller %d + commission %d != buyer %d", seller, commission, buyer)
	}
	return nil
}

// ledgerTotalLocked adds up every account. Holds are deliberately excluded:
// they are a reclassification of an existing buyer balance, not new money.
func (a *Accounts) ledgerTotalLocked() (uint64, error) {
	var total uint64
	add := func(v uint64) error {
		next, ok := addChecked(total, v)
		if !ok {
			return fmt.Errorf("ledger total overflows at %d + %d", total, v)
		}
		total = next
		return nil
	}
	for _, v := range a.balance {
		if err := add(v); err != nil {
			return 0, err
		}
	}
	for _, v := range a.sellers {
		if err := add(v); err != nil {
			return 0, err
		}
	}
	if err := add(a.platform); err != nil {
		return 0, err
	}
	return total, nil
}

// checkConservationLocked re-derives the ledger total and compares it with the
// invariant established at load. A settlement only moves money between the
// three roles, so a changed total means a mutation credited or dropped a side
// — the one class of bug that silently creates or destroys money. The pass is
// the same order as the atomic rewrite that follows it (which serializes and
// fsyncs these very maps), so it costs nothing next to the write it guards.
func (a *Accounts) checkConservationLocked() error {
	total, err := a.ledgerTotalLocked()
	if err != nil {
		return err
	}
	if total != a.total {
		return fmt.Errorf("ledger does not conserve: total %d, want %d (a settlement moved money without its counterpart)", total, a.total)
	}
	return nil
}

// addCredits applies the seller and platform sides of a settlement with
// overflow checks, returning the new values without mutating anything so a
// failure leaves the ledger untouched.
func addCredits(sellerHave, seller, platformHave, commission uint64) (uint64, uint64, error) {
	sellerBalance, ok := addChecked(sellerHave, seller)
	if !ok {
		return 0, 0, fmt.Errorf("seller balance %d + %d overflows", sellerHave, seller)
	}
	platform, ok := addChecked(platformHave, commission)
	if !ok {
		return 0, 0, fmt.Errorf("platform balance %d + %d overflows", platformHave, commission)
	}
	return sellerBalance, platform, nil
}

// persistLocked rewrites the balance file atomically: write a temporary file
// beside it, fsync it, rename over the target, fsync the directory so the
// rename itself is durable. A crash mid-write leaves either the old file or
// the new one, never a partial one.
func (a *Accounts) persistLocked() error {
	doc := accountsFile{
		Tenants:  a.balance,
		Sellers:  a.sellers,
		Platform: a.platform,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode balance file %s: %w", a.path, err)
	}
	tmp := a.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write balance file %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write balance file %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync balance file %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close balance file %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, a.path); err != nil {
		return fmt.Errorf("install balance file %s: %w", a.path, err)
	}
	if dir, err := os.Open(filepath.Dir(a.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
