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

// Accounts is the Hub's prepaid-balance ledger: one balance per tenant, with
// the balance file on disk as the only authoritative record.
//
// Debt is impossible by construction. Every job takes a hold of exactly
// MaxJobMicros before dispatch (available = balance - held must cover it), a
// settled buyer bill is capped at MaxJobMicros (ErrJobPriceExceeded), and
// settle converts the hold into the charge, so balance >= held*hold always
// holds and a settle can never push the balance below zero. A tenant with no
// money — or less money than one hold — is refused before a provider is ever
// asked to spend a credential.
//
// Persistence shape: a single JSON file rewritten atomically (temporary file,
// fsync, rename, fsync of the directory) on every balance mutation. Holds and
// releases are deliberately not persisted: a hold exists only while its job
// runs, jobs do not survive a process restart, and replaying stale holds
// would freeze money for jobs that no longer exist. The file therefore reads
// back as exactly the settled state, and the only crash window is a charge
// whose file write never landed — the receipt is already in the provider's
// store, so the gap is detectable there, the same direction as every other
// "executed but unbilled" path.
type Accounts struct {
	path string

	mu      sync.Mutex
	balance map[string]uint64
	held    map[string]uint64
	broken  bool
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
		if err := a.persistLocked(); err != nil {
			return nil, false, err
		}
		return a, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	var doc struct {
		Tenants map[string]uint64 `json:"tenants"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("parse balance file %s: %w", path, err)
	}
	if doc.Tenants != nil {
		a.balance = doc.Tenants
	}
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

// Settle converts an active hold into the buyer's actual charge: the hold
// leaves the held pool and the price leaves the balance, persisted before the
// in-memory state moves so the disk is always at least as old as memory and
// never the reverse. price above hold is a Hub bug (the per-job ceiling is
// what sized the hold) and is refused rather than booked.
func (a *Accounts) Settle(tenant string, hold, price uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if price > hold {
		a.broken = true
		return fmt.Errorf("settle for tenant %q: price %d exceeds hold %d", tenant, price, hold)
	}
	if a.held[tenant] < hold {
		a.broken = true
		return fmt.Errorf("settle for tenant %q: held %d does not cover hold %d", tenant, a.held[tenant], hold)
	}
	if a.balance[tenant] < price {
		a.broken = true
		return fmt.Errorf("settle for tenant %q: balance %d cannot cover price %d", tenant, a.balance[tenant], price)
	}
	a.held[tenant] -= hold
	a.balance[tenant] -= price
	if err := a.persistLocked(); err != nil {
		a.broken = true
		return err
	}
	return nil
}

// Charge bills a buyer whose hold is already gone — the one ordering a
// watchdog-closed session can produce: the connection close releases the hold
// before the truncated receipt is priced, and the charge is still due. The
// debt-safety argument is unchanged (the hold backed this job at admission
// and every competing hold backs its own), and a balance that cannot cover
// the price is a bug, refused and marked broken rather than booked negative.
func (a *Accounts) Charge(tenant string, price uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.balance[tenant] < price {
		a.broken = true
		return fmt.Errorf("charge for tenant %q: balance %d cannot cover price %d", tenant, a.balance[tenant], price)
	}
	a.balance[tenant] -= price
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

// persistLocked rewrites the balance file atomically: write a temporary file
// beside it, fsync it, rename over the target, fsync the directory so the
// rename itself is durable. A crash mid-write leaves either the old file or
// the new one, never a partial one.
func (a *Accounts) persistLocked() error {
	doc := struct {
		Tenants map[string]uint64 `json:"tenants"`
	}{Tenants: a.balance}
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
