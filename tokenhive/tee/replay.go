package tee

import (
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// A job is self-contained: a spec, a body, and the agent's sealed credential
// for it, all signed by nobody — the spec carries no submitter signature by
// design, because the Hub is its author. So a captured /v1/execute request is
// replayable verbatim for as long as its spec stays unexpired, and a replay
// spends the provider's sequence numbers and quota exactly as a fresh job does,
// in a way the Hub never sees and never books.
//
// mTLS answers who may submit; it does not answer whether a given submission
// has been made before. The guard here is the second half: a job ID the enclave
// has already looked at inside the spec's window is refused, so a package
// lifted off the wire dies the second it is used twice.
//
// It is deliberately not a persistent ledger. The window is the lifetime of the
// thing it protects, and losing the table on restart costs at most the replay
// of a job whose spec has not expired yet — a window in which the enclave that
// would have refused it also lost its sequence numbers. Persistent replay
// state would be a second thing to seal, back up and restore, guarding a hole
// that restart already opens wider.
const (
	// replayWindow bounds how long a job ID stays spent. It matches the
	// validity the Hub gives a spec (an hour), so a job cannot outlive its own
	// guard entry.
	replayWindow = time.Hour

	// maxReplayEntries bounds the table's memory: about five megabytes of live
	// job IDs. Reaching it takes tens of thousands of jobs inside one window,
	// and the entries closest to expiring are dropped first, which is the half
	// of the table least likely to be replayed.
	maxReplayEntries = 1 << 16
)

// replayGuard is the enclave's table of job IDs it has already seen.
type replayGuard struct {
	mu   sync.Mutex
	seen map[[jobs.JobIDLength]byte]int64
}

func newReplayGuard() *replayGuard {
	return &replayGuard{seen: make(map[[jobs.JobIDLength]byte]int64)}
}

// spend records a job ID and reports whether it may run: false means the ID was
// already spent and has not aged out. It is called once per job, before
// anything is authorized or sent, and it records refusals as well as
// executions — a job the enclave declined is still a job it has seen, so
// replaying the same refusal is refused too.
//
// expiry is the end of the spec's own validity, capped by the window, and it is
// what the entry is retained until.
func (g *replayGuard) spend(jobID []byte, now, expiry time.Time) bool {
	if len(jobID) != jobs.JobIDLength {
		// Shape is validated before this point; a guard that cannot name the
		// job has nothing to remember, so it does not stand in the way of the
		// checks that will.
		return true
	}
	if windowEnd := now.Add(replayWindow); expiry.After(windowEnd) {
		expiry = windowEnd
	}
	var key [jobs.JobIDLength]byte
	copy(key[:], jobID)

	g.mu.Lock()
	defer g.mu.Unlock()

	until, spent := g.seen[key]
	if spent && until > now.Unix() {
		return false
	}
	g.makeRoomLocked(now.Unix())
	g.seen[key] = expiry.Unix()
	return true
}

// makeRoomLocked keeps the table inside its bound: expired entries first, then
// the entries expiring soonest. Callers must hold mu.
func (g *replayGuard) makeRoomLocked(now int64) {
	if len(g.seen) < maxReplayEntries {
		return
	}
	for id, until := range g.seen {
		if until <= now {
			delete(g.seen, id)
		}
	}
	for len(g.seen) >= maxReplayEntries {
		var (
			oldest [jobs.JobIDLength]byte
			until  int64
			found  bool
		)
		for id, at := range g.seen {
			if !found || at < until {
				oldest, until, found = id, at, true
			}
		}
		if !found {
			return
		}
		delete(g.seen, oldest)
	}
}
