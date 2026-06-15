package handlers

import "time"

// tombstoneTTL bounds how long a retired pair_id is remembered so a still-
// running TEE can't re-register it after /dead. Sized to outlive a TEE's
// heartbeat retry cycle. Tombstones live in the Store, so the guard holds
// across router replicas.
const tombstoneTTL = 5 * time.Minute
