package shared

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// AttestationHealth tracks consecutive attestation-generation failures so a TEE
// can gate itself off the router (report unhealthy) and self-reset when the SEV
// report path wedges — the only known recovery, observed 2026-07-13 when GCP
// us-central1 SEV guests returned ENOTTY until a VM reset. Concurrency-safe and
// nil-safe (a nil receiver reports healthy and no-ops).
type AttestationHealth struct {
	mu           sync.Mutex
	consecFails  int
	diagCaptured bool
	lastSelfHeal time.Time
	logger       *Logger
}

const (
	attestUnhealthyAfter = 3
	attestSelfHealAfter  = 6
	attestSelfHealMinGap = 15 * time.Minute
)

func NewAttestationHealth(logger *Logger) *AttestationHealth {
	return &AttestationHealth{logger: logger}
}

// RecordSuccess clears the failure streak.
func (a *AttestationHealth) RecordSuccess() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.consecFails > 0 && a.logger != nil {
		a.logger.Info("attestation recovered", zap.Int("after_consecutive_failures", a.consecFails))
	}
	a.consecFails = 0
	a.diagCaptured = false
	a.mu.Unlock()
}

// RecordFailure increments the streak, captures one-shot device/kernel
// diagnostics on the first failure, and triggers a rate-limited self-reset once
// the streak crosses the self-heal threshold.
func (a *AttestationHealth) RecordFailure(err error) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.consecFails++
	n := a.consecFails
	captureDiag := !a.diagCaptured
	a.diagCaptured = true
	selfHeal := n >= attestSelfHealAfter && time.Since(a.lastSelfHeal) >= attestSelfHealMinGap
	if selfHeal {
		a.lastSelfHeal = time.Now()
	}
	logger := a.logger
	a.mu.Unlock()

	if logger != nil {
		logger.Error("attestation generation failed",
			zap.Int("consecutive_failures", n),
			zap.Bool("healthy", n < attestUnhealthyAfter),
			zap.Error(err))
		if captureDiag {
			logger.Error("attestation failure diagnostics", captureAttestationDiag(err)...)
		}
	}
	if selfHeal {
		if logger != nil {
			logger.Error("attestation wedged past self-heal threshold; self-resetting VM",
				zap.Int("consecutive_failures", n))
			logger.Sync()
		}
		go attestSelfReset(logger)
	}
}

// Healthy reports whether the TEE can currently attest. Folded into the
// heartbeat's control-health so the router gates sessions off an unhealthy TEE.
func (a *AttestationHealth) Healthy() bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.consecFails < attestUnhealthyAfter
}
