//go:build linux && !mobile

package shared

import (
	"errors"
	"os"
	"strings"
	"syscall"

	"go.uber.org/zap"
)

// isTerminalAttestWedge reports whether err is the sticky SEV-guest failure —
// the kernel driver wiped the VMPCK (fail-closed) so every report ioctl now
// returns ENOTTY until a reboot re-provisions the secrets page.
func isTerminalAttestWedge(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOTTY) {
		return true
	}
	return strings.Contains(err.Error(), "inappropriate ioctl for device")
}

// captureAttestationDiag gathers reset-proof, in-guest evidence for an
// attestation failure: the raw errno, the SEV guest device state, and kernel
// ring-buffer lines mentioning the SEV/CCP path. Confidentiality-preserving
// substitute for serial-console logging (we control exactly what it emits).
func captureAttestationDiag(err error) []zap.Field {
	fields := []zap.Field{}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		fields = append(fields, zap.String("errno", errno.Error()), zap.Int("errno_num", int(errno)))
	}
	if fi, serr := os.Stat(sevGuestDevice); serr == nil {
		fields = append(fields, zap.Bool("sev_guest_present", true), zap.String("sev_guest_mode", fi.Mode().String()))
	} else {
		fields = append(fields, zap.Bool("sev_guest_present", false), zap.String("sev_guest_stat_err", serr.Error()))
	}
	fields = append(fields, zap.Strings("kmsg", kmsgTail("sev", "ccp", "psp", "snp", "vmpck")))
	return fields
}

// kmsgTail replays /dev/kmsg non-blocking and returns up to the last 20 lines
// whose text contains any of the given lowercase substrings.
func kmsgTail(match ...string) []string {
	f, err := os.OpenFile("/dev/kmsg", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return []string{"kmsg open: " + err.Error()}
	}
	defer f.Close()
	buf := make([]byte, 8192)
	var hits []string
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			low := strings.ToLower(string(buf[:n]))
			for _, m := range match {
				if strings.Contains(low, m) {
					hits = append(hits, strings.TrimSpace(string(buf[:n])))
					break
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	if len(hits) > 20 {
		hits = hits[len(hits)-20:]
	}
	return hits
}

// attestSelfReset warm-reboots the guest (LINUX_REBOOT_CMD_RESTART) — the only
// known recovery for a wedged SEV report path. Best-effort: on missing
// CAP_SYS_BOOT it logs and returns (router health-gate + alert cover it). It
// must NOT os.Exit — tee-restart-policy=Never would leave the VM powered off.
func attestSelfReset(logger *Logger) {
	if os.Getenv("SNP_ATTEST_SELFHEAL") == "0" {
		if logger != nil {
			logger.Warn("attestation self-heal disabled (SNP_ATTEST_SELFHEAL=0)")
		}
		return
	}
	if !IsSEVSNPMode() {
		return
	}
	syscall.Sync()
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART); err != nil && logger != nil {
		logger.Error("self-reset reboot failed; staying up (evicted) for manual reset", zap.Error(err))
	}
}
