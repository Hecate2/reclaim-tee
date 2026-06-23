// prober is a test app for the two-tier SEV-SNP image. The loader measures it
// into PCR 8 (the app digest) and execs it; it reads vTPM PCR 11 (the base UKI,
// measured by systemd-stub) and PCR 8 (its own loader-measured digest) plus the
// SEV-SNP report, and prints them to the console for reading off the serial
// port. A change to this binary changes PCR 8.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/google/go-sev-guest/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const banner = "===== SNP-PROBE ====="

// buildTag is set via -ldflags "-X main.buildTag=..." so we can produce two
// binaries that differ by a few bytes and confirm PCR 8 (the app digest)
// changes between them.
var buildTag = "dev"

func main() {
	// When run as PID 1 (no-rootfs UKI: binary is the initrd /init), there is no
	// init system, so set up the pseudo-filesystems ourselves and power off at
	// the end (otherwise the kernel panics when PID 1 exits).
	if os.Getpid() == 1 {
		mountPseudo()
		defer powerOff()
	}

	out := io.MultiWriter(os.Stdout, openConsole())
	fmt.Fprintln(out, banner)
	fmt.Fprintf(out, "build_tag          = %s\n", buildTag)

	if h, err := selfHash(); err == nil {
		fmt.Fprintf(out, "self_binary_sha256 = %s\n", hex.EncodeToString(h[:]))
	} else {
		fmt.Fprintf(out, "self_binary_sha256 ERROR: %v\n", err)
	}

	if v, err := readPCR(11); err == nil {
		fmt.Fprintf(out, "PCR11_sha256       = %s (base UKI)\n", hex.EncodeToString(v))
	} else {
		fmt.Fprintf(out, "PCR11 ERROR: %v\n", err)
	}

	if v, err := readPCR(8); err == nil {
		fmt.Fprintf(out, "PCR8_sha256        = %s (app, loader-measured)\n", hex.EncodeToString(v))
	} else {
		fmt.Fprintf(out, "PCR8 ERROR: %v\n", err)
	}

	if m, rd, err := readSNP(); err == nil {
		fmt.Fprintf(out, "snp_measurement    = %s\n", hex.EncodeToString(m))
		fmt.Fprintf(out, "snp_report_data    = %s\n", hex.EncodeToString(rd))
	} else {
		fmt.Fprintf(out, "snp report ERROR: %v\n", err)
	}

	fmt.Fprintln(out, banner+" END")
}

// mountPseudo mounts /proc, /sys and a devtmpfs /dev so PID 1 can reach
// /dev/tpmrm0 and /dev/sev-guest (their drivers are builtin in the GCP kernel,
// so no module loading is needed).
func mountPseudo() {
	for _, m := range []struct{ src, tgt, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
	} {
		_ = os.MkdirAll(m.tgt, 0o555)
		_ = syscall.Mount(m.src, m.tgt, m.fs, 0, "")
	}
}

// powerOff cleanly halts the VM after the probe so the test instance stops
// instead of leaving PID 1 exited (which the kernel treats as a panic).
func powerOff() {
	// Hold before powering off so the serial console reliably flushes and the
	// external poll can capture the output (GCP can't read serial from a
	// TERMINATED instance).
	fmt.Println("[init] probe done; holding 90s for serial capture, then power off")
	time.Sleep(90 * time.Second)
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}

// openConsole returns /dev/console if it can be opened, else io.Discard, so the
// output reaches the GCP serial port even when run as PID-adjacent service.
func openConsole() io.Writer {
	f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return io.Discard
	}
	return f
}

func readPCR(index int) ([]byte, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		tpm, err = linuxtpm.Open("/dev/tpm0")
		if err != nil {
			return nil, fmt.Errorf("open tpm: %w", err)
		}
	}
	defer tpm.Close()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: pcrSelectBitmap(index),
		}},
	}
	resp, err := tpm2.PCRRead{PCRSelectionIn: sel}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("pcrread: %w", err)
	}
	if len(resp.PCRValues.Digests) == 0 {
		return nil, fmt.Errorf("no PCR digest returned")
	}
	return resp.PCRValues.Digests[0].Buffer, nil
}

// pcrSelectBitmap builds the 3-byte PC-Client PCR-select bitmap (PCRs 0..23)
// with the bit for index set.
func pcrSelectBitmap(index int) []byte {
	b := make([]byte, 3)
	b[index/8] |= 1 << (index % 8)
	return b
}

func readSNP() (measurement, reportData []byte, err error) {
	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, nil, fmt.Errorf("quote provider: %w", err)
	}
	var rd [64]byte
	h, _ := selfHash()
	copy(rd[32:], h[:])
	att, err := client.GetQuoteProto(qp, rd)
	if err != nil {
		return nil, nil, fmt.Errorf("get report: %w", err)
	}
	r := att.GetReport()
	return r.GetMeasurement(), r.GetReportData(), nil
}

func selfHash() ([32]byte, error) {
	var sum [32]byte
	exe, err := os.Executable()
	if err != nil {
		return sum, err
	}
	f, err := os.Open(exe)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	hsh := sha256.New()
	if _, err := io.Copy(hsh, f); err != nil {
		return sum, err
	}
	copy(sum[:], hsh.Sum(nil))
	return sum, nil
}
