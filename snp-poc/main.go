// snp-poc proves we can pull and verify a raw SEV-SNP attestation report on a
// plain GCP Confidential VM (N2D), i.e. outside the Confidential Space launcher.
// It mirrors the report_data layout sketched in MULTI_PAIR_ARCHITECTURE_PLAN.md
// Appendix C: [0..32)=sha256(SPKI placeholder), [32..64)=sha256(self binary).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/go-sev-guest/client"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	tpmclient "github.com/google/go-tpm-tools/client"
	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

func main() {
	skipVerify := flag.Bool("skip-verify", false, "skip AMD signature-chain verification (no KDS egress)")
	dump := flag.String("dump", "", "write the marshaled go-sev-guest Attestation proto to this path (for test fixtures)")
	combined := flag.String("combined", "", "generate the combined GCP vTPM+SEV attestation, write proto to this path and the SPKI DER to <path>.spki")
	flag.Parse()

	if *combined != "" {
		if err := runCombined(*combined); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*skipVerify, *dump); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// runCombined captures a combined vTPM+SEV-SNP attestation fixture: it binds a
// fresh ephemeral SPKI (stand-in for the RA-TLS key), writes the marshaled
// go-tpm-tools Attestation proto and the SPKI DER so the verifier can recompute
// report_data = sha512(AkPub || SPKI).
func runCombined(path string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	att, err := generateCombined(spki)
	if err != nil {
		return fmt.Errorf("generate combined attestation: %w", err)
	}
	if err := os.WriteFile(path, att, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(path+".spki", spki, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote combined attestation (%d bytes) to %s\n", len(att), path)
	fmt.Printf("wrote spki (%d bytes) to %s.spki\n", len(spki), path)
	fmt.Printf("spki_sha256 = %s\n", hex.EncodeToString(func() []byte { h := sha256.Sum256(spki); return h[:] }()))
	return nil
}

// generateCombined mirrors shared.GenerateCombinedGCPAttestation (kept inline so
// this standalone poc tool needs no cross-module dependency): GCE vTPM AK +
// PCR quotes + SEV report, with report_data = sha512(AkPub || spkiDER).
func generateCombined(spkiDER []byte) ([]byte, error) {
	rwc, err := legacytpm.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, fmt.Errorf("open tpm: %w", err)
	}
	defer rwc.Close()
	ak, err := tpmclient.GceAttestationKeyECC(rwc)
	if err != nil {
		return nil, fmt.Errorf("load GCE AK: %w", err)
	}
	defer ak.Close()
	akPub, err := ak.PublicArea().Encode()
	if err != nil {
		return nil, fmt.Errorf("encode AK pub: %w", err)
	}
	h := sha512.New()
	h.Write(akPub)
	h.Write(spkiDER)
	var rd [64]byte
	copy(rd[:], h.Sum(nil))
	nonce := sha256.Sum256(spkiDER)
	sev, err := tpmclient.CreateSevSnpQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("sev provider: %w", err)
	}
	defer sev.Close()
	att, err := ak.Attest(tpmclient.AttestOpts{Nonce: nonce[:], TEENonce: rd[:], TEEDevice: sev, TCGEventLog: []byte{}, CertChainFetcher: &http.Client{Timeout: 30 * time.Second}})
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	return proto.Marshal(att)
}

func run(skipVerify bool, dumpPath string) error {
	reportData, binHash, err := buildReportData()
	if err != nil {
		return err
	}
	fmt.Printf("report_data (64B) = %s\n", hex.EncodeToString(reportData[:]))
	fmt.Printf("  [ 0..32) spki_placeholder = %s\n", hex.EncodeToString(reportData[:32]))
	fmt.Printf("  [32..64) sha256(self bin) = %s\n", hex.EncodeToString(binHash[:]))

	d, err := client.OpenDevice()
	if err != nil {
		return fmt.Errorf("open /dev/sev-guest (is this a SEV-SNP CVM?): %w", err)
	}
	defer d.Close()

	att, err := client.GetExtendedReport(d, reportData)
	if err != nil {
		return fmt.Errorf("get extended report: %w", err)
	}
	report := att.GetReport()

	fmt.Println("--- report ---")
	fmt.Printf("version            = %d\n", report.GetVersion())
	fmt.Printf("vmpl               = %d\n", report.GetVmpl())
	fmt.Printf("policy             = 0x%x\n", report.GetPolicy())
	fmt.Printf("measurement (48B)  = %s\n", hex.EncodeToString(report.GetMeasurement()))
	fmt.Printf("report_data echoed = %s\n", hex.EncodeToString(report.GetReportData()))
	fmt.Printf("host_data (32B)    = %s\n", hex.EncodeToString(report.GetHostData()))
	fmt.Printf("chip_id (64B)      = %s\n", hex.EncodeToString(report.GetChipId()))

	certs := att.GetCertificateChain()
	fmt.Printf("cert_chain present = vcek:%d vlek:%d ask:%d ark:%d\n",
		len(certs.GetVcekCert()), len(certs.GetVlekCert()), len(certs.GetAskCert()), len(certs.GetArkCert()))

	if dumpPath != "" {
		b, err := proto.Marshal(att)
		if err != nil {
			return fmt.Errorf("marshal attestation: %w", err)
		}
		if err := os.WriteFile(dumpPath, b, 0o644); err != nil {
			return fmt.Errorf("write dump: %w", err)
		}
		fmt.Printf("wrote attestation proto (%d bytes) to %s\n", len(b), dumpPath)
	}

	if !bytesEqual(report.GetReportData(), reportData[:]) {
		return fmt.Errorf("report_data round-trip mismatch")
	}
	fmt.Println("report_data round-trip OK")

	if skipVerify {
		fmt.Println("verification SKIPPED (--skip-verify)")
		return dumpJSON(report)
	}

	opts := verify.DefaultOptions()
	if err := verify.SnpAttestation(att, opts); err != nil {
		return fmt.Errorf("AMD chain verification failed: %w", err)
	}
	fmt.Println("AMD signature-chain verification OK")
	return dumpJSON(report)
}

// buildReportData lays out the 64-byte user field: a fixed placeholder where
// the real SPKI hash will go, and sha256 of this running binary.
func buildReportData() ([64]byte, [32]byte, error) {
	var rd [64]byte
	spkiPlaceholder := sha256.Sum256([]byte("reclaim-snp-poc-spki-placeholder"))
	copy(rd[:32], spkiPlaceholder[:])

	binHash, err := selfHash()
	if err != nil {
		return rd, binHash, err
	}
	copy(rd[32:], binHash[:])
	return rd, binHash, nil
}

func selfHash() ([32]byte, error) {
	var sum [32]byte
	exe, err := os.Executable()
	if err != nil {
		return sum, fmt.Errorf("locate self: %w", err)
	}
	f, err := os.Open(exe)
	if err != nil {
		return sum, fmt.Errorf("open self: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("hash self: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dumpJSON(report *pb.Report) error {
	out := map[string]string{
		"measurement": hex.EncodeToString(report.GetMeasurement()),
		"report_data": hex.EncodeToString(report.GetReportData()),
		"chip_id":     hex.EncodeToString(report.GetChipId()),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println("--- summary json ---")
	fmt.Println(string(b))
	return nil
}
