// snp-eventlog-inspect replays a raw TCG firmware event log against TPM PCRs
// and reports the Secure Boot signing authority. PCR inputs must come from a
// separately verified provider quote in production; the cloud probe supplies
// direct TPM reads only for this diagnostic.
package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-eventlog/extract"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }

func (f *repeatedFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	var pcrs repeatedFlag
	eventLogPath := flag.String("event-log", "", "raw binary_bios_measurements file")
	bankName := flag.String("bank", "sha256", "PCR bank: sha256 or sha384")
	trustedCertPath := flag.String("trusted-authority", "", "PEM or DER release-authority certificate")
	flag.Var(&pcrs, "pcr", "quoted PCR as INDEX=HEX; repeat for each PCR to replay")
	flag.Parse()

	if *eventLogPath == "" || *trustedCertPath == "" || len(pcrs) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	bank, err := parseBank(*bankName)
	fatalIf(err)
	mrs, err := parsePCRs(pcrs, bank)
	fatalIf(err)
	raw, err := os.ReadFile(*eventLogPath)
	fatalIf(err)
	trusted, err := readCertificate(*trustedCertPath)
	fatalIf(err)

	events, err := tcg.ParseAndReplay(raw, mrs, tcg.ParseOpts{AllowPadding: true})
	fatalIf(err)
	state, err := extract.ParseSecurebootStateLegacy(events)
	fatalIf(err)

	trustedFingerprint := certificateFingerprint(trusted)
	trustedDBEntries := countCertificate(state.PermittedKeys, trustedFingerprint)
	trustedInDB := trustedDBEntries != 0
	trustedDBXEntries := countCertificate(state.ForbiddenKeys, trustedFingerprint)
	preAuthorityUses := countCertificate(state.PreSeparatorAuthority, trustedFingerprint)
	postAuthorityUses := countCertificate(state.PostSeparatorAuthority, trustedFingerprint)

	fmt.Printf("event_log_bytes=%d\n", len(raw))
	fmt.Printf("replayed_bank=%s\n", *bankName)
	fmt.Printf("replayed_pcrs=%s\n", joinedPCRIndices(mrs))
	fmt.Printf("verified_events=%d\n", len(events))
	fmt.Printf("secure_boot_enabled=%t\n", state.Enabled)
	fmt.Printf("platform_keys=%d exchange_keys=%d permitted_keys=%d permitted_hashes=%d forbidden_keys=%d forbidden_hashes=%d\n",
		len(state.PlatformKeys), len(state.ExchangeKeys), len(state.PermittedKeys), len(state.PermittedHashes),
		len(state.ForbiddenKeys), len(state.ForbiddenHashes))
	fmt.Printf("trusted_authority_sha256=%s\n", hex.EncodeToString(trustedFingerprint))
	fmt.Printf("trusted_authority_in_db=%t\n", trustedInDB)
	fmt.Printf("trusted_authority_in_dbx=%t\n", trustedDBXEntries != 0)
	fmt.Printf("trusted_authority_uses_pre_separator=%d\n", preAuthorityUses)
	fmt.Printf("trusted_authority_uses_post_separator=%d\n", postAuthorityUses)

	counts := make(map[string]int)
	for _, event := range events {
		key := fmt.Sprintf("PCR%d %s", event.MRIndex(), event.UntrustedType().TCGString())
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("event_count[%s]=%d\n", key, counts[key])
	}

	policy := secureBootPolicy{
		enabled:                state.Enabled,
		permittedKeys:          len(state.PermittedKeys),
		permittedHashes:        len(state.PermittedHashes),
		trustedDBEntries:       trustedDBEntries,
		trustedDBXEntries:      trustedDBXEntries,
		preAuthorities:         len(state.PreSeparatorAuthority),
		postAuthorities:        len(state.PostSeparatorAuthority),
		trustedPostAuthorities: postAuthorityUses,
	}
	if !secureBootAuthorityOK(policy) {
		fatalIf(fmt.Errorf("event log does not prove an R-only post-separator Secure Boot policy"))
	}
	fmt.Println("secure_boot_authority_policy=OK")
}

type secureBootPolicy struct {
	enabled                bool
	permittedKeys          int
	permittedHashes        int
	trustedDBEntries       int
	trustedDBXEntries      int
	preAuthorities         int
	postAuthorities        int
	trustedPostAuthorities int
}

func secureBootAuthorityOK(policy secureBootPolicy) bool {
	return policy.enabled &&
		policy.permittedKeys == 1 &&
		policy.permittedHashes == 0 &&
		policy.trustedDBEntries == 1 &&
		policy.trustedDBXEntries == 0 &&
		policy.preAuthorities == 0 &&
		policy.postAuthorities > 0 &&
		policy.trustedPostAuthorities == policy.postAuthorities
}

func parseBank(name string) (crypto.Hash, error) {
	switch name {
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("unsupported PCR bank %q", name)
	}
}

func parsePCRs(values []string, bank crypto.Hash) ([]register.MR, error) {
	mrs := make([]register.MR, 0, len(values))
	seen := make(map[int]bool)
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid PCR %q: want INDEX=HEX", value)
		}
		index, err := strconv.Atoi(parts[0])
		if err != nil || index < 0 || index > 23 {
			return nil, fmt.Errorf("invalid PCR index %q", parts[0])
		}
		if seen[index] {
			return nil, fmt.Errorf("duplicate PCR index %d", index)
		}
		digest, err := hex.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("decode PCR %d: %w", index, err)
		}
		if len(digest) != bank.Size() {
			return nil, fmt.Errorf("PCR %d digest is %d bytes; %s needs %d", index, len(digest), bank, bank.Size())
		}
		seen[index] = true
		mrs = append(mrs, register.PCR{Index: index, Digest: digest, DigestAlg: bank})
	}
	return mrs, nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("parse trusted authority: %w", err)
	}
	return cert, nil
}

func certificateFingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

func countCertificate(certs []x509.Certificate, fingerprint []byte) int {
	count := 0
	for i := range certs {
		if hex.EncodeToString(certificateFingerprint(&certs[i])) == hex.EncodeToString(fingerprint) {
			count++
		}
	}
	return count
}

func joinedPCRIndices(mrs []register.MR) string {
	indices := make([]int, 0, len(mrs))
	for _, mr := range mrs {
		indices = append(indices, mr.Idx())
	}
	sort.Ints(indices)
	parts := make([]string, 0, len(indices))
	for _, index := range indices {
		parts = append(parts, strconv.Itoa(index))
	}
	return strings.Join(parts, ",")
}

func fatalIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}
