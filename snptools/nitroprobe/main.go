// nitroprobe validates the AWS combined attestation producer on a NitroTPM +
// SEV-SNP instance: it generates an ephemeral SPKI, builds the combined
// attestation (NitroTPM doc + SEV report bound by sha512(SPKI)), and writes the
// envelope + SPKI so the verifier can be checked offline.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spki:", err)
		os.Exit(1)
	}
	env, err := shared.GenerateCombinedAWSAttestation(spki, make([]byte, 32))
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/aws-combined.bin", env, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write env:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/aws-combined.spki", spki, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write spki:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: %d-byte AWS combined attestation (+ %d-byte spki)\n", len(env), len(spki))
}
