// Command oprfshare moves a TEE MPC OPRF key share between clouds:
//
//	export  GCP Secret Manager -> local file (raw 16 bytes)
//	import  local file -> AWS Secrets Manager (raw 16 bytes, SecretBinary)
//
// The secret name is identical on both clouds (cache-<role>-<deploymentKey>-
// oprf-key-share, sanitized), so the AWS TEE loads the SAME share the GCP CS
// fleet uses — which is what makes SNP-served claims produce identical OPRF
// output. Only a sha256 fingerprint is printed; the share itself never is.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "export":
		runExport(os.Args[2:])
	case "import":
		runImport(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: oprfshare {export|import} [flags]")
	fmt.Fprintln(os.Stderr, "  export  -role -deployment-key -project -kms-location -kms-keyring -kms-key -out")
	fmt.Fprintln(os.Stderr, "  import  -role -deployment-key -in [-region] [-kms-key-id]")
	os.Exit(2)
}

func runExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	role := fs.String("role", "", "tee_k or tee_t")
	dk := fs.String("deployment-key", "", "KMS_ENCLAVE_DOMAIN_KEY value, e.g. tt.reclaimprotocol.org")
	project := fs.String("project", "", "GCP project id")
	loc := fs.String("kms-location", "", "GCP KMS location")
	keyring := fs.String("kms-keyring", "", "GCP KMS keyring")
	key := fs.String("kms-key", "", "GCP KMS crypto key")
	out := fs.String("out", "", "output file for the raw 16-byte share")
	_ = fs.Parse(args)
	requireFlags(map[string]string{"role": *role, "deployment-key": *dk, "project": *project,
		"kms-location": *loc, "kms-keyring": *keyring, "kms-key": *key, "out": *out})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := shared.NewSecretStore(ctx, *project, *loc, *keyring, *key)
	fatalIf("new gcp secret store", err)

	share, err := store.LoadExistingOPRFShare(ctx, *role, *dk)
	fatalIf("load gcp share", err)

	fatalIf("write file", os.WriteFile(*out, share, 0o600))
	fmt.Printf("exported %s/%s -> %s  sha256=%s\n", *role, *dk, *out, fingerprint(share))
}

func runImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	role := fs.String("role", "", "tee_k or tee_t")
	dk := fs.String("deployment-key", "", "KMS_ENCLAVE_DOMAIN_KEY value, e.g. tt.reclaimprotocol.org")
	in := fs.String("in", "", "input file with the raw 16-byte share")
	region := fs.String("region", "", "AWS region (else AWS_REGION env)")
	kmsKeyID := fs.String("kms-key-id", "", "KMS CMK id/arn for the secret (empty = aws/secretsmanager default)")
	_ = fs.Parse(args)
	requireFlags(map[string]string{"role": *role, "deployment-key": *dk, "in": *in})

	if *region != "" {
		_ = os.Setenv("AWS_REGION", *region)
	}

	share, err := os.ReadFile(*in)
	fatalIf("read file", err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := shared.NewAWSSecretStore(ctx, *kmsKeyID)
	fatalIf("new aws secret store", err)

	fatalIf("store aws share", store.StoreOPRFShare(ctx, *role, *dk, share))
	fmt.Printf("imported %s/%s -> AWS Secrets Manager  sha256=%s\n", *role, *dk, fingerprint(share))
}

func fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func requireFlags(m map[string]string) {
	for name, v := range m {
		if v == "" {
			fmt.Fprintf(os.Stderr, "missing required -%s\n", name)
			os.Exit(2)
		}
	}
}

func fatalIf(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}
