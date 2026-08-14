# Reclaim TEE

Secure TLS attestation protocol using Trusted Execution Environments (TEE) and Multi-Party Computation (MPC). Users can prove data from any HTTPS website while keeping sensitive parts private through redaction and zero-knowledge proofs. Runs on GCP Confidential Space.

## Architecture

Two TEE services split the TLS processing so neither has full access alone:

- **TEE_K** (`tee_k/`) -- Holds TLS keys, handles encryption, manages connections to target websites. Port 8080.
- **TEE_T** (`tee_t/`) -- Computes authentication tags without key access, verifies integrity. Port 8081.
- **Client** (`client/`, `demo_standalone/`) -- Orchestrates the protocol, handles redaction, generates proofs.

Supporting:
- `minitls/` -- Custom TLS 1.2/1.3 with split AEAD support
- `oprfmpc/` -- MPC OPRF using garbled circuits with OT precomputation
- `shared/` -- GCP integrations (KMS, attestation, logging, cert management)
- `proto/` -- Protocol buffer definitions
- `providers/` -- HTTP request/response parsing and validation

## Quick Start

```bash
# Build everything
./build.sh

# Run the demo (starts both TEEs + client)
./demo.sh
```

## Build

```bash
./build.sh                    # all services
cd tee_k && go build .        # just TEE_K
cd tee_t && go build .        # just TEE_T

# Regenerate protobuf (after .proto changes)
protoc -I proto --go_out=proto/ --go_opt=paths=source_relative proto/*.proto
```

## Test

```bash
go test ./...                 # all tests
go test ./minitls/...         # specific package
go test -cover ./...          # with coverage
```

## Protocol Flow

1. Client connects to TEE_K and TEE_T over WebSocket
2. TEE_K and TEE_T perform mutual attestation and OT precomputation (100,000 initial OTs)
3. TEE_K establishes TLS connection with the target website
4. Client sends redacted request through split AEAD (TEE_K encrypts, TEE_T computes tags)
5. Response decrypted and verified through same split process
6. MPC OPRF with garbled circuits and precomputed random OT for key derivation proofs
7. Client generates ZK proofs and verification bundle
8. Attestor validates the bundle and issues a signed claim

## Deployment

Both TEE services run as GCP Confidential Space VMs. A single Docker image per service is used across all regions -- region-specific config (domain, KMS keys) is injected via instance metadata.

### Build & Deploy

```bash
./deploy/build.sh             # build reproducible images, push to registry
./deploy/build.sh v2 <commit> # rebuild from a specific commit
./deploy/update-image-history.sh  # record digests in image-history.json
```

### Update Pinned Versions

Base image (Go/Alpine) and BuildKit are pinned by digest for reproducibility:

```bash
./deploy/update-pins.sh           # show current versions
./deploy/update-pins.sh --update  # pull latest and update pins
```

## Reproducible Builds

Image digests serve as enclave identity (PCR0) in GCP Confidential Space. Anyone can verify deployed images match source code:

```bash
./deploy/verify.sh
```

This rebuilds both images from source using the pinned BuildKit, Go version, and `SOURCE_DATE_EPOCH` from `deploy/image-history.json`, then compares digests. No GCP credentials needed. Requires Docker with buildx and Python 3.

Current production digests: [`deploy/image-history.json`](deploy/image-history.json)

### What makes builds reproducible

- Pinned base image and BuildKit by digest
- `-trimpath -buildid=` eliminates host-dependent Go build artifacts
- `--chown=0:0` on all COPY instructions normalizes file ownership
- File mtimes normalized to commit timestamp before building
- `SOURCE_DATE_EPOCH` + `rewrite-timestamp` clamps all layer timestamps
- `crane push` preserves exact OCI digest

## Attestation & Certificate Verification

Both TEEs include their TLS certificate hash in GCP attestation nonces (`eat_nonce` array):
- `nonces[0]`: `tee_k_public_key:0x...` or `tee_t_public_key:0x...`
- `nonces[1]`: `tee_k_cert_hash:<sha256>` or `tee_t_cert_hash:<sha256>`

The client verifies these hashes match the TLS certificates on its WebSocket connections before submitting the verification bundle.

## Debugging

```bash
# Demo logs
tail -f /tmp/demo_teek.log
tail -f /tmp/demo_teet.log

# Force TLS version
FORCE_TLS_VERSION=1.3 ./demo.sh
```
