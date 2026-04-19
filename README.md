# TEE + MPC Protocol Implementation

This is a production-grade implementation of the TEE + MPC protocol for secure TLS communication with split AEAD processing. The system enables users to prove data from HTTPS websites while maintaining privacy through redaction capabilities and zero-knowledge proofs.

## Project Structure

The codebase is organized into multiple components for modularity and maintainability:

```
reclaim-tee/
├── tee_k/              # TEE_K service (key holder)
│   ├── main.go         # Service entry point
│   ├── tee_k.go        # Core TEE_K logic
│   ├── session_manager.go
│   ├── tls_handlers.go
│   ├── crypto.go
│   ├── attestation.go
│   └── ...
├── tee_t/              # TEE_T service (tag computation)
│   ├── main.go         # Service entry point
│   ├── tee_t.go        # Core TEE_T logic
│   ├── crypto_handlers.go
│   ├── attestation.go
│   └── ...
├── demo_standalone/    # Standalone client application
│   └── main.go         # Client entry point
├── client/             # Client library package
│   └── client.go       # Client implementation
├── minitls/            # Custom TLS implementation
│   ├── client.go
│   ├── client12.go
│   ├── crypto12.go
│   ├── handshake12.go
│   └── ...
├── shared/             # Shared utilities and services
│   ├── attestation_*.go
│   ├── kms_*.go
│   ├── cert_*.go
│   ├── logger.go
│   └── ...
├── lib/                # Shared C library (libreclaim.so)
│   ├── libreclaim.go   # CGO implementation
│   ├── libreclaim.h    # C header
│   └── Makefile
├── demo_lib/           # Sample app using shared library
├── proxy/              # HTTP/HTTPS proxy service
│   ├── main.go
│   ├── http_router.go
│   ├── https_router.go
│   ├── kms_proxy.go
│   └── go.mod          # Separate module
├── proto/              # Protocol buffer definitions
│   ├── common.proto
│   ├── transport.proto
│   ├── attestor_api.proto
│   └── ...
├── providers/          # Provider implementations
│   ├── http.go
│   ├── http_parser.go
│   └── validation.go
├── proofverifier/      # Proof verification logic
├── circuits/           # ZK circuit files (proving keys, R1CS)
├── deploy/             # Deployment configurations
├── bin/                # Compiled executables (created by build.sh)
│   ├── tee_k
│   ├── tee_t
│   ├── client
│   └── proxy
├── build.sh            # Build script for all services
├── demo.sh             # Demo orchestration script
├── lib.sh              # Shared library build/run script
├── go.mod              # Go module configuration
└── README.md           # This file
```

## Components

### Core Services

- **TEE_K** (tee_k/) - Key holder TEE service that manages TLS connections
  - Handles TLS handshake with target websites
  - Performs encryption operations with actual keys
  - Manages session state and WebSocket connections
  - Provides attestation capabilities
  - Runs on port 8080 by default

- **TEE_T** (tee_t/) - Tag computation TEE service for authentication
  - Computes and verifies authentication tags
  - Assists in split AEAD processing without key access
  - Handles transcript generation
  - Provides independent attestation
  - Runs on port 8081 by default

- **Client** (demo_standalone/) - Orchestrates the protocol
  - Establishes secure WebSocket connections with both TEEs
  - Manages request redaction and response verification
  - Initializes ZK circuits for OPRF proofs
  - Generates final proof transcripts

### Supporting Components

- **Proxy** (proxy/) - HTTP/HTTPS proxy service for protocol mediation
  - Routes requests between clients and TEE services
  - Provides KMS and CloudWatch proxy functionality
  - Separate Go module with independent deployment

- **Shared Library** (lib/) - C-compatible library (libreclaim.so)
  - Enables integration with non-Go applications
  - Provides FFI bindings for core functionality

- **MiniTLS** (minitls/) - Custom TLS 1.2/1.3 implementation
  - Supports split AEAD modifications
  - Implements required cipher suites
  - Enables fine-grained control over TLS operations

- **Providers** (providers/) - HTTP parsing and validation
  - JSON/XML/XPath positioned parsing
  - Response extraction and validation

## Building

### Build All Services

The recommended way to build is using the build script, which builds all services and generates protobuf code:

```bash
./build.sh
```

This will:
1. Generate Go code from protocol buffer definitions
2. Build TEE_K service → `bin/tee_k`
3. Build TEE_T service → `bin/tee_t`
4. Build Client → `bin/client`
5. Build Proxy → `bin/proxy`

### Build Individual Services

You can also build services individually:

```bash
# Build TEE_K
cd tee_k && go build -o ../bin/tee_k . && cd ..

# Build TEE_T
cd tee_t && go build -o ../bin/tee_t . && cd ..

# Build Client
cd demo_standalone && go build -o ../bin/client . && cd ..

# Build Proxy (has separate go.mod)
cd proxy && go mod download && go build -o ../bin/proxy . && cd ..
```

### Build Shared Library

To build the shared library for C/Go interop:

```bash
./lib.sh build
```

This creates `lib/libreclaim.so` that can be used by other applications.

### Generate Protobuf Code

If you modify .proto files, regenerate Go code:

```bash
protoc -I proto --go_out=proto/ --go_opt=paths=source_relative proto/*.proto
```

## Running

### Running the Demo (Recommended)

The easiest way to run the complete system:

```bash
./demo.sh
```

This script will:
1. Build all services using `./build.sh`
2. Start TEE_K service on port 8080 (logs to `/tmp/demo_teek.log`)
3. Start TEE_T service on port 8081 (logs to `/tmp/demo_teet.log`)
4. Run the Client which connects to both services
5. Execute the full TEE + MPC protocol with a test request
6. Display results and shut down gracefully

You can pass additional arguments to configure the demo:
```bash
./demo.sh [client-args]
```

### Running Individual Services

Each service can be run independently for development or testing:

```bash
# Run TEE_K service
./bin/tee_k [port]       # Default: 8080

# Run TEE_T service
./bin/tee_t [port]       # Default: 8081

# Run Client (requires TEE_K and TEE_T to be running)
./bin/client [teek_url]  # Default: ws://localhost:8080/ws

# Run Proxy service
./bin/proxy
```

### Running with the Shared Library

To run the demo using the shared library:

```bash
./lib.sh run
```

Or manually:
```bash
# Build library first
./lib.sh build

# Set library path and run sample app
cd demo_lib
LD_LIBRARY_PATH=../bin:$LD_LIBRARY_PATH ./sample_app_shared
```

## Protocol Overview

This implementation follows the [TEE + MPC protocol](https://reclaimprotocol.notion.site/New-design-research-TEE-MPC-1f1275b816cb80caaa60fcb58a3e780d) for privacy-preserving TLS attestation.



## Dependencies

### Core Dependencies

- Go 1.25.3 or later
- github.com/gorilla/websocket v1.5.3
- golang.org/x/crypto v0.43.0
- google.golang.org/protobuf v1.36.10

### ZK and Cryptography

- github.com/reclaimprotocol/zk-symmetric-crypto/gnark
- github.com/ethereum/go-ethereum v1.16.5
- github.com/consensys/gnark v0.14.0

### Cloud Services

- cloud.google.com/go/kms v1.23.2
- cloud.google.com/go/secretmanager v1.16.0
- cloud.google.com/go/logging v1.13.1

### AWS Nitro Enclaves

- github.com/anjuna-security/go-nitro-attestation
- github.com/austinast/nitro-enclaves-sdk-go
- github.com/hf/nsm
- github.com/mdlayher/vsock v1.2.1

See `go.mod` for complete dependency list.

## Testing

### Run Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./minitls/...
go test ./tee_k/...
go test ./tee_t/...
go test ./providers/...

# Run with verbose output
go test -v ./...
```

### Integration Testing

```bash
# Full integration test via demo
./demo.sh

# Test shared library
./lib.sh run

# Check service logs during demo
tail -f /tmp/demo_teek.log
tail -f /tmp/demo_teet.log
```

## Configuration

### Environment Variables

```bash
# Development mode (disables some security checks)
export DEVELOPMENT=true

# Google Cloud configuration
export GCP_PROJECT_ID=your-project-id
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json

# AWS configuration for KMS/Secrets Manager
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key

# Nitro Enclave mode
export NITRO_ENCLAVE=true
export PARENT_VSOCK_PORT=5000

# Logging
export LOG_LEVEL=debug  # or info, warn, error
```

## Deployment

For production deployment to AWS Nitro Enclaves (TEE_K) and GCP Confidential Space (TEE_T), see [DEPLOYMENT.md](DEPLOYMENT.md).

## Development

### Project Organization

- Monorepo structure with single `go.mod` at root (except proxy which has its own)
- Each service is independently buildable
- Shared packages (minitls, shared, providers) used across services
- Protocol definitions centralized in `proto/`

### Code Organization

```
Core Services:     tee_k/, tee_t/, demo_standalone/
Libraries:         minitls/, shared/, providers/, client/
Infrastructure:    proxy/, lib/, proto/
ZK Circuits:       circuits/
Verification:      proofverifier/
```

### Common Development Tasks

```bash
# Regenerate protobufs after .proto changes
protoc -I proto --go_out=proto/ --go_opt=paths=source_relative proto/*.proto

# Build and test
./build.sh && go test ./...

# Run with debug logging
LOG_LEVEL=debug ./demo.sh

# Format and vet code
go fmt ./...
go vet ./...
```

## Troubleshooting

### Common Issues

**Service fails to start:**
- Check if ports 8080/8081 are available
- Verify protobuf files are generated: run `./build.sh`
- Check logs: `/tmp/demo_teek.log` and `/tmp/demo_teet.log`

**TLS connection failures:**
- Ensure target website supports TLS 1.2 or 1.3
- Verify cipher suite compatibility (AES-128-GCM, AES-256-GCM)
- Check certificate validation settings

**WebSocket connection errors:**
- Ensure TEE services are running before starting client
- Check firewall rules and network connectivity
- Verify WebSocket URLs are correct (default: ws://localhost:8080/ws)

**Build failures:**
- Run `go mod download` to fetch dependencies
- Ensure Go 1.25.3+ is installed
- Check for missing protoc compiler installation

**ZK circuit errors:**
- Verify `circuits/` directory contains required proving key and R1CS files
- Check that .pk and .r1cs files exist for configured algorithms
- Ensure sufficient memory for proof generation

## Reproducible Builds & Image Verification

TEE image digests serve as the enclave identity (PCR0 equivalent) in GCP Confidential Space. Clients validate claims against these digests. The build system produces identical image hashes from identical source code, allowing anyone to verify that deployed images match the public source.

### Verifying Production Images

Clone the repo and run:

```bash
./deploy/verify.sh
```

This rebuilds both `tee-k` and `tee-t` from source using the same pinned BuildKit, Go version, and `SOURCE_DATE_EPOCH` recorded in `deploy/image-history.json`, then compares the resulting digests. No GCP credentials required.

**Requirements:**
- Docker with buildx
- Python 3

### Current Production Digests

See [`deploy/image-history.json`](deploy/image-history.json) for the current and historical image digests, including the source commit and epoch used for each build.

### How It Works

- **Pinned base image:** `golang:alpine` pinned by platform-specific digest in both Dockerfiles
- **Deterministic Go build:** `-trimpath -buildvcs=false -buildid=` eliminates host-dependent artifacts
- **Timestamp clamping:** `SOURCE_DATE_EPOCH` + BuildKit `rewrite-timestamp` ensures identical layer timestamps
- **File mtime normalization:** All source files are touched to the epoch before building
- **Pinned BuildKit:** Builder uses a digest-pinned `moby/buildkit` image with `native` snapshotter
- **No network-dependent steps:** No `apk add` or package downloads in the final image stage
- **`crane push`:** Preserves the exact OCI digest from the local build when pushing to the registry

### Build & Deploy Workflow

```bash
# 1. Build (uses HEAD commit epoch by default)
./deploy/build.sh v2

# 2. Deploy
./deploy/update-eu.sh all
./deploy/update-prod.sh all

# 3. Record digests
./deploy/update-image-history.sh

# 4. Commit image-history.json
```

To rebuild from a specific commit (e.g. after committing image-history.json):

```bash
./deploy/build.sh v2 <commit-hash>
``` 