# MPC AES-CMAC

This package implements the two-party AES-CMAC operation used by the paired TEEs.

TEE_K owns one 80-byte XOR share. TEE_T owns the other share.

The circuit computes this function:

```text
plaintext = keystream_K XOR ciphertext_T
key       = key_share_K XOR key_share_T
output    = AES-CMAC(key, plaintext)
```

The implementation preserves the legacy circuit result. Differential tests compare both packages with the same random inputs.

The caller zero-pads each selected range to 64 bytes. The circuit processes four complete CMAC blocks, matching the legacy behavior.

## Result

The new online path removes all elliptic-curve work. It uses Free-XOR, half-gates, fixed-key AES-128, and precomputed KOS random OT.

These local medians use one core of an Intel Core i9-12900K under WSL2. They do not represent AMD Milan results.

| Operation | Legacy | New | Change |
| --- | ---: | ---: | ---: |
| Complete in-process OPRF | 55.79 ms | 2.52 ms | 22.1 times faster |
| Garbler online work | 30.37 ms | 1.36 ms | 22.4 times faster |
| Payload serialization | 585 microseconds | 111.9 microseconds | 5.2 times faster |
| Actual online payload | 1,772,536 bytes | 1,034,536 bytes | 41.6 percent smaller |
| End-to-end allocations | 3,081,250 bytes | 108,338 bytes | 96.5 percent lower |

The first garbler benchmark includes circuit compilation and pool creation. Later runs reuse those process-wide resources.

The four-block AES-NI helper takes 7.88 ns on this host. Four standard `cipher.Block` calls take 17.41 ns.

## Circuit

The process compiles the existing MPCL source once. The online path uses a compact, flat execution plan.

| Property | Value |
| --- | ---: |
| Input bits per party | 640 |
| Output bits | 128 |
| Total gates | 184,496 |
| XOR gates | 152,477 |
| XNOR gates | 11 |
| AND gates | 32,007 |
| INV gates | 1 |
| Nonlinear depth | 240 |

Free-XOR removes communication and cryptographic work for XOR gates. Each AND gate uses two 128-bit half-gate table entries.

The serializer omits one length word for every gate. The fixed circuit defines all table positions in advance.

## OT precomputation

Each corrected KOS2 batch uses 128 P-256 Chou-Orlandi base OTs and applies the revised KOS/SoftSpoken repetition-code consistency check with `kappa = s = 128`. The initial batch expands 100,000 random OTs; refills expand 50,000.

One OPRF consumes 640 random OTs. A 100,000-entry batch supports 156 complete OPRFs.

The production TEE handlers accept at most 100,000 OTs in one batch. They reject zero, negative, or larger counts before they create a session, mutate pool state, start base OT, or allocate extension matrices. The generic `mpc` extension primitive has a separate internal limit; that limit is not the production wire limit. At the production maximum, the KOF2 opaque payload is 1,607,840 bytes, and its protobuf control envelope remains below the 30 MiB WebSocket limit.

The local median costs are:

| Precomputation operation | Median |
| --- | ---: |
| Corrected repetition-code proof, 100,000 OTs | 1.066 ms |
| Full KOS2 symmetric extension, both parties, 100,000 OTs | 20.73 ms |
| 128 P-256 base OTs | 11.90 ms |
| Combined sequential CPU per batch | 32.63 ms |
| Amortized CPU per OPRF | 0.209 ms |

These medians use the benchmark host described above. The full symmetric benchmark excludes P-256 base OT, protobuf/WebSocket framing, and network time.

The protocol reuses the existing precomputation protobuf byte fields. Version-2 phase tags distinguish seven internal frames. The schema adds peer-only online fields 73 and 74; client messages do not change.

TEE_T first fixes the base-OT ciphertexts and complete IKNP `U` matrix. TEE_K parses and validates that commitment before it samples and sends every independent `chi` coefficient. TEE_T returns `x` and all 128 column values `t_i`; TEE_K verifies every equation `q_i = t_i XOR (delta_i ? x : 0)` before either pool can commit.

For a 100,000-OT batch, the KOS2 opaque payloads total 1,627,080 bytes, compared with 1,612,185 bytes for KOS1. This is 14,895 bytes, or about 0.924 percent, more. Protobuf and WebSocket overhead is additional. Precomputation grows from five to seven frames. The online protocol grows from two messages to four so the evaluator commits its hidden choice corrections before TEE_K sends correction-aware masks.

Both sides commit a batch only after the KOS proof passes. The pool token rotates after each committed batch.

The receiver accepts disjoint online ranges in any order. A per-entry marker rejects replay and partial overlap.

Consumed labels are cleared. The pool compacts only a fully consumed prefix.

## CPU paths

The amd64 garbling path uses AES-NI assembly. It encrypts four independent hash blocks with shared round-key loads.

The KOS proof uses PCLMULQDQ assembly. Runtime feature checks select both assembly paths.

Other processors use constant-time Go standard-library AES and a constant-time Go field multiplication.

The enclave binaries remain pure Go. They build with `CGO_ENABLED=0` and the existing static enclave tags.

AMD EPYC Milan supports AES, AVX2, PCLMULQDQ, VAES, and VPCLMULQDQ. The current code uses AES-NI and PCLMULQDQ.

VAES needs a separate CPUID check in Go. Add that path only after a Milan benchmark proves a useful gain.

## Protocol comparison

The comparison requires the current XOR-shared input, XOR-shared key, exact AES-CMAC result, and two-party trust model.

| Protocol | Scalar multiplication | Fit for this operation |
| --- | --- | --- |
| Half-gate Yao with KOS OT | 128 base OTs per large batch | Selected. It keeps four online messages and exact results. |
| GMW with precomputed triples | No online curve work | The circuit has nonlinear depth 240. GMW needs about 240 online exchanges. |
| TinyTable or dedicated AES lookup MPC | No online curve work | It needs function-specific preprocessing and more rounds for five chained AES calls. |
| Three-Halves garbling | Same OT model | It reduces tables by 23 percent but uses 50 percent more hash calls. |
| Projective S-box garbling | Same OT model | AES evaluation is faster. Garbling and bandwidth increase, sometimes by up to four and eight times. |
| Three-party replicated sharing | No public-key work after setup | It requires a third independently trusted party and changes the deployment model. |
| Ristretto VOPRF | Curve work per request | One server needs the key and one client needs the complete input. That ownership model does not match. |
| Threshold Ristretto VOPRF | Curve work per request | It shares the key, but still needs a complete blinded input. Hash-to-group on XOR shares requires MPC. |

The 2025 active-security construction also uses half-gates as its practical base. It requires dual execution and progressive output release.

That construction targets mutually distrustful software parties. This deployment instead binds both parties to measured TEE code.

Relevant primary sources include the current 2022-09-16 revision of the [KOS ePrint](https://eprint.iacr.org/2015/546.pdf), [SoftSpokenOT](https://eprint.iacr.org/2022/192.pdf), [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html), [Half-Gates](https://www.cs.virginia.edu/~evans/pubs/ec2015/halfgates.pdf), and [Three-Halves](https://eprint.iacr.org/2021/749.pdf).

Also see [TinyTable](https://eprint.iacr.org/2016/695.pdf), [projective S-box garbling](https://arxiv.org/abs/2405.20713), and [active two-party computation](https://eprint.iacr.org/2025/614.pdf).

## Implementation survey

The survey covered mature C++, Rust, Java, and Go implementations. Local comparisons use pinned source revisions.

| Ecosystem | Implementation | Relevant result |
| --- | --- | --- |
| C++ | [libOTe](https://github.com/osu-crypto/libOTe) at `d644366` | KOS took 2.86 ms for 100,000 OTs. Silent malicious OT took 13.80 ms. |
| C++ | [EMP-tool](https://github.com/emp-toolkit/emp-tool) at `ef0bf1e` | A local half-gate primitive test reached 38.0 million combined gates per second. |
| Rust | [Swanky](https://github.com/GaloisInc/swanky) | It provides production-oriented garbling and OT components. |
| Java | [MPC4J](https://github.com/alibaba-edu/mpc4j) | It provides broad protocol coverage, including silent OT families. |
| Rust | [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) at `a354947` | Ristretto fixed-base multiplication took 6.87 microseconds. Variable-base took 20.05 microseconds. |
| Go | [gtank/ristretto255](https://github.com/gtank/ristretto255) at `60e34dc` | Fixed-base multiplication took 8.27 microseconds. Variable-base took 26.4 microseconds. |

The EMP figure measures only its half-gate primitive. It does not measure this complete AES-CMAC circuit or its network protocol.

Ristretto improves individual variable-base multiplication over P-256. OT extension removes 640 online multiplications instead.

For the 100,000-entry refill, local libOTe KOS was faster than its silent malicious OT implementation.

## Security scope

Mutual SEV-SNP attestation binds each peer to the expected TEE image and TLS key.

The corrected repetition-code check detects inconsistent IKNP matrices from the OT receiver under the revised KOS analysis. Session identifiers, a versioned pool epoch, and transcript hashes bind the base-OT ciphertexts, extension matrix, full challenge, proof, and pool index. KOS1 frames and epochs are rejected; there is no downgrade or cross-version resume path.

This check does not turn the complete system into generic malicious-secure two-party computation. The P-256 Chou-Orlandi implementation is not claimed to provide standalone malicious-secure or composably secure base OT. Its messages remain inside the secure, mutually attested TEE-to-TEE control channel, and its implementation remains inside the measured-code trust boundary. The deployment relies on both TEEs running the expected attested code. The commit protocol provides fail-closed consistency and single-use accounting; it does not make an unattested peer trustworthy.

The online path uses single-use OTs and single-use session state. TEE_K verifies every returned output label before trusting the CMAC.

The garbled circuit does not use cut-and-choose. It relies on attestation to prevent a malicious garbler from running different code.

The fixed-key hash follows the half-gate AES construction. Its public key is independent from the secret wire-label offset.

Its hash input uses invertible doubling in GF(2^128). A truncating shift would discard one label bit and create collisions.

The package clears consumed pool entries, session secrets, and temporary OT matrices after use.

## SEV-SNP deployment gate

The current attestation code verifies AMD signatures, measurements, VMPL 0, and the disabled debug policy.

It does not enforce a minimum reported TCB version. `go-sev-guest` supports this check through `validate.Options.MinimumTCB`.

AMD lists Milan firmware requirements in [AMD-SB-3019](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3019.html).

AMD states that MilanLaunchy needs MilanPI 1.0.0.3 or later in [AMD-SB-3045](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3045.html).

Select the minimum TCB from the production cloud and image policy. Do not deploy this change without that explicit value.

Google currently limits SEV-SNP Confidential VMs to AMD Milan N2D machines in its [supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations).

## Verification

Run focused tests and the race detector:

```sh
go test ./mpc ./tee_k ./tee_t
go test -race ./mpc ./tee_k ./tee_t
```

Run the complete repository tests:

```sh
go test ./...
```

Run the stable online benchmarks on one core:

```sh
GOMAXPROCS=1 go test ./mpc -run '^$' \
  -bench 'Benchmark(OPRFNewEndToEnd|OPRFNewGarbler|OPRFNewSerialize)$' \
  -benchmem -benchtime=1s -count=5 -cpu=1
```

The reported KOS2 medians used these exact benchmark commands:

```sh
GOCACHE=/tmp/reclaim-tee-go-cache GOMAXPROCS=1 go test ./mpc -run '^$' \
  -bench 'BenchmarkKOS2(Proof|Full)100K$' \
  -benchmem -benchtime=5x -count=5 -cpu=1

GOCACHE=/tmp/reclaim-tee-go-cache GOMAXPROCS=1 go test ./mpc -run '^$' \
  -bench '^BenchmarkBaseOTBatch128$' \
  -benchmem -benchtime=20x -count=5 -cpu=1
```

Repeat the benchmarks on the exact Milan SEV-SNP machine type before rollout.
