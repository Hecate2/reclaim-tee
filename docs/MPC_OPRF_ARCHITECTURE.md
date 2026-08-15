# MPC OPRF Architecture

## Purpose

The MPC OPRF computes AES-CMAC on XOR-shared data and an XOR-shared key.

TEE_K has a TLS keystream share and a 16-byte key share. TEE_T has a ciphertext share and another key share.

The circuit computes these values:

```text
plaintext = keystream_K XOR ciphertext_T
key       = key_share_K XOR key_share_T
output    = AES-CMAC(key, plaintext)
```

The plaintext and combined key do not leave the circuit. Both TEEs learn the 16-byte CMAC output.

The caller zero-pads each range to 64 bytes. The circuit processes four complete CMAC blocks.

## Roles

- TEE_K is the garbler and random OT sender.

- TEE_T is the evaluator and random OT receiver.

- The client sends each OPRF range to TEE_K.

- TEE_K sends the authoritative range data to TEE_T.

The TEEs use a mutually attested connection. Each application session uses a separate WebSocket connection.

## Circuit

The package compiles the legacy AES-CMAC MPCL source once. It converts the result into a flat execution plan.

The circuit has 184,496 gates. It contains 32,007 AND gates and has nonlinear depth 240.

Free-XOR handles XOR and XNOR gates. Half-gates use two labels for each AND gate.

The amd64 path hashes four labels in one AES-NI assembly call. Portable targets use standard-library AES.

## OT precomputation

TEE_K starts each batch with a random 32-byte extension session identifier.

TEE_T creates one P-256 Chou-Orlandi sender setup. It owns 128 random seed pairs.

TEE_K selects one seed from each pair. Its 128 selection bits form the KOS correlation value.

TEE_T expands both seed sets, creates the IKNP matrix correction, and sends the complete matrix together with the base-OT ciphertexts. This fixes its values before it learns the consistency challenge.

TEE_K parses and validates the complete commitment. It then samples and sends a full vector of independent 128-bit `chi` values.

TEE_T computes the corrected KOS/SoftSpoken repetition-code proof. The proof contains one `x` value and all 128 values `t_i`.

TEE_K expands its selected seeds and checks every equation `q_i = t_i XOR (delta_i ? x : 0)`. It rejects the complete batch after any transcript or proof failure.

TEE_K sends a commit message after successful verification. TEE_T commits its pending receiver entries after this message.

The initial batch contains 100,000 entries. One OPRF consumes 640 entries.

The production handlers reject counts outside 1 through 100,000 before they create a session, mutate pool state, start base OT, or allocate extension matrices. The generic `mpc` extension primitive keeps its separate internal limit. That internal limit is not accepted by the production wire handlers. At 100,000 OTs, the largest opaque frame is the 1,607,840-byte KOF2 commitment, and its protobuf envelope remains below the 30 MiB WebSocket limit.

The following flow uses the existing protobuf byte fields:

```text
TEE_K                                             TEE_T
  |                                                  |
  |-- KOB2: versioned epoch, session, start, count -->|
  |                                                  |
  |<-- KBS2: wrapped P-256 base-OT sender point -----|
  |                                                  |
  |-- KBC2: wrapped 128 base-OT choice points ------>|
  |                                                  |
  |<-- KOF2: base ciphertexts and complete U matrix -|
  |                                                  |
  |-- KCH2: full independent chi vector ------------>|
  |                                                  |
  |<-- KPR2: x and all 128 column checks ------------|
  |                                                  |
  |-- OTPrecomputeComplete: generated total -------->|
  |                                                  |
```

Both sides derive a version-2 pool token from the committed extension session. A lost commit message makes resume fail closed. Version-1 frames and tokens cannot resume or downgrade a version-2 pool. A pair must therefore deploy the protocol change together.

The seven opaque frame sizes for a 100,000-OT batch are 91 bytes for a standard 41-byte epoch begin, 105 bytes for base setup, 4,296 bytes for base choices, 1,607,840 bytes for the commitment, 12,616 bytes for the challenge, 2,132 bytes for the proof, and the existing protobuf completion message. The opaque payload total before protobuf and WebSocket framing is 1,627,080 bytes.

## Pool rules

TEE_K reserves increasing absolute ranges. It sends each starting index in the first online message.

Different application sessions use different connections. Their messages can reach TEE_T in a different order.

TEE_T therefore accepts disjoint unused ranges in any order. It rejects a replay or any partial overlap.

Both pools return owned copies to online sessions. Disconnect cleanup cannot change a range after reservation.

Both pools clear consumed secrets. They compact only a contiguous consumed prefix.

On reconnect, TEE_K sends its reservation frontier and pool token. TEE_T rejects a rewind, overflow, or token mismatch.

TEE_T clears every unused entry below an accepted sender frontier. This step closes gaps from interrupted sessions.

## Online protocol

The online protocol uses four messages for each OPRF range:

```text
TEE_K                                             TEE_T
  |                                                  |
  |-- OPRFOnlineFull: circuit and translations ----->|
  |                                                  |
  |<-- OPRFMPCRound2: choice corrections ------------|
  |                                                  |
  |-- OPRFMPCRound3: corrected OT masks ------------>|
  |                                                  |
  |<-- OPRFMPCResult: evaluated output labels -------|
  |                                                  |
```

### Message 1

TEE_K garbles the AES-CMAC circuit. It sends tables, its input labels, and one translation bit for each output wire.

TEE_K keeps both labels for every evaluator input wire. It also keeps both output labels.

The `MPC1` payload has an exact size of 1,034,536 bytes.

### Message 2

TEE_T converts its 80-byte input into 640 bits. It sends this correction for every bit:

```text
c = d XOR b
```

The random choice `d` is uniform, private, and single-use. The correction does not disclose `b` to TEE_K.

### Message 3

TEE_K sends two masks for every evaluator input wire.

For `c=0`, it sends these masks:

```text
M0 = L0 XOR R0
M1 = L1 XOR R1
```

For `c=1`, it swaps the random OT pads:

```text
M0 = L0 XOR R1
M1 = L1 XOR R0
```

TEE_T knows only `R_d`. It selects `M_b` and recovers `L_b`.

The message never contains `R0 XOR R1`. TEE_T cannot derive the other pad from the transcript.

### Message 4

TEE_T evaluates the circuit with one label for every input wire. It returns only the selected output labels.

TEE_K compares each label with its local pair. It derives the CMAC only from valid labels.

## Message definitions

The protocol uses these messages from `proto/transport.proto`; `OPRFMPCRound2` and `OPRFMPCRound3` are peer-only additions:

- `OTPrecomputeRequest` carries the KOS2 begin, base-OT choices, or full challenge.

- `OTPrecomputeResponse` carries the base setup, fixed BOT+U commitment, or repetition-code proof.

- `OTPrecomputeComplete` commits one verified extension batch.

- `OTResumeRequest` and `OTResumeResponse` synchronize a retained pool.

- `OPRFOnlineFull` carries the circuit, range, OT index, TLS hash, and OPRF session identifier.

- `OPRFMPCRound2` carries exactly 80 bytes of packed corrections.

- `OPRFMPCRound3` carries 640 pairs of 16-byte masks.

- `OPRFMPCResult` carries 128 evaluated output labels.

Fields 8, 9, and 11 of `OPRFOnlineFull` remain reserved. They previously carried unsafe or obsolete values.

### Cumulative OT index compatibility

`OTResumeRequest.next_index`, `OTPrecomputeComplete.pool_size`, and
`OPRFOnlineFull.ot_start_index` are cumulative `uint64` frontiers. The field
numbers and protobuf varint wire type did not change. Values through
`MaxUint32` therefore have exactly the same bytes as the previous `uint32`
fields. Values above that boundary use at most five additional varint bytes.

This migration does not change client messages or client APIs. Per-batch OT
counts remain `uint32`, and production batches remain limited to 1 through
100,000 OTs. Only the cumulative lifetime of a retained TEE_K/TEE_T pool
changes.

Go source compatibility is narrower than wire compatibility. The exported
`mpc.SenderPool.TotalCount` and `mpc.ReceiverPool.TotalCount` return types, and
the generated Go types for the three internal protobuf fields, change to
`uint64`. The repository's current clients do not use these APIs and remain
unchanged. Direct external Go consumers of those MPC or internal protobuf types
must update any `int` or `uint32` assignments and recompile.

Deploy TEE_T first and then TEE_K. Mixed versions are wire-compatible while
the cumulative frontier is at most `MaxUint32`. Above that boundary, an old
peer truncates the new value and fails the existing pool-total, resume, or
duplicated MPC1/protobuf index checks; it cannot silently reuse wrapped OTs.
After a pool crosses the boundary, rollback must not retain or resume that pool.
The required recovery is a forced control reconnect followed by a successful
full initial precompute, which resets both pools before online work resumes.
Restarting the TEE_K/TEE_T pair is the conservative operational procedure that
guarantees this reset, but a VM/process restart is not an implementation
requirement when the forced reconnect and full reset complete successfully.

## Replay and failure handling

TEE_K creates a random OPRF session identifier for each circuit. Every online message carries it and the range index.

Both handlers validate the envelope session, OPRF session, and range. A mismatch terminates the application session.

TEE_K applies corrections once. TEE_T evaluates once. TEE_K accepts one output result.

TEE_T validates the complete online payload before it consumes random OTs.

Any disconnect aborts an active precomputation waiter. A committed pool remains available only through a successful resume exchange.

## Security scope

The protocol relies on mutual attestation for the expected TEE code. It does not use cut-and-choose against a malicious garbler.

The corrected KOS2 proof checks receiver consistency during OT extension using the revised repetition-code construction with `kappa = s = 128`. It does not use the original compressed one-equation KOS check.

The implemented order and formula follow Figure 10 in the current 2022-09-16 revision of the [KOS ePrint](https://eprint.iacr.org/2015/546.pdf) and the corresponding repetition-code check in pinned libOTe revision `d644366`.

Chou-Orlandi supplies the 128 base OTs. The P-256 implementation is not claimed to provide standalone malicious-secure or composably secure base OT. Its messages stay inside the secure, mutually attested TEE-to-TEE control channel, and its implementation stays inside the measured-code trust boundary. Base-OT correctness, garbler correctness, and the choice of the intended circuit rely on that boundary. This protocol is not a substitute for malicious-secure garbling against arbitrary unattested code.

The output-label check prevents the evaluator from substituting arbitrary output bytes.

The fixed-key half-gate hash uses a public AES-128 key. This key is independent from the secret global offset.

The hash applies invertible GF(2^128) doubling. Tests reject the legacy truncating-shift collision.

Any OPRF error terminates the application session. A failed state cannot produce a signed session result.

## Implementation

The `mpc` package owns the circuit, OT extension, pool, serializers, and CPU-specific helpers.

TEE_K routes online messages in `tee_k/oprf_handler.go`. It routes precomputation in `tee_k/ot_precompute.go`.

TEE_T routes online messages in `tee_t/oprf_evaluator.go`. It routes precomputation in `tee_t/ot_precompute.go`.

See [mpc/README.md](../mpc/README.md) for benchmarks, alternative protocols, and the SEV-SNP deployment gate.

## Tests

The tests cover these properties:

- The new circuit matches the legacy circuit and direct AES-CMAC.

- Modified output labels fail verification.

- Correction, evaluation, output, and base-OT states reject reuse.

- KOS2 rejects matrix, BOT, epoch, challenge, proof, session, index, version, order, truncation, and trailing-data changes.

- A deterministic oracle checks the literal repetition-code formula, and tests prove that every one of the 128 column equations is enforced.

- A failed proof commits no sender entries. Both pools commit only after proof acceptance and the existing completion exchange.

- A full in-memory primitive/protobuf exchange checks all seven frame codecs, metadata, pool epochs, readiness, and matching entries.

- Production-handler tests drive the real K and T control state machines over captured in-memory WebSockets. They check generation ownership, pending phases, exact frame order, zero pre-proof pool commits, completion, epochs, readiness, and matching committed entries.

- Production count tests accept 100,000, reject 100,001 before state or base-OT work, inject an epoch-randomness failure, and keep the maximum protobuf frame below the WebSocket limit.

- Pools reject replay and overlap while accepting out-of-order ranges.

- Resume rejects rewinds, overflow, and pool-token mismatch.

- Assembly AES and PCLMUL results match their portable implementations.

- The half-gate hash keeps every label bit through field doubling.

- Serializers reject incorrect sizes, counts, versions, and trailing data.
