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

TEE_T expands both seed sets and creates the IKNP matrix correction. It also creates the KOS consistency proof.

TEE_K expands its selected seeds and verifies the proof. It rejects the complete batch after any proof failure.

TEE_K sends a commit message after successful verification. TEE_T commits its pending receiver entries after this message.

The initial batch contains 100,000 entries. One OPRF consumes 640 entries.

The following flow uses the existing protobuf byte fields:

```text
TEE_K                                             TEE_T
  |                                                  |
  |-- KOB1: batch session, start, count ------------>|
  |                                                  |
  |<-- BOS1: P-256 base-OT sender point -------------|
  |                                                  |
  |-- BOC1: 128 base-OT choice points -------------->|
  |                                                  |
  |<-- KOF1: base ciphertexts, IKNP matrix, proof ---|
  |                                                  |
  |-- OTPrecomputeComplete: generated total -------->|
  |                                                  |
```

Both sides derive a new pool token from the committed extension session. A lost commit message makes resume fail closed.

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

The protocol uses these existing messages from `proto/transport.proto`:

- `OTPrecomputeRequest` carries the KOS begin message or base-OT choices.

- `OTPrecomputeResponse` carries the base setup or final KOS data.

- `OTPrecomputeComplete` commits one verified extension batch.

- `OTResumeRequest` and `OTResumeResponse` synchronize a retained pool.

- `OPRFOnlineFull` carries the circuit, range, OT index, TLS hash, and OPRF session identifier.

- `OPRFMPCRound2` carries exactly 80 bytes of packed corrections.

- `OPRFMPCRound3` carries 640 pairs of 16-byte masks.

- `OPRFMPCResult` carries 128 evaluated output labels.

Fields 8, 9, and 11 of `OPRFOnlineFull` remain reserved. They previously carried unsafe or obsolete values.

## Replay and failure handling

TEE_K creates a random OPRF session identifier for each circuit. Every online message carries it and the range index.

Both handlers validate the envelope session, OPRF session, and range. A mismatch terminates the application session.

TEE_K applies corrections once. TEE_T evaluates once. TEE_K accepts one output result.

TEE_T validates the complete online payload before it consumes random OTs.

Any disconnect aborts an active precomputation waiter. A committed pool remains available only through a successful resume exchange.

## Security scope

The protocol relies on mutual attestation for the expected TEE code. It does not use cut-and-choose against a malicious garbler.

The KOS proof checks receiver consistency during OT extension. Chou-Orlandi supplies the 128 base OTs.

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

- KOS rejects matrix, proof, session, and index changes.

- Pools reject replay and overlap while accepting out-of-order ranges.

- Resume rejects rewinds, overflow, and pool-token mismatch.

- Assembly AES and PCLMUL results match their portable implementations.

- The half-gate hash keeps every label bit through field doubling.

- Serializers reject incorrect sizes, counts, versions, and trailing data.
