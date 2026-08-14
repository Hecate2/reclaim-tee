# MPC OPRF Architecture

## Purpose

The MPC OPRF computes AES-CMAC on XOR-shared data and an XOR-shared key.

TEE_K has a TLS keystream share and a 16-byte key share. TEE_T has a ciphertext share and another 16-byte key share.

The circuit computes these values:

```text
plaintext = keystream_K XOR ciphertext_T
key       = key_share_K XOR key_share_T
output    = AES-CMAC(key, plaintext)
```

The plaintext and the combined key do not leave the circuit. Both TEEs learn the 16-byte CMAC output.

## Roles

- TEE_K is the garbler and the random-OT sender.
- TEE_T is the evaluator and the random-OT receiver.
- The client sends each OPRF range to TEE_K.
- TEE_K sends the authoritative range data to TEE_T in `OPRFOnlineFull`.

The TEEs use a mutually attested connection. Each application session uses a separate WebSocket connection between the TEEs.

## OT Precomputation

TEE_K creates P-256 Chou-Orlandi sender setups. TEE_T creates one cryptographically random choice `d` for each setup.

Each side stores its half of the random OT. The initial pool contains 100,000 entries. One OPRF consumes 640 entries.

Both pools mark entries as used before the online computation. A second use returns an error and terminates the application session.

## Online Protocol

The online protocol uses four messages for each OPRF range:

```text
TEE_K                                              TEE_T
  |                                                   |
  |-- OPRFOnlineFull: circuit and translations ------>|
  |                                                   |
  |<-- OPRFMPCRound2: choice corrections -------------|
  |                                                   |
  |-- OPRFMPCRound3: corrected OT masks ------------->|
  |                                                   |
  |<-- OPRFMPCResult: evaluated output labels --------|
  |                                                   |
```

### Message 1: Circuit

TEE_K garbles the AES-CMAC circuit. It sends the garbled tables, its input labels, and one translation bit for each output wire.

TEE_K keeps both labels for each evaluator input wire. It also keeps both labels for each output wire.

TEE_K derives random-OT pads `R0` and `R1`. These pads stay in the garbler session until message 2 arrives.

### Message 2: Choice Corrections

TEE_T converts its 80-byte input into 640 bits. For each bit `b`, TEE_T sends this correction:

```text
c = d XOR b
```

The random choice `d` is uniform, private, and single-use. Thus, the correction does not disclose `b` to TEE_K.

### Message 3: OT Masks

For `c=0`, TEE_K sends these masks:

```text
M0 = L0 XOR R0
M1 = L1 XOR R1
```

For `c=1`, TEE_K swaps the pads:

```text
M0 = L0 XOR R1
M1 = L1 XOR R0
```

TEE_T knows only `R_d`. It selects `M_b` and computes `L_b = M_b XOR R_d`.

The message does not contain `R0 XOR R1`. Therefore, TEE_T cannot derive the other pad from the protocol transcript.

### Message 4: Result

TEE_T evaluates the circuit with one label for each input wire. It decodes each output with the corresponding translation bit.

TEE_T returns only the evaluated output labels. It does not send a trusted CMAC value or hash value.

TEE_K compares each returned label with its two local output labels. TEE_K derives the CMAC only from labels that match.

## Output Translation

The garbling library uses a global Free-XOR offset. A complete output-label pair discloses that offset.

`OPRFOnlineFull` contains one `L0` permutation bit for each output wire. It never contains complete output-label pairs.

The permutation bit lets TEE_T decode the output. It does not disclose the 128-bit Free-XOR offset.

## Message Definitions

The protocol uses these messages from `proto/transport.proto`:

- `OPRFOnlineFull` carries the circuit payload, range data, OT index, TLS session hash, and OPRF session ID.
- `OPRFMPCRound2` carries 640 packed correction bits. The encoded value is exactly 80 bytes.
- `OPRFMPCRound3` carries 640 pairs of 16-byte OT masks.
- `OPRFMPCResult` carries 128 evaluated output labels.

The protobuf keeps fields 8, 9, and 11 of `OPRFOnlineFull` reserved. These fields previously carried unsafe or obsolete values.

## Replay and State Protection

TEE_K creates a random OPRF session ID for each garbled circuit. Every online message carries this ID and the range index.

Both handlers compare the envelope session ID, the OPRF session ID, and the range index. A mismatch terminates the session.

TEE_K applies choice corrections once. TEE_T evaluates each prepared session once. TEE_K accepts one output result for each session.

TEE_K also sends a TLS session hash. TEE_T stores the first hash and compares all later hashes in the same application session.

## Implementation

The main package functions are:

- `CMACGarblerOnline` creates the garbled circuit and stores random-OT pads.
- `CMACEvaluatorPrepare` creates the correction bits and stores evaluator state.
- `CMACGarblerApplyCorrections` creates correction-aware OT masks.
- `CMACEvaluatorOnline` evaluates the circuit and returns output labels.
- `CMACGarblerVerifyOutput` compares output labels and derives the CMAC.

TEE_K routes these messages in `tee_k/oprf_handler.go`. TEE_T routes them in `tee_t/oprf_evaluator.go`.

## Security Scope

The protocol relies on mutual attestation for the expected TEE code. It does not use cut-and-choose to protect against a malicious garbler.

The random-OT conversion relies on the privacy of the Chou-Orlandi choice. It also relies on cryptographically random, single-use receiver choices.

The garbled-circuit verification stops an evaluator from substituting arbitrary output bytes. It does not make an invalid TEE measurement trustworthy.

Any OPRF protocol error terminates the application session. A failed OPRF state cannot produce a signed session result.

## Tests

The `oprfmpc` tests cover these properties:

- All four combinations of `d` and `b` recover the selected label.
- The corrected transcript does not decrypt the unselected mask with `R_d`.
- A regression test reproduces the removed `R0 XOR R1` disclosure.
- The circuit output matches NIST AES-CMAC vectors.
- Modified output labels fail verification.
- Correction, evaluation, and output sessions reject reuse.
- Serialization rejects incorrect lengths and trailing data.
