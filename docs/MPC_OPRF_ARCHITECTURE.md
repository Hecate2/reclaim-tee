# MPC OPRF Architecture and Design

## Overview

MPC OPRF (`oprf-mpc`) is a TEE-to-TEE Multi-Party Computation protocol using Garbled Circuits to compute AES-CMAC OPRF on XOR-shared data. This runs **alongside** (not replacing) the existing client-side TOPRF (`oprf`).

## Purpose

Enable privacy-preserving verification of redacted data where:
- Neither TEE learns the plaintext
- Both TEEs contribute key shares
- The OPRF output proves data authenticity without revealing content

## Architecture

### Network Topology

```
                    ┌─────────────┐
                    │   Client    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │ WebSocket  │  WebSocket │
              ▼            │            ▼
       ┌──────────┐        │     ┌──────────┐
       │  TEE_K   │◄───────┴────►│  TEE_T   │
       │ (Garbler)│  Persistent  │(Evaluator)│
       │ Port 8080│  WebSocket   │ Port 8081│
       └──────────┘              └──────────┘
```

- **Client** has TWO WebSocket connections (to TEE_K and TEE_T)
- **TEE_K and TEE_T** share ONE persistent connection (mutual attestation at startup)

### Data Flow

```
TEE_K has:  Keystream (K)     + Key Share A
TEE_T has:  Ciphertext (C)    + Key Share B

XOR inside circuit: K ⊕ C = Plaintext (never revealed outside circuit)
Combined key: A ⊕ B (combined inside circuit)

OPRF Output: AES-CMAC(combined_key, plaintext)
```

## Protocol Flow

```
Client                           TEE_K                    TEE_T
   │                               │                        │
   │──[OprfRangesSubmission]──────►│                        │
   │──[OprfRangesSubmission]──────────────────────────────►│
   │                               │                        │
   │──[RedactionSpec]─────────────►│                        │
   │                               │──[Finished]───────────►│
   │                               │                        │
   │                               │  (MPC OPRF 4 rounds)   │
   │                               │──[Round1: OT Setup]───►│
   │                               │◄─[Round2: OT Choices]──│
   │                               │──[Round3: GC + Inputs]►│
   │                               │◄─[Round4: Result]──────│
   │                               │                        │
   │◄─[SignedMessage K_OUTPUT]─────│                        │
   │◄─[SignedMessage T_OUTPUT]─────────────────────────────│
   │                               │                        │
   │  (verify outputs match)       │                        │
```

## Components

### 1. Garbled Circuit Package (`oprfmpc/`)

Location: `/home/scratch/reclaim-tee/oprfmpc/`

Core functions:
- `CMACGarblerRound1()` - Generate OT setup (TEE_K)
- `CMACGarblerRound3()` - Generate garbled circuit with inputs (TEE_K)
- `CMACEvaluatorRound2()` - Generate OT choices (TEE_T)
- `CMACEvaluatorRound4()` - Evaluate circuit, get CMAC result (TEE_T)
- `PadZeros64()` - Zero-pad data to 64 bytes

### 2. Protocol Messages (`proto/transport.proto`)

```protobuf
// Client -> both TEEs
message OPRFRangesSubmission {
  string session_id = 1;
  repeated OPRFRangeSpec ranges = 2;
}

message OPRFRangeSpec {
  int32 tls_start = 1;
  int32 tls_length = 2;  // max 64 bytes
}

// TEE_K -> TEE_T
message MPCOPRFRound1 {
  string session_id = 1;
  uint64 oprf_session_id = 2;
  bytes ot_setup = 3;
  int32 range_index = 4;
  int32 tls_start = 5;
  int32 tls_length = 6;
  bytes tls_session_hash = 7;  // Replay protection
}

// TEE_T -> TEE_K
message MPCOPRFRound2 {
  string session_id = 1;
  uint64 oprf_session_id = 2;
  bytes ot_choices = 3;
}

// TEE_K -> TEE_T
message MPCOPRFRound3 {
  string session_id = 1;
  uint64 oprf_session_id = 2;
  bytes garbled_circuit = 3;
  bytes garbler_inputs = 4;
  bytes ot_ciphertexts = 5;
  bytes output_hints = 6;
}

// TEE_T -> TEE_K
message MPCOPRFResult {
  string session_id = 1;
  uint64 oprf_session_id = 2;
  int32 range_index = 3;
  bytes cmac_output = 4;  // 16 bytes
  bytes hash_output = 5;  // 32 bytes SHA256(cmac)
}
```

### 3. TEE_K Implementation (`tee_k/`)

**Session State** (`session_manager.go`):
```go
type TEEKSessionState struct {
    // ... existing fields ...

    // MPC OPRF state
    ConsolidatedKeystream []byte
    OPRFKeyShare          []byte                              // 16-byte key share
    GarblerSessions       map[int]*oprfmpc.CMACGarblerSession
    OPRFRanges            []*teeproto.OPRFRangeSpec
    OPRFResults           map[int]*shared.OPRFResult
    OPRFState             shared.OPRFSessionState
    OPRFExpectedCount     int
    ClientRangesReceived  bool
}
```

**Handler** (`oprf_handler.go`):
- `handleOPRFRangesFromClient()` - Receive ranges, queue if keystream not ready
- `processQueuedOPRFRanges()` - Process after keystream available
- `initiateOPRFForRange()` - Start MPC for single range
- `handleOPRFRound2()` - Process Round2 from TEE_T
- `handleOPRFResult()` - Store result, check completion
- `buildOPRFOutputsForSigning()` - Build outputs for signature

### 4. TEE_T Implementation (`tee_t/`)

**Session State** (`session_manager.go`):
```go
type TEETSessionState struct {
    // ... existing fields ...

    // MPC OPRF state
    OPRFKeyShare         []byte
    EvaluatorSessions    map[int]*oprfmpc.CMACEvaluatorSession
    ClientOPRFRanges     []*teeproto.OPRFRangeSpec
    ClientRangesReceived bool
    PendingRound1s       []*teeproto.MPCOPRFRound1  // Queue for out-of-order
    OPRFResults          map[int]*shared.OPRFResult
    OPRFState            shared.OPRFSessionState
    OPRFExpectedCount    int
    TLSSessionHash       []byte  // Cached for replay protection
}
```

**Evaluator** (`oprf_evaluator.go`):
- `handleOPRFRangesFromClient()` - Receive ranges, process queued Round1s
- `handleOPRFRound1()` - Queue if ranges not received, else process
- `processOPRFRound1()` - Validate positions, generate Round2
- `handleOPRFRound3()` - Evaluate circuit, send result

### 5. Client Implementation (`client/`)

**Range Building** (`redaction.go`):
- `buildMPCOPRFRanges()` - Convert HTTP positions to TLS positions
- Send ranges to BOTH TEEs via `sendOPRFRangesToBothTEEs()`

**Verification** (`verification_bundle.go`):
- `verifyMPCOPRFOutputsMatch()` - Verify TEE_K and TEE_T outputs match

## Security Model

### Zero-Error Policy

Any error terminates the session immediately:
- `ReasonOPRFProtocolFailed` termination reason
- `OPRFStateFailed` does NOT allow signature
- All handlers call `terminateSessionWithError()` on failure

### Replay Protection

TEE_K computes TLS session hash from:
```go
h := sha256.New()
h.Write([]byte(sessionID))
h.Write(teekState.ClientHello)
h.Write(teekState.ServerHello)
return h.Sum(nil)
```

TEE_T caches and verifies this hash from Round1 messages.

### Position Validation

TEE_T validates TEE_K positions match client-provided ranges:
```go
if msg.TlsStart != clientRange.TlsStart || msg.TlsLength != clientRange.TlsLength {
    return fmt.Errorf("position mismatch")
}
```

### Input Validation

Both TEEs validate:
- Range bounds: `start >= 0`, `length > 0`, `length <= 64`
- Range doesn't exceed data length
- Range count limits (DoS prevention)

## Signature Integration

OPRF outputs are included in both TEE signatures:

**TEE_K** (`transcript.go`):
```go
kPayload := &teeproto.KOutputPayload{
    // ... existing fields ...
    OprfOutputs: t.buildOPRFOutputsForSigning(teekState),
}
```

**TEE_T** (`transcript_handlers.go`):
```go
tPayload := &teeproto.TOutputPayload{
    // ... existing fields ...
    OprfOutputs: t.buildOPRFOutputsForSigning(teetState),
}
```

Both TEEs wait for OPRF completion before signing:
```go
func isOPRFReady(state shared.OPRFSessionState) bool {
    return state == shared.OPRFStateNone ||
        state == shared.OPRFStateComplete
    // Failed is NOT ready - zero error policy
}
```

## Usage

In provider configuration, set `hash: "oprf-mpc"` for MPC OPRF:

```go
ResponseRedactions: []providers.ResponseRedaction{
    {
        XPath: "/html/body/div/span",
        Regex: `data="(?<value>[^"]+)"`,
        Hash:  ptrString("oprf-mpc"),  // Use MPC OPRF
    },
}
```

Comparison:
- `hash: "oprf"` - Client-side TOPRF with attestor
- `hash: "oprf-mpc"` - TEE-to-TEE MPC OPRF (this implementation)

## Files Changed/Added

### New Files
- `oprfmpc/circuit.go` - Garbled circuit implementation
- `oprfmpc/circuit_test.go` - Circuit tests
- `oprfmpc/serialization.go` - Message serialization
- `tee_k/oprf_handler.go` - TEE_K OPRF handlers
- `tee_t/oprf_evaluator.go` - TEE_T OPRF evaluator

### Modified Files
- `proto/transport.proto` - MPC OPRF messages
- `proto/signing.proto` - OPRFOutput in payloads
- `shared/types.go` - OPRFSessionState, OPRFResult
- `shared/session_termination.go` - ReasonOPRFProtocolFailed
- `tee_k/session_manager.go` - TEEKSessionState OPRF fields
- `tee_k/websocket.go` - Message routing, error termination
- `tee_k/response_handlers.go` - OPRF ready check
- `tee_k/transcript.go` - Include OPRF in signature
- `tee_k/crypto.go` - Copy keystream to state
- `tee_t/session_manager.go` - TEETSessionState OPRF fields
- `tee_t/websocket_handlers.go` - Message routing, error termination
- `tee_t/transcript_handlers.go` - OPRF ready check, include in signature
- `client/client.go` - MPC OPRF state fields
- `client/redaction.go` - Build and send MPC OPRF ranges
- `client/websocket.go` - Send to both TEEs
- `client/verification_bundle.go` - Verify outputs match

## Testing

```bash
# Build all
./build.sh

# Run demo with MPC OPRF
./demo.sh

# Expected log messages:
# - "Received OPRF ranges from client"
# - "Processing queued OPRF ranges"
# - "Sending MPC OPRF Round1 to TEE_T"
# - "Received MPC OPRF Round2 from TEE_T"
# - "MPC OPRF evaluation complete"
# - "All MPC OPRF computations complete"
# - "Included OPRF outputs in signed payload"
# - "Verified MPC OPRF outputs match between TEE_K and TEE_T"
```
