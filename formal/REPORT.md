# Split-AEAD — formal verification report

Symbolic analysis of the split-AEAD protocol (whitepaper §3.2, Algorithms 3–6)
in **Tamarin 1.12.0** / Maude 3.5.1.

Every lemma below has a definite verdict. Nothing times out, nothing exhausts
memory. Full suite: `./verify_all.sh`, about four minutes at 8G.

**Naming.** `TEE_K` holds the TLS keys and keystreams. `TEE_A` computes
authentication tags and holds ciphertexts. (`TEE_A` is `tee_t/` in the source.)

---

## Why Tamarin

Split-AEAD is XOR. Its correctness is the reassociation

```
((R_S ⊕ Str_S) ⊕ KS) ⊕ Str_S  =  R_S ⊕ KS
```

which needs associative-commutative unification. Two tools were ruled out
before starting:

- **Verifpal** — its complete equational theory is Diffie-Hellman
  commutativity plus fixed decompose/rewrite rules (`src/theory.rs:13-28`);
  there is no XOR anywhere in its source, and term equality
  (`src/equivalence.rs:61-107`) has no AC-unification. Adding an XOR primitive
  does not help: `PrimitiveSpec` rules are fixed-shape patterns.
- **ProVerif** — ruled out by its own manual, p53: *"associativity cannot be
  handled by ProVerif for this reason, which prevents the modeling of
  primitives such as XOR (exclusive or) or groups."*

Tamarin has had native XOR since CSF'18 and is the only mainstream option.

---

## Results

### Correctness

The statements that require AC-XOR, and that no Verifpal-class tool can express.

| Lemma | Model | Verdict |
|---|---|---|
| `correctness_request` — website recovers **exactly** the user's request, and the tag verifies | `correctness.spthy` | verified (16) |
| `correctness_response` — user recovers **exactly** what the website sent | `splitaead_privacy2.spthy` | verified (16) |

### Privacy against a compromised TEE

Three-segment request split, confirmed in two independent models.

| | TEE_A compromised | TEE_K compromised |
|---|---|---|
| `R_S` (sensitive, never revealed) | **verified** (1631 / 969) | falsified (7) |
| `R_SP` (sensitive, revealed in proof) | **verified** (1631 / 967) | falsified (7) |
| response body | **verified** (8) | falsified (8) |
| both compromised → secret leaks | verified (8) — anti-vacuity | |

Models: `request_privacy2.spthy` (request phase), `splitaead_privacy2.spthy`
(response phase).

**Read the falsified column correctly.** Those lemmas hand the adversary
TEE_K's entire state *and* network access. TEE_K holds every key and
keystream, so of course it can decrypt — the split never claimed otherwise.
What it claims is that TEE_K is never *given* the response ciphertext or the
user masks. Those lemmas destroy that premise by construction, so falsification
is the only possible answer; they are negative controls, not findings. The real
claim is stated as invariants below. The **verified TEE_A column** is the
compromise the design claims to survive, and it does.

### TEE-view invariants

What the split actually rests on: not that either TEE is cryptographically
unable to decrypt, but what each one is ever handed. Honest protocol, no
compromise rules.

| Lemma | Verdict |
|---|---|
| `teek_never_holds_response_ciphertext` | verified (9) |
| `teek_never_holds_a_mask` | verified (18) |
| `teea_never_holds_a_key` | verified (48) |
| `teea_never_holds_a_keystream` | verified (121) |
| `sanity_protocol_completes` | verified (16) |

`teea_never_holds_a_keystream` is the non-trivial one: TEE_A handles `renc`,
`final`, `respenc` and both tag secrets, every one of which has keystream mixed
into it, and the proof establishes that no bare keystream block is ever
separable from those.

### Redaction — what the attestor sees

Adversary here is the attestor plus everyone else who sees the published proof.
All parties honest.

| Lemma | Verdict |
|---|---|
| `attestor_cannot_see_redacted_response` | verified (9) |
| `attestor_cannot_see_RS` | verified (5) |
| `attestor_sees_revealed_response` | verified (6) |
| `attestor_sees_RSP` | verified (5) |
| `attestor_sees_RNS` | verified (5) |

Both directions, which is what makes it meaningful: the attestor learns
`R_NS`, `R_SP` and the non-redacted response, and nothing about `R_S` or the
redacted bytes. The three `exists-trace` lemmas are the anti-vacuity half —
without them a model where the attestor sees nothing at all would "pass".

### Non-repudiation

| Lemma | Verdict |
|---|---|
| `no_forged_transcript` | verified (12) |
| `sanity_honest_run` | verified (12 / 14) |
| `chosen_content_forgery` | falsified, no trace (46 / 52) |

Models: `transcript.spthy`, `transcript_full.spthy` (the latter with the
complete `R_red ‖ Str_Dec,Red ‖ Cert` and `Resp_enc ‖ T_resp ‖ Str_SP`
payloads). Same verdicts either way.

### Negative controls

A secrecy proof is worth only as much as its sensitivity. Each control breaks
one safeguard and confirms the corresponding lemma then fails.

| Control | Breaks | Result |
|---|---|---|
| `redaction_negctl_fullks` | signs the full keystream instead of `RedactedStreams` (`tee_k/crypto.go:569`) | `attestor_cannot_see_redacted_response` **falsified** (6) |
| `redaction_negctl_appkey` | leaves `ServerAppKey` in the attestor bundle, i.e. skips `stripUnsignedFields` (`client/verification_bundle.go:292-304`) | `attestor_cannot_see_redacted_response` **falsified** (8) |
| `transcript_negctl_nobinding` | removes `session_id` from both signed payloads | `no_forged_transcript` **falsified** (12 / 14) |

All three safeguards are load-bearing, not incidental.

> `client/verification_bundle.go:291` currently describes `stripUnsignedFields`
> as bandwidth hygiene — *"to avoid sending unnecessary data"*. It is a
> security invariant: with `ServerAppKey` present the attestor reconstructs the
> keystream and redaction collapses. Worth recomping so nobody optimises it
> back in.

---

## Assumptions

Each of these is an assumption, not a result. A symbolic model cannot discharge
any of them.

- `ks`, `tagsec` and `mac` are **free function symbols**. Keystream
  pseudorandomness, TagSecrets hiding the key, and MAC unforgeability are
  assumed. Property 1's actual content — *computationally* indistinguishable
  from random — is not expressible here; that belongs in CryptoVerif or a hand
  reduction.
- **No TLS handshake.** `k_enc`/`k_dec` appear as fresh shared secrets. No
  certificate validation, no RA-TLS, no SEV-SNP measurement.
- Keystream slices `ks(k,n,i)` are independent terms, not slices of one PRF
  stream. Justified by PRF security, not proved.
- Record nonces are modelled **public** (they derive from the TLS sequence
  number). Modelling them secret makes a compromised TEE_K look harmless and
  silently inflates the K-direction results.
- One record per direction; three request segments, two response segments; one
  TEE pair. No OPRF, no key rotation.
- The invariants prove the **design** has the property and pin exactly what
  must hold. They say nothing about the shipped binary — that gap closes
  through reproducible builds, SEV-SNP measurement and the RA-TLS peer check,
  which is a supply-chain and hardware-root-of-trust argument, not a protocol
  theorem.

**Known disclosure, outside the model.** `KOutputPayload.oprf_outputs` carries
`SHA256(CMAC)` over ranges of the **un-redacted** plaintext
(`tee_k/crypto.go:587` deliberately feeds OPRF the original keystream).
Symbolically a hash hides its preimage, so including them would still report
secrecy — but they are a deterministic function of redacted data and therefore
permit equality testing and linking across proofs. That is the intended
unique-ID feature; the redaction result above should not be read as covering
it.

---

## Reproducing

Toolchain (release binaries, no sudo, ~60MB):

```bash
mkdir -p ~/.local/tamarin && cd ~/.local/tamarin
curl -sSL -o t.tar.gz https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz
tar xzf t.tar.gz && chmod +x tamarin-prover
curl -sSL -o m.zip https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip
mkdir -p maudedir && cd maudedir && unzip -oq ../m.zip && chmod +x maude
```

Then:

```bash
cd formal
./verify_all.sh            # everything -> RESULTS.txt
./run.sh redaction.spthy --prove          # one model
./prove_all.sh request_privacy2.spthy     # one model, per-lemma
```

`run.sh` caps the GHC heap with `+RTS -M`. **Do not use `ulimit -v`** — GHC
reserves ~1TB of address space up front, so it aborts at startup; an uncapped
run OOM-killed the machine once.

---

## Proof performance

The `*_against_TEEA` lemmas do not terminate under the default heuristic —
heap-exhausted at 4G and at 9G alike. This was a **heuristic problem wearing a
memory problem's clothes**, and the fix needs *less* memory, not more.

Method, reusable for any XOR model here:

1. Run `probe.oracle`, a pass-through oracle that logs every goal, against the
   stuck lemma. That produced 28,059 goals in 240s.
2. Read the profile. The killer class was `!KU( (z ⊕ <term>) )` — the adversary
   assembling an XOR term around an **unconstrained** variable `z` — plus
   `splitEqs(6..14)` downstream. Bury those.
3. Prioritise goals that **close** branches rather than expand them: bare
   `ks(...)` keystream terms, which no rule ever emits, so resolving one kills
   the branch outright.
4. Order `splitEqs(N)` low-index-first, as in Tamarin's own `LD07.oracle`.

Result on `secrecy_RS_against_TEEA`:

| | time | heap | verdict |
|---|---|---|---|
| default heuristic | 1394s | 9G | heap exhausted |
| `request_privacy2.oracle` | **47s** | **6G** | **verified (1631 steps)** |

### Where the blowup comes from

Bisecting up from a minimal core (`rs_vs_teea_minimal.spthy`) located it
precisely — it is the number of independently-masked segments whose masks the
adversary knows, not the tags and not the compromise direction:

| Masked segments | Result |
|---|---|
| 0 (response — no user mask) | verified, 8 steps |
| 1 | verified, 183 steps |
| 1 + tag secrets (`bisect_a_withtag.spthy`) | verified, 208 steps |
| 2 (`bisect_b_twoseg.spthy`) | does not terminate without the oracle |

Each known mask is a summand the adversary can cancel, so the set of derivable
XOR normal forms grows multiplicatively.

---

## Files

| File | Contents |
|---|---|
| `correctness.spthy` | `correctness_request`; the only model with the website's decrypt-and-verify path |
| `request_privacy2.spthy` | request-phase secrecy, three segments |
| `splitaead_privacy2.spthy` | response phase + `correctness_response` |
| `invariants.spthy` | the four TEE-view invariants |
| `redaction.spthy` | what the attestor learns, both directions |
| `redaction_negctl_{appkey,fullks}.spthy` | redaction ablations |
| `transcript{,_full}.spthy` | non-repudiation |
| `transcript_negctl_nobinding{,_full}.spthy` | session-binding ablation |
| `rs_vs_teea_minimal.spthy`, `bisect_{a_withtag,b_twoseg}.spthy` | performance diagnostics |
| `request_privacy2.oracle`, `splitaead_privacy2.oracle` | proof oracles |
| `probe.oracle` | goal-profiling oracle used to write them |
| `run.sh`, `prove_all.sh`, `verify_all.sh` | runners |
