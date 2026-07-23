# Reclaim TEE — interactive 3D walkthrough

An annotated, animated 3D system diagram of the TEE proving flow: who talks to whom,
what crosses each wire, and where the trust comes from. Built with three.js.

## Build

```
npm install
npm run build     # -> dist/index.html, one self-contained file
npm run dev       # live-reload dev server
```

`dist/index.html` inlines everything (three.js, fonts, CSS) — it opens offline with a
double-click and survives a strict CSP with no external hosts, so it can be published
as a Claude Artifact or dropped anywhere as a single file.

## Controls

Drag to orbit, scroll to zoom. Prev/Next or arrow keys step the tour; space toggles
autoplay; the tour loops on its own when playing. `#step=N&theme=dark|light&play=0`
in the URL deep-links a state (used for headless screenshots).

## Accuracy notes

The flow is grounded in the actual code (client/, tee_k/, tee_t/, router/,
proto/transport.proto, attestor-core) as of 2026-07-23:

- Naming: the code says TEE_T, but official docs call it TEE_A — all on-screen
  text uses TEE_A (and A-OUTPUT). Source identifiers keep the repo's teeT naming.

- The client is the only party that touches the target site and the attestor; TEEs
  talk only to each other and the client.
- The handshake/response boundary is `HandshakeComplete` — after it, captured records
  go to TEE_T only, never TEE_K (there is no TCPData-ack protocol; that design was
  abandoned).
- One request/response per session; auth material arrives pre-provided as secret params.
- OPRF ranges go to TEE_K only; TEE_K relays them to TEE_T (`OPRFOnlineFull`).
- Attestor: XORs keystream ⊕ ciphertext at revealed positions, checks responseMatches,
  verifies attestations to hardware roots; pins exactly two SNP base digests (GCP +
  AWS PCR 11) and publishes the PCR 8 app digest in the claim (`pcr0_k`/`pcr0_t`).
