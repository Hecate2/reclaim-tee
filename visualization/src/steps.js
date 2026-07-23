// The guided tour. Copy is grounded in client/, router/, tee_k/, tee_t/,
// proto/transport.proto and attestor-core — do not invent protocol steps.
export const STEPS = [
  {
    eyebrow: 'Overview',
    title: 'Five parties, one secret that never moves',
    body: `
      <p>Reclaim lets your device <strong>prove what a website told it</strong> — a balance,
      a grade, a follower count — without showing anyone the whole conversation.</p>
      <p>The <strong>client</strong> is the only party that ever talks to the website, and the
      only place the full response exists in the clear. Two hardware enclaves,
      <strong>TEE_K</strong> and <strong>TEE_A</strong> — one in Google Cloud, one in AWS —
      each hold half of the cryptographic picture, a design we call
      <strong>Split-AEAD</strong>. A neutral <strong>attestor</strong> reunites the halves
      and signs the claim.</p>
      <p>Press play, or step through with the arrows.</p>`,
    wire: [],
    cam: { pos: [0, 30, 42], tgt: [0, 1, 0] },
    dur: 12,
    fx: [
      { type: 'glow', node: 'client' },
    ],
  },
  {
    eyebrow: 'Step 1 · Allocate',
    title: 'The router hands out an enclave pair',
    body: `
      <p>The client asks the router for a TEE pair, announcing which attestation flavors it
      can verify — Confidential Space, SEV-SNP. The router picks a <em>ready</em> pair —
      preferring SEV-SNP for capable clients and the geo-nearest region — and returns the two
      enclave addresses plus a short-lived <strong>JWT</strong> scoped to that pair.</p>
      <p>Pairs earned their place earlier, at registration: the router verified each enclave's
      attestation, checked its measured code digest against an allowlist, and pinned the
      SEV-SNP base image — fail-closed.</p>`,
    wire: [
      { label: 'POST /allocate', color: 'control' },
      { label: 'supported attestation types', color: 'control' },
      { label: 'pair + JWT', color: 'control' },
    ],
    cam: { pos: [-26, 15, 12], tgt: [-13, 2, -4] },
    dur: 13,
    fx: [
      { type: 'packets', link: 'clientRouter', dir: 1, color: 'control', label: 'POST /allocate', period: 4.2, offset: 0.4, dur: 1.5 },
      { type: 'packets', link: 'clientRouter', dir: -1, color: 'control', label: 'pair + JWT', period: 4.2, offset: 2.5, dur: 1.5 },
      { type: 'glow', node: 'router' },
    ],
  },
  {
    eyebrow: 'Step 2 · Attest',
    title: 'Verify the enclaves before trusting them',
    body: `
      <p>The client opens WebSockets to both enclaves over <strong>RA-TLS</strong>: each
      enclave's TLS certificate carries its hardware attestation in a custom extension
      (OID <code>1.3.6.1.4.1.65998.1</code> for Confidential Space, <code>.2</code> for SEV-SNP).
      The attestation binds the certificate's own public key, so it can't be lifted onto an
      impostor.</p>
      <p>Verification happens <em>during the TLS handshake itself</em> — before a single
      protocol byte. The first message on each socket is the router's JWT. The two enclaves
      also attest each other, pinning exact code digests.</p>`,
    wire: [
      { label: 'RA-TLS cert + attestation', color: 'attest' },
      { label: "the router's JWT", color: 'control' },
    ],
    cam: { pos: [-4, 15, 22], tgt: [3, 2, -4] },
    dur: 14,
    open: ['kt'],
    fx: [
      { type: 'packets', link: 'clientK', dir: -1, color: 'attest', label: 'RA-TLS attestation', period: 4.5, offset: 0.3, dur: 1.6 },
      { type: 'packets', link: 'clientT', dir: -1, color: 'attest', label: 'RA-TLS attestation', period: 4.5, offset: 1.0, dur: 1.6 },
      { type: 'packets', link: 'clientK', dir: 1, color: 'control', label: 'session JWT', period: 4.5, offset: 2.6, dur: 1.4 },
      { type: 'packets', link: 'clientT', dir: 1, color: 'control', label: 'session JWT', period: 4.5, offset: 3.2, dur: 1.4 },
      { type: 'glow', node: 'enclave' },
    ],
  },
  {
    eyebrow: 'Step 3 · Roots of trust',
    title: 'Why the attestation is believable',
    body: `
      <p>For SEV-SNP the chain runs from silicon to signature. <strong>AMD's root keys</strong>
      (ARK&nbsp;→&nbsp;ASK&nbsp;→&nbsp;VCEK) sign a report produced inside the CPU — debug mode
      and elevated privilege are rejected. The report binds a <strong>vTPM quote</strong>
      (Google-rooted on GCP, NitroTPM on AWS) carrying two measurements:
      <strong>PCR&nbsp;11</strong>, the base OS image — the attestor hardcodes exactly two
      allowed bases, one per cloud — and <strong>PCR&nbsp;8</strong>, the application bundle,
      published inside every claim for anyone to audit.</p>
      <p>The enclave's <em>signing key</em> rides inside the same hardware-signed report, so a
      signature later proves “this exact code, on real hardware, said this.” And the pair
      spans clouds — TEE_K in Google Cloud, TEE_A in AWS — so no single cloud operator ever
      holds both halves.</p>`,
    wire: [
      { label: 'SNP report (AMD-signed)', color: 'attest' },
      { label: 'vTPM / NitroTPM quote', color: 'attest' },
      { label: 'PCR 11 base · PCR 8 app', color: 'attest' },
    ],
    cam: { pos: [12, 9.5, 18.5], tgt: [12, 5, -1] },
    dur: 18,
    open: ['clientK','clientT','kt'],
    fx: [
      { type: 'totem' },
      { type: 'glow', node: 'enclave' },
    ],
  },
  {
    eyebrow: 'Step 4 · Split-AEAD',
    title: 'One cipher key, pried in two',
    body: `
      <p>TLS guards every byte with an <strong>AEAD</strong> cipher — AES-GCM or
      ChaCha20-Poly1305 — where a single key <code>K</code> does two jobs at once:
      it <em>encrypts</em> (plaintext ⊕ pseudorandom keystream = ciphertext) and it
      <em>authenticates</em> (a tag sealing each record).</p>
      <p><strong>Split-AEAD is Reclaim's core design: those two jobs are separated across
      the clouds.</strong> <code>K</code> is born inside TEE_K during the TLS handshake and
      never leaves. What crosses to TEE_A is only <strong>TagSecrets</strong> —
      <code>E_K(0¹²⁸)</code>, <code>E_K(IV∥0³¹∥1)</code> — enough to compute and verify tags
      over ciphertext, yet revealing nothing about <code>K</code>. So TEE_A may safely see
      ciphertext it can never read, TEE_K never sees the response at all, and stealing your
      data would take both clouds falling within a single TLS session.</p>`,
    wire: [
      { label: 'K — stays in TEE_K', color: 'keys' },
      { label: 'TagSecrets: K → A', color: 'keys' },
      { label: 'ciphertext — safe for TEE_A', color: 'cipher' },
    ],
    cam: { pos: [3, 13, 16], tgt: [7.5, 3, -5] },
    dur: 30,
    cycle: 15,
    open: ['clientK', 'clientT', 'kt'],
    fx: [
      {
        type: 'aead', shardAt: 4.2, flightDur: 2.4,
        roleCipherAt: 7.6, roleTagAt: 9.8, rolesEndAt: 13.2,
        states: [
          { at: 1.2, text: 'one key K — encrypts and authenticates' },
          { at: 4.3, text: 'K stays in TEE_K — only TagSecrets cross to TEE_A' },
          { at: 7.6, text: 'TEE_K: keystream ⊕ plaintext = this ciphertext' },
          { at: 9.8, text: 'TEE_A: tag from TagSecrets = E_K(0¹²⁸) · E_K(IV∥0³¹∥1)' },
          { at: 12.2, text: 'neither half alone reveals anything' },
        ],
      },
      { type: 'glow', node: 'enclave' },
    ],
  },
  {
    eyebrow: 'Step 5 · Handshake',
    title: 'TEE_K shakes hands through a blind relay',
    body: `
      <p>The client dials the website over plain TCP — <span class="never">no enclave ever
      connects to the target</span>. But the client is only a relay: <strong>TEE_K is the real
      TLS endpoint</strong>. It composes the handshake inside the enclave, its records travel
      through the client to the website, and every reply is forwarded straight back.</p>
      <p>All session keys are derived — and stay — inside TEE_K. When it reports
      the handshake is complete, that wire goes quiet — watch it dim:
      <strong>nothing captured from the website is ever sent to TEE_K again</strong>. The
      connection itself stays open; only other kinds of traffic will cross it from now on.</p>`,
    wire: [
      { label: 'relayed TLS records', color: 'control' },
      { label: 'handshake-complete signal', color: 'control' },
    ],
    cam: { pos: [-10, 22, 28], tgt: [-6, 1, -1] },
    dur: 16,
    open: ['clientT','kt'],
    cycle: 16,
    fx: [
      { type: 'packets', link: 'clientK', dir: -1, color: 'control', label: 'TLS records out', period: 3.4, offset: 0.4, until: 8, dur: 1.2 },
      { type: 'packets', link: 'clientTarget', dir: 1, color: 'control', label: '', period: 3.4, offset: 1.5, until: 9, dur: 1.0 },
      { type: 'packets', link: 'clientTarget', dir: -1, color: 'control', label: '', period: 3.4, offset: 2.5, until: 9.5, dur: 1.0 },
      { type: 'packets', link: 'clientK', dir: 1, color: 'control', label: 'reply records in', period: 3.4, offset: 3.4, until: 10, dur: 1.2 },
      { type: 'packets', link: 'clientK', dir: -1, color: 'control', label: 'handshake complete', period: 99, offset: 11.2, dur: 1.4 },
      { type: 'boundary', link: 'clientK', at: 12.9, text: 'captured data stops here — wire goes idle' },
      { type: 'glow', node: 'teeK' },
    ],
  },
  {
    eyebrow: 'Step 6 · Request',
    title: 'One request, secrets already redacted',
    body: `
      <p>The app supplied the provider parameters and secrets — cookies, tokens — ahead of
      time; each session makes <strong>exactly one request</strong>. The client redacts the
      secret bytes and splits the evidence: the <strong>redacted request</strong> goes to
      TEE_K; one-time <strong>masking streams</strong> that cover the secret ranges go to
      TEE_A.</p>
      <p>TEE_K encrypts what it's allowed to see with the real TLS keys; TEE_A patches the
      secret ranges back <em>in ciphertext space</em> and finishes the auth tag. The client
      gets a sealed TLS record and forwards it to the website. Neither enclave ever saw the
      secrets in the clear.</p>`,
    wire: [
      { label: 'redacted request → TEE_K', color: 'redact' },
      { label: 'masking streams → TEE_A', color: 'redact' },
      { label: 'sealed request record', color: 'cipher' },
    ],
    cam: { pos: [-8, 20, 27], tgt: [-4, 1, 0] },
    dur: 16,
    fx: [
      { type: 'packets', link: 'clientK', dir: 1, color: 'redact', label: 'redacted request', period: 7.6, offset: 0.3, dur: 1.4 },
      { type: 'packets', link: 'clientT', dir: 1, color: 'redact', label: 'masking streams', period: 7.6, offset: 1.0, dur: 1.4 },
      { type: 'packets', link: 'kt', dir: 1, color: 'cipher', label: 'encrypted fragments + TagSecrets', period: 7.6, offset: 2.6, dur: 1.6, text: '6b f0 21 8d 4e a7' },
      { type: 'packets', link: 'clientT', dir: -1, color: 'cipher', label: 'sealed record', period: 7.6, offset: 4.3, dur: 1.8, text: '17 03 03 00 8a 5d f1 0c' },
      { type: 'packets', link: 'clientTarget', dir: 1, color: 'cipher', label: 'HTTPS request', period: 7.6, offset: 6.2, dur: 1.8, text: '17 03 03 00 8a 5d f1 0c' },
    ],
  },
  {
    eyebrow: 'Step 7 · Split-AEAD, live',
    title: 'The response splits in two',
    body: `
      <p>Now the split from step 4 does its job. The website answers with encrypted TLS
      records. The client keeps the <strong>ciphertext</strong> and sends it — with each
      record's auth tag — to <strong>TEE_A</strong>, which verifies every tag (GHASH or
      Poly1305) using the <strong>TagSecrets</strong> TEE_K derived from its keys. TEE_A
      holds no TLS keys; TEE_K <span class="never">never receives a byte of the
      response</span>.</p>
      <p>TEE_K streams the matching <strong>keystream</strong> to the client, which XORs
      locally — so the plaintext materializes <em>only inside the client</em>. Each enclave
      saw half the picture; neither saw the words.</p>`,
    wire: [
      { label: 'ciphertext + tags → TEE_A', color: 'cipher' },
      { label: 'tag secrets K → A', color: 'keys' },
      { label: 'keystream → client', color: 'keys' },
    ],
    cam: { pos: [-5, 19, 26], tgt: [-3, 1, -2] },
    dur: 16,
    fx: [
      { type: 'packets', link: 'clientTarget', dir: -1, color: 'cipher', label: 'HTTPS response', period: 6.8, offset: 0.2, dur: 1.9, text: '9e 41 c2 88 5f 03 71 b4' },
      { type: 'packets', link: 'clientT', dir: 1, color: 'cipher', label: 'ciphertext + tags', period: 6.8, offset: 2.0, dur: 1.9, text: '9e 41 c2 88 5f 03 71 b4' },
      { type: 'packets', link: 'kt', dir: 1, color: 'keys', label: 'tag secrets', period: 6.8, offset: 2.8, dur: 1.4, text: 'e8 30 71 5a' },
      { type: 'packets', link: 'clientK', dir: -1, color: 'keys', label: 'keystream', period: 6.8, offset: 4.2, dur: 1.9, text: 'f2 7d 0a 96 c8 33 61' },
      { type: 'screen', revealAt: 6.3, lineGap: 0.6 },
      { type: 'glow', node: 'client' },
    ],
  },
  {
    eyebrow: 'Step 8 · Choose & redact',
    title: 'Choose what the world may see',
    body: `
      <p>Provider rules — XPath, JSONPath, regex — resolve on the client into exact
      <strong>byte ranges</strong>: reveal this, hide the rest. The choices go to
      <em>TEE_K only</em>, which relays them to TEE_A — one ordered source, so the untrusted
      client can't tell the enclaves different stories.</p>
      <p>TEE_K then edits the keystream the way CRISPR edits genes: <strong>every byte
      outside the revealed ranges is destroyed</strong> before anything is signed. What
      survives can only ever decrypt the bytes you chose to show — and it is this
      <em>redacted</em> keystream that will ride in the proof bundle. When the attestor
      later XORs it with the ciphertext, hidden spans dissolve into ✱✱✱ and only your
      chosen fields become words.</p>`,
    wire: [
      { label: 'reveal / hide choices → TEE_K', color: 'redact' },
      { label: 'keystream — kept ranges only', color: 'keys' },
    ],
    cam: { pos: [1, 8.5, 11], tgt: [4, 3.2, -2.5] },
    dur: 24,
    cycle: 14,
    screen: 3,
    open: ['clientT', 'kt'],
    fx: [
      { type: 'packets', link: 'clientK', dir: 1, color: 'redact', label: 'reveal / hide choices', period: 99, offset: 0.6, until: 0.6, dur: 1.5 },
      {
        type: 'redactor', startAt: 3.2, cellDur: 0.42, keepAt: 2.4,
        states: [
          { at: 0.8, text: "TEE_K's response keystream" },
          { at: 3.4, text: 'bytes outside your reveal choices are destroyed' },
          { at: 8.6, text: 'this redacted keystream is what gets signed into the proof' },
        ],
      },
      { type: 'glow', node: 'teeK' },
    ],
  },
  {
    eyebrow: 'Step 9 · OPRF-MPC',
    title: 'If needed, PII becomes a blind fingerprint',
    body: `
      <p>Some hidden fields still need a stable reference — the same account should produce
      the same proof tomorrow, without ever exposing its ID. When a provider asks for it,
      that field is <strong>deterministically hashed with OPRF-MPC</strong> instead of being
      revealed or simply hidden.</p>
      <p>The enclaves compute it together: TEE_K brings the keystream, TEE_A brings the
      ciphertext, and the joint circuit combines them into the real value <em>only inside
      itself</em> — then instantly collapses it to an opaque fingerprint.
      <strong>Both enclaves get the same fingerprint; neither ever saw the value.</strong>
      If nothing needs blinding, this step simply doesn't run.</p>
      <p>The faint TEE_A wire is idle — the connection stays open all session.</p>`,
    wire: [
      { label: 'garbled circuit: K → A', color: 'redact' },
      { label: 'keystream + ciphertext → MPC', color: 'keys' },
      { label: 'same fingerprint → both TEEs', color: 'redact' },
    ],
    cam: { pos: [12, 8.5, 14.5], tgt: [12, 3, -6] },
    dur: 28,
    screen: 3,
    cycle: 14,
    open: ['clientT'],
    fx: [
      { type: 'packets', link: 'kt', dir: 1, color: 'redact', label: 'garbled-circuit tables', period: 99, offset: 1.4, until: 1.4, dur: 1.1 },
      { type: 'packets', link: 'kMpc', dir: 1, color: 'keys', label: 'keystream (from TEE_K)', period: 99, offset: 3.3, until: 3.3, dur: 2.4, text: 'f2 7d 0a 96 c8' },
      { type: 'packets', link: 'tMpc', dir: 1, color: 'cipher', label: 'ciphertext (from TEE_A)', period: 99, offset: 3.7, until: 3.7, dur: 2.4, text: '9e 41 c2 88 5f' },
      { type: 'mpc', piiAt: 6.4, hashAt: 8.4, hideAt: 12.6, pii: 'John Smith', hash: 'tZ4vQk8pR1mXw9c=' },
      { type: 'packets', link: 'kMpc', dir: -1, color: 'redact', label: 'same fingerprint', period: 99, offset: 10.2, until: 10.2, dur: 2.6, text: 'tZ4vQk8pR1mXw9c=' },
      { type: 'packets', link: 'tMpc', dir: -1, color: 'redact', label: 'same fingerprint', period: 99, offset: 10.5, until: 10.5, dur: 2.6, text: 'tZ4vQk8pR1mXw9c=' },
      { type: 'glow', node: 'enclave' },
    ],
  },
  {
    eyebrow: 'Step 10 · The gauntlet',
    title: 'The attestor checks everything, then signs',
    body: `
      <p>Each enclave signs its half with the key baked into its attestation: TEE_K the
      consolidated <strong>keystream</strong>, TEE_A the consolidated <strong>ciphertext</strong>.
      The client bundles both and carries them over —
      <span class="never">enclaves never talk to the attestor directly</span>.</p>
      <p>Then the bundle runs a gauntlet — watch the checklist: attestations walked back to
      hardware roots, PCRs extracted and the base pinned, signatures matched to attested keys,
      the two OPRF lists compared, keystream&nbsp;⊕&nbsp;ciphertext recovered, assertions
      tested. <strong>Only when every gate passes does it sign.</strong> What it never redoes:
      tags and TLS — the enclaves signed those facts, and their word is the hardware's word.</p>`,
    wire: [
      { label: 'signed keystream — from TEE_K', color: 'keys' },
      { label: 'signed ciphertext — from TEE_A', color: 'cipher' },
      { label: 'proof bundle → attestor', color: 'attest' },
    ],
    cam: { pos: [-27, 18, 29], tgt: [-7, 2, 7] },
    dur: 21,
    screen: 3,
    cycle: 19,
    open: ['kt'],
    fx: [
      { type: 'packets', link: 'clientK', dir: -1, color: 'keys', label: 'signed keystream', period: 99, offset: 0.2, until: 0.2, dur: 1.3 },
      { type: 'packets', link: 'clientT', dir: -1, color: 'cipher', label: 'signed ciphertext', period: 99, offset: 0.7, until: 0.7, dur: 1.3 },
      { type: 'packets', link: 'clientAttestor', dir: 1, color: 'attest', label: 'proof bundle', period: 99, offset: 1.8, until: 1.8, dur: 1.6 },
      {
        type: 'checklist', at: 3.8, gap: 1.45, xorIndex: 6, signIndex: 8,
        items: [
          'both signed halves present',
          'attestations chain to AMD + cloud roots',
          'PCR 11 base allowlisted · PCR 8 published',
          'TEE signatures ↔ attested keys',
          'timestamps fresh · same session id',
          'blinded hashes: both TEEs agree',
          'XOR keystream ⊕ ciphertext',
          'claimed facts match revealed bytes',
          'sign the claim',
        ],
      },
      { type: 'glow', node: 'attestor' },
    ],
  },
  {
    eyebrow: 'Step 11 · The claim',
    title: 'A portable, signed fact',
    body: `
      <p>Satisfied, the attestor signs the claim and hands it back — and now the phone
      <strong>holds it</strong>: a compact, portable proof that a specific website served
      specific bytes, checkable by anyone, revealing only what was chosen.</p>
      <p><strong>What never happened:</strong> the plaintext never left the client. No enclave
      touched the website or the attestor. TEE_K never saw the response; TEE_A never saw the
      keys. And every trusted statement traces back to attested hardware, not to promises.</p>`,
    wire: [
      { label: 'signed claim', color: 'claim' },
    ],
    cam: { pos: [-2, 26, 38], tgt: [-2, 1, 2] },
    dur: 14,
    screen: 3,
    open: ['clientK','clientT'],
    fx: [
      { type: 'packets', link: 'clientAttestor', dir: -1, color: 'claim', label: 'signed claim', period: 99, offset: 0.5, until: 0.5, dur: 1.8 },
      { type: 'claim', at: 2.5 },
      { type: 'glow', node: 'client' },
    ],
  },
]
