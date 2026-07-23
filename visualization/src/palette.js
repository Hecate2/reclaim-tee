// Payload colors — single source of truth for the 3D scene.
// Keep aligned with the CSS custom properties in styles.css.
export const PAYLOAD = {
  control:   0x7e90b4, // session plumbing: allocate, TCPData relay, acks
  attest:    0x2ec5a2, // attestation & trust material
  cipher:    0x8b7cf6, // TLS ciphertext + tags
  keys:      0xe8a33d, // keystream & tag secrets (from TEE_K's keys)
  redact:    0xe0609a, // redaction specs, OPRF ranges & MPC
  plaintext: 0x4cc276, // never travels — lives inside the client only
  claim:     0xe5c558, // the signed claim
}

export const PAYLOAD_CSS = Object.fromEntries(
  Object.entries(PAYLOAD).map(([k, v]) => [k, '#' + v.toString(16).padStart(6, '0')])
)

export const LEGEND = [
  { key: 'control',   name: 'Session control',   note: 'allocate, relayed TLS records' },
  { key: 'attest',    name: 'Attestation',       note: 'hardware-signed identity' },
  { key: 'cipher',    name: 'Ciphertext',        note: 'encrypted bytes + auth tags' },
  { key: 'keys',      name: 'Keystream',         note: 'tag secrets, decryption streams' },
  { key: 'redact',    name: 'Redaction / OPRF',  note: 'reveal ranges, blinded hashes' },
  { key: 'claim',     name: 'Signed claim',      note: 'the portable proof' },
  { key: 'plaintext', name: 'Plaintext',         note: 'never leaves the client' },
]

// Scene colors per theme.
export const THEMES = {
  dark: {
    bg: 0x0c1120,
    fog: 0x0c1120,
    fogNear: 42,
    fogFar: 110,
    floor: 0x111a2e,
    grid: 0x243350,
    linkBase: 0x45587e,
    linkOpacity: 0.62,
    bodyMat: 0x38455f,
    bodyDark: 0x232e45,
    hemi: 0x8fa3c8,
    hemiGround: 0x141c2e,
    hemiIntensity: 0.75,
    keyLight: 0xffffff,
    keyIntensity: 1.6,
    rim: 0x4a6aa8,
    domeOpacity: 0.10,
  },
  light: {
    bg: 0xe9edf5,
    fog: 0xe9edf5,
    fogNear: 48,
    fogFar: 130,
    floor: 0xdde3ee,
    grid: 0xb9c3d6,
    linkBase: 0x9aa8c2,
    linkOpacity: 0.55,
    bodyMat: 0x8fa0bd,
    bodyDark: 0x6b7b98,
    hemi: 0xffffff,
    hemiGround: 0xb8c2d4,
    hemiIntensity: 0.9,
    keyLight: 0xffffff,
    keyIntensity: 1.9,
    rim: 0x7d92b8,
    domeOpacity: 0.13,
  },
}
