import * as THREE from 'three'
import { CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js'
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js'
import { PAYLOAD } from './palette.js'
import logoUrl from '../assets/reclaim-logo.png'
import gcpUrl from '../assets/gcp-logo.png'
import awsUrl from '../assets/aws-logo.png'

function loadTex(url) {
  const t = new THREE.TextureLoader().load(url)
  t.colorSpace = THREE.SRGBColorSpace
  t.anisotropy = 4
  return t
}
const logoTex = loadTex(logoUrl)
const gcpTex = loadTex(gcpUrl)
const awsTex = loadTex(awsUrl)

function logoBadge(tex, w = 1, h = 1, transparent = false) {
  const g = new THREE.Group()
  const backing = new THREE.Mesh(
    new THREE.BoxGeometry(w * 1.16, h * 1.16, 0.06),
    new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.35, metalness: 0.1 })
  )
  g.add(backing)
  const face = new THREE.Mesh(
    new THREE.PlaneGeometry(w, h),
    new THREE.MeshBasicMaterial({ map: tex, toneMapped: false, transparent })
  )
  face.position.z = 0.035
  g.add(face)
  return g
}

export const POS = {
  client:   new THREE.Vector3(-6, 0, 2),
  router:   new THREE.Vector3(-20, 0, -10),
  teeK:     new THREE.Vector3(8.8, 0, -9.8),
  teeT:     new THREE.Vector3(15.2, 0, -6.2),
  enclave:  new THREE.Vector3(12, 0, -8),
  target:   new THREE.Vector3(-22, 0, 4),
  attestor: new THREE.Vector3(-8, 0, 14),
  totem:    new THREE.Vector3(12, 0, 2.4),
}

export const ANCHOR = {
  client:   new THREE.Vector3(-6, 2.3, 2),
  router:   new THREE.Vector3(-20, 1.7, -10),
  teeK:     new THREE.Vector3(8.8, 2.1, -9.8),
  teeT:     new THREE.Vector3(15.2, 2.1, -6.2),
  target:   new THREE.Vector3(-22, 2.2, 4),
  attestor: new THREE.Vector3(-8, 3.0, 14),
  mpc:      new THREE.Vector3(12, 3.4, -4.2),
  aead:     new THREE.Vector3(2, 3.6, -1),
}

const RESPONSE_LINES = ['200 OK', 'name: John Smith', 'gpa: 9.2 / 10']

// the phone screen: request always visible, response lines appear only once
// the keystream arrives and the client decrypts locally (step "Split-AEAD, live")
function makeScreen() {
  const c = document.createElement('canvas')
  c.width = 256; c.height = 512
  const g = c.getContext('2d')
  const tex = new THREE.CanvasTexture(c)
  tex.colorSpace = THREE.SRGBColorSpace
  tex.anisotropy = 4
  function draw(revealed) {
    g.fillStyle = '#081410'
    g.fillRect(0, 0, 256, 512)
    const grad = g.createRadialGradient(128, 250, 20, 128, 250, 260)
    grad.addColorStop(0, `rgba(76,194,118,${revealed > 0 ? 0.34 : 0.18})`)
    grad.addColorStop(1, 'rgba(76,194,118,0)')
    g.fillStyle = grad
    g.fillRect(0, 0, 256, 512)
    g.fillStyle = 'rgba(96,214,138,0.5)'
    g.fillRect(22, 44, 60, 5)
    g.font = '500 17px "IBM Plex Mono", monospace'
    const put = (t, a, i) => {
      g.fillStyle = `rgba(96,214,138,${a})`
      g.fillText(t, 22, 92 + i * 34)
    }
    put('GET /portal/grades', 0.9, 0)
    put('cookie: ******', 0.35, 1)
    put('session: ******', 0.35, 2)
    g.strokeStyle = 'rgba(96,214,138,0.25)'
    g.beginPath(); g.moveTo(22, 196); g.lineTo(234, 196); g.stroke()
    if (revealed === 0) {
      put('awaiting response…', 0.45, 4)
    } else {
      RESPONSE_LINES.slice(0, revealed).forEach((t, i) => put(t, 0.95, 4 + i))
      if (revealed >= RESPONSE_LINES.length) put('✓ decrypted locally', 0.55, 8)
    }
    tex.needsUpdate = true
  }
  draw(0)
  return { tex, draw }
}

function nodeLabel(name, sub, y = 0) {
  const div = document.createElement('div')
  div.className = 'node-label'
  div.innerHTML = `<div class="nl-name">${name}</div><div class="nl-sub">${sub}</div>`
  const obj = new CSS2DObject(div)
  obj.center.set(0.5, 1)
  obj.position.set(0, y, 0)
  return obj
}

export function buildNodes(stage) {
  const { scene, onTheme } = stage
  const bodyMats = []   // re-tinted per theme
  const darkMats = []
  const spinners = []   // {mesh, speed, bob}

  function bodyMat(opts = {}) {
    const m = new THREE.MeshStandardMaterial({ color: 0x38455f, roughness: 0.55, metalness: 0.25, ...opts })
    bodyMats.push(m)
    return m
  }
  function darkMat(opts = {}) {
    const m = new THREE.MeshStandardMaterial({ color: 0x232e45, roughness: 0.8, metalness: 0.1, ...opts })
    darkMats.push(m)
    return m
  }
  function coreMat(hex) {
    return new THREE.MeshStandardMaterial({
      color: hex, emissive: hex, emissiveIntensity: 0.9,
      roughness: 0.3, metalness: 0, flatShading: true,
    })
  }
  function keyMesh(hex, s = 1) {
    const g = new THREE.Group()
    const mat = coreMat(hex)
    const head = new THREE.Mesh(new THREE.TorusGeometry(0.3 * s, 0.1 * s, 12, 32), mat)
    head.position.y = 0.8 * s
    g.add(head)
    const shaft = new THREE.Mesh(new THREE.CylinderGeometry(0.08 * s, 0.08 * s, 1.1 * s, 12), mat)
    shaft.position.y = -0.1 * s
    g.add(shaft)
    for (const [y, w] of [[-0.42, 0.3], [-0.6, 0.22]]) {
      const tooth = new THREE.Mesh(new THREE.BoxGeometry(w * s, 0.1 * s, 0.1 * s), mat)
      tooth.position.set((w / 2 + 0.05) * s, y * s, 0)
      g.add(tooth)
    }
    return g
  }
  function tagMesh(hex, s = 1) {
    const g = new THREE.Group()
    const mat = coreMat(hex)
    const plate = new THREE.Mesh(new RoundedBoxGeometry(0.72 * s, 1.0 * s, 0.12 * s, 2, 0.09), mat)
    plate.position.y = -0.15 * s
    g.add(plate)
    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.13 * s, 0.055 * s, 10, 24), mat)
    ring.position.y = 0.48 * s
    g.add(ring)
    return g
  }
  function pedestal(radius) {
    const g = new THREE.Group()
    const base = new THREE.Mesh(new THREE.CylinderGeometry(radius, radius * 1.12, 0.3, 48), darkMat())
    base.position.y = 0.15
    base.receiveShadow = true
    g.add(base)
    return g
  }
  function shadowed(mesh) { mesh.castShadow = true; mesh.receiveShadow = true; return mesh }

  const registry = { cores: {}, glow: {} }

  // ── Client: a phone, the plaintext lives here ──
  {
    const g = pedestal(2.9)
    g.position.copy(POS.client)
    const phone = new THREE.Group()
    const body = shadowed(new THREE.Mesh(
      new RoundedBoxGeometry(2.35, 4.7, 0.36, 4, 0.18),
      new THREE.MeshStandardMaterial({ color: 0x1c2536, roughness: 0.3, metalness: 0.6 })
    ))
    phone.add(body)
    const screenObj = makeScreen()
    registry.screen = screenObj
    const screen = new THREE.Mesh(
      new THREE.PlaneGeometry(2.05, 4.35),
      new THREE.MeshBasicMaterial({ map: screenObj.tex, toneMapped: false })
    )
    screen.position.z = 0.19
    phone.add(screen)
    const notch = new THREE.Mesh(
      new RoundedBoxGeometry(0.6, 0.12, 0.04, 2, 0.05),
      new THREE.MeshStandardMaterial({ color: 0x0a0f1a, roughness: 0.6 })
    )
    notch.position.set(0, 1.95, 0.21)
    phone.add(notch)
    phone.position.y = 2.65
    phone.rotation.x = -0.1
    phone.rotation.y = 0.22
    g.add(phone)
    const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.62, 0), coreMat(PAYLOAD.plaintext))
    core.position.y = 5.75
    g.add(core)
    const glow = new THREE.PointLight(PAYLOAD.plaintext, 6, 9)
    glow.position.y = 4.2
    g.add(glow)
    spinners.push({ mesh: core, speed: 0.5, bob: 0.16, baseY: 5.75 })
    g.add(nodeLabel('Client', 'your phone · holds the plaintext', 7.3))
    scene.add(g)
    registry.client = g
    registry.cores.client = core
    registry.glow.client = glow

    // the signed claim the client ends up holding (revealed in the final step)
    const claim = new THREE.Group()
    const gem = new THREE.Mesh(new THREE.OctahedronGeometry(0.55, 0), coreMat(PAYLOAD.claim))
    claim.add(gem)
    const halo = new THREE.Mesh(
      new THREE.TorusGeometry(0.95, 0.045, 10, 48),
      new THREE.MeshStandardMaterial({ color: PAYLOAD.claim, emissive: PAYLOAD.claim, emissiveIntensity: 0.6, transparent: true, opacity: 0.8 })
    )
    halo.rotation.x = Math.PI / 2.6
    claim.add(halo)
    const claimLight = new THREE.PointLight(PAYLOAD.claim, 7, 8)
    claim.add(claimLight)
    const chip = document.createElement('div')
    chip.className = 'claim-chip'
    chip.textContent = '✓ signed claim'
    const chipObj = new CSS2DObject(chip)
    chipObj.position.set(0, -1.15, 0)
    claim.add(chipObj)
    claim.position.set(1.9, 6.4, 1.0)
    claim.visible = false
    spinners.push({ mesh: gem, speed: 0.9 })
    g.add(claim)
    registry.claim = claim
  }

  // ── Router: dispatcher ring beacon ──
  {
    const g = pedestal(2.2)
    g.position.copy(POS.router)
    const body = shadowed(new THREE.Mesh(new THREE.CylinderGeometry(1.5, 1.7, 1.2, 32), bodyMat()))
    body.position.y = 0.9
    g.add(body)
    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(2.3, 0.07, 12, 64),
      new THREE.MeshStandardMaterial({ color: PAYLOAD.control, emissive: PAYLOAD.control, emissiveIntensity: 0.5, roughness: 0.4 })
    )
    ring.rotation.x = Math.PI / 2
    ring.position.y = 1.7
    g.add(ring)
    spinners.push({ mesh: ring, speed: 0.35, axis: 'z' })
    const mast = shadowed(new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 1.5, 8), bodyMat()))
    mast.position.y = 2.2
    g.add(mast)
    const tip = new THREE.Mesh(new THREE.SphereGeometry(0.22, 16, 16), coreMat(PAYLOAD.control))
    tip.position.y = 3.05
    g.add(tip)
    registry.cores.router = tip
    g.add(nodeLabel('Router', '/allocate · picks the pair', 4.3))
    scene.add(g)
    registry.router = g
  }

  // ── Enclave dome + the two TEE vaults ──
  {
    const domeMat = new THREE.MeshPhysicalMaterial({
      color: PAYLOAD.attest, transparent: true, opacity: 0.1,
      roughness: 0.35, metalness: 0, side: THREE.DoubleSide, depthWrite: false,
    })
    const dome = new THREE.Mesh(new THREE.SphereGeometry(6.6, 48, 24, 0, Math.PI * 2, 0, Math.PI / 2), domeMat)
    dome.position.copy(POS.enclave)
    scene.add(dome)
    const ringMat = new THREE.MeshStandardMaterial({
      color: PAYLOAD.attest, emissive: PAYLOAD.attest, emissiveIntensity: 0.35,
      transparent: true, opacity: 0.6, roughness: 0.4,
    })
    const ring = new THREE.Mesh(new THREE.TorusGeometry(6.6, 0.06, 10, 96), ringMat)
    ring.rotation.x = Math.PI / 2
    ring.position.copy(POS.enclave).y = 0.08
    scene.add(ring)
    const encLabel = nodeLabel('Attested enclave pair', 'SEV-SNP · one enclave per cloud')
    encLabel.position.copy(POS.enclave).add(new THREE.Vector3(1.5, 9.4, 0))
    scene.add(encLabel)
    registry.enclaveDome = domeMat
    registry.enclaveRing = ringMat

    function vault(pos, hex, name, sub, cloudTex, cloudAspect, coreBuilder) {
      const g = pedestal(2.0)
      g.position.copy(pos)
      const prism = shadowed(new THREE.Mesh(new THREE.CylinderGeometry(1.55, 1.75, 2.5, 6), bodyMat({ flatShading: true })))
      prism.position.y = 1.55
      prism.rotation.y = Math.PI / 6
      g.add(prism)
      const cap = shadowed(new THREE.Mesh(new THREE.CylinderGeometry(1.15, 1.6, 0.5, 6), bodyMat({ flatShading: true })))
      cap.position.y = 3.05
      cap.rotation.y = Math.PI / 6
      g.add(cap)
      const core = coreBuilder()
      core.position.y = 4.3
      g.add(core)
      spinners.push({ mesh: core, speed: 0.8, bob: 0.12, baseY: 4.3 })
      const badge = logoBadge(logoTex, 0.85, 0.85)
      badge.position.set(0, 1.85, 1.56)
      g.add(badge)
      const cloud = logoBadge(cloudTex, 1.0, 1.0 / cloudAspect, true)
      cloud.position.set(0, 0.82, 1.64)
      g.add(cloud)
      const glow = new THREE.PointLight(hex, 4, 7)
      glow.position.y = 4.2
      g.add(glow)
      g.add(nodeLabel(name, sub, 5.6))
      scene.add(g)
      return { group: g, core, glow }
    }
    const k = vault(POS.teeK, PAYLOAD.keys, 'TEE_K', 'Google Cloud · TLS keys — never sees data', gcpTex, 360 / 290, () => keyMesh(PAYLOAD.keys, 0.85))
    const t = vault(POS.teeT, PAYLOAD.cipher, 'TEE_A', 'AWS · verifies tags — never sees keys', awsTex, 360 / 216, () => tagMesh(PAYLOAD.cipher, 0.9))
    registry.teeK = k.group; registry.cores.teeK = k.core; registry.glow.teeK = k.glow
    registry.teeT = t.group; registry.cores.teeT = t.core; registry.glow.teeT = t.glow
  }

  // ── Target: server obelisk ──
  {
    const g = pedestal(2.7)
    g.position.copy(POS.target)
    const winMat = new THREE.MeshStandardMaterial({ color: 0x9fb2d8, emissive: 0x9fb2d8, emissiveIntensity: 0.55 })
    for (let i = 0; i < 3; i++) {
      const slab = shadowed(new THREE.Mesh(new THREE.BoxGeometry(3.4, 1.0, 2.6), bodyMat()))
      slab.position.y = 0.85 + i * 1.2
      g.add(slab)
      for (let w = 0; w < 3; w++) {
        const win = new THREE.Mesh(new THREE.BoxGeometry(0.42, 0.1, 0.06), winMat)
        win.position.set(-1.05 + w * 0.75, 0.85 + i * 1.2, 1.34)
        g.add(win)
      }
    }
    const mast = shadowed(new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 1.2, 8), bodyMat()))
    mast.position.y = 4.2
    g.add(mast)
    g.add(nodeLabel('Target website', 'the site being proven · HTTPS', 5.4))
    scene.add(g)
    registry.target = g
  }

  // ── Attestor: notary prism ──
  {
    const g = pedestal(2.4)
    g.position.copy(POS.attestor)
    const column = shadowed(new THREE.Mesh(new THREE.CylinderGeometry(0.95, 1.4, 1.7, 32), bodyMat()))
    column.position.y = 1.15
    g.add(column)
    const badge = logoBadge(logoTex, 0.75, 0.75)
    badge.position.set(0, 1.15, 1.22)
    badge.rotation.x = -0.12
    g.add(badge)
    const prism = new THREE.Mesh(
      new THREE.OctahedronGeometry(1.25, 0),
      new THREE.MeshStandardMaterial({
        color: 0xdce6f5, emissive: 0xbcd0ee, emissiveIntensity: 0.22,
        roughness: 0.15, metalness: 0.5, flatShading: true,
      })
    )
    prism.position.y = 3.4
    shadowed(prism)
    g.add(prism)
    spinners.push({ mesh: prism, speed: 0.4, bob: 0.15, baseY: 3.4 })
    const halo = new THREE.Mesh(
      new THREE.TorusGeometry(1.95, 0.05, 10, 64),
      new THREE.MeshStandardMaterial({ color: PAYLOAD.attest, emissive: PAYLOAD.attest, emissiveIntensity: 0.3, transparent: true, opacity: 0.55 })
    )
    halo.rotation.x = Math.PI / 2
    halo.position.y = 3.4
    g.add(halo)
    const glow = new THREE.PointLight(0xbcd0ee, 3, 8)
    glow.position.y = 3.5
    g.add(glow)
    g.add(nodeLabel('Attestor', 'reunites the halves · signs the claim', 5.6))
    scene.add(g)
    registry.attestor = g
    registry.cores.attestor = prism
    registry.glow.attestor = glow
  }

  // ── Split-AEAD explainer: a TLS record and the key that splits ──
  {
    const g = new THREE.Group()
    g.position.copy(ANCHOR.aead)
    function segment(w, hex, x, name) {
      const mat = new THREE.MeshStandardMaterial({
        color: hex, emissive: hex, emissiveIntensity: 0.3,
        roughness: 0.4, transparent: true, opacity: 0.92,
      })
      const m = new THREE.Mesh(new THREE.BoxGeometry(w, 0.85, 0.4), mat)
      m.position.x = x
      g.add(m)
      const div = document.createElement('div')
      div.className = 'totem-label'
      div.innerHTML = `<strong>${name}</strong>`
      const lbl = new CSS2DObject(div)
      lbl.position.set(x, -0.85, 0)
      g.add(lbl)
      return mat
    }
    segment(0.5, 0x38455f, -2.0, 'header')
    const cipherSeg = segment(2.6, PAYLOAD.cipher, -0.35, 'ciphertext')
    const tagSeg = segment(0.85, PAYLOAD.cipher, 1.55, 'auth tag')
    function roleChip(text, x) {
      const div = document.createElement('div')
      div.className = 'msg-label hidden'
      div.innerHTML = `<span class="dot" style="background:#e8a33d"></span>${text}`
      const obj = new CSS2DObject(div)
      obj.position.set(x, 0.1, 0.45)
      g.add(obj)
      return div
    }
    const roleK = roleChip("TEE_K's keystream makes this", -0.35)
    const roleA = roleChip('TEE_A computes & checks this', 1.55)
    const shard = tagMesh(PAYLOAD.keys, 0.55)
    shard.visible = false
    scene.add(shard)
    spinners.push({ mesh: shard, speed: 1.4 })
    // the key K is TEE_K's own core — this label points at it during the step
    const keyLbl = document.createElement('div')
    keyLbl.className = 'msg-label hidden'
    keyLbl.innerHTML = '<span class="dot" style="background:#e8a33d"></span>the key K — never leaves TEE_K'
    const keyLblObj = new CSS2DObject(keyLbl)
    keyLblObj.position.copy(POS.teeK).add(new THREE.Vector3(-1.2, 4.3, 0.4))
    keyLblObj.center.set(1, 0.5)
    scene.add(keyLblObj)
    const readout = document.createElement('div')
    readout.className = 'mpc-readout hidden'
    const readoutObj = new CSS2DObject(readout)
    readoutObj.position.set(0, -1.9, 0)
    g.add(readoutObj)
    g.visible = false
    scene.add(g)
    registry.aead = { group: g, readout, cipherSeg, tagSeg, roleK, roleA, shard, keyLabel: keyLbl }
  }

  // ── Keystream redaction strip: TEE_K destroys keystream outside reveal ranges ──
  {
    const CELLS = ['f2', '7d', '0a', '96', 'c8', '33', '61', 'b4', '9e', '12', '44', 'aa', '07', 'd3', '5c', '8f']
    const KEEP = [6, 9] // cells kept intact (the revealed range)
    const ORDER = [0, 1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15]
    const cv = document.createElement('canvas')
    cv.width = 1024; cv.height = 130
    const cg = cv.getContext('2d')
    const tex = new THREE.CanvasTexture(cv)
    tex.colorSpace = THREE.SRGBColorSpace
    tex.anisotropy = 4
    function draw(n) {
      cg.clearRect(0, 0, 1024, 130)
      const cellW = 60, x0 = 32, y = 78
      cg.strokeStyle = 'rgba(76,194,118,0.9)'
      cg.lineWidth = 3
      cg.strokeRect(x0 + KEEP[0] * cellW - 8, 28, (KEEP[1] - KEEP[0] + 1) * cellW + 4, 74)
      cg.font = '600 40px "IBM Plex Mono", monospace'
      cg.textAlign = 'center'
      const gone = new Set(ORDER.slice(0, n))
      CELLS.forEach((cell, i) => {
        const x = x0 + i * cellW + 22
        if (gone.has(i)) {
          cg.fillStyle = '#5d6a86'
          cg.fillText('✱', x, y)
        } else {
          cg.fillStyle = i >= KEEP[0] && i <= KEEP[1] ? '#4cc276' : '#e8a33d'
          cg.fillText(cell, x, y)
        }
      })
      if (n < ORDER.length) {
        cg.fillStyle = '#e0609a'
        cg.fillRect(x0 + ORDER[n] * cellW - 6, 106, cellW - 8, 6)
      }
      tex.needsUpdate = true
    }
    const g = new THREE.Group()
    g.position.set(4.0, 3.6, -2.0)
    const plane = new THREE.Mesh(
      new THREE.PlaneGeometry(8.6, 1.1),
      new THREE.MeshBasicMaterial({ map: tex, transparent: true, toneMapped: false })
    )
    g.add(plane)
    const keep = document.createElement('div')
    keep.className = 'msg-label hidden'
    keep.innerHTML = `<span class="dot" style="background:${'#4cc276'}"></span>kept — will decrypt “gpa: 9.2”`
    const keepObj = new CSS2DObject(keep)
    keepObj.position.set(0.6, 1.05, 0)
    g.add(keepObj)
    const readout = document.createElement('div')
    readout.className = 'mpc-readout hidden'
    const readoutObj = new CSS2DObject(readout)
    readoutObj.position.set(0, -1.25, 0)
    g.add(readoutObj)
    g.visible = false
    scene.add(g)
    draw(0)
    registry.redactor = { group: g, draw, total: ORDER.length, keep, readout }
  }

  // ── the attestor's view after XOR: asterisks around the revealed field ──
  {
    const div = document.createElement('div')
    div.className = 'xor-reveal hidden'
    div.innerHTML = '<span class="xh">✱✱✱✱✱✱</span><span class="xs">gpa: 9.2 / 10</span><span class="xh">✱✱✱✱✱</span>'
    const obj = new CSS2DObject(div)
    obj.position.copy(POS.attestor).add(new THREE.Vector3(0, 6.7, 0))
    scene.add(obj)
    registry.xorReveal = div
  }

  // ── MPC: virtual joint computation, exists only while running (step 7) ──
  {
    const g = new THREE.Group()
    g.position.copy(ANCHOR.mpc)
    const wireMat = new THREE.LineBasicMaterial({ color: PAYLOAD.redact, transparent: true, opacity: 0.85 })
    const shell = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(1.25, 0)), wireMat)
    g.add(shell)
    const inner = new THREE.Mesh(
      new THREE.IcosahedronGeometry(0.55, 0),
      new THREE.MeshStandardMaterial({
        color: PAYLOAD.redact, emissive: PAYLOAD.redact, emissiveIntensity: 0.8,
        transparent: true, opacity: 0.5, flatShading: true,
      })
    )
    g.add(inner)
    const light = new THREE.PointLight(PAYLOAD.redact, 5, 8)
    g.add(light)
    spinners.push({ mesh: shell, speed: 0.55 })
    spinners.push({ mesh: inner, speed: -0.9 })
    const name = nodeLabel('MPC', 'joint circuit — neither enclave alone', -3.4)
    g.add(name)
    const readout = document.createElement('div')
    readout.className = 'mpc-readout hidden'
    const readoutObj = new CSS2DObject(readout)
    readoutObj.position.set(0, -1.6, 0)
    g.add(readoutObj)
    g.visible = false
    scene.add(g)
    registry.mpc = { group: g, inner, light, readout }
  }

  // ── Trust totem (revealed in step 3) ──
  {
    const g = new THREE.Group()
    g.position.copy(POS.totem)
    const PLATES = [
      ['<strong>AMD silicon</strong> — ARK → ASK → VCEK'],
      ['<strong>SNP report</strong> — CPU-signed · no debug · VMPL 0'],
      ['<strong>vTPM quote</strong> — Google root / AWS NitroTPM'],
      ['<strong>PCR 11 · base image</strong> — pinned, 2 allowed bases'],
      ['<strong>PCR 8 · app bundle</strong> — published in the claim'],
      ['<strong>TEE signing key</strong> — bound inside the report'],
    ]
    const plates = []
    PLATES.forEach(([html], i) => {
      const y = 0.9 + i * 1.3
      const mat = bodyMat({ flatShading: true })
      const plate = shadowed(new THREE.Mesh(new THREE.CylinderGeometry(1.15, 1.15, 0.2, 6), mat))
      plate.position.y = y
      g.add(plate)
      if (i > 0) {
        const linkRod = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 1.1, 8), darkMat())
        linkRod.position.y = y - 0.65
        g.add(linkRod)
      }
      const div = document.createElement('div')
      div.className = 'totem-label'
      div.innerHTML = html
      const lbl = new CSS2DObject(div)
      lbl.position.set(1.9, y, 0)
      lbl.center.set(0, 0.5)
      g.add(lbl)
      plates.push({ plate, mat, label: div, y })
    })
    const orb = new THREE.Mesh(new THREE.SphereGeometry(0.3, 20, 20), coreMat(PAYLOAD.attest))
    orb.visible = false
    g.add(orb)
    const orbGlow = new THREE.PointLight(PAYLOAD.attest, 4, 5)
    orb.add(orbGlow)
    g.visible = false
    scene.add(g)
    registry.totem = { group: g, plates, orb }
  }

  onTheme(t => {
    bodyMats.forEach(m => m.color.setHex(t.bodyMat))
    darkMats.forEach(m => m.color.setHex(t.bodyDark))
  })

  registry.update = (time, dt) => {
    for (const s of spinners) {
      if (s.axis === 'z') s.mesh.rotation.z += s.speed * dt
      else s.mesh.rotation.y += s.speed * dt
      if (s.bob) s.mesh.position.y = s.baseY + Math.sin(time * 1.4 + s.baseY) * s.bob
    }
  }

  return registry
}
