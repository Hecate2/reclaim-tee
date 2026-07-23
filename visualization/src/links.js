import * as THREE from 'three'
import { CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js'
import { PAYLOAD, PAYLOAD_CSS } from './palette.js'
import { ANCHOR, POS } from './nodes.js'

const charTexCache = new Map()
function charTexture(ch, cssColor) {
  const key = ch + cssColor
  let tex = charTexCache.get(key)
  if (tex) return tex
  const c = document.createElement('canvas')
  c.width = 64; c.height = 96
  const g = c.getContext('2d')
  g.font = '600 54px "IBM Plex Mono", monospace'
  g.textAlign = 'center'
  g.textBaseline = 'middle'
  g.shadowColor = cssColor
  g.shadowBlur = 14
  g.fillStyle = cssColor
  g.fillText(ch, 32, 50)
  tex = new THREE.CanvasTexture(c)
  tex.colorSpace = THREE.SRGBColorSpace
  charTexCache.set(key, tex)
  return tex
}

// a string of character sprites snaking along a link's curve
class TextStream {
  constructor(scene, link, dir, text, colorKey, dur) {
    this.scene = scene
    this.link = link
    this.dir = dir
    this.dur = dur
    this.t = 0
    const css = PAYLOAD_CSS[colorKey]
    const len = link.curve.getLength()
    this.sp = 0.42 / len
    this.span = this.sp * (text.length - 1)
    this.sprites = [...text].map(ch => {
      if (ch === ' ') return null
      const mat = new THREE.SpriteMaterial({
        map: charTexture(ch, css), transparent: true, depthWrite: false,
      })
      const s = new THREE.Sprite(mat)
      s.scale.set(0.52, 0.78, 1)
      s.visible = false
      scene.add(s)
      return s
    })
  }
  update(dt) {
    this.t += dt / this.dur
    const head = this.t * (1 + this.span)
    let done = true
    this.sprites.forEach((s, i) => {
      if (!s) return
      const u = head - i * this.sp
      if (u <= 0) { s.visible = false; done = false; return }
      if (u >= 1) { s.visible = false; return }
      done = false
      s.visible = true
      const uu = this.dir === 1 ? u : 1 - u
      s.position.copy(this.link.curve.getPointAt(uu))
      s.position.y += 0.18
      s.material.opacity = Math.min(1, u / 0.1, (1 - u) / 0.1)
    })
    return done
  }
  dispose() {
    for (const s of this.sprites) {
      if (s) { this.scene.remove(s); s.material.dispose() }
    }
  }
}

function makeGlowTexture() {
  const c = document.createElement('canvas')
  c.width = c.height = 128
  const g = c.getContext('2d')
  const grad = g.createRadialGradient(64, 64, 2, 64, 64, 64)
  grad.addColorStop(0, 'rgba(255,255,255,1)')
  grad.addColorStop(0.25, 'rgba(255,255,255,0.5)')
  grad.addColorStop(1, 'rgba(255,255,255,0)')
  g.fillStyle = grad
  g.fillRect(0, 0, 128, 128)
  const tex = new THREE.CanvasTexture(c)
  tex.colorSpace = THREE.SRGBColorSpace
  return tex
}

class Link {
  constructor(scene, from, to, { lift = 0.22, sag = 1.6 } = {}) {
    this.from = from.clone()
    this.to = to.clone()
    const mid = from.clone().add(to).multiplyScalar(0.5)
    mid.y += from.distanceTo(to) * lift * 0.5 + sag
    this.curve = new THREE.QuadraticBezierCurve3(this.from, mid, this.to)
    this.mat = new THREE.MeshStandardMaterial({
      color: 0x2c3a58, roughness: 0.6, metalness: 0.1,
      transparent: true, opacity: 0.5,
    })
    this.mesh = new THREE.Mesh(new THREE.TubeGeometry(this.curve, 64, 0.06, 8, false), this.mat)
    scene.add(this.mesh)
    this.baseColor = new THREE.Color(0x2c3a58)
    this.baseOpacity = 0.5
    this.activeColor = null
    this.heat = 0 // 0 = idle, 1 = active
    this.state = 'off' // off = no connection, open = held open but idle, used = carrying data
    this.vis = 0

    const div = document.createElement('div')
    div.className = 'msg-label hidden'
    this.labelDiv = div
    this.label = new CSS2DObject(div)
    this.label.position.copy(this.curve.getPointAt(0.5)).add(new THREE.Vector3(0, 0.8, 0))
    scene.add(this.label)
    this.labelTimer = 0
  }
  setBase(hex, opacity) {
    this.baseColor.setHex(hex)
    this.baseOpacity = opacity
  }
  activate(colorHex) { this.activeColor = new THREE.Color(colorHex) }
  deactivate() { this.activeColor = null }
  showMessage(text, colorKey) {
    if (text) {
      this.labelDiv.innerHTML = `<span class="dot" style="background:${PAYLOAD_CSS[colorKey]}"></span>${text}`
      this.labelDiv.classList.remove('hidden')
      this.labelTimer = 2.2
    }
  }
  update(dt) {
    const targetHeat = this.activeColor ? 1 : 0
    this.heat += (targetHeat - this.heat) * Math.min(1, dt * 4)
    const visTarget = this.state === 'used' ? 1 : this.state === 'open' ? 0.3 : 0
    this.vis += (visTarget - this.vis) * Math.min(1, dt * 3.5)
    if (this.activeColor) this.mat.color.copy(this.baseColor).lerp(this.activeColor, this.heat * 0.85)
    else this.mat.color.copy(this.baseColor)
    this.mat.opacity = (this.baseOpacity + this.heat * 0.4) * this.vis
    this.mat.emissive.copy(this.mat.color).multiplyScalar(this.heat * 0.5 * this.vis)
    this.mesh.visible = this.vis > 0.02
    if (this.labelTimer > 0) {
      this.labelTimer -= dt
      if (this.labelTimer <= 0) this.labelDiv.classList.add('hidden')
    }
  }
}

export function buildLinks(stage) {
  const { scene, onTheme } = stage
  const glowTex = makeGlowTexture()

  const links = {
    clientRouter:   new Link(scene, ANCHOR.client, ANCHOR.router, { sag: 2.4 }),
    clientK:        new Link(scene, ANCHOR.client, ANCHOR.teeK, { sag: 2.2 }),
    clientT:        new Link(scene, ANCHOR.client, ANCHOR.teeT, { sag: 2.8 }),
    kt:             new Link(scene, ANCHOR.teeK, ANCHOR.teeT, { sag: 1.4, lift: 0.3 }),
    clientTarget:   new Link(scene, ANCHOR.client, ANCHOR.target, { sag: 2.6 }),
    clientAttestor: new Link(scene, ANCHOR.client, ANCHOR.attestor, { sag: 1.8 }),
    kMpc:           new Link(scene, ANCHOR.teeK, ANCHOR.mpc, { sag: 0.7, lift: 0.1 }),
    tMpc:           new Link(scene, ANCHOR.teeT, ANCHOR.mpc, { sag: 0.7, lift: 0.1 }),
  }

  onTheme(t => {
    Object.values(links).forEach(l => l.setBase(t.linkBase, t.linkOpacity))
  })

  // ── packets ──
  const packets = []
  const packetPool = []
  const streams = []
  function spawn(linkKey, dir, colorKey, label, dur, text) {
    const link = links[linkKey]
    if (!link) return
    if (text) {
      streams.push(new TextStream(scene, link, dir, text, colorKey, dur))
      link.activate(PAYLOAD[colorKey])
      link.showMessage(label, colorKey)
      return
    }
    let p = packetPool.pop()
    if (!p) {
      const mat = new THREE.MeshBasicMaterial({ color: 0xffffff })
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(0.24, 16, 16), mat)
      const sprite = new THREE.Sprite(new THREE.SpriteMaterial({
        map: glowTex, color: 0xffffff, transparent: true,
        blending: THREE.AdditiveBlending, depthWrite: false,
      }))
      sprite.scale.setScalar(2.2)
      mesh.add(sprite)
      scene.add(mesh)
      p = { mesh, mat, sprite }
    }
    const hex = PAYLOAD[colorKey]
    p.mat.color.setHex(hex)
    p.sprite.material.color.setHex(hex)
    p.mesh.visible = true
    packets.push({ ...p, link, dir, t: 0, dur })
    link.activate(hex)
    link.showMessage(label, colorKey)
  }
  function ease(x) { return x < 0.5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2 }

  function setState(key, state) {
    const l = links[key]
    if (l) {
      l.state = state
      if (state !== 'used') { l.labelDiv.classList.add('hidden'); l.labelTimer = 0 }
    }
  }
  function setStates(used, open) {
    for (const k of Object.keys(links)) setState(k, used.has(k) ? 'used' : open.has(k) ? 'open' : 'off')
  }
  function showMessage(key, text, colorKey) {
    links[key]?.showMessage(text, colorKey)
  }

  function linkBusy(link) {
    return packets.some(q => q.link === link) || streams.some(q => q.link === link)
  }

  function update(time, dt) {
    Object.values(links).forEach(l => l.update(dt))
    for (let i = packets.length - 1; i >= 0; i--) {
      const p = packets[i]
      p.t += dt / p.dur
      if (p.t >= 1) {
        p.mesh.visible = false
        packets.splice(i, 1)
        packetPool.push(p)
        if (!linkBusy(p.link)) p.link.deactivate()
        continue
      }
      const u = p.dir === 1 ? ease(p.t) : 1 - ease(p.t)
      p.mesh.position.copy(p.link.curve.getPointAt(u))
    }
    for (let i = streams.length - 1; i >= 0; i--) {
      const st = streams[i]
      if (st.update(dt)) {
        st.dispose()
        streams.splice(i, 1)
        if (!linkBusy(st.link)) st.link.deactivate()
      }
    }
  }

  function clear() {
    for (const p of packets) { p.mesh.visible = false; packetPool.push(p) }
    packets.length = 0
    for (const st of streams) st.dispose()
    streams.length = 0
    Object.values(links).forEach(l => { l.deactivate(); l.labelDiv.classList.add('hidden'); l.labelTimer = 0 })
  }

  return { links, spawn, update, clear, setState, setStates, showMessage }
}
