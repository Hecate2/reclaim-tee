import * as THREE from 'three'
import { CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js'
import { PAYLOAD } from './palette.js'
import { ANCHOR } from './nodes.js'
import { STEPS } from './steps.js'

const easeInOut = x => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2)

export class Tour {
  constructor(stage, nodes, wires, ui, reducedMotion) {
    this.stage = stage
    this.nodes = nodes
    this.wires = wires
    this.ui = ui
    this.rm = reducedMotion
    this.idx = 0
    this.playing = true
    this.stepT = 0
    this.lastTc = 0
    this.camTween = null
    this.schedulers = []
    this.glowNodes = []
    this.boundaryFx = null
    this.totemActive = false
    this.xorFx = null
    this.xorFlash = 0
    this.flashHex = PAYLOAD.plaintext
    this.usedLinks = new Set()
    this.checkObjs = []
    this.checklistFx = null
    this.enter(0, true)
  }

  get step() { return STEPS[this.idx] }

  enter(i, instant = false) {
    this.idx = (i + STEPS.length) % STEPS.length
    this.stepT = 0
    this.lastTc = 0
    const s = this.step

    this.wires.clear()
    this.resetTotem()
    this.schedulers = []
    this.glowNodes = []
    this.boundaryFx = null
    this.xorFx = null
    this.totemActive = false
    this.usedLinks = new Set()
    this.mpcFx = null
    this.mpcState = ''
    this.nodes.mpc.group.visible = false
    this.nodes.mpc.readout.classList.add('hidden')
    for (const o of this.checkObjs) this.stage.scene.remove(o)
    this.checkObjs = []
    this.checklistFx = null
    this.claimFx = null
    this.nodes.claim.visible = false
    this.redactorFx = null
    this.redactorN = -1
    this.redactorText = ''
    this.nodes.redactor.group.visible = false
    this.nodes.redactor.readout.classList.add('hidden')
    this.nodes.redactor.keep.classList.add('hidden')
    this.nodes.xorReveal.classList.add('hidden')
    this.aeadFx = null
    this.nodes.aead.group.visible = false
    this.nodes.aead.readout.classList.add('hidden')
    this.nodes.aead.keyLabel.classList.add('hidden')
    this.nodes.aead.shard.visible = false
    this.nodes.aead.roleK.classList.add('hidden')
    this.nodes.aead.roleA.classList.add('hidden')

    for (const fx of s.fx) {
      if (fx.type === 'packets') {
        this.schedulers.push({ ...fx, period: this.rm ? fx.period * 1.6 : fx.period, next: fx.offset })
        this.usedLinks.add(fx.link)
      } else if (fx.type === 'glow') {
        this.glowNodes.push(fx.node)
      } else if (fx.type === 'boundary') {
        this.boundaryFx = { ...fx, stage: 0 }
      } else if (fx.type === 'totem') {
        this.totemActive = true
        this.nodes.totem.group.visible = true
        this.nodes.totem.orb.visible = true
      } else if (fx.type === 'xor') {
        this.xorFx = { ...fx, nextK: fx.kOffset, nextT: fx.tOffset, nextFlash: fx.kOffset + fx.dur }
        this.usedLinks.add('clientAttestor')
      } else if (fx.type === 'mpc') {
        this.mpcFx = { ...fx }
        this.nodes.mpc.group.visible = true
      } else if (fx.type === 'claim') {
        this.claimFx = fx
      } else if (fx.type === 'redactor') {
        this.redactorFx = fx
        this.nodes.redactor.group.visible = true
        this.nodes.redactor.draw(0)
        this.redactorN = 0
      } else if (fx.type === 'aead') {
        this.aeadFx = fx
        this.nodes.aead.group.visible = true
      } else if (fx.type === 'checklist') {
        this.checklistFx = fx
        fx.items.forEach((text, j) => {
          const div = document.createElement('div')
          div.className = j === fx.signIndex ? 'check-item check-sign' : 'check-item'
          div.innerHTML = `<span class="ci-inner"><span class="ck">✓</span>${text}</span>`
          const obj = new CSS2DObject(div)
          obj.position.set(ANCHOR.attestor.x - 5.6, 8.2 - j * 0.82, ANCHOR.attestor.z)
          obj.center.set(1, 0.5)
          this.stage.scene.add(obj)
          this.checkObjs.push(obj)
        })
      }
    }
    this.wires.setStates(this.usedLinks, new Set(s.open || []))

    // camera
    const cam = this.stage.camera, ctl = this.stage.controls
    const toPos = new THREE.Vector3(...s.cam.pos)
    const toTgt = new THREE.Vector3(...s.cam.tgt)
    if (instant || this.rm) {
      cam.position.copy(toPos)
      ctl.target.copy(toTgt)
      this.camTween = null
    } else {
      this.camTween = {
        t: 0, dur: 1.7,
        fromPos: cam.position.clone(), fromTgt: ctl.target.clone(),
        toPos, toTgt,
      }
      ctl.enabled = false
    }
    ctl.autoRotate = this.idx === 0
    ctl.autoRotateSpeed = 0.4

    this.screenFx = s.fx.find(f => f.type === 'screen') || null
    this.screenCount = s.screen ?? 0
    this.nodes.screen.draw(this.screenCount)

    this.ui.showStep(this.idx, s)
  }

  next() { this.enter(this.idx + 1) }
  prev() { this.enter(this.idx - 1) }
  setPlaying(p) { this.playing = p; this.stage.controls.autoRotate = p && this.idx === 0 }

  resetTotem() {
    const t = this.nodes.totem
    t.group.visible = false
    t.orb.visible = false
    for (const p of t.plates) {
      p.mat.emissive.setHex(0x000000)
      p.mat.emissiveIntensity = 0
      p.label.classList.remove('lit')
    }
  }

  resetCycle() {
    for (const sc of this.schedulers) sc.next = sc.offset
    if (this.boundaryFx) {
      this.boundaryFx.stage = 0
      this.wires.setState(this.boundaryFx.link, 'used')
    }
  }

  update(time, dt) {
    // camera tween
    if (this.camTween) {
      const tw = this.camTween
      tw.t += dt / tw.dur
      const k = easeInOut(Math.min(tw.t, 1))
      this.stage.camera.position.lerpVectors(tw.fromPos, tw.toPos, k)
      this.stage.controls.target.lerpVectors(tw.fromTgt, tw.toTgt, k)
      if (tw.t >= 1) {
        this.camTween = null
        this.stage.controls.enabled = true
      }
    }

    const s = this.step
    // the step clock always runs — pause only stops auto-advance
    this.stepT += dt
    const tc = s.cycle ? this.stepT % s.cycle : this.stepT
    const prevTc = tc < this.lastTc ? -1 : this.lastTc
    if (tc < this.lastTc) this.resetCycle()
    this.lastTc = tc

    for (const sc of this.schedulers) {
      while (tc >= sc.next) {
        if (sc.until !== undefined && sc.next > sc.until) { sc.next = Infinity; break }
        this.wires.spawn(sc.link, sc.dir, sc.color, sc.label, sc.dur, sc.text)
        sc.next += sc.period
      }
    }
    if (this.xorFx) {
      const x = this.xorFx
      if (tc >= x.nextK) { this.wires.spawn('clientAttestor', 1, 'keys', 'signed keystream ⊕', x.dur); x.nextK += x.period }
      if (tc >= x.nextT) { this.wires.spawn('clientAttestor', 1, 'cipher', 'signed ciphertext', x.dur); x.nextT += x.period }
      if (tc >= x.nextFlash) { this.xorFlash = 1; x.nextFlash += x.period }
    }
    if (this.boundaryFx) {
      const b = this.boundaryFx
      if (b.stage === 0 && tc >= b.at) {
        b.stage = 1
        this.wires.showMessage(b.link, b.text, 'control')
      }
      if (b.stage === 1 && tc >= b.at + 1.8) {
        b.stage = 2
        this.wires.setState(b.link, 'open')
      }
    }

    // split-AEAD explainer: K lives at TEE_K; only a TagSecrets shard crosses to
    // TEE_A over their real wire; then each record segment is annotated in place
    if (this.aeadFx) {
      const a = this.nodes.aead, fx = this.aeadFx
      a.group.scale.setScalar(Math.max(0.001, Math.min(1, this.stepT / 0.7)))
      a.keyLabel.classList.toggle('hidden', this.stepT < 1.0)
      if (prevTc < fx.shardAt && tc >= fx.shardAt) {
        this.wires.showMessage('kt', 'TagSecrets — derived from K, no key inside', 'keys')
        this.wires.setState('kt', 'used')
      }
      if (prevTc < fx.shardAt + fx.flightDur && tc >= fx.shardAt + fx.flightDur) {
        this.wires.setState('kt', 'open')
      }
      const p = (tc - fx.shardAt) / fx.flightDur
      if (p > 0 && p < 1) {
        a.shard.visible = true
        a.shard.position.copy(this.wires.links.kt.curve.getPointAt(p))
        a.shard.position.y += 0.25
      } else a.shard.visible = false
      const kRole = tc >= fx.roleCipherAt && tc < fx.rolesEndAt
      const aRole = tc >= fx.roleTagAt && tc < fx.rolesEndAt
      a.roleK.classList.toggle('hidden', !kRole)
      a.roleA.classList.toggle('hidden', !aRole)
      a.cipherSeg.emissiveIntensity = kRole ? 0.45 + Math.sin(time * 4) * 0.25 : 0.3
      a.tagSeg.emissiveIntensity = aRole ? 0.45 + Math.sin(time * 4) * 0.25 : 0.3
      let current = null
      for (const st of fx.states) if (tc >= st.at) current = st
      const text = current ? current.text : ''
      if (text !== this.aeadText) {
        this.aeadText = text
        a.readout.classList.toggle('hidden', !text)
        a.readout.textContent = text
      }
    }

    // the phone screen: response lines appear as the keystream is XORed in
    // (monotonic on the step clock, so cycle wraps don't "re-encrypt" the screen)
    if (this.screenFx) {
      const f = this.screenFx
      const n = Math.max(0, Math.min(3, Math.floor((this.stepT - f.revealAt) / f.lineGap) + 1))
      if (n !== this.screenCount) {
        this.screenCount = n
        this.nodes.screen.draw(n)
      }
    }

    // keystream redaction: cells outside the reveal range are destroyed one by one
    if (this.redactorFx) {
      const fx = this.redactorFx, r = this.nodes.redactor
      r.group.scale.setScalar(Math.max(0.001, Math.min(1, this.stepT / 0.7)))
      r.keep.classList.toggle('hidden', tc < fx.keepAt)
      const n = Math.max(0, Math.min(r.total, Math.floor((tc - fx.startAt) / fx.cellDur)))
      if (n !== this.redactorN) {
        this.redactorN = n
        r.draw(n)
      }
      let current = null
      for (const st of fx.states) if (tc >= st.at) current = st
      const text = current ? current.text : ''
      if (text !== this.redactorText) {
        this.redactorText = text
        r.readout.classList.toggle('hidden', !text)
        r.readout.textContent = text
      }
    }

    // the signed claim materializes at the client and stays
    if (this.claimFx) {
      const on = tc >= this.claimFx.at
      this.nodes.claim.visible = on
      if (on) this.nodes.claim.scale.setScalar(Math.min(1, (tc - this.claimFx.at) / 0.5))
    }

    // attestor verification checklist: gates light one by one, sign only at the end
    if (this.checklistFx) {
      const c = this.checklistFx
      this.checkObjs.forEach((obj, j) => {
        const th = c.at + j * c.gap
        obj.element.classList.toggle('lit', tc >= th)
        if (prevTc < th && tc >= th) {
          if (j === c.xorIndex) { this.xorFlash = 1; this.flashHex = PAYLOAD.plaintext }
          if (j === c.signIndex) { this.xorFlash = 1; this.flashHex = PAYLOAD.claim }
        }
      })
      // once the XOR gate passes, show what the attestor actually sees
      const xrOn = tc >= c.at + c.xorIndex * c.gap && tc < c.at + c.items.length * c.gap + 3.5
      this.nodes.xorReveal.classList.toggle('hidden', !xrOn)
    }

    // mpc entity: scale in, readout shows the value only while it exists inside the circuit
    if (this.mpcFx) {
      const m = this.nodes.mpc, fx = this.mpcFx
      m.group.scale.setScalar(Math.max(0.001, Math.min(1, this.stepT / 0.8)))
      m.light.intensity = 4 + Math.sin(time * 3) * 2
      const state = tc >= fx.piiAt && tc < fx.hashAt ? 'pii' : tc >= fx.hashAt && tc < fx.hideAt ? 'hash' : ''
      if (state !== this.mpcState) {
        this.mpcState = state
        m.readout.classList.toggle('hidden', state === '')
        m.readout.classList.toggle('pii', state === 'pii')
        m.readout.classList.toggle('hash', state === 'hash')
        if (state === 'pii') m.readout.textContent = fx.pii
        if (state === 'hash') m.readout.textContent = fx.hash
      }
      const hot = state === 'pii' ? PAYLOAD.plaintext : PAYLOAD.redact
      m.inner.material.emissive.setHex(hot)
      m.inner.material.color.setHex(hot)
      m.light.color.setHex(hot)
    }

    // glow pulses
    const pulse = this.rm ? 0.9 : 0.75 + Math.sin(time * 2.2) * 0.35
    for (const n of this.glowNodes) {
      if (n === 'enclave') {
        this.nodes.enclaveDome.opacity = 0.09 + (this.rm ? 0.05 : (0.5 + Math.sin(time * 2.2) * 0.5) * 0.09)
        this.nodes.enclaveRing.emissiveIntensity = 0.3 + (this.rm ? 0.3 : (0.5 + Math.sin(time * 2.2) * 0.5) * 0.7)
      } else if (this.nodes.glow[n]) {
        this.nodes.glow[n].intensity = 4 + pulse * 4
      }
    }
    if (!this.glowNodes.includes('enclave')) {
      this.nodes.enclaveDome.opacity += (0.1 - this.nodes.enclaveDome.opacity) * Math.min(1, dt * 3)
      this.nodes.enclaveRing.emissiveIntensity += (0.35 - this.nodes.enclaveRing.emissiveIntensity) * Math.min(1, dt * 3)
    }

    // totem choreography
    if (this.totemActive) {
      const t = this.nodes.totem
      const reveal = this.stepT
      t.plates.forEach((p, i) => {
        const litAt = 1.2 + i * 1.9
        if (reveal >= litAt) {
          p.mat.emissive.setHex(PAYLOAD.attest)
          p.mat.emissiveIntensity = Math.min(0.38, (reveal - litAt) * 0.8)
          p.label.classList.add('lit')
        }
      })
      const span = t.plates[t.plates.length - 1].y - t.plates[0].y
      const cycle = this.rm ? 0.5 : (this.stepT * 0.16) % 1.25
      t.orb.position.y = t.plates[0].y + Math.min(cycle, 1) * span
      t.orb.visible = cycle <= 1.05
    }

    // xor flash at the attestor prism
    if (this.xorFlash > 0) {
      this.xorFlash = Math.max(0, this.xorFlash - dt * 1.4)
      const f = this.xorFlash
      this.nodes.cores.attestor.material.emissiveIntensity = 0.22 + f * 2.2
      this.nodes.cores.attestor.material.emissive.setHex(f > 0.45 ? this.flashHex : 0xbcd0ee)
      this.nodes.glow.attestor.intensity = 3 + f * 14
      this.nodes.glow.attestor.color.setHex(f > 0.45 ? this.flashHex : 0xbcd0ee)
    }

    // autoplay advance — held while narration is still speaking
    if (this.playing && this.stepT >= s.dur && !(this.ui.holdAdvance && this.ui.holdAdvance())) this.next()
  }
}
