import './styles.css'
import * as voice from './voice.js'
import { createStage } from './scene.js'
import { buildNodes } from './nodes.js'
import { buildLinks } from './links.js'
import { Tour } from './tour.js'
import { STEPS } from './steps.js'
import { LEGEND, PAYLOAD_CSS } from './palette.js'

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

// ── theme ──
const root = document.documentElement
const mql = window.matchMedia('(prefers-color-scheme: light)')
function currentTheme() {
  const forced = root.dataset.theme
  if (forced) return forced
  return mql.matches ? 'light' : 'dark'
}

// ── stage ──
const stage = createStage(document.getElementById('scene'), document.getElementById('labels'))
const nodes = buildNodes(stage)
const wires = buildLinks(stage)
stage.applyTheme(currentTheme())

document.getElementById('theme-toggle').addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark'
  root.dataset.theme = next
  stage.applyTheme(next)
})
mql.addEventListener('change', () => { if (!root.dataset.theme) stage.applyTheme(currentTheme()) })

// ── legend ──
const legendList = document.getElementById('legend-list')
for (const item of LEGEND) {
  const li = document.createElement('li')
  li.innerHTML = `<span class="swatch" style="background:${PAYLOAD_CSS[item.key]}"></span>` +
    `<span class="name">${item.name}</span> <span class="note">${item.note}</span>`
  legendList.appendChild(li)
}
const legend = document.getElementById('legend')
document.getElementById('legend-toggle').addEventListener('click', () => {
  legend.classList.toggle('closed')
  document.getElementById('legend-toggle').setAttribute('aria-expanded', String(!legend.classList.contains('closed')))
})

// ── panel + controls UI ──
const el = id => document.getElementById(id)
const dots = el('dots')
STEPS.forEach((_, i) => {
  const b = document.createElement('button')
  b.className = 'dot-step'
  b.setAttribute('role', 'tab')
  b.setAttribute('aria-label', `Step ${i}`)
  b.addEventListener('click', () => { tour.enter(i); markInteracted() })
  dots.appendChild(b)
})
el('step-total').textContent = String(STEPS.length - 1)

let isPlaying = false
const ui = {
  holdAdvance: () => voice.isSpeaking(),
  showStep(idx, s) {
    if (isPlaying) voice.play(idx)
    else voice.pause()
    el('step-num').textContent = String(idx)
    el('step-eyebrow').textContent = s.eyebrow
    el('step-title').textContent = s.title
    el('step-body').innerHTML = s.body
    const chips = el('wire-chips')
    chips.innerHTML = ''
    for (const w of s.wire) {
      const c = document.createElement('span')
      c.className = 'wire-chip'
      c.innerHTML = `<span class="dot" style="background:${PAYLOAD_CSS[w.color]}"></span>${w.label}`
      chips.appendChild(c)
    }
    el('wire-block').style.display = s.wire.length ? '' : 'none'
    dots.querySelectorAll('.dot-step').forEach((d, i) => d.classList.toggle('active', i === idx))
  },
}

const tour = new Tour(stage, nodes, wires, ui, reducedMotion)

const voiceBtn = el('voice-toggle')
if (voice.hasVoice) {
  voiceBtn.hidden = false
  voiceBtn.classList.remove('muted') // narration defaults on; it starts with the play button
  voiceBtn.addEventListener('click', () => {
    const on = !voice.isEnabled()
    voice.setEnabled(on, isPlaying ? tour.idx : undefined)
    voiceBtn.classList.toggle('muted', !on)
  })
} else {
  voice.setEnabled(false)
}

const playBtn = el('btn-play')
function setPlaying(p) {
  isPlaying = p
  tour.setPlaying(p)
  playBtn.classList.toggle('playing', p)
  if (p) voice.resume(tour.idx)
  else voice.pause()
}
setPlaying(false) // load paused — audio starts naturally with the user's play click
playBtn.addEventListener('click', () => { setPlaying(!tour.playing) })
el('btn-prev').addEventListener('click', () => { tour.prev(); markInteracted() })
el('btn-next').addEventListener('click', () => { tour.next(); markInteracted() })

window.addEventListener('keydown', e => {
  if (e.key === 'ArrowRight') { tour.next(); markInteracted() }
  else if (e.key === 'ArrowLeft') { tour.prev(); markInteracted() }
  else if (e.key === ' ') { e.preventDefault(); setPlaying(!tour.playing) }
})

// deep-link for testing: #step=4&theme=dark&play=0
const params = new URLSearchParams(location.hash.slice(1))
if (params.get('theme')) {
  root.dataset.theme = params.get('theme')
  stage.applyTheme(currentTheme())
}
if (params.get('step') !== null) tour.enter(+params.get('step'), true)
if (params.get('play') === '0') setPlaying(false)
if (params.get('t')) tour.stepT = +params.get('t')

let interacted = false
function markInteracted() {
  if (interacted) return
  interacted = true
  el('hint').classList.add('faded')
}
stage.renderer.domElement.addEventListener('pointerdown', markInteracted, { once: true })

// ── loop ──
let last = performance.now()
function frame(now) {
  const dt = Math.min(0.05, (now - last) / 1000)
  last = now
  const time = now / 1000
  nodes.update(time, dt)
  wires.update(time, dt)
  tour.update(time, dt)
  stage.render()
  requestAnimationFrame(frame)
}
requestAnimationFrame(frame)
