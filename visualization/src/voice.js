// Narration playback. Clips are embedded at build time; if none were
// generated, hasVoice is false and the toggle stays hidden.
const files = import.meta.glob('../assets/voice/step-*.mp3', {
  eager: true, query: '?url', import: 'default',
})
const clips = {}
for (const [path, url] of Object.entries(files)) {
  const m = path.match(/step-(\d+)\.mp3$/)
  if (m) clips[parseInt(m[1], 10)] = url
}

export const hasVoice = Object.keys(clips).length > 0

let enabled = true
let currentIdx = -1
const audio = new Audio()
audio.preload = 'auto'

export function isEnabled() { return enabled }
export function isSpeaking() { return enabled && !audio.paused && !audio.ended }

export function setEnabled(on, idx) {
  enabled = on
  if (!on) {
    audio.pause()
  } else if (idx !== undefined) {
    play(idx)
  }
}

export function play(idx) {
  currentIdx = idx
  if (!enabled || !clips[idx]) { audio.pause(); return }
  audio.src = clips[idx]
  audio.currentTime = 0
  audio.play().catch(() => {})
}

export function pause() { audio.pause() }

// resume mid-clip if it's still the same step, else start that step's clip
export function resume(idx) {
  if (!enabled) return
  if (idx === currentIdx && audio.src && !audio.ended) audio.play().catch(() => {})
  else play(idx)
}
