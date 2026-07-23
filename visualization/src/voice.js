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

let enabled = false
const audio = new Audio()
audio.preload = 'auto'

export function isEnabled() { return enabled }
export function isSpeaking() { return enabled && !audio.paused && !audio.ended }

export function setEnabled(on, currentIdx) {
  enabled = on
  if (!on) {
    audio.pause()
  } else if (currentIdx !== undefined) {
    play(currentIdx)
  }
}

export function play(idx) {
  if (!enabled || !clips[idx]) { audio.pause(); return }
  audio.src = clips[idx]
  audio.currentTime = 0
  audio.play().catch(() => {})
}
