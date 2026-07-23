// Generates one MP3 per tour step via the ElevenLabs API.
// Usage: ELEVENLABS_API_KEY=... node scripts/generate-voice.mjs
//        VOICE_ID=<id> to override the default narrator.
import { mkdir, writeFile } from 'node:fs/promises'
import { NARRATION } from './narration.mjs'

const KEY = process.env.ELEVENLABS_API_KEY
if (!KEY) {
  console.error('ELEVENLABS_API_KEY not set')
  process.exit(1)
}
const VOICE = process.env.VOICE_ID || 'JBFqnCBsd6RMkjVDRZzb' // "George" — warm narrator
const MODEL = process.env.MODEL_ID || 'eleven_turbo_v2_5'
const OUT = new URL('../assets/voice/', import.meta.url)

await mkdir(OUT, { recursive: true })
for (let i = 0; i < NARRATION.length; i++) {
  const res = await fetch(
    `https://api.elevenlabs.io/v1/text-to-speech/${VOICE}?output_format=mp3_22050_32`,
    {
      method: 'POST',
      headers: { 'xi-api-key': KEY, 'content-type': 'application/json' },
      body: JSON.stringify({
        text: NARRATION[i],
        model_id: MODEL,
        voice_settings: { stability: 0.45, similarity_boost: 0.7 },
      }),
    }
  )
  if (!res.ok) {
    console.error(`step ${i}: ${res.status} ${await res.text()}`)
    process.exit(1)
  }
  const buf = Buffer.from(await res.arrayBuffer())
  const file = new URL(`step-${String(i).padStart(2, '0')}.mp3`, OUT)
  await writeFile(file, buf)
  console.log(`step ${i}: ${(buf.length / 1024).toFixed(0)} KB`)
}
console.log('done — rebuild with `npm run build` to embed')
