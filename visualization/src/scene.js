import * as THREE from 'three'
import { OrbitControls } from 'three/addons/controls/OrbitControls.js'
import { CSS2DRenderer } from 'three/addons/renderers/CSS2DRenderer.js'
import { THEMES } from './palette.js'

export function createStage(canvas, labelRoot) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false })
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
  renderer.toneMapping = THREE.ACESFilmicToneMapping
  renderer.toneMappingExposure = 1.15
  renderer.shadowMap.enabled = true
  renderer.shadowMap.type = THREE.PCFSoftShadowMap

  const labelRenderer = new CSS2DRenderer({ element: labelRoot })

  const scene = new THREE.Scene()
  scene.fog = new THREE.Fog(0x0c1120, 42, 110)

  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 300)
  camera.position.set(0, 30, 42)

  const controls = new OrbitControls(camera, canvas)
  controls.enableDamping = true
  controls.dampingFactor = 0.06
  controls.enablePan = false
  controls.minDistance = 10
  controls.maxDistance = 80
  controls.maxPolarAngle = 1.38
  controls.target.set(0, 1, 0)

  // Lights
  const hemi = new THREE.HemisphereLight(0x8fa3c8, 0x141c2e, 0.75)
  scene.add(hemi)
  const key = new THREE.DirectionalLight(0xffffff, 1.6)
  key.position.set(18, 30, 14)
  key.castShadow = true
  key.shadow.mapSize.set(2048, 2048)
  key.shadow.camera.left = -32
  key.shadow.camera.right = 32
  key.shadow.camera.top = 32
  key.shadow.camera.bottom = -32
  key.shadow.bias = -0.0004
  scene.add(key)
  const rim = new THREE.DirectionalLight(0x4a6aa8, 0.6)
  rim.position.set(-20, 12, -24)
  scene.add(rim)

  // Floor: soft radial disc + fine polar grid
  const floorTex = makeRadialTexture()
  const floorMat = new THREE.MeshStandardMaterial({
    color: 0x111a2e, roughness: 0.95, metalness: 0,
    map: floorTex, transparent: true,
  })
  const floor = new THREE.Mesh(new THREE.CircleGeometry(58, 96), floorMat)
  floor.rotation.x = -Math.PI / 2
  floor.receiveShadow = true
  scene.add(floor)

  const grid = new THREE.PolarGridHelper(56, 24, 14, 96, 0x243350, 0x243350)
  grid.material.transparent = true
  grid.material.opacity = 0.22
  grid.position.y = 0.02
  scene.add(grid)

  function resize() {
    const w = window.innerWidth, h = window.innerHeight
    renderer.setSize(w, h, false)
    labelRenderer.setSize(w, h)
    camera.aspect = w / h
    camera.updateProjectionMatrix()
  }
  window.addEventListener('resize', resize)
  resize()

  const themed = []  // callbacks(theme) registered by other modules
  function applyTheme(name) {
    const t = THEMES[name]
    renderer.setClearColor(t.bg)
    scene.fog.color.setHex(t.fog)
    scene.fog.near = t.fogNear
    scene.fog.far = t.fogFar
    floorMat.color.setHex(t.floor)
    grid.material.color.setHex(t.grid)
    hemi.color.setHex(t.hemi)
    hemi.groundColor.setHex(t.hemiGround)
    hemi.intensity = t.hemiIntensity
    key.intensity = t.keyIntensity
    rim.color.setHex(t.rim)
    themed.forEach(fn => fn(t, name))
  }

  return {
    renderer, labelRenderer, scene, camera, controls,
    applyTheme,
    onTheme: fn => themed.push(fn),
    render() {
      controls.update()
      renderer.render(scene, camera)
      labelRenderer.render(scene, camera)
    },
  }
}

function makeRadialTexture() {
  const c = document.createElement('canvas')
  c.width = c.height = 512
  const g = c.getContext('2d')
  const grad = g.createRadialGradient(256, 256, 40, 256, 256, 256)
  grad.addColorStop(0, 'rgba(255,255,255,0.55)')
  grad.addColorStop(0.55, 'rgba(255,255,255,0.28)')
  grad.addColorStop(1, 'rgba(255,255,255,0)')
  g.fillStyle = grad
  g.fillRect(0, 0, 512, 512)
  const tex = new THREE.CanvasTexture(c)
  tex.colorSpace = THREE.SRGBColorSpace
  return tex
}
