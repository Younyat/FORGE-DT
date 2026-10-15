import * as THREE from "three";
import { OrbitControls } from "/vendor/three/addons/OrbitControls.js";
import { CSS2DRenderer } from "/vendor/three/addons/CSS2DRenderer.js";

export function createScene(container) {
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x050b14, 0.004);

  const bgTexture = new THREE.TextureLoader().load("/images/my_space.png");
  bgTexture.colorSpace = THREE.SRGBColorSpace;
  scene.background = bgTexture;
  // Darkens the background render like nighttime while keeping the image
  // itself fully intact/visible underneath -- multiplies its RGB rather
  // than painting an opaque overlay on top of it.
  scene.backgroundIntensity = 0.35;

  // Entity boxes use MeshStandardMaterial (metalness/roughness) for a real
  // sheen/highlight that shifts with camera angle -- these two lights are
  // what that material needs to render anything but black. Deliberately
  // NOT MeshPhysicalMaterial+transmission: that forces an extra scene-
  // capture render pass per transmissive object and was already measured
  // this session to visibly drop frames with a dozen+ boxes on screen.
  // Standard lit materials cost the same as any normal lit mesh -- no extra
  // passes -- so this stays within the same performance budget.
  // Low ambient + one strong, clearly-lateral key light -- a "sun from one
  // side" setup. The previous key light sat at (40,80,60), almost the same
  // world direction the camera itself always approaches from (focusOn/
  // focusOnGroups' fixed dir (0.4,0.5,1)) -- a light coming from nearly the
  // same angle as the viewer looks flat, like an on-camera flash, so the
  // metal sheen barely showed. Biasing the light heavily onto +X (with a
  // shift onto -Z, roughly the camera's own on-screen "right") instead
  // rakes it in from a distinctly different angle than the view direction,
  // so rotating boxes actually sweep a visible highlight.
  scene.add(new THREE.AmbientLight(0x6c86a8, 0.45));
  const keyLight = new THREE.DirectionalLight(0xfff3d6, 1.9);
  keyLight.position.set(150, 60, -30);
  scene.add(keyLight);

  const camera = new THREE.PerspectiveCamera(48, container.clientWidth / container.clientHeight, 0.1, 5000);
  camera.position.set(0, 34, 78);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  // Capped at 1.5, not 2 -- on a HiDPI/Retina display (devicePixelRatio=2)
  // this cuts the number of pixels actually shaded by (2/1.5)^2 ~= 1.8x,
  // a real, broad win across every pixel this scene renders (independent
  // of and additive with the per-model triangle-count fixes elsewhere
  // this session), for a barely-perceptible softness trade-off. Left
  // antialiasing on (unlike pixelRatio, MSAA isn't the dominant cost here,
  // and this dashboard's clean wireframe-edge look depends on it more).
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  renderer.setSize(container.clientWidth, container.clientHeight);
  container.appendChild(renderer.domElement);

  const labelRenderer = new CSS2DRenderer();
  labelRenderer.setSize(container.clientWidth, container.clientHeight);
  Object.assign(labelRenderer.domElement.style, { position: "absolute", top: "0", left: "0", pointerEvents: "none" });
  container.appendChild(labelRenderer.domElement);

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.minDistance = 12;
  controls.maxDistance = 280;
  controls.maxPolarAngle = Math.PI * 0.49;
  controls.target.set(0, 0, 0);

  // OrbitControls' native wheel zoom scales distance by the RAW deltaY of
  // each wheel event, unclamped. On a trackpad a small swipe can fire many
  // events with large deltaY, so a "tenth of a turn" could multiply the
  // zoom factor dozens of times in one gesture -- jumping straight from the
  // full campaign overview to a single box. Disable it and drive zoom
  // ourselves: every wheel event moves a target distance by the same small,
  // fixed step regardless of the device's delta magnitude, and the actual
  // camera distance eases toward that target a little every frame, so the
  // zoom level always changes gradually and predictably.
  controls.enableZoom = false;
  let targetDistance = camera.position.distanceTo(controls.target);
  const ZOOM_STEP = 0.06;
  renderer.domElement.addEventListener(
    "wheel",
    (event) => {
      event.preventDefault();
      const dir = Math.sign(event.deltaY);
      if (!dir) return;
      const factor = dir > 0 ? 1 + ZOOM_STEP : 1 - ZOOM_STEP;
      targetDistance = THREE.MathUtils.clamp(targetDistance * factor, controls.minDistance, controls.maxDistance);
    },
    { passive: false },
  );

  const grid = new THREE.GridHelper(500, 50, 0x0e3a4a, 0x0a2230);
  grid.position.y = -34;
  scene.add(grid);

  function onResize() {
    const w = container.clientWidth, h = container.clientHeight;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
    labelRenderer.setSize(w, h);
  }
  window.addEventListener("resize", onResize);

  // CSS2DRenderer repositions every label's DOM element via a style.transform
  // write on every single call, unconditionally -- with a dozen+ cards each
  // carrying a blurred box-shadow "cage" glow, that forces the browser to
  // recompute and repaint that blur every time, whether or not the box is
  // even on screen. Two cheap, purely additive mitigations, per the request
  // to only pay for what's actually visible:
  //  1) skip the whole label pass for any box currently outside the camera's
  //     view (projected NDC outside [-1,1]) -- CSS2DRenderer already respects
  //     `object.visible` and early-outs (sets display:none) without touching
  //     transform/style for invisible objects.
  //  2) the label pass only needs to look right, not be pixel-perfect every
  //     16ms -- running it at ~30fps instead of the WebGL scene's 60fps
  //     halves that DOM/paint cost with no visible difference.
  let getEntities = () => [];
  function setEntities(getter) {
    getEntities = typeof getter === "function" ? getter : () => [];
  }

  const _ndc = new THREE.Vector3();
  function updateEntityVisibility() {
    for (const g of getEntities()) {
      const cardObject = g.userData?.cardObject;
      if (!cardObject) continue;
      _ndc.copy(g.position).project(camera);
      cardObject.visible = _ndc.x >= -1.2 && _ndc.x <= 1.2 && _ndc.y >= -1.2 && _ndc.y <= 1.2 && _ndc.z < 1;
    }
  }

  let labelFrameSkip = 0;
  let lastRotationTime = performance.now();
  // A slow, continuous spin on every box's own Y axis -- the metallic
  // MeshStandardMaterial only actually reads as "reflective metal" once its
  // surface moves relative to the fixed lights; a perfectly static box under
  // a static light shows no visible sheen change at all. Y-axis only (never
  // X/Z) because every box's card sits on the local Y axis at x=0,z=0 --
  // rotating around Y leaves that point invariant, so labels never drift,
  // and connectors/relation lines (which bake off `.position`, never
  // rotation) stay correctly attached regardless of spin.
  const ROTATION_SPEED = 0.15; // rad/s -- one full turn every ~42s, deliberately subtle
  function render() {
    const now = performance.now();
    const dt = Math.min(0.05, (now - lastRotationTime) / 1000);
    lastRotationTime = now;
    for (const g of getEntities()) g.rotation.y += ROTATION_SPEED * dt;

    const currentDistance = camera.position.distanceTo(controls.target);
    if (Math.abs(currentDistance - targetDistance) > 0.01) {
      const eased = THREE.MathUtils.lerp(currentDistance, targetDistance, 0.15);
      const dir = camera.position.clone().sub(controls.target).normalize();
      camera.position.copy(controls.target).addScaledVector(dir, eased);
    }
    controls.update();
    renderer.render(scene, camera);
    labelFrameSkip = (labelFrameSkip + 1) % 2;
    if (labelFrameSkip === 0) {
      updateEntityVisibility();
      labelRenderer.render(scene, camera);
    }
  }

  function focusOn(position, distance = 40, { duration = 650 } = {}) {
    const dir = new THREE.Vector3(0.4, 0.5, 1).normalize();
    const target = new THREE.Vector3(position.x, position.y, position.z);
    const camTarget = target.clone().addScaledVector(dir, distance);
    const start = camera.position.clone();
    const startTarget = controls.target.clone();
    const t0 = performance.now();
    const dur = duration;
    function step() {
      const t = Math.min(1, (performance.now() - t0) / dur);
      const ease = 1 - Math.pow(1 - t, 3);
      camera.position.lerpVectors(start, camTarget, ease);
      controls.target.lerpVectors(startTarget, target, ease);
      targetDistance = camera.position.distanceTo(controls.target);
      if (t < 1) requestAnimationFrame(step);
    }
    step();
  }

  /**
   * Eases the camera so every given entity group is inside the viewport at
   * once -- used after expanding/collapsing a host, where the newly created
   * boxes can sit well outside whatever the camera happened to be framing
   * (e.g. below and to the side of a host that was off-center), forcing the
   * user to manually pan/zoom just to see what appeared. Computes the real
   * world-space bounding box from each group's stored width/height/depth
   * (not just its center point) so nothing is clipped at the edges.
   */
  function focusOnGroups(groups, { paddingFactor = 1.35, duration = 650 } = {}) {
    const list = (groups || []).filter(Boolean);
    if (!list.length) return;
    const box = new THREE.Box3();
    const half = new THREE.Vector3();
    const corner = new THREE.Vector3();
    for (const g of list) {
      half.set((g.userData.width || 10) / 2, (g.userData.height || 6) / 2, (g.userData.depth || 8) / 2);
      box.expandByPoint(corner.copy(g.position).sub(half));
      box.expandByPoint(corner.copy(g.position).add(half));
    }
    const center = box.getCenter(new THREE.Vector3());
    const size = box.getSize(new THREE.Vector3());

    const fovV = THREE.MathUtils.degToRad(camera.fov);
    const fovH = 2 * Math.atan(Math.tan(fovV / 2) * camera.aspect);
    const distV = (size.y / 2) / Math.tan(fovV / 2);
    const distH = (size.x / 2) / Math.tan(fovH / 2);
    const distance = THREE.MathUtils.clamp(
      Math.max(distV, distH, 20) * paddingFactor + size.z / 2,
      controls.minDistance,
      controls.maxDistance,
    );

    const dir = new THREE.Vector3(0.4, 0.5, 1).normalize();
    const camTarget = center.clone().addScaledVector(dir, distance);
    const start = camera.position.clone();
    const startTarget = controls.target.clone();
    const t0 = performance.now();
    const dur = duration;
    function step() {
      const t = Math.min(1, (performance.now() - t0) / dur);
      const ease = 1 - Math.pow(1 - t, 3);
      camera.position.lerpVectors(start, camTarget, ease);
      controls.target.lerpVectors(startTarget, center, ease);
      targetDistance = camera.position.distanceTo(controls.target);
      if (t < 1) requestAnimationFrame(step);
    }
    step();
  }

  return { scene, camera, renderer, labelRenderer, controls, render, focusOn, focusOnGroups, setEntities, container };
}
