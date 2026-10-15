import * as THREE from "three";

// ---------------------------------------------------------------------------
// Reusable 3D "physical instrument" builders for the Control Room -- the
// pieces a real SOC/plant control desk is made of: pilot lamps, toggle
// switches, bezeled screens and cable runs. Pure procedural geometry (no
// external model files), so they stay tiny and load instantly. Each one is
// driven by a real boolean/status from the platform, never decorative.
// ---------------------------------------------------------------------------

const COLOR_HEX = { green: 0x29f18b, yellow: 0xffd925, red: 0xff3038, gray: 0x5a6b76, cyan: 0x20d8ff };

export function colorFor(state) {
  return COLOR_HEX[state] ?? COLOR_HEX.gray;
}

export function createIndicatorLamp(state, { radius = 3.4 } = {}) {
  const color = colorFor(state);
  const group = new THREE.Group();
  const base = new THREE.Mesh(
    new THREE.CylinderGeometry(radius * 1.15, radius * 1.15, 1.4, 16),
    new THREE.MeshStandardMaterial({ color: 0x1c242b, metalness: 0.7, roughness: 0.4 })
  );
  base.rotation.x = Math.PI / 2;
  group.add(base);
  const bulbLit = state !== "gray";
  const bulb = new THREE.Mesh(
    new THREE.SphereGeometry(radius, 14, 10),
    new THREE.MeshStandardMaterial({
      color, emissive: color, emissiveIntensity: bulbLit ? 1.4 : 0.05,
      metalness: 0.1, roughness: 0.3, transparent: true, opacity: 0.95,
    })
  );
  bulb.position.z = 1.6;
  group.add(bulb);
  if (bulbLit) {
    const light = new THREE.PointLight(color, 2.2, 22, 2);
    light.position.z = 2;
    group.add(light);
  }
  group.userData.setState = (newState) => {
    const c = colorFor(newState);
    bulb.material.color.setHex(c);
    bulb.material.emissive.setHex(c);
    bulb.material.emissiveIntensity = newState !== "gray" ? 1.4 : 0.05;
  };
  return group;
}

export function createToggleSwitch(isOn, { color = 0x20d8ff } = {}) {
  const group = new THREE.Group();
  const plate = new THREE.Mesh(
    new THREE.BoxGeometry(6, 9, 2),
    new THREE.MeshStandardMaterial({ color: 0x22292f, metalness: 0.6, roughness: 0.5 })
  );
  group.add(plate);
  const lever = new THREE.Mesh(
    new THREE.CapsuleGeometry(0.8, 4, 4, 8),
    new THREE.MeshStandardMaterial({ color, metalness: 0.3, roughness: 0.35, emissive: color, emissiveIntensity: 0.25 })
  );
  lever.position.z = 1.2;
  lever.rotation.x = isOn ? -0.5 : 0.5;
  lever.position.y = isOn ? 1.6 : -1.6;
  group.add(lever);
  group.userData.setOn = (on) => {
    lever.rotation.x = on ? -0.5 : 0.5;
    lever.position.y = on ? 1.6 : -1.6;
  };
  return group;
}

export function createBezelScreen(w, h, state) {
  const color = colorFor(state);
  const group = new THREE.Group();
  const frame = new THREE.Mesh(
    new THREE.BoxGeometry(w, h, 2.4),
    new THREE.MeshStandardMaterial({ color: 0x171e24, metalness: 0.55, roughness: 0.5 })
  );
  group.add(frame);
  const screen = new THREE.Mesh(
    new THREE.PlaneGeometry(w * 0.86, h * 0.8),
    new THREE.MeshStandardMaterial({ color: 0x040c13, emissive: color, emissiveIntensity: 0.35, metalness: 0, roughness: 0.6 })
  );
  screen.position.z = 1.25;
  group.add(screen);
  group.userData.setState = (newState) => {
    const c = colorFor(newState);
    screen.material.emissive.setHex(c);
  };
  return group;
}

// Shared tube-cable builder (same CatmullRom + TubeGeometry technique already
// used for the visual mode's metallic pipes) -- exposed here so the
// instrument strip can wire lamps/switches together with real cable runs.
export function createCableRun(points3d, state, { radius = 0.9 } = {}) {
  const color = colorFor(state);
  const curve = new THREE.CatmullRomCurve3(points3d, false, "catmullrom", 0.1);
  const geo = new THREE.TubeGeometry(curve, Math.max(8, points3d.length * 6), radius, 8, false);
  const mat = new THREE.MeshStandardMaterial({ color: 0x11161a, metalness: 0.7, roughness: 0.4, emissive: color, emissiveIntensity: 0.4 });
  return new THREE.Mesh(geo, mat);
}
