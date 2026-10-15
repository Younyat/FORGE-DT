// Forensic watcher · read-only digital-twin observer. Meters, y-up.
// Adapted 2026-10-14 from the 3D asset the user provided ("vigia-forense.js")
// for Reconstruction View -- geometry and idle animation UNCHANGED from the
// original; the only addition is lookAt() (turns the head toward a real
// world point, e.g. the node the twin just observed) and getGroups()
// (exposes root+cone so the caller adds/removes them from the scene itself,
// outside reconstruction.js's own per-beat teardown cycle -- see that
// module's own comment on why nothing "persistent" survives a scrub unless
// it's managed that way).
import * as THREE from "three";

const M = (name, color, o = {}) => { const m = new THREE.MeshStandardMaterial({ color, roughness: o.r ?? 0.5, metalness: o.m ?? 0.2, emissive: o.e ?? 0x000000, emissiveIntensity: o.ei ?? 0, transparent: !!o.t, opacity: o.t ?? 1, side: o.side ?? THREE.FrontSide, depthWrite: !o.t }); m.name = name; return m; };
const mesh = (name, geo, mat, p = [0, 0, 0], r = [0, 0, 0]) => { const x = new THREE.Mesh(geo, mat); x.name = name; x.position.set(...p); x.rotation.set(...r); x.castShadow = x.receiveShadow = true; return x; };

export const STATES = {
  match:        { color: 0x2fbf71, label: "Match" },
  deviation:    { color: 0xf2a516, label: "Deviation" },
  discrepancy:  { color: 0xe5484d, label: "Discrepancy" },
};

export function buildVigia() {
  const root = new THREE.Group(); root.name = "forensic_watcher";
  const graphite = M("graphite", 0x2a2d31, { r: 0.6, m: 0.4 });
  const steel = M("steel", 0xb9bcc0, { r: 0.35, m: 0.8 });
  const white = M("white_shell", 0xeceae5, { r: 0.4 });
  const glass = M("lens_glass", 0x0d1b24, { r: 0.05, m: 0.9 });
  const eyeMat = M("eye_emissive", 0x7fe3ff, { e: 0x39c6ff, ei: 2.2, r: 0.2 });
  const haloMat = M("halo_emissive", 0xfff2c8, { e: 0xffd977, ei: 1.6, r: 0.3 });
  const wingMat = M("wing_sensor", 0xdedbd4, { r: 0.45, m: 0.15 });
  const coneMat = M("vision_cone", 0x7fe3ff, { t: 0.10, e: 0x39c6ff, ei: 0.4, side: THREE.DoubleSide });

  // Node 1 - Anchored base (purely structural, acts on nothing)
  const base = new THREE.Group(); base.name = "N1_base"; root.add(base);
  base.add(mesh("base_plate", new THREE.CylinderGeometry(0.34, 0.38, 0.06, 6), graphite, [0, 0.03, 0]));
  base.add(mesh("base_socket", new THREE.CylinderGeometry(0.2, 0.26, 0.12, 6), white, [0, 0.12, 0]));
  // Data diode: information only ever flows out, never in
  const diode = mesh("data_diode", new THREE.BoxGeometry(0.16, 0.1, 0.1), graphite, [0.24, 0.11, 0.14]);
  base.add(diode);
  const arrow = mesh("diode_arrow", new THREE.ConeGeometry(0.022, 0.05, 3), eyeMat, [0.24, 0.11, 0.195], [Math.PI / 2, 0, 0]);
  base.add(arrow);

  // Node 2 - Mast
  const mast = new THREE.Group(); mast.name = "N2_mast"; root.add(mast);
  mast.add(mesh("mast_tube", new THREE.CylinderGeometry(0.045, 0.06, 1.2, 24), steel, [0, 0.78, 0]));
  [0.5, 0.9].forEach((y, i) => mast.add(mesh("mast_ring_" + i, new THREE.CylinderGeometry(0.07, 0.07, 0.025, 24), graphite, [0, y, 0])));
  // Status beacon (what it "says")
  const beacon = new THREE.Group(); beacon.name = "status_beacon"; beacon.position.set(0.075, 0.62, 0); mast.add(beacon);
  const beaconMats = {};
  Object.entries(STATES).forEach(([k, s], i) => {
    const m = M("beacon_" + k, s.color, { e: s.color, ei: 0.05, r: 0.3, t: 0.95 }); beaconMats[k] = m;
    beacon.add(mesh("beacon_" + k, new THREE.CylinderGeometry(0.028, 0.028, 0.05, 20), m, [0.03, 0.12 - i * 0.055, 0]));
  });
  beacon.add(mesh("beacon_mount", new THREE.BoxGeometry(0.03, 0.02, 0.02), graphite, [0.0, 0.0, 0]));

  // Node 3 - Head with eye (turns and observes)
  const head = new THREE.Group(); head.name = "N3_head"; head.position.set(0, 1.46, 0); root.add(head);
  head.add(mesh("head_neck", new THREE.CylinderGeometry(0.05, 0.07, 0.08, 24), graphite, [0, -0.08, 0]));
  head.add(mesh("head_dome", new THREE.SphereGeometry(0.14, 40, 24), white));
  head.add(mesh("head_visor", new THREE.TorusGeometry(0.1, 0.022, 14, 40), graphite, [0, 0, 0.1]));
  head.add(mesh("eye_lens", new THREE.CylinderGeometry(0.085, 0.085, 0.03, 40), glass, [0, 0, 0.115], [Math.PI / 2, 0, 0]));
  const eye = mesh("eye_pupil", new THREE.SphereGeometry(0.04, 24, 16), eyeMat, [0, 0, 0.12]); head.add(eye);
  // Vision cone: lives outside the exportable object; added to the scene
  // separately and follows the head every frame
  const cono = new THREE.Group(); cono.name = "vision_cone_overlay";
  const conoM = new THREE.Mesh(new THREE.ConeGeometry(0.9, 2.2, 40, 1, true), coneMat);
  conoM.position.set(0, 0, 1.22); conoM.rotation.x = -Math.PI / 2; conoM.renderOrder = 2; cono.add(conoM);
  const _p = new THREE.Vector3(), _q = new THREE.Quaternion();

  // Node 4 - Sensor wings (passive, read-only)
  const wings = new THREE.Group(); wings.name = "N4_wings"; wings.position.set(0, 1.38, -0.06); root.add(wings);
  const wingShape = () => { const s = new THREE.Shape(); s.moveTo(0, 0); s.quadraticCurveTo(0.25, 0.32, 0.62, 0.36); s.lineTo(0.56, 0.22); s.quadraticCurveTo(0.42, 0.1, 0.48, -0.04); s.quadraticCurveTo(0.3, -0.02, 0.32, -0.16); s.quadraticCurveTo(0.14, -0.1, 0, -0.04); return s; };
  const wingGeo = new THREE.ExtrudeGeometry(wingShape(), { depth: 0.018, bevelEnabled: true, bevelThickness: 0.004, bevelSize: 0.004, bevelSegments: 2 });
  const wingLenses = [];
  [1, -1].forEach(side => {
    const wing = new THREE.Group(); wing.name = side > 0 ? "wing_right" : "wing_left";
    wing.position.set(side * 0.1, 0, 0); wing.rotation.set(side > 0 ? 0.25 : -0.25, side > 0 ? -0.55 : Math.PI + 0.55, 0.12);
    wing.add(mesh(wing.name + "_panel", wingGeo, wingMat));
    [[0.18, 0.08], [0.32, 0.17], [0.46, 0.25], [0.24, -0.02], [0.38, 0.06]].forEach(([x, y], i) => {
      const l = mesh(wing.name + "_sensor_" + i, new THREE.CylinderGeometry(0.018, 0.018, 0.012, 16), eyeMat, [x, y, 0.025], [Math.PI / 2, 0, 0]);
      wing.add(l); wingLenses.push(l);
    });
    wings.add(wing);
  });

  // Scan halo
  const halo = new THREE.Group(); halo.name = "scan_halo"; halo.position.set(0, 1.64, 0); root.add(halo);
  halo.add(mesh("halo_ring", new THREE.TorusGeometry(0.2, 0.012, 12, 72), haloMat, [0, 0, 0], [Math.PI / 2, 0, 0]));
  for (let i = 0; i < 8; i++) { const a = i / 8 * Math.PI * 2; halo.add(mesh("halo_node_" + i, new THREE.SphereGeometry(0.016, 12, 8), haloMat, [Math.cos(a) * 0.2, 0, Math.sin(a) * 0.2])); }

  const _v = new THREE.Vector3();
  let state = "match", yaw = 0;
  // lookAt override: when the twin "observes" something real, the head
  // stops its free scanning and turns to the exact point, for `lookAtUntil`
  // ms -- then resumes normal scanning on its own. Never replaces the scan
  // mechanism, only pauses it temporarily, the same way
  // `controls.addEventListener('start', ...)` already pauses autorotate in
  // three-d-stage.js (same pattern: a real interaction wins over the idle
  // animation, which resumes by itself afterward).
  let lookAtTarget = null, lookAtUntil = 0;
  const setState = k => { state = k; for (const [n, m] of Object.entries(beaconMats)) m.emissiveIntensity = n === k ? 2.4 : 0.05; eyeMat.emissive.setHex(k === "match" ? 0x39c6ff : STATES[k].color); coneMat.emissive.setHex(k === "match" ? 0x39c6ff : STATES[k].color); coneMat.color.setHex(k === "match" ? 0x7fe3ff : STATES[k].color); };
  setState("match");
  // targetLocalPos: position ALREADY relative to root.position (the caller
  // subtracts root.position.clone() before passing it in) -- head.lookAt
  // expects coordinates in the head's parent space, which IS root.
  const lookAt = (targetLocalPos, durationMs = 3200) => {
    lookAtTarget = targetLocalPos.clone();
    lookAtUntil = performance.now() + durationMs;
  };
  const tick = (t, scan = true) => {
    halo.rotation.y = t * 0.6;
    halo.position.y = 1.64 + Math.sin(t * 1.4) * 0.01;
    if (lookAtTarget && performance.now() < lookAtUntil) {
      const dx = lookAtTarget.x - head.position.x, dz = lookAtTarget.z - head.position.z;
      yaw = Math.atan2(dx, dz);
      head.rotation.y = yaw;
    } else {
      lookAtTarget = null;
      if (scan) { yaw = Math.sin(t * 0.45) * 1.05; head.rotation.y = yaw; }
    }
    eyeMat.emissiveIntensity = 1.6 + Math.sin(t * 3) * 0.6;
    wingLenses.forEach((l, i) => l.scale.setScalar(0.85 + 0.15 * Math.sin(t * 2 + i)));
    if (cono.parent) { head.updateWorldMatrix(true, false); head.matrixWorld.decompose(_p, _q, _v); cono.position.copy(_p); cono.quaternion.copy(_q); cono.scale.copy(_v); }
  };
  root.userData = { setState, getState: () => state, tick, setVisionCone: v => (cono.visible = v), cono, getYaw: () => head.rotation.y, lookAt };
  return root;
}
