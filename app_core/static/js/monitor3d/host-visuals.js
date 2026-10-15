import * as THREE from "three";
import { buildNode } from "./node-models/node-builders.js";
import { collapseDrawCalls, markShared } from "./geometry-utils.js";

// Maps this platform's own real host role strings (node_health_api.py's
// _classify_role: "attacker"/"victim"/"plc"/"scada"/"monitor") onto the five
// detailed node models supplied in /home/younes/Downloads/forge-vi-nodos
// (kinds: atacante/victima/plc/fuxa/monitor). "unknown" has no model --
// callers fall back to the plain wireframe box for it, same as always.
const ROLE_TO_MODEL_KIND = {
  attacker: "atacante",
  victim: "victima",
  plc: "plc",
  scada: "fuxa",
  monitor: "monitor",
};

// Each model's own reference accent (from the supplied nodos-3d.html demo)
// -- kept per-role instead of collapsing to this platform's existing plain
// blue/red split, since the neon frame and emissive parts of each model
// were tuned against these specific colors.
const MODEL_ACCENT = {
  attacker: 0xff2d38,
  victim: 0x1e9bff,
  plc: 0x12e05a,
  scada: 0x8b2dff,
  monitor: 0xffbe1a,
};

export function hasHostVisual(role) {
  return Object.prototype.hasOwnProperty.call(ROLE_TO_MODEL_KIND, role);
}

// Role -> { model, size } cache. A host's role never changes (scenario
// topology is stable) and exactly one instance of each role is ever on
// screen at a time (live or reconstruction, never both, never more than
// one repetition's hosts at once) -- so the expensive part (building +
// merging a model, ~130k triangles' worth of geometry construction) only
// ever needs to happen ONCE per role for the whole page's lifetime, not
// once per rebuild. This is the fix for the real, measured cause of "the
// scene got sluggish to orbit" -- the live-poll snapshot's hash changes
// on essentially every poll (host vitals are volatile), so app.js's
// rebuildScene() was reconstructing all 5 models from scratch roughly
// every 2-3 seconds. With plain boxes that rebuild was instant; with
// these models it was real, blocking main-thread work landing right in
// the middle of orbiting. Geometries/materials cached here are flagged
// `userData.sharedNodeVisual` so entities.js's disposeEntity() knows to
// never dispose them when an individual host box is torn down.
const modelCache = new Map();

function getCachedModel(role) {
  if (modelCache.has(role)) return modelCache.get(role);
  const modelKind = ROLE_TO_MODEL_KIND[role];
  if (!modelKind) return null;
  const model = collapseDrawCalls(buildNode(modelKind, MODEL_ACCENT[role]));
  const box = new THREE.Box3().setFromObject(model);
  if (box.isEmpty()) return null;
  const size = box.getSize(new THREE.Vector3());
  model.position.sub(box.getCenter(new THREE.Vector3())); // center once, cached pre-centered
  markShared(model);
  const entry = { model, size };
  modelCache.set(role, entry);
  return entry;
}

/**
 * Returns one of the five detailed node models (built once per role, then
 * reused -- see modelCache above), scaled uniformly (never stretched/
 * distorted) to fit inside a targetWidth x targetHeight x targetDepth
 * footprint. Already centered so its bounding box sits on the returned
 * group's local origin -- the exact same convention BoxGeometry(w,h,d)
 * already uses, so everything downstream that assumes a centered box
 * (connector anchors, row layout, camera framing, which all read
 * group.userData.width/height/depth rather than inspecting geometry)
 * keeps working unmodified.
 *
 * Returns null for a role with no matching model (caller keeps the plain
 * box for that case).
 */
export function buildHostVisual(role, targetWidth, targetHeight, targetDepth) {
  const entry = getCachedModel(role);
  if (!entry) return null;
  const scale = Math.min(
    targetWidth / (entry.size.x || 1),
    targetHeight / (entry.size.y || 1),
    targetDepth / (entry.size.z || 1),
  );
  const wrapper = new THREE.Group();
  wrapper.name = `nodo_${ROLE_TO_MODEL_KIND[role]}_visual`;
  wrapper.add(entry.model); // same cached object every call -- Object3D.add() re-parents it, which is exactly what's wanted when the previous host box using it is being torn down in the same rebuild
  wrapper.scale.setScalar(scale);
  return wrapper;
}
