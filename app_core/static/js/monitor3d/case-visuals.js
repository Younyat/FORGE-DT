import * as THREE from "three";
import { buildNode } from "./node-models/node-builders.js";
import { collapseDrawCalls, markShared } from "./geometry-utils.js";

// The detailed forensic-case model ("forense" in node-builders.js's NODOS
// map, built from nodo-caso_forense.js -- a rigid field forensic kit case:
// lid with the acquisition workstation screen, base tray with two open
// disks, a bridge board, keyboard, touch panel and cabling). Unlike hosts
// there's only ever one "case" shape (no per-role variants), so this
// module is a single-entry version of host-visuals.js's cache/fit pattern
// rather than a role-keyed map.
const CASE_ACCENT = 0x6366f1; // violet -- matches this dashboard's existing evidentiary color (host->case cables, evidence-core glow)

let cached = null;

function getCachedCaseModel() {
  if (cached) return cached;
  const model = collapseDrawCalls(buildNode("forense", CASE_ACCENT));
  const box = new THREE.Box3().setFromObject(model);
  if (box.isEmpty()) return null;
  const size = box.getSize(new THREE.Vector3());
  model.position.sub(box.getCenter(new THREE.Vector3())); // center once, cached pre-centered
  markShared(model);
  cached = { model, size };
  return cached;
}

/**
 * Returns the detailed forensic-case model (built once for the page's
 * whole lifetime, then reused -- see getCachedCaseModel above), scaled
 * uniformly (never stretched/distorted) to fit inside a targetWidth x
 * targetHeight x targetDepth footprint. Already centered so its bounding
 * box sits on the returned group's local origin -- the same convention
 * BoxGeometry(w,h,d) already uses, so connectors/row layout/camera
 * framing (which all read group.userData.width/height/depth, corrected
 * to the model's real rendered bounds by createEntityBox itself) keep
 * working unmodified. Mirrors host-visuals.js::buildHostVisual exactly,
 * just without a role dimension.
 */
export function buildCaseVisual(targetWidth, targetHeight, targetDepth) {
  const entry = getCachedCaseModel();
  if (!entry) return null;
  const scale = Math.min(
    targetWidth / (entry.size.x || 1),
    targetHeight / (entry.size.y || 1),
    targetDepth / (entry.size.z || 1),
  );
  const wrapper = new THREE.Group();
  wrapper.name = "nodo_forense_visual";
  wrapper.add(entry.model); // same cached object every call -- Object3D.add() re-parents it, exactly what's wanted when the previous case box using it is torn down in the same rebuild
  wrapper.scale.setScalar(scale);
  return wrapper;
}
