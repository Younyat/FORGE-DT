import * as THREE from "three";
import { CSS2DObject } from "/vendor/three/addons/CSS2DRenderer.js";
import { mergeIndexedGeometries } from "./geometry-utils.js";

const STATUS_COLOR = {
  completed: 0x34d399, installed: 0x34d399, ready: 0x34d399, ok: 0x34d399,
  idle: 0x2f6f7f,
  running: 0x22d3ee, live: 0x22d3ee,
  installing_tools: 0x3b82f6, provisioning: 0x3b82f6, acquiring_evidence: 0x3b82f6, partial: 0x3b82f6,
  under_attack: 0xf59e0b, warning: 0xf59e0b, degraded: 0xfb923c, blocked: 0xf59e0b,
  pending: 0x4b6572,
  error: 0xef4444, failed: 0xef4444,
  stopped: 0x8b98a3, unknown: 0x556570,
  info: 0x38bdf8,
};

export function statusColor(status) {
  return STATUS_COLOR[String(status || "unknown").toLowerCase()] ?? STATUS_COLOR.unknown;
}

function statusHex(status) {
  return "#" + statusColor(status).toString(16).padStart(6, "0");
}

// Box identity color: every box is transparent blue except the attacker's,
// which is transparent red -- independent of operational status (status
// still drives the small badge pill inside the card).
export const BOX_COLOR_DEFAULT = 0x3b82f6;
export const BOX_COLOR_ATTACKER = 0xef4444;

// Small stroke-only glyphs (currentColor) per box kind, matching the
// reference design's line-icon HUD style -- a real, if minimal, visual cue
// rather than plain text, since that was the specific gap flagged: the
// reference image was described but never actually reproduced visually.
const ICONS = {
  campaign: `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 2 7l10 5 10-5-10-5Z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>`,
  case: `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/></svg>`,
  host: `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="7" rx="1"/><rect x="2" y="14" width="20" height="7" rx="1"/><path d="M6 6.5h.01M6 17.5h.01"/></svg>`,
  tool: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 1-5.6 5.6l-6.4 6.4a1.6 1.6 0 0 0 2.3 2.3l6.4-6.4a4 4 0 0 1 5.6-5.6l-2.3 2.3-1.8-1.8Z"/></svg>`,
  repetition: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 2.1 21 6l-4 3.9"/><path d="M3 12v-1a5 5 0 0 1 5-5h13"/><path d="m7 21.9-4-3.9 4-3.9"/><path d="M21 12v1a5 5 0 0 1-5 5H3"/></svg>`,
  stage: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 22V4a1 1 0 0 1 1-1h10l4 4v9a1 1 0 0 1-1 1H5"/><path d="M4 15h13"/></svg>`,
  evidence: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 11 4.6-2.3 8-6 8-11V5l-8-3Z"/></svg>`,
  telemetry: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 18 0"/><path d="M12 12 16 8"/><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none"/></svg>`,
};

// A small SVG donut -- the reference design shows progress as a ring with
// the percentage inside it, not as plain text.
export function progressRing(pct, colorHex, size = 34) {
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  const r = (size - 5) / 2;
  const c = 2 * Math.PI * r;
  const off = c * (1 - p / 100);
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" class="ring">
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="rgba(255,255,255,0.14)" stroke-width="3"/>
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${colorHex}" stroke-width="3" stroke-linecap="round"
      stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 ${size / 2} ${size / 2})"/>
    <text x="50%" y="52%" text-anchor="middle" dominant-baseline="middle" fill="#fff" font-size="${Math.round(size * 0.3)}" font-weight="700">${Math.round(p)}%</text>
  </svg>`;
}

/**
 * A wireframe 3D box with a rich HTML info-card floating above it (CSS2D --
 * real DOM content positioned by the 3D projection, not baked-in geometry
 * text). `userData` carries everything the interaction layer + side panel
 * need, so clicking never needs a re-fetch.
 */
export function createEntityBox({ id, kind, title, subtitle, status, statusLabel, statLines = [], width = 10, height = 6, depth = 8, raw = null, boxColor = BOX_COLOR_DEFAULT, cardOffsetY = 0, ringPct = null, extraHtml = "", ghost = false, visualModel = null }) {
  const group = new THREE.Group();
  group.userData = { id, kind, title, status, raw };
  const boxHex = "#" + boxColor.toString(16).padStart(6, "0");

  // visualModel (from host-visuals.js) swaps in one of the detailed node
  // models instead of the plain wireframe box -- already scaled/centered by
  // the caller to this exact width/height/depth footprint. Everything below
  // this branch (card, ring, badge, connector metadata, click resolution)
  // stays completely unaware of the difference: it only ever reads
  // group.userData.width/height/depth, never the mesh's own geometry.
  let mesh, edgeMaterial = null, haloLine = null;
  if (visualModel) {
    mesh = visualModel;
    mesh.traverse((o) => { if (o.isMesh) o.userData = group.userData; });
    group.add(mesh);
    // host-visuals.js scales the model uniformly to FIT WITHIN
    // width/height/depth without distorting it -- unless its own
    // proportions happen to match the target box exactly, it won't
    // actually reach all three requested boundaries (this one is
    // typically shorter than the requested height). Everything that
    // anchors to these numbers -- connectors especially, which must
    // touch both the host box and the case box, not end floating short
    // of the model's real top -- needs the model's ACTUAL rendered
    // extent here, not the requested footprint it was fitted inside.
    const realBox = new THREE.Box3().setFromObject(mesh);
    if (!realBox.isEmpty()) {
      const realSize = realBox.getSize(new THREE.Vector3());
      if (realSize.x > 0) width = realSize.x;
      if (realSize.y > 0) height = realSize.y;
      if (realSize.z > 0) depth = realSize.z;
    }
    if (!ghost) {
      // A detailed model has no single geometry to outline, but selection/
      // critical-status still needs *some* glow -- reuse the exact same
      // "invisible until warranted" halo cage as the plain box, sized to
      // the model's own target footprint instead of its real (lumpy)
      // silhouette.
      const haloGeo = new THREE.EdgesGeometry(new THREE.BoxGeometry(width, height, depth));
      const haloMaterial = new THREE.LineBasicMaterial({
        color: boxColor, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false,
      });
      haloLine = new THREE.LineSegments(haloGeo, haloMaterial);
      haloLine.scale.setScalar(1.06);
      group.add(haloLine);
    }
  } else {
    const geometry = new THREE.BoxGeometry(width, height, depth);
    // Physically-based transmission (real glass refraction) forces an extra
    // scene-capture render pass per transmissive object, per frame -- with a
    // dozen+ boxes on screen that was expensive enough to visibly drop frames
    // and make orbiting feel stepped, so that stays off the table. A lit
    // MeshStandardMaterial (metalness/roughness) instead gives a real sheen
    // that shifts with camera angle under the two lights scene.js now adds --
    // same render cost as any other lit mesh, no extra passes -- for a
    // "polished metal/glass" look instead of the previous flat unlit tint.
    const material = new THREE.MeshStandardMaterial({
      color: boxColor, transparent: true, opacity: ghost ? 0.035 : 0.36,
      metalness: 0.8, roughness: 0.16,
    });
    mesh = new THREE.Mesh(geometry, material);
    mesh.userData = group.userData;
    group.add(mesh);

    // A preserved artifact isn't just another box with a label -- give it
    // a real physical presence: a small glowing "data core" floating
    // inside its own glass shell, an emissive icosahedron that reads
    // instantly as "this is data" rather than "this is infrastructure"
    // (the same box style every other kind already uses). Purely additive
    // geometry, same lit-material cost class as the box itself.
    if (kind === "evidence" && !ghost) {
      const core = new THREE.Mesh(
        new THREE.IcosahedronGeometry(Math.min(width, height, depth) * 0.22, 1),
        new THREE.MeshStandardMaterial({
          color: boxColor, emissive: boxColor, emissiveIntensity: 1.6,
          roughness: 0.25, metalness: 0.1, transparent: true, opacity: 0.92,
        }),
      );
      core.name = "evidence_core";
      group.add(core);
    }

    const edges = new THREE.EdgesGeometry(geometry);
    edgeMaterial = new THREE.LineBasicMaterial({ color: boxColor, transparent: true, opacity: ghost ? 0.28 : 0.95 });
    const line = new THREE.LineSegments(edges, edgeMaterial);
    group.add(line);

    // A slightly-oversized, additively-blended duplicate of the same edges --
    // a "selective bloom" stand-in (spec section 44) for boxes that actually
    // need visual emphasis (selected / attacker identity / a critical status),
    // without paying for a full EffectComposer bloom pass on every box. Starts
    // fully transparent; applyVisualState() below turns it up only when
    // warranted, so most boxes on screen never pay any extra draw cost beyond
    // one more (invisible-until-needed) LineSegments.
    if (!ghost) {
      const haloMaterial = new THREE.LineBasicMaterial({
        color: boxColor, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false,
      });
      haloLine = new THREE.LineSegments(edges, haloMaterial);
      haloLine.scale.setScalar(1.035);
      group.add(haloLine);
    }
  }
  const CRITICAL_STATUSES = ["error", "failed", "under_attack", "warning", "blocked"];
  const alwaysGlow = !ghost && (boxColor === BOX_COLOR_ATTACKER || CRITICAL_STATUSES.includes(String(status || "").toLowerCase()));

  const card = document.createElement("div");
  card.className = `ent-card kind-${kind}${ghost ? " ent-card-ghost" : ""}`;
  card.style.setProperty("--cage-color", boxHex);
  // A ghost shell is the parent/grandparent context kept faintly visible
  // while drilled into a child (spec: "parent context must remain visible
  // as a transparent shell") -- just a dim label, not the full rich card,
  // so it reads as background context rather than competing for attention.
  card.innerHTML = ghost
    ? `<div class="ent-title">${escapeHtml(title)}</div>${subtitle ? `<div class="ent-sub">${escapeHtml(subtitle)}</div>` : ""}`
    : `
    <span class="corner tl"></span><span class="corner tr"></span><span class="corner bl"></span><span class="corner br"></span>
    <div class="ent-head">
      <span class="ent-icon">${ICONS[kind] || ""}</span>
      <div class="ent-head-text">
        <div class="ent-title">${escapeHtml(title)}</div>
        ${subtitle ? `<div class="ent-sub">${escapeHtml(subtitle)}</div>` : ""}
      </div>
      ${ringPct !== null ? `<div class="ent-ring">${progressRing(ringPct, boxHex)}</div>` : ""}
    </div>
    <div class="ent-badge" style="color:${statusHex(status)};border-color:${statusHex(status)}">${escapeHtml(statusLabel || status || "unknown")}</div>
    ${statLines.map((l) => `<div class="ent-stat">${l}</div>`).join("")}
    ${extraHtml}
  `;
  const cardObj = new CSS2DObject(card);
  // Centered inside the box volume by default -- not floating above it. A
  // container box that also has children nested INSIDE its own footprint
  // (the drilled host view) instead offsets its own title card toward the
  // top so it doesn't collide with the nested boxes' cards at the center.
  cardObj.position.set(0, cardOffsetY, 0);
  group.add(cardObj);
  group.userData.card = card;
  group.userData.cardObject = cardObj;

  group.userData.mesh = mesh;
  group.userData.edgeMaterial = edgeMaterial;
  group.userData.haloLine = haloLine;
  group.userData.alwaysGlow = alwaysGlow;
  group.userData.width = width;
  group.userData.height = height;
  group.userData.depth = depth;
  return group;
}

/**
 * CSS2DRenderer only ever appends label DOM elements to its container; it
 * never removes one unless the CSS2DObject itself is detached from its
 * direct parent. Removing an ancestor Group from the scene (the normal way
 * to tear down an entity box) does NOT fire that detach, so without this
 * every scene rebuild leaves the previous set of label elements orphaned
 * in the DOM forever, growing GPU/DOM memory and looking like duplicated,
 * frozen labels on screen.
 */
export function disposeEntity(entityGroup) {
  entityGroup.traverse((obj) => {
    if (obj.isCSS2DObject && obj.element?.parentNode) {
      obj.element.parentNode.removeChild(obj.element);
    }
    // host-visuals.js caches each detailed node model's geometry/material
    // PER ROLE (rebuilding+merging one from scratch is expensive enough to
    // visibly stutter every live-poll rebuild, measured this session) and
    // reuses the same objects across every host box of that role for the
    // life of the page -- disposing them here on every ordinary box
    // teardown would silently destroy that cache the first time any host
    // box is ever rebuilt. Sharable resources are marked once at creation;
    // everything else (the vast majority -- plain boxes, cards, per-box
    // halo/edge lines) disposes exactly as before.
    if (obj.geometry && !obj.geometry.userData?.sharedNodeVisual) obj.geometry.dispose();
    if (obj.material && !obj.material.userData?.sharedNodeVisual) obj.material.dispose();
  });
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function applyVisualState(entityGroup) {
  const selected = !!entityGroup.userData.selected;
  const dimmed = !!entityGroup.userData.dimmed;
  const baseFillOpacity = selected ? 0.28 : 0.1;
  const factor = dimmed ? 0.25 : 1; // faded, never hidden -- context must survive filtering (spec section 37)
  // A detailed node-model "mesh" is a multi-part Group (host-visuals.js),
  // not a single Mesh with one .material -- nothing sensible to dim/tint
  // there the way a plain box's translucent fill can be, so this is a
  // no-op for that case; the halo cage below still carries the same
  // selection feedback either way.
  if (entityGroup.userData.mesh.material) {
    entityGroup.userData.mesh.material.opacity = baseFillOpacity * factor;
  }
  entityGroup.userData.card.classList.toggle("selected", selected);
  entityGroup.userData.card.classList.toggle("dimmed", dimmed);

  const halo = entityGroup.userData.haloLine;
  if (halo) {
    const baseHalo = selected ? 0.45 : entityGroup.userData.alwaysGlow ? 0.22 : 0;
    halo.material.opacity = baseHalo * factor;
  }
}

export function setSelected(entityGroup, selected) {
  entityGroup.userData.selected = !!selected;
  applyVisualState(entityGroup);
}

// Dims (never hides) a box that doesn't belong to the currently active Data
// Sources filter layer -- independent of selection, so both states combine
// instead of one silently overwriting the other's opacity change.
export function setDimmed(entityGroup, dimmed) {
  entityGroup.userData.dimmed = !!dimmed;
  applyVisualState(entityGroup);
}

// The three functions below patch an already-created entity's card/materials
// in place -- same "mutate, don't rebuild" pattern as setSelected/setDimmed
// above. Used by the reconstruction ("construction sequence") player to
// update a persistent box's progress ring/badge/color as real beats complete,
// without disposing and recreating the box each time. A no-op when the
// targeted DOM node isn't present (e.g. ringPct wasn't set at creation).

export function updateRing(card, pct, colorHex) {
  const ring = card?.querySelector(".ent-ring");
  if (!ring) return;
  ring.innerHTML = progressRing(pct, colorHex);
}

export function updateBadge(card, status, label) {
  const badge = card?.querySelector(".ent-badge");
  if (!badge) return;
  const hex = statusHex(status);
  badge.textContent = label ?? status ?? "unknown";
  badge.style.color = hex;
  badge.style.borderColor = hex;
}

// Same update-in-place pattern as updateRing/updateBadge above -- statLines
// are rendered once at creation (card.innerHTML, right after .ent-badge in
// source order) with no dedicated wrapper of their own, so replacing them
// means removing the existing .ent-stat elements and re-inserting the new
// ones right after the badge, in that same position.
export function updateStatLines(card, lines) {
  const badge = card?.querySelector(".ent-badge");
  if (!badge) return;
  card.querySelectorAll(".ent-stat").forEach((el) => el.remove());
  const html = (lines || []).map((l) => `<div class="ent-stat">${l}</div>`).join("");
  badge.insertAdjacentHTML("afterend", html);
}

export function recolorEntity(group, colorHex) {
  const hex = "#" + colorHex.toString(16).padStart(6, "0");
  if (group.userData.mesh?.material) group.userData.mesh.material.color.setHex(colorHex);
  if (group.userData.edgeMaterial) group.userData.edgeMaterial.color.setHex(colorHex);
  if (group.userData.haloLine) group.userData.haloLine.material.color.setHex(colorHex);
  group.userData.card?.style.setProperty("--cage-color", hex);
}

/** A hierarchy "cable" between a parent and child box -- campaign->
 * repetition, host->case, etc. Built as a real 3D tube along a hand-shaped
 * hanging-rope curve (two sagging, sideways-bowed control points through a
 * CatmullRomCurve3), not a thin straight-ish Line: a hairline Line renders
 * as a near-invisible 1px thread at overview camera distance (WebGL
 * ignores `linewidth` on most GPUs) and a single shallow quadratic bow
 * still reads as a rigid strut. The sideways bow uses a fixed world-up
 * reference, so it never degenerates to zero even when parent and child
 * line up exactly vertically (the common case for this hierarchy, which
 * stacks boxes straight down the Y axis).
 *
 * `colorHex` lets a caller tint cables by hierarchy LEVEL (e.g. structural
 * campaign/host cables one hue, evidentiary host/case cables another) --
 * defaults to the existing child-status tint when omitted. `opacity`
 * defaults lower than a solid cable (0.5, was 0.8) so a scene with several
 * of these doesn't read as visually noisy/obstructive. */
export function createConnector(parentGroup, childGroup, { colorHex = null, opacity = 0.5 } = {}) {
  const parentBottom = parentGroup.position.clone();
  parentBottom.y -= (parentGroup.userData.height || 6) / 2;
  const childTop = childGroup.position.clone();
  childTop.y += (childGroup.userData.height || 6) / 2;

  const span = Math.max(1, parentBottom.distanceTo(childTop));
  const sag = Math.max(1.1, span * 0.16);
  const dir = childTop.clone().sub(parentBottom).normalize();
  let across = new THREE.Vector3().crossVectors(dir, new THREE.Vector3(0, 1, 0));
  if (across.lengthSq() < 1e-6) across.set(1, 0, 0); // dir parallel to Y -- pick any perpendicular
  across.normalize().multiplyScalar(span * 0.09);

  const p1 = parentBottom.clone().lerp(childTop, 0.3).add(across);
  p1.y -= sag;
  const p2 = parentBottom.clone().lerp(childTop, 0.68).sub(across);
  p2.y -= sag * 0.65;
  const curve = new THREE.CatmullRomCurve3([parentBottom, p1, p2, childTop], false, "catmullrom", 0.5);
  const geometry = new THREE.TubeGeometry(curve, 28, Math.min(0.16, span * 0.012), 6, false);
  const material = new THREE.MeshStandardMaterial({
    color: colorHex ?? statusColor(childGroup.userData.status), transparent: true, opacity,
    metalness: 0.25, roughness: 0.55,
  });
  const mesh = new THREE.Mesh(geometry, material);
  // Same reason createSaggingCable exposes this (see its own docstring
  // below): lets a caller send a real "photon" traveling along this EXACT
  // hierarchy cable the moment real data genuinely moves along it (a host
  // finishing deployment, evidence reaching the case, ...) -- added
  // 2026-10-14 for Reconstruction View's data-flow visualization, reusing
  // this cable unchanged rather than drawing a second one.
  mesh.userData.cableCurve = curve;
  return mesh;
}

/**
 * A lateral relation line between two boxes that are NOT in a parent-child
 * hierarchy relationship -- an attacker->victim path (spec section 20) or an
 * evidence-source link (spec section 21). Bows upward so it visually reads
 * as a distinct cross-cutting overlay rather than another hierarchy cable.
 * Built as a thin tube (not a THREE.Line) because WebGL silently ignores
 * `linewidth` on most GPUs/drivers -- a hairline Line here would render as a
 * near-invisible 1px thread at overview camera distance; a tube gets real,
 * controllable on-screen thickness for the cost of one small extra mesh.
 */
export function createRelationLine(groupA, groupB, colorHex, { opacity = 0.85, bow = 6, radius = 0.18 } = {}) {
  const a = groupA.position.clone();
  const b = groupB.position.clone();
  const mid = a.clone().lerp(b, 0.5);
  mid.y += bow;
  const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
  const tubeGeo = new THREE.TubeGeometry(curve, 32, radius, 6, false);

  // Arrowhead at the B end, oriented along the curve's own tangent there --
  // makes the direction explicit (e.g. attacker -> target) instead of an
  // undifferentiated tube that reads the same read either way. Merged into
  // one geometry (not a second child object) so this stays a single Mesh:
  // every caller already treats createRelationLine's return value as one
  // disposable object with one .material to fade in/out.
  const tangent = curve.getTangentAt(1).normalize();
  const arrowLength = radius * 6;
  const arrowRadius = radius * 2.4;
  const coneGeo = new THREE.ConeGeometry(arrowRadius, arrowLength, 12);
  coneGeo.applyQuaternion(new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 1, 0), tangent));
  const tip = curve.getPointAt(1);
  const coneCenter = tip.clone().addScaledVector(tangent, -arrowLength / 2);
  coneGeo.translate(coneCenter.x, coneCenter.y, coneCenter.z);

  const geometry = mergeIndexedGeometries([tubeGeo, coneGeo]);
  tubeGeo.dispose();
  coneGeo.dispose();
  const material = new THREE.MeshBasicMaterial({ color: colorHex, transparent: true, opacity });
  const mesh = new THREE.Mesh(geometry, material);
  // Same reason createSaggingCable/createConnector expose this -- lets a
  // caller send a real photon along this exact arc (e.g. Reconstruction
  // View's attacker->target beat, 2026-10-14).
  mesh.userData.cableCurve = curve;
  return mesh;
}

/**
 * A natural-looking sagging cable between two arbitrary points -- NOT the
 * parent-above/child-below hierarchy createConnector() assumes, and
 * deliberately NOT an upward "highlighted path" arc like createRelationLine
 * (built for a transient, attention-grabbing event such as an attack).
 * Real-world wires/cables droop under gravity; this mirrors that, so a
 * PERSISTENT, always-on infrastructure link (a monitoring agent's real
 * connection to its manager, a real Modbus polling link, a C2 channel)
 * reads as "a real wire that's just there", not as a called-out event.
 * User's own correction (2026-10-13): the first version of these ambient
 * links reused createRelationLine's arc, which "no son correctos" -- this
 * is the fix, same visual philosophy as the reconstruction hierarchy
 * cables the user pointed to as the right reference.
 *
 * Exposes the real curve via `mesh.userData.cableCurve` so a caller can
 * animate a small "photon" traveling along the EXACT same path when real
 * data is observed flowing across this link (see live_attack.js's
 * spawnPhotonAlongCable) -- the cable itself is static; the photon is the
 * honest, event-driven signal that something real just crossed it.
 */
export function createSaggingCable(groupA, groupB, colorHex, { opacity = 0.75, radius = 0.05, sagFactor = 0.14 } = {}) {
  const a = groupA.position.clone();
  const b = groupB.position.clone();
  const span = Math.max(1, a.distanceTo(b));
  const sag = Math.max(0.6, span * sagFactor);
  const mid = a.clone().lerp(b, 0.5);
  mid.y -= sag;
  const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
  const tubeGeo = new THREE.TubeGeometry(curve, 32, radius, 6, false);

  const tangent = curve.getTangentAt(1).normalize();
  const arrowLength = radius * 6;
  const arrowRadius = radius * 2.4;
  const coneGeo = new THREE.ConeGeometry(arrowRadius, arrowLength, 12);
  coneGeo.applyQuaternion(new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 1, 0), tangent));
  const tip = curve.getPointAt(1);
  const coneCenter = tip.clone().addScaledVector(tangent, -arrowLength / 2);
  coneGeo.translate(coneCenter.x, coneCenter.y, coneCenter.z);

  const geometry = mergeIndexedGeometries([tubeGeo, coneGeo]);
  tubeGeo.dispose();
  coneGeo.dispose();
  const material = new THREE.MeshBasicMaterial({ color: colorHex, transparent: true, opacity });
  const mesh = new THREE.Mesh(geometry, material);
  mesh.userData.cableCurve = curve;
  return mesh;
}

/** A small floating HTML tag anchored at a fixed 3D point -- used to attach
 * real, short status text (e.g. a detection outcome) to a relation line
 * without inventing a whole new entity box for it. */
export function createFloatingLabel(position, html, className) {
  const el = document.createElement("div");
  el.className = `relation-label ${className}`;
  el.innerHTML = html;
  const obj = new CSS2DObject(el);
  obj.position.copy(position);
  return obj;
}

/**
 * A small glowing sphere that travels ONCE along a real cable's own curve
 * (`mesh.userData.cableCurve`, exposed by createConnector/createRelationLine/
 * createSaggingCable) -- the honest, event-driven signal that real data
 * genuinely just moved across that specific link, never a decorative,
 * continuously-looping effect. Shared implementation (2026-10-14, pulled out
 * of live_attack.js's own spawnPhotonAlongCable so Reconstruction View can
 * reuse the exact same mechanism instead of a second copy): `addObject`/
 * `removeObject` let each caller plug in its own scene-tracking (live_attack.js
 * passes monitorBridge directly; reconstruction.js passes its own track()/
 * untrack-and-dispose, since it never shares object-lifecycle state with
 * app.js's live mode).
 */
export function spawnPhoton(curve, colorHex, addObject, removeObject, { travelMs = 1100, reverse = false, radius = 0.22 } = {}) {
  if (!curve) return;
  const geometry = new THREE.SphereGeometry(radius, 10, 10);
  const material = new THREE.MeshBasicMaterial({ color: colorHex });
  const dot = new THREE.Mesh(geometry, material);
  dot.position.copy(curve.getPointAt(reverse ? 1 : 0));
  addObject(dot);
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / travelMs);
    dot.position.copy(curve.getPointAt(reverse ? 1 - t : t));
    if (t < 1) { requestAnimationFrame(step); return; }
    removeObject(dot);
  }
  step();
}
