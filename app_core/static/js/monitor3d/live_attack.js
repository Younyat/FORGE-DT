import * as THREE from "three";
import { createEntityBox, createRelationLine, createSaggingCable, createFloatingLabel, disposeEntity, setSelected, spawnPhoton, BOX_COLOR_DEFAULT, BOX_COLOR_ATTACKER } from "./entities.js";
import { applyRowLayout } from "./layout.js";
import { buildHostVisual } from "./host-visuals.js";
import { monitorBridge } from "./app.js";

// PlayStation-pad-style attack launcher: reuses the EXACT real endpoint
// (POST /api/hud/attack/execute) and attack_ids already used by the real
// Attack Lab dashboard (dashboard_especial.html) -- these 4 are its most-used
// attacks, in the requested priority order. No new attack-launching backend
// is introduced here, only a second real UI for the one that already exists.
// target_roles copied verbatim from each attack's own real definition
// (app_core/infrastructure/attack/catalog.py) -- the backend already
// enforces these (POST /execute returns 400 "target_role not allowed for
// this attack" otherwise); shown here too so a button for a role-incompatible
// target is visibly disabled BEFORE a click, rather than only failing after
// a confirm() dialog with a misleadingly-already-drawn arrow (real bug found
// and fixed 2026-10-05: File Modification against the PLC was always
// rejected server-side, but the arrow used to be drawn before that rejection
// was known).
// `severity` copied verbatim too (catalog.py's own severity="..." per
// attack -- LOW/MEDIUM/HIGH are the only 3 values that exist anywhere in
// the real catalog, confirmed by grep) -- this is "the system that governs
// the severity attacks produce" the user pointed to: the same field the
// real Attack Lab dashboard already surfaces per attack, not a new,
// invented scale.
const ATTACK_BUTTONS = [
  { key: "ping", label: "Ping / Recon", attack_id: "T1595_ACTIVE_SCANNING_ICMP_RECON", target_roles: ["victim", "monitor", "plc", "scada"], severity: "LOW" },
  { key: "access", label: "Unauthorized Access", attack_id: "T1110_001_SSH_PASSWORD_GUESSING", target_roles: ["victim", "scada"], severity: "MEDIUM" },
  { key: "file", label: "File Modification", attack_id: "T1565_001_STORED_DATA_MANIPULATION_FIM", target_roles: ["victim", "scada"], severity: "HIGH" },
  { key: "modbus", label: "Modbus Manipulation", attack_id: "T0831_MANIPULATION_OF_CONTROL_MODBUS", target_roles: ["plc", "scada"], severity: "HIGH" },
];
// Same palette already used elsewhere in this dashboard for these exact
// severity words (monitor3d.html's own --cyan/--amber/--red CSS vars).
const SEVERITY_COLOR = { LOW: 0x22d3ee, MEDIUM: 0xf59e0b, HIGH: 0xef4444 };
function severityColor(sev) { return SEVERITY_COLOR[sev] || SEVERITY_COLOR.HIGH; }

let selectedTarget = null; // {instance_id, name, role, ip}
let selectedTargetBox = null;

// ---------------------------------------------------------------------------
// Live Attack View: a dedicated, campaign-free mode showing ONLY the real
// scenario nodes (no campaign/repetition/case boxes), with a real-time feed
// of what's actually happening to them -- attacks (drawn as a red arc from
// attacker to target, exactly like the existing security-flow overlay, just
// transient and independent of any one campaign's focus state), node-level
// alerts (SIEM/IDS, floating label on the affected node), and forensic case
// creation (notification only, per explicit request -- no case box here).
// Polls GET /api/monitor3d/live-events?since=<iso>, a NEW incremental
// endpoint (monitor3d/service.py::get_live_attack_feed) -- everything else
// reuses existing, already-built pieces (createEntityBox, createRelationLine,
// createFloatingLabel, applyRowLayout, buildHostVisual, monitorBridge).
// ---------------------------------------------------------------------------

const ARROW_LIFETIME_MS = 12000;
const POLL_MS = 2500;

let active = false;
let pollTimer = null;
let sinceIso = null;
let savedState = null;
let nodeBoxes = new Map(); // instance_id -> group
let liveObjects = []; // node boxes, must be cleared on exit
let transientTimers = [];
let feedItems = []; // {id, kind, ts, title, detail, sev}
let feedIdSeq = 0;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export function isActive() {
  return active;
}

function findNodeByHostRef(hostRef) {
  if (!hostRef) return null;
  return nodeBoxes.get(hostRef.instance_id) || null;
}

async function fetchSnapshotOnce() {
  const r = await fetch("/api/monitor3d/snapshot", { cache: "no-store" });
  return r.json();
}

function buildNodesOnlyScene(hosts) {
  nodeBoxes.clear();
  const boxes = (hosts || []).map((h) => {
    const vitals = h.vitals || {};
    const statLines = [];
    if (vitals.cpu_usage_pct != null) statLines.push(`CPU ${vitals.cpu_usage_pct}%`);
    if (vitals.memory_usage_pct != null) statLines.push(`Mem ${vitals.memory_usage_pct}%`);
    if (vitals.disk_root_use_pct != null) statLines.push(`Disk ${vitals.disk_root_use_pct}%`);
    const box = createEntityBox({
      id: `livenode:${h.instance_id}`, kind: "host", title: h.name, subtitle: h.ip_floating || h.ip_private,
      status: h.status === "ACTIVE" ? "idle" : h.status, statusLabel: h.status === "ACTIVE" ? "online" : h.status,
      statLines, width: 10, height: 5.5, depth: 7, raw: h,
      boxColor: h.role === "attacker" ? BOX_COLOR_ATTACKER : BOX_COLOR_DEFAULT,
      visualModel: buildHostVisual(h.role, 10, 5.5, 7),
    });
    monitorBridge.addObject(box);
    liveObjects.push(box);
    nodeBoxes.set(h.instance_id, box);
    return box;
  });
  applyRowLayout(boxes, { y: 10, spacing: 13, maxPerRow: 5 });
  drawDefaultRelationships(boxes);
}

// Default, persistent (not transient) topology cables -- thin, always on,
// never waiting for a real attack/alert event. User's own request
// (2026-10-13), with a reference image of thin glowing arrows between node
// boxes. The exact relationships drawn are real, verified against this
// scenario's own config/code, never copied from the picture blindly:
//   - victim/scada(FUXA)/plc -> monitor: each of those 3 roles installs
//     `wazuh_agent`, which connects to the Wazuh MANAGER running on
//     `monitor` (level_c_orchestrator._TOOL_SCIENTIFIC_ORDER, phase 3/4
//     comments: "connects to Wazuh Manager (phase 1 done)") -- a real,
//     always-on monitoring relationship, not an attack path.
//   - attacker -> victim: `victim` is the only OTHER role that installs
//     `caldera_agent`, which connects to the Caldera C2 SERVER running on
//     `attack` (same table, phase 2/3: "connects to Caldera Server (phase 2
//     done)") -- a real adversary-emulation infrastructure link, separate
//     from any specific attack being launched.
//   - scada(FUXA) -> plc: FUXA's own real project file
//     (industrial-scenario/FUXA/fuxa_mi_proyecto_simple.json, device
//     "d_plc_tank") polls address "10.0.2.101:502" -- the PLC's real
//     Modbus TCP endpoint -- continuously, as part of normal HMI operation,
//     independent of any attack.
// Drawn with createSaggingCable (a real, natural-drooping wire -- the same
// visual philosophy as the reconstruction hierarchy's own cables, per the
// user's explicit correction 2026-10-13 that the first version's upward
// arc "no son correctos"), not createRelationLine's attention-grabbing arc
// (kept below, unchanged, for the structural "potential attack surface"
// lines, which are deliberately NOT meant to read as real live wiring).
//
//   - attacker -> {scada, plc, monitor}: kept as the original low-opacity
//     arc, meaning something DIFFERENT from the cables above -- not
//     "currently connected", but "a real, valid target per the attack
//     catalog" (every one of these 3 roles appears as a real
//     `target_roles` entry for at least one attack in attack/catalog.py;
//     `victim` is omitted here since it already has its own cable above).
const DEFAULT_RELATIONSHIPS = [
  { from: "victim", to: "monitor", color: 0x3b82f6 },
  { from: "scada", to: "monitor", color: 0x3b82f6 },
  { from: "plc", to: "monitor", color: 0x3b82f6 },
  { from: "attacker", to: "victim", color: 0x22d3ee },
  { from: "scada", to: "plc", color: 0xf59e0b },
];
const POTENTIAL_TARGET_ROLES = ["scada", "plc", "monitor"]; // victim excluded -- already has its own cable above

// role -> {cable mesh, color} for every REAL cable drawn, so a later real
// event (see spawnAlertLabel below) can animate a "photon" along the EXACT
// same curve instead of redrawing anything. Keyed "from->to" (both
// directions registered, same mesh/curve -- a cable's own direction is
// about the arrowhead, not about which way a photon can travel on it).
let relationshipCables = new Map();

function drawDefaultRelationships(boxes) {
  relationshipCables = new Map();
  const byRole = new Map();
  for (const box of boxes) {
    const role = box.userData.raw?.role;
    if (role && !byRole.has(role)) byRole.set(role, box); // first node of a role, if more than one ever exists
  }
  for (const { from, to, color } of DEFAULT_RELATIONSHIPS) {
    const a = byRole.get(from), b = byRole.get(to);
    if (!a || !b || a === b) continue;
    const cable = createSaggingCable(a, b, color, { opacity: 0.75, radius: 0.05 });
    monitorBridge.addObject(cable);
    liveObjects.push(cable);
    relationshipCables.set(`${from}->${to}`, { cable, color });
    relationshipCables.set(`${to}->${from}`, { cable, color });
  }
  const attacker = byRole.get("attacker");
  if (attacker) {
    for (const role of POTENTIAL_TARGET_ROLES) {
      const target = byRole.get(role);
      if (!target || target === attacker) continue;
      const line = createRelationLine(attacker, target, 0xef4444, { opacity: 0.3, bow: 2.5, radius: 0.04 });
      monitorBridge.addObject(line);
      liveObjects.push(line);
    }
  }
}

// A small glowing dot traveling along a real cable's own curve -- the
// honest, event-driven signal that real data was JUST observed crossing
// that link, as opposed to the cable itself (always drawn, whether or not
// anything is flowing right now). User's own words (2026-10-13): "si hay
// realmente info pasando de un nodo hacia otro, que el enlace empiece a
// mandar puntos como si fueran fotones". Never animated on a timer/loop --
// only ever spawned from a real event handler (see spawnAlertLabel).
const PHOTON_TRAVEL_MS = 1100;

// Shared implementation now lives in entities.js (spawnPhoton, 2026-10-14)
// so Reconstruction View's data-flow visualization reuses the exact same
// mechanism instead of a second copy -- behavior here is unchanged, just
// delegated: liveObjects still gets the dot for exit() to sweep up, same
// as before this refactor.
function spawnPhotonAlongCable(cableEntry, reverse = false) {
  if (!cableEntry) return;
  const curve = cableEntry.cable?.userData?.cableCurve;
  if (!curve) return;
  spawnPhoton(
    curve, cableEntry.color,
    (dot) => { monitorBridge.addObject(dot); liveObjects.push(dot); },
    (dot) => { monitorBridge.removeObject(dot); disposeEntity(dot); liveObjects = liveObjects.filter((o) => o !== dot); },
    { travelMs: PHOTON_TRAVEL_MS, reverse },
  );
}

function pushFeedItem(item) {
  feedItems.unshift({ id: ++feedIdSeq, ts: Date.now(), ...item });
  feedItems = feedItems.slice(0, 60);
  renderFeed();
}

function scheduleTransient(fn, ms) {
  const t = setTimeout(fn, ms);
  transientTimers.push(t);
}

// Shared by both attack sources this view can show: a real passive-detection
// event polled from attack_attestation.json (spawnAttackArrow, below -- only
// populated once a forensic case has been reconstructed around the attack,
// which can lag well behind the attack itself or never happen for an ad-hoc
// one), and an attack launched directly from this view's own pad
// (launchAttack, further down) -- which must show the arrow immediately
// rather than depend on that same case-reconstruction pipeline at all.
// Higher, slower arc than a plain static line: a small glowing projectile
// actually flies from attacker to target along a tall ballistic curve over
// MISSILE_DURATION_MS (not an instant pop-in, the previous behavior) --
// only once it "lands" does the persistent trail tube + label appear, same
// as a real missile's impact leaving a mark behind it.
const MISSILE_BOW = 22;
const MISSILE_DURATION_MS = 2000;

function spawnMissileProjectile(attackerBox, targetBox, colorHex, onArrive) {
  const a = attackerBox.position.clone();
  const b = targetBox.position.clone();
  const mid = a.clone().lerp(b, 0.5);
  mid.y += MISSILE_BOW;
  const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
  const geometry = new THREE.SphereGeometry(0.6, 12, 12);
  const material = new THREE.MeshBasicMaterial({ color: colorHex });
  const mesh = new THREE.Mesh(geometry, material);
  mesh.position.copy(a);
  monitorBridge.addObject(mesh);
  liveObjects.push(mesh); // so exit() mid-flight still cleans it up, same as every other live object here
  const t0 = performance.now();
  function step() {
    if (!active) return; // view was exited mid-flight -- liveObjects' own teardown in exit() handles removal
    const t = Math.min(1, (performance.now() - t0) / MISSILE_DURATION_MS);
    const ease = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2; // ease-in-out: accelerates off the launcher, decelerates into impact
    curve.getPointAt(ease, mesh.position);
    if (t < 1) {
      requestAnimationFrame(step);
    } else {
      monitorBridge.removeObject(mesh);
      disposeEntity(mesh);
      const idx = liveObjects.indexOf(mesh);
      if (idx !== -1) liveObjects.splice(idx, 1);
      onArrive?.();
    }
  }
  requestAnimationFrame(step);
}

function drawAttackArrow(attackerBox, targetBox, title, detailHtml, colorHex = 0xef4444) {
  if (!attackerBox || !targetBox || attackerBox === targetBox) return false;
  spawnMissileProjectile(attackerBox, targetBox, colorHex, () => {
    if (!active) return;
    const line = createRelationLine(attackerBox, targetBox, colorHex, { bow: MISSILE_BOW, radius: 0.22 });
    monitorBridge.addObject(line);
    const midpoint = attackerBox.position.clone().lerp(targetBox.position, 0.5);
    midpoint.y += MISSILE_BOW + 2.5;
    const label = createFloatingLabel(midpoint, `${esc(title)}<br>${detailHtml}`, "security");
    monitorBridge.addObject(label);
    scheduleTransient(() => {
      monitorBridge.removeObject(line); disposeEntity(line);
      monitorBridge.removeObject(label); disposeEntity(label);
    }, ARROW_LIFETIME_MS);
  });
  return true;
}

function findAttackerBox() {
  for (const box of nodeBoxes.values()) {
    if (box.userData.raw && box.userData.raw.role === "attacker") return box;
  }
  return null;
}

function spawnAttackArrow(ev) {
  const attackerBox = findNodeByHostRef(ev.attacker_host);
  const targetBox = findNodeByHostRef(ev.target_host);
  const title = `${ev.attack_name || "Attack"}${ev.mitre_technique ? ` (${ev.mitre_technique})` : ""}`;
  const drawn = attackerBox && targetBox
    ? drawAttackArrow(attackerBox, targetBox, title, `${esc(ev.attacker_host.name)} &rarr; ${esc(ev.target_host.name)}`)
    : false;
  pushFeedItem({
    kind: "attack", sev: "critical", title,
    detail: `${ev.attacker_host ? ev.attacker_host.name : ev.attacker_ip || "?"} &rarr; ${ev.target_host ? ev.target_host.name : ev.target_ip || "?"}`,
    raw: ev,
    resolved: drawn,
  });
}

function spawnAlertLabel(ev) {
  const targetBox = findNodeByHostRef(ev.target_host);
  if (targetBox) {
    const pos = targetBox.position.clone();
    pos.y += 6;
    const label = createFloatingLabel(pos, `${esc(ev.title || "Alert")}<br>${esc(ev.detail || "")}`, ev.severity === "critical" ? "security" : "evidence");
    monitorBridge.addObject(label);
    scheduleTransient(() => { monitorBridge.removeObject(label); disposeEntity(label); }, ARROW_LIFETIME_MS);
    // This alert is real data this node really sent, really received by the
    // Wazuh Manager on `monitor` over its own real wazuh_agent cable (see
    // drawDefaultRelationships) -- animate the photon traveling that exact
    // real path, honestly tied to a real event, never a decorative loop.
    const role = targetBox.userData.raw?.role;
    if (role) spawnPhotonAlongCable(relationshipCables.get(`${role}->monitor`));
  }
  pushFeedItem({ kind: "alert", sev: ev.severity || "warning", title: ev.title || "Alert", detail: ev.detail || "", raw: ev, resolved: !!targetBox });
}

function spawnCaseNotification(ev) {
  pushFeedItem({ kind: "case", sev: "info", title: "Forensic case created", detail: ev.case_id, raw: ev, resolved: true });
}

// A real fault_injection apply/revert (app_core/infrastructure/fault_injection),
// polled from the same /api/monitor3d/live-events feed as attacks/alerts
// (monitor3d.service.get_live_attack_feed's new "faults" key, sourced from
// forensic_twin's event store -- GENUINE lifecycle events, not an attack).
// Deliberately NOT an arrow/missile: a fault has only one real endpoint
// (the node it was applied to), no attacker side -- shown instead as an
// expanding ring local to that node, color-coded apply (cyan, info) vs.
// revert (green, cleared), distinct from the red attack missiles/arcs so
// the two are never visually confused.
const FAULT_RING_MS = 1600;
const FAULT_APPLY_COLOR = 0x38bdf8;
const FAULT_REVERT_COLOR = 0x34d399;

function spawnFaultPulse(targetBox, ev) {
  const color = ev.phase === "reverted" ? FAULT_REVERT_COLOR : FAULT_APPLY_COLOR;
  if (targetBox) {
    const geometry = new THREE.RingGeometry(3, 3.6, 32);
    const material = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.85, side: THREE.DoubleSide });
    const ring = new THREE.Mesh(geometry, material);
    ring.rotation.x = -Math.PI / 2;
    ring.position.copy(targetBox.position);
    ring.position.y += 0.2;
    monitorBridge.addObject(ring);
    liveObjects.push(ring);
    const t0 = performance.now();
    function step() {
      if (!active) return;
      const t = Math.min(1, (performance.now() - t0) / FAULT_RING_MS);
      const scale = 1 + t * 3;
      ring.scale.set(scale, scale, scale);
      material.opacity = 0.85 * (1 - t);
      if (t < 1) {
        requestAnimationFrame(step);
      } else {
        monitorBridge.removeObject(ring);
        disposeEntity(ring);
        const idx = liveObjects.indexOf(ring);
        if (idx !== -1) liveObjects.splice(idx, 1);
      }
    }
    requestAnimationFrame(step);
    const pos = targetBox.position.clone();
    pos.y += 6;
    const label = createFloatingLabel(pos, `${esc(ev.fault_id || "fault")} ${esc(ev.phase)}<br>${esc(ev.evidence || "")}`, "fault");
    monitorBridge.addObject(label);
    scheduleTransient(() => { monitorBridge.removeObject(label); disposeEntity(label); }, ARROW_LIFETIME_MS);
  }
  pushFeedItem({
    kind: "fault_injection", sev: "info",
    title: `${ev.fault_id || "fault"}: ${ev.phase}`,
    detail: `${esc((targetBox && targetBox.userData.title) || ev.node_id || "?")} -- ${esc(ev.evidence || "")}`,
    raw: ev, resolved: !!targetBox,
  });
}

function spawnFaultEvent(ev) {
  const targetBox = findNodeByHostRef(ev.target_host);
  spawnFaultPulse(targetBox, ev);
}

async function pollOnce() {
  try {
    const r = await fetch(`/api/monitor3d/live-events?since=${encodeURIComponent(sinceIso)}`, { cache: "no-store" });
    const data = await r.json();
    sinceIso = data.generated_at || sinceIso;
    (data.attacks || []).forEach(spawnAttackArrow);
    (data.alerts || []).forEach(spawnAlertLabel);
    (data.faults || []).forEach(spawnFaultEvent);
    (data.new_cases || []).forEach(spawnCaseNotification);
  } catch (e) { /* transient network hiccup — next tick retries */ }
}

function schedulePoll() {
  pollTimer = setTimeout(async () => { if (active) { await pollOnce(); schedulePoll(); } }, POLL_MS);
}

function renderFeed() {
  const el = document.getElementById("live-attack-feed-list");
  if (!el) return;
  if (!feedItems.length) {
    el.innerHTML = `<div class="detail-empty">No events yet — waiting for real attacks, alerts, or cases.</div>`;
    return;
  }
  const sevColor = { critical: "#ef4444", warning: "#f59e0b", info: "#38bdf8" };
  el.innerHTML = feedItems.map((it) => {
    const time = new Date(it.ts).toLocaleTimeString();
    const color = sevColor[it.sev] || "#94a3b8";
    return `<div class="live-feed-item" data-feed-id="${it.id}" style="border-left:3px solid ${color}">
      <div class="live-feed-time">${time} &middot; ${it.kind}${it.resolved === false ? " (node not resolved)" : ""}</div>
      <div class="live-feed-title">${esc(it.title)}</div>
      <div class="live-feed-detail">${it.detail}</div>
    </div>`;
  }).join("");
}

function showFeedDetail(id) {
  const item = feedItems.find((it) => it.id === Number(id));
  if (!item) return;
  const body = document.getElementById("detail-body");
  if (!body) return;
  body.innerHTML = `<div class="kv-row"><span class="k">Kind</span><span class="v">${esc(item.kind)}</span></div>
    <div class="kv-row"><span class="k">Time</span><span class="v">${new Date(item.ts).toLocaleString()}</span></div>
    <pre style="white-space:pre-wrap;font-size:11px;color:#93a5b8;margin-top:8px">${esc(JSON.stringify(item.raw, null, 2))}</pre>`;
}

// Called from app.js's onSelect when a node box is clicked while this mode
// is active -- selects that node as the attack target (visually highlighted
// via the same setSelected() the normal drill-down selection already uses)
// and enables the attack pad buttons.
export function handleSelect(hit) {
  if (!active || hit.kind !== "host") return;
  const group = nodeBoxes.get(hit.raw.instance_id);
  if (!group) return;
  if (selectedTargetBox && selectedTargetBox !== group) setSelected(selectedTargetBox, false);
  selectedTargetBox = group;
  setSelected(group, true);
  selectedTarget = {
    instance_id: hit.raw.instance_id, name: hit.raw.name, role: hit.raw.role,
    ip: hit.raw.ip_floating || hit.raw.ip_private,
  };
  renderAttackPad();
}

function renderAttackPad() {
  const label = document.getElementById("live-attack-target-label");
  const pad = document.getElementById("live-attack-pad");
  if (!label || !pad) return;
  const hasIp = !!(selectedTarget && selectedTarget.ip);
  label.textContent = selectedTarget
    ? `Target: ${selectedTarget.name}${hasIp ? ` (${selectedTarget.ip})` : " — no IP, cannot launch"}`
    : "Click a machine box to select it as target";
  pad.querySelectorAll("button").forEach((b) => {
    // The fireworks button lives in this same grid for identical circular
    // sizing, but it picks its own targets automatically -- it's never
    // gated by selectedTarget the way the 4 per-target attack buttons are.
    if (b.id === "btn-fireworks") return;
    const def = ATTACK_BUTTONS.find((d) => d.key === b.dataset.attackKey);
    const roleOk = !hasIp || !def || !selectedTarget.role || def.target_roles.includes(selectedTarget.role);
    b.disabled = !hasIp || !roleOk;
    b.title = (hasIp && def && !roleOk)
      ? `Not valid against role "${selectedTarget.role}" -- this attack only targets: ${def.target_roles.join(", ")}`
      : (b.dataset.originalTitle || "");
  });
}

// Shared by both the pad (one attack against the selected target) and the
// fireworks barrage (several attacks, each against its own target) -- fires
// the real request, and only draws the arrow once the backend has actually
// ACCEPTED it (res.ok reflects the response headers, sent as soon as the
// real attack script starts streaming -- a validation rejection, e.g. a
// target_role the attack_id doesn't allow, like trying File Modification
// against the PLC, returns a non-2xx BEFORE any script runs, with no stream
// body at all). Drawing it unconditionally on confirm() -- the previous
// behavior -- showed a real-looking arrow for an attack that was never
// actually launched, confirmed live: PLC + T1565_001_STORED_DATA_MANIPULATION_FIM
// really does get rejected (HTTP 400, "target_role not allowed for this
// attack" -- that attack's real target_roles are only victim/scada, never
// plc). The arrow color reflects the attack's own real severity
// (LOW/MEDIUM/HIGH, catalog.py's own field).
async function executeAttack(def, targetBox, target) {
  const attackerBox = findAttackerBox();
  pushFeedItem({ kind: "attack_launch", sev: "critical", title: `Launching: ${def.label}`, detail: `target ${esc(target.name)} (${esc(target.ip)})`, raw: def, resolved: true });
  try {
    const res = await fetch("/api/hud/attack/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        attack_id: def.attack_id, target_ip: target.ip, target_role: target.role || "",
        attacker_ip: "", target_os: "", case_dir: "", parameters: {},
      }),
    });
    if (res.ok) {
      drawAttackArrow(attackerBox, targetBox, `"${def.label}" attack launching`, `${esc(attackerBox?.userData.title || "attacker")} &rarr; ${esc(target.name)} &middot; severity: ${esc(def.severity)}`, severityColor(def.severity));
    }
    let lastLine = "";
    if (res.body) {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        decoder.decode(value, { stream: true }).split("\n").forEach((line) => {
          if (line.startsWith("data:")) lastLine = line.replace("data:", "").trim();
        });
      }
    }
    pushFeedItem({
      kind: "attack_launch", sev: res.ok ? "info" : "critical",
      title: `${def.label}: ${res.ok ? "completed" : "failed"}`,
      detail: esc(lastLine || (res.ok ? "no output" : `HTTP ${res.status}`)),
      raw: {}, resolved: true,
    });
  } catch (e) {
    pushFeedItem({ kind: "attack_launch", sev: "critical", title: `${def.label}: request failed`, detail: esc(e.message), raw: {}, resolved: true });
  }
}

async function launchAttack(def) {
  if (!selectedTarget || !selectedTarget.ip) return;
  const confirmed = window.confirm(
    `Launch REAL attack "${def.label}" against ${selectedTarget.name} (${selectedTarget.ip})?\n\n` +
    `This executes for real via the platform's Attack Lab backend against the live scenario VM.`
  );
  if (!confirmed) return;
  await executeAttack(def, selectedTargetBox, selectedTarget);
}

// "Fireworks Barrage" -- one of each of the 4 real attacks above, each
// against a different real compatible node, fired in a staggered sequence
// (not all at once) so arrows keep lighting up one after another for a few
// seconds, each colored by that attack's own real severity -- the visual
// the user asked for, built entirely out of the same real, sanctioned
// attack catalog as every other button here (no new attack-launching
// backend, no fabricated effect).
function pickFireworksTargets() {
  const attackerBox = findAttackerBox();
  const candidates = Array.from(nodeBoxes.entries()).filter(([, box]) => box !== attackerBox);
  const used = new Set();
  const picks = [];
  for (const def of ATTACK_BUTTONS) {
    const compatible = candidates.filter(([, box]) => def.target_roles.includes(box.userData.raw.role));
    if (!compatible.length) continue;
    const fresh = compatible.filter(([id]) => !used.has(id));
    const pool = fresh.length ? fresh : compatible;
    const [id, box] = pool[Math.floor(Math.random() * pool.length)];
    used.add(id);
    picks.push({ def, targetBox: box, target: { instance_id: id, name: box.userData.title, role: box.userData.raw.role, ip: box.userData.raw.ip_floating || box.userData.raw.ip_private } });
  }
  return picks;
}

async function launchFireworks() {
  const picks = pickFireworksTargets();
  const statusEl = document.getElementById("fireworks-status");
  if (!picks.length) {
    if (statusEl) statusEl.textContent = "No compatible real targets found in this scene.";
    return;
  }
  const summary = picks.map((p) => `- ${p.def.label} (${p.def.severity}) -> ${p.target.name}`).join("\n");
  const confirmed = window.confirm(
    `Launch a barrage of ${picks.length} REAL attacks, one after another over a few seconds, each against a different real node?\n\n${summary}\n\n` +
    `This executes for real via the platform's Attack Lab backend against the live scenario VMs.`
  );
  if (!confirmed) return;
  const btn = document.getElementById("btn-fireworks");
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = `Launching ${picks.length} attacks...`;
  picks.forEach((p, i) => {
    scheduleTransient(() => executeAttack(p.def, p.targetBox, p.target), i * 700);
  });
  scheduleTransient(() => {
    if (btn) btn.disabled = false;
    if (statusEl) statusEl.textContent = "";
  }, picks.length * 700 + 2000);
}

function wirePad() {
  document.getElementById("live-attack-pad").querySelectorAll("button").forEach((btn) => {
    if (btn.id === "btn-fireworks") return; // wired separately in enter(), picks its own targets
    if (btn.dataset.originalTitle === undefined) btn.dataset.originalTitle = btn.title;
    btn.onclick = () => {
      const def = ATTACK_BUTTONS.find((d) => d.key === btn.dataset.attackKey);
      if (def) launchAttack(def);
    };
  });
}

export async function enter() {
  if (active) return;
  active = true;
  sinceIso = new Date().toISOString();
  savedState = monitorBridge.getState();
  monitorBridge.stopLivePolling();
  monitorBridge.clearLiveScene();
  monitorBridge.setConnStatus("live attack view · loading nodes…");
  feedItems = [];
  selectedTarget = null;
  selectedTargetBox = null;
  renderFeed();
  wirePad();
  renderAttackPad();
  const fireworksBtn = document.getElementById("btn-fireworks");
  if (fireworksBtn) fireworksBtn.onclick = launchFireworks; // .onclick, not addEventListener -- idempotent across repeated enter() calls, same reasoning as wirePad()
  document.getElementById("live-attack-panel").hidden = false;
  document.getElementById("live-sources-panel").hidden = true;
  document.getElementById("live-attack-feed-list").addEventListener("click", (ev) => {
    const row = ev.target.closest("[data-feed-id]");
    if (row) showFeedDetail(row.dataset.feedId);
  });
  try {
    const snap = await fetchSnapshotOnce();
    buildNodesOnlyScene(snap.campaign?.hosts || []);
    monitorBridge.setConnStatus(`live attack view · ${nodeBoxes.size} node(s)`);
  } catch (e) {
    monitorBridge.setConnStatus("live attack view · failed to load nodes", { error: true });
  }
  schedulePoll();
}

export function exit() {
  if (!active) return;
  active = false;
  clearTimeout(pollTimer);
  transientTimers.forEach(clearTimeout);
  transientTimers = [];
  for (const obj of liveObjects) { monitorBridge.removeObject(obj); disposeEntity(obj); }
  liveObjects = [];
  nodeBoxes.clear();
  relationshipCables = new Map();
  selectedTarget = null;
  selectedTargetBox = null;
  document.getElementById("live-attack-panel").hidden = true;
  document.getElementById("live-sources-panel").hidden = false;
  if (savedState) monitorBridge.setState(savedState);
  monitorBridge.rebuildScene();
  monitorBridge.startLivePolling();
}

export function getAllRenderedGroups() {
  return liveObjects;
}
