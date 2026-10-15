import { createScene } from "./scene.js";
import { createEntityBox, setSelected, setDimmed, createConnector, createRelationLine, createFloatingLabel, disposeEntity, statusColor, BOX_COLOR_DEFAULT, BOX_COLOR_ATTACKER } from "./entities.js";
import { applyRowLayout } from "./layout.js";
import { attachInteraction } from "./interaction.js";
import { startPolling, stopPolling, fetchHostVitals, fetchRepetitionDetail } from "./api.js";
import * as reconstruction from "./reconstruction.js";
import * as liveAttack from "./live_attack.js";
import * as digitalTwin from "./digital_twin_view.js";
import { buildHostVisual } from "./host-visuals.js";
import { buildCaseVisual } from "./case-visuals.js";
import { renderPhaseTimelineHtml } from "./phase_timeline.js";

const viewport = document.getElementById("viewport");
const three = createScene(viewport);

let snapshot = null; // campaign object
let entityGroups = [];
let ghostShells = []; // faint ancestor-context boxes, not interactive
let connectors = [];
let relationObjects = []; // security-flow / evidence-link overlay lines + labels
// Each Level C repetition launches its own distinct Level B job/case (verified:
// 10 different level_b_job_id values across a real 10-rep campaign) -- so the
// Case box can't just always show snapshot.case (the campaign's current/last
// repetition). When the user clicks a specific repetition, this holds THAT
// repetition's own resolved case/level_b bundle so the Case box (and the
// relation overlays, which read the same attack/detection/acquisition data)
// reflect what was actually clicked instead of staying frozen. Cleared
// whenever the focus repetition itself is re-selected, or the job changes.
let repFocusOverride = null; // { repetition_number, case, level_b, snapshot_infrastructure } | null
let selectedId = null;
let drilledHostId = null;
let drilledCase = false; // the campaign has at most one case, so a boolean is enough
let drilledCampaign = false; // Level C drill-down -- also just one campaign focused at a time

// Wired up further down (once `reconstruction` is fully usable) to fall back
// to reconstruction's own groups while it owns the viewport -- see the
// `three.setEntities(...)` call near the bottom of this file.

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmt(v) { return v === null || v === undefined || v === "" ? "—" : String(v); }
function fmtElapsed(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  seconds = Math.floor(seconds);
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60), s = seconds % 60;
  return h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
}
function fmtBytes(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(bytes), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}
function badge(status, label) {
  const s = String(status || "unknown").toLowerCase();
  return `<span class="badge b-${esc(s)}">${esc(label || status || "unknown")}</span>`;
}
// Real alert severity, color-coded for a non-specialist reading at a
// glance -- the generic `.badge`/`b-*` CSS classes don't cover severity
// words (critical/high/medium/low), so this inlines its own colors instead
// of silently falling back to no color.
const SEVERITY_COLORS = { critical: "var(--red)", high: "var(--red)", medium: "var(--amber)", low: "var(--cyan)" };
function severityBadge(sev) {
  const s = String(sev || "unknown").toLowerCase();
  const color = SEVERITY_COLORS[s] || "var(--text-dim)";
  return `<span style="display:inline-block;padding:1px 9px;border-radius:999px;font-size:10px;font-weight:700;text-transform:uppercase;color:${color};border:1px solid ${color};">${esc(s)}</span>`;
}
function bar(pct) {
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  const cls = p >= 90 ? "crit" : p >= 75 ? "warn" : "";
  return `<div class="bar-track"><div class="bar-fill ${cls}" style="width:${p}%"></div></div>`;
}

// ---------------------------------------------------------------------
// Static description of the real backend modules this scene fuses --
// architecture facts, not live-changing values, so a static list is
// honest here (each one really is read live on every poll).
// ---------------------------------------------------------------------
// Each source is also a real visual filter/correlation layer (spec section
// 15): `match` decides, for any box actually in the scene right now,
// whether it belongs to that data domain. Selecting one dims (not hides --
// section 37: context must be preserved) everything that doesn't match.
const DATA_SOURCES = [
  { name: "Campaign execution engine", desc: "level_c_orchestrator — real phases & repetitions", match: (g) => ["campaign", "repetition", "stage"].includes(g.userData.kind) },
  { name: "Case metadata & manifest", desc: "campaign_repetitions + forensics manifest/custody", match: (g) => g.userData.kind === "case" },
  { name: "Infrastructure inventory", desc: "node_health — live OpenStack node list", match: (g) => g.userData.kind === "host" },
  { name: "Host telemetry", desc: "SSH probe — CPU, memory, disk, network", match: (g) => g.userData.kind === "telemetry" },
  { name: "Tool installation status", desc: "tools-installer state files", match: (g) => g.userData.kind === "tool" },
  { name: "Time synchronization", desc: "node_health clock-offset measurements", match: (g) => g.userData.kind === "telemetry" && g.userData.title === "Clock" },
  { name: "Preservation & acquisition", desc: "Level B acquisition results (memory/disk/net/OT)", match: (g) => g.userData.kind === "evidence" },
  { name: "Case integrity & custody", desc: "manifest hash re-verified live, custody chain", match: (g) => g.userData.kind === "case" },
  { name: "Host activity (derived)", desc: "job phase + attack attestation + pipeline events", match: (g) => g.userData.kind === "host" && !["idle", "unknown", undefined].includes(g.userData.status) },
];

let activeSourceIndex = null;

document.getElementById("sources-list").innerHTML = DATA_SOURCES.map(
  ({ name, desc }, i) => `<div class="src-item" data-idx="${i}"><span class="src-dot"></span><div><div class="src-name">${esc(name)}</div><div class="src-desc">${esc(desc)}</div></div></div>`
).join("");

document.querySelectorAll("#sources-list .src-item").forEach((el) => {
  el.addEventListener("click", () => {
    const idx = Number(el.dataset.idx);
    activeSourceIndex = activeSourceIndex === idx ? null : idx;
    document.querySelectorAll("#sources-list .src-item").forEach((e2, i2) => e2.classList.toggle("active", i2 === activeSourceIndex));
    refreshVisualState();
  });
});

function refreshVisualState() {
  const filter = activeSourceIndex !== null ? DATA_SOURCES[activeSourceIndex].match : null;
  entityGroups.forEach((g) => {
    setSelected(g, g.userData.id === selectedId);
    setDimmed(g, !!filter && !filter(g));
  });
}

// ---------------------------------------------------------------------
// Relationship overlays (spec sections 20/21): cross-cutting lines that
// don't follow the Campaign->Case->Host hierarchy -- an attacker->victim
// event path with its real detection outcome, and a case->source-host
// acquisition link. Both are gated on real level_b data (attack.target_node)
// and only ever drawn in the Overview scene, since that's the only level
// where attacker/victim/case boxes are simultaneously visible. Off by
// default -- the user explicitly activates a layer, per the spec wording.
// ---------------------------------------------------------------------
const RELATION_LAYERS = [
  { id: "security", name: "Security flow", desc: "Attacker → victim path, with the real detection/alert outcome" },
  { id: "evidence", name: "Evidence source link", desc: "Case → the specific host it was acquired from" },
];
let securityFlowActive = false;
let evidenceLinkActive = false;

document.getElementById("layers-list").innerHTML = RELATION_LAYERS.map(
  ({ id, name, desc }) => `<label class="layer-toggle"><input type="checkbox" data-layer="${id}"><div><div class="lt-name">${esc(name)}</div><div class="lt-desc">${esc(desc)}</div></div></label>`
).join("");

document.querySelectorAll("#layers-list input[data-layer]").forEach((el) => {
  el.addEventListener("change", () => {
    if (el.dataset.layer === "security") securityFlowActive = el.checked;
    if (el.dataset.layer === "evidence") evidenceLinkActive = el.checked;
    rebuildScene();
  });
});

function addRelation(obj) {
  three.scene.add(obj);
  relationObjects.push(obj);
}

function detectionLabelText(detection) {
  if (!detection) return null;
  if (detection.outcome === "detected") {
    const rule = detection.trigger_alert_rule ? `: ${esc(detection.trigger_alert_rule)}` : "";
    const sev = detection.trigger_alert_severity ? ` (${esc(detection.trigger_alert_severity)})` : "";
    return `Alert${rule}${sev}`;
  }
  if (detection.outcome === "never_detected_stream_silent") return "No alert — detection stream silent";
  if (detection.outcome === "never_detected_exhausted_attempts") return "No alert — attempts exhausted";
  if (detection.outcome === "never_detected") return "No alert recorded yet";
  return null;
}

// Draws the two relation overlays into the Overview scene, using only
// fields already confirmed real (attack.target_node identifies the actual
// victim host; host.role === "attacker" identifies the attacker box --
// the same fields buildHostEvidenceBoxes() already relies on). No target,
// no attacker box, or no acquisition data all mean: draw nothing.
function renderRelationOverlays(hostBoxes, caseBox, levelB) {
  const attack = (levelB || {}).attack;
  if (!attack || !attack.target_node) return;
  const targetBox = hostBoxes.find((b) => b.userData.raw?.name === attack.target_node);
  if (!targetBox) return;

  if (securityFlowActive) {
    const attackerBox = hostBoxes.find((b) => b.userData.raw?.role === "attacker");
    if (attackerBox && attackerBox !== targetBox) {
      addRelation(createRelationLine(attackerBox, targetBox, 0xef4444, { bow: 8, radius: 0.22 }));
      const detection = (levelB || {}).detection;
      const midpoint = attackerBox.position.clone().lerp(targetBox.position, 0.5);
      midpoint.y += 10.5; // above the tube's own peak (bow: 8), so the label reads as an annotation on the path, not a cap sitting on top of it
      const detectionText = detectionLabelText(detection);
      const html = `${esc(attack.attack_name || "Attack")}${attack.protocol ? ` (${esc(attack.protocol)})` : ""}${detectionText ? `<br>${detectionText}` : ""}`;
      addRelation(createFloatingLabel(midpoint, html, "security"));
    }
  }

  if (evidenceLinkActive && caseBox) {
    const acquisition = (levelB || {}).acquisition;
    if (acquisition) {
      addRelation(createRelationLine(caseBox, targetBox, 0x6366f1, { bow: 3, radius: 0.16 }));
      const midpoint = caseBox.position.clone().lerp(targetBox.position, 0.5);
      midpoint.y += 5;
      addRelation(createFloatingLabel(midpoint, `Acquired from ${esc(attack.target_node)}`, "evidence"));
    }
  }
}

// ---------------------------------------------------------------------
// Scene assembly. Two levels, matching the reference design's drill-down
// model: "overview" (Campaign -> Case -> Hosts, connected by cables, always
// the entry point) and "host" (double-click a host to drill into it -- it
// is rendered as one large glass box with its real tools as smaller boxes
// positioned INSIDE that box's own volume, visible through its transparent
// walls, rather than dangling below on a cable).
// ---------------------------------------------------------------------

function clearScene() {
  for (const g of entityGroups) { three.scene.remove(g); disposeEntity(g); }
  for (const g of ghostShells) { three.scene.remove(g); disposeEntity(g); }
  for (const c of connectors) { three.scene.remove(c); c.geometry.dispose(); c.material.dispose(); }
  for (const o of relationObjects) { three.scene.remove(o); if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); }
  entityGroups = [];
  ghostShells = [];
  connectors = [];
  relationObjects = [];
}

function addConnector(parent, child) {
  const line = createConnector(parent, child);
  three.scene.add(line);
  connectors.push(line);
}

// Every box the camera should account for when framing the current level --
// real, interactive boxes plus the faint ghost shells kept around for
// orientation, which are deliberately NOT in entityGroups (not clickable/
// raycast targets) but still need to be included so the camera fit doesn't
// crop them.
function allVisibleGroups() {
  return [...entityGroups, ...ghostShells];
}

// A faint, non-interactive outline of an ancestor level, kept visible while
// drilled into one of its descendants ("parent context must remain visible
// as a transparent shell" -- never added to entityGroups, so it's inert for
// clicks/raycasting and only ever built from real snapshot data already on
// hand, never fabricated.
function addGhostShell({ id, kind, title, subtitle, width, height, depth, boxColor }) {
  const box = createEntityBox({ id, kind, title, subtitle, status: "unknown", statusLabel: "", width, height, depth, boxColor, ghost: true });
  box.position.set(0, 0, 0);
  three.scene.add(box);
  ghostShells.push(box);
  return box;
}

// Real per-host metrics already fetched for the side panel, surfaced
// directly on the box itself too ("more metrics around the scenario").
// `compact` trims it to fit the smaller overview-mode card.
function hostStatLines(h, { compact = false } = {}) {
  const vitals = h.vitals || {};
  const lines = [];
  if (vitals.cpu_usage_pct !== undefined && vitals.cpu_usage_pct !== null) lines.push(`CPU ${vitals.cpu_usage_pct}%`);
  if (vitals.memory_usage_pct !== undefined && vitals.memory_usage_pct !== null) lines.push(`Mem ${vitals.memory_usage_pct}%`);
  if (vitals.disk_root_use_pct !== undefined && vitals.disk_root_use_pct !== null) lines.push(`Disk ${vitals.disk_root_use_pct}%`);
  if (!compact) {
    if (h.clock_offset_ms !== undefined && h.clock_offset_ms !== null) lines.push(`Clock ${h.clock_offset_ms}ms`);
    if (vitals.network) lines.push(`Net ↓${fmtBytes(vitals.network.rx_bytes)} ↑${fmtBytes(vitals.network.tx_bytes)}`);
  }
  lines.push(`${(h.tools || []).length} tool(s)`);
  return lines;
}

// Each Level C repetition destroys and redeploys every VM from scratch, so a
// past repetition's own IP/instance_id/tool-inventory genuinely differ from
// today's live infrastructure -- they are NOT the same machine, just the
// same named role. campaign_repetitions already captures exactly this per
// repetition in snapshot_infrastructure.instances (real ip_private/
// ip_floating/status/tools recorded at that repetition's own snapshot time),
// so a historical repetition's host card is built from THAT record instead
// of reusing today's live node_health reading, which would just repeat the
// current machine's data under a different rep number.
function hostInfraForRepetition(hostName, snapshotInfrastructure) {
  return (snapshotInfrastructure?.instances || []).find((i) => i.name === hostName) || null;
}

// Real completion fraction as a 0-100 number for the progress ring --
// null (no ring drawn) when there's nothing to divide by, never a fake 0.
function completionPct(items, doneTest) {
  if (!items || !items.length) return null;
  return Math.round((items.filter(doneTest).length / items.length) * 100);
}

function renderOverview() {
  // Defaults to the campaign snapshot's own focus repetition; overridden only
  // when the user has explicitly clicked a different repetition box.
  const focusRepNum = repFocusOverride?.repetition_number ?? snapshot.focus_repetition;
  const focusCase = repFocusOverride ? repFocusOverride.case : snapshot.case;
  const focusLevelB = repFocusOverride ? repFocusOverride.level_b : snapshot.level_b;

  const stages = snapshot.stages || [];
  const campaignBox = createEntityBox({
    id: `campaign:${snapshot.job_id}`, kind: "campaign", title: snapshot.job_id,
    subtitle: `Repetition ${snapshot.focus_repetition}/${snapshot.total_repetitions}`,
    status: snapshot.is_live ? "running" : snapshot.status, statusLabel: snapshot.is_live ? "running" : snapshot.status,
    statLines: [fmtElapsed(snapshot.total_elapsed_seconds), `${stages.filter((s) => s.status === "completed").length}/${stages.length} stages`],
    ringPct: completionPct(stages, (s) => s.status === "completed"),
    width: 14, height: 7, depth: 10, raw: snapshot,
  });
  campaignBox.position.set(0, 26, 0);
  three.scene.add(campaignBox);
  entityGroups.push(campaignBox);

  // Level C repetitions -- the campaign's own outer loop (up to 10 runs of
  // destroy/deploy/attack/detect), one small box per repetition, colored by
  // its real status (not the blue/red identity scheme, since here status
  // IS the thing worth seeing at a glance across all of them). A 1-rep
  // campaign has nothing to show here, so the row is skipped.
  const repetitions = snapshot.repetitions || [];
  let focusRepBox = null;
  if (repetitions.length > 1) {
    const repBoxes = repetitions.map((r) => {
      const box = createEntityBox({
        id: `rep:${r.repetition_number}`, kind: "repetition", title: `Rep ${r.repetition_number}`,
        subtitle: r.is_focus ? "current" : null,
        status: r.status, statusLabel: r.status,
        statLines: [], width: 4.5, height: 3.5, depth: 3.5, raw: r,
        boxColor: statusColor(r.status),
      });
      entityGroups.push(box);
      three.scene.add(box);
      addConnector(campaignBox, box);
      if (r.is_focus) focusRepBox = box;
      return box;
    });
    applyRowLayout(repBoxes, { y: 18, spacing: 6, maxPerRow: 10 });
  }

  // Case sits BELOW the hosts, not above them -- matches the real
  // chronological order this whole hierarchy otherwise reads top-to-bottom
  // (scenario/campaign created first, then machines, then only once an
  // attack is detected does a case get created) and stops its cables from
  // crossing back up through the host row to reach it.
  let caseBox = null;
  if (focusCase) {
    const integ = focusCase.integrity || {};
    const evidenceSteps = focusCase.evidence_pipeline || [];
    caseBox = createEntityBox({
      id: `case:${focusCase.case_id}`, kind: "case", title: focusCase.case_id,
      // Always names which repetition this case belongs to -- each repetition
      // has its own independent case/seal status, so without this label a
      // sealed vs. unsealed badge reads as unexplained rather than as "this
      // particular repetition's case".
      subtitle: `${focusCase.case_real_name} · Rep ${focusRepNum}`,
      status: integ.case_sealed ? "completed" : "pending", statusLabel: integ.case_sealed ? "sealed" : "unsealed",
      statLines: [`${evidenceSteps.filter((s) => s.status === "completed").length}/${evidenceSteps.length} evidence steps`, `${fmt(integ.artifacts_with_hash)}/${fmt(integ.artifacts_total)} artifacts`],
      ringPct: completionPct(evidenceSteps, (s) => s.status === "completed"),
      width: 12, height: 6, depth: 8, raw: focusCase,
      visualModel: buildCaseVisual(12, 6, 8),
    });
    caseBox.position.set(0, -6, 0);
    three.scene.add(caseBox);
    entityGroups.push(caseBox);
    // Connected below, once the host boxes exist -- one real cable per
    // host straight into the case (evidence from all 5 machines feeding
    // the same case), not a single case<-repetition link.
  }

  // Role (attacker/victim/plc/...) is stable scenario topology, so it's
  // genuinely correct for it not to change. Everything else that actually
  // is repetition-specific -- IP, instance status, tool inventory -- is
  // swapped to that repetition's own captured infrastructure snapshot when
  // one is focused, instead of silently repeating today's live reading
  // under a different "Rep N" label.
  const hosts = snapshot.hosts || [];
  const hostBoxes = hosts.map((h) => {
    const infra = repFocusOverride ? hostInfraForRepetition(h.name, repFocusOverride.snapshot_infrastructure) : null;
    const ip = infra ? (infra.ip_floating || infra.ip_private) : (h.ip_floating || h.ip_private);
    const rawStatus = infra ? infra.status : h.status;
    const toolCount = infra ? (infra.tools || []).filter((t) => String(t.status).toUpperCase() === "INSTALLED").length : (h.tools || []).length;

    const statLines = infra ? [`${toolCount} tool(s)`] : hostStatLines(h, { compact: true });
    if (infra) statLines[statLines.length - 1] = `${toolCount} tool(s) · Rep ${focusRepNum} snapshot`;

    const attack = focusLevelB?.attack;
    const isAttackTarget = attack?.target_node === h.name;
    if (isAttackTarget) {
      const detectionText = detectionLabelText(focusLevelB?.detection) || "";
      statLines.unshift(`Attack target this case${detectionText ? " · " + detectionText : ""}`);
    }

    let status;
    if (isAttackTarget) status = "under_attack";
    else if (infra) status = rawStatus === "ACTIVE" ? "idle" : rawStatus; // historical snapshot has no live current_activity
    else status = h.current_activity?.state || (rawStatus === "ACTIVE" ? "idle" : rawStatus);

    const box = createEntityBox({
      id: `host:${h.instance_id}`, kind: "host", title: h.name, subtitle: ip,
      status,
      statusLabel: isAttackTarget ? "attack target" : (rawStatus === "ACTIVE" ? "online" : rawStatus),
      statLines, width: 10, height: 5.5, depth: 7, raw: infra ? { ...h, ...infra, tools: infra.tools } : h,
      boxColor: h.role === "attacker" ? BOX_COLOR_ATTACKER : BOX_COLOR_DEFAULT,
      visualModel: buildHostVisual(h.role, 10, 5.5, 7),
    });
    entityGroups.push(box);
    three.scene.add(box);
    addConnector(focusRepBox || campaignBox, box);
    return box;
  });
  applyRowLayout(hostBoxes, { y: 10, spacing: 13, maxPerRow: 5 });

  // Evidentiary cables: one per host, straight down into the case -- a
  // violet tint (matches this dashboard's existing "evidence source link"
  // color elsewhere) distinguishes them from the structural campaign/
  // repetition/host cables above, which keep their normal status tint.
  if (caseBox) {
    for (const host of hostBoxes) addConnector(host, caseBox, { colorHex: 0x6366f1 });
  }

  renderRelationOverlays(hostBoxes, caseBox, focusLevelB);
}

function metricTile(label, value) {
  return `<div class="metric-tile"><div class="mt-label">${esc(label)}</div><div class="mt-value">${esc(value)}</div></div>`;
}

// Real metrics as small dashboard-style tiles (reference design shows CPU/
// Memory/Disk/etc. as individual tiles, not plain text lines) plus a
// read-only "Host Information" panel -- both built only from fields the
// backend already exposes, nothing invented.
// CPU/Memory/Disk/Clock/Network moved out of this card into their own
// small 3D telemetry modules inside the host volume (spec section 6/9:
// "smaller 3D modules physically contained inside the host", not one flat
// panel) -- this card now only carries identity, kept deliberately short.
function hostDetailExtraHtml(host) {
  return `<div class="info-panel">
    <div class="panel-title">Host information</div>
    <div class="panel-row"><span class="k">Role</span><span class="v">${esc(fmt(host.role))}</span></div>
    <div class="panel-row"><span class="k">OS</span><span class="v">${esc(fmt(host.os))}</span></div>
    <div class="panel-row"><span class="k">Activity</span><span class="v">${esc(fmt(host.current_activity?.state))}</span></div>
    <div class="panel-row"><span class="k">Tools</span><span class="v">${(host.tools || []).length} installed</span></div>
  </div>`;
}

// Real usage-based color: healthy green under 60%, amber warning up to 85%,
// red critical beyond that -- consistent with the platform's existing
// status-color semantics (section 19), not a new invented palette.
function utilizationStatus(pct) {
  if (pct == null) return "unknown";
  if (pct >= 85) return "error";
  if (pct >= 60) return "warning";
  return "ok";
}

// One small 3D module per real telemetry reading -- null/unavailable
// metrics are simply omitted, never shown as a fake 0.
function buildTelemetryBoxes(host) {
  const vitals = host.vitals || {};
  const specs = [];
  if (vitals.cpu_usage_pct != null) specs.push(["CPU", `${vitals.cpu_usage_pct}%`, utilizationStatus(vitals.cpu_usage_pct)]);
  if (vitals.memory_usage_pct != null) specs.push(["Memory", `${vitals.memory_usage_pct}%`, utilizationStatus(vitals.memory_usage_pct)]);
  if (vitals.disk_root_use_pct != null) specs.push(["Disk", `${vitals.disk_root_use_pct}%`, utilizationStatus(vitals.disk_root_use_pct)]);
  if (host.clock_offset_ms != null) specs.push(["Clock", `${host.clock_offset_ms} ms`, "info"]);
  if (vitals.network) specs.push(["Network", `↓${fmtBytes(vitals.network.rx_bytes)} ↑${fmtBytes(vitals.network.tx_bytes)}`, "info"]);
  return specs.map(([label, value, status]) => createEntityBox({
    id: `telemetry:${host.instance_id}:${label}`, kind: "telemetry", title: label,
    status, statusLabel: value, statLines: [], width: 5, height: 3, depth: 3.5, raw: { label, value, host },
  }));
}

// Evidence/acquisition is only ever real for the ONE host the attack
// actually targeted (level_b.attack.target_node) -- showing it on every
// host would misrepresent hosts that were never touched. No target, no
// acquisition data, or a name mismatch all mean: render nothing here.
function buildHostEvidenceBoxes(host) {
  const attack = (snapshot.level_b || {}).attack;
  const acquisition = (snapshot.level_b || {}).acquisition;
  if (!attack || !acquisition || attack.target_node !== host.name) return [];
  const specs = [
    ["Memory", acquisition.memory_status, acquisition.memory_size_bytes ? fmtBytes(acquisition.memory_size_bytes) : null],
    ["Disk", acquisition.disk_status, acquisition.disk_size_bytes ? fmtBytes(acquisition.disk_size_bytes) : null],
    ["Network", acquisition.network_status, acquisition.pcap_segments_imported ? `${acquisition.pcap_segments_imported} segment(s)` : null],
    ["OT / Industrial", acquisition.ot_status, null],
  ];
  return specs.map(([label, status, detail]) => createEntityBox({
    id: `hostevidence:${host.instance_id}:${label}`, kind: "evidence", title: label,
    status: status || "pending", statusLabel: status || "pending", statLines: detail ? [esc(detail)] : [],
    width: 5.5, height: 3.2, depth: 4, raw: { label, status, detail, host },
  }));
}

// The drilled-into host: one large "crystal" box holding its own tools
// literally inside its footprint (same x/z center, small scale) instead of
// a row hanging off a cable -- this is the nested-glass-box look asked for.
function renderDrilledHost(host) {
  const hostHeight = 30, hostWidth = 32, hostDepth = 30;

  // Faint ancestor context (spec section 12): Case and Campaign stay
  // visible as transparent shells around the host so orientation in the
  // hierarchy is never lost while inspecting it up close.
  const hasCase = !!snapshot.case;
  if (hasCase) {
    addGhostShell({
      id: "ghost:case", kind: "case", title: snapshot.case.case_id, subtitle: "case context",
      width: hostWidth * 1.55, height: hostHeight * 1.4, depth: hostDepth * 1.55, boxColor: BOX_COLOR_DEFAULT,
    });
  }
  addGhostShell({
    id: "ghost:campaign", kind: "campaign", title: snapshot.job_id, subtitle: "campaign context",
    width: hostWidth * (hasCase ? 2.2 : 1.55), height: hostHeight * (hasCase ? 1.9 : 1.4), depth: hostDepth * (hasCase ? 2.2 : 1.55),
    boxColor: BOX_COLOR_DEFAULT,
  });

  const tools = host.tools || [];
  const hostBox = createEntityBox({
    id: `host:${host.instance_id}`, kind: "host", title: host.name, subtitle: host.ip_floating || host.ip_private,
    status: host.current_activity?.state || (host.status === "ACTIVE" ? "idle" : host.status), statusLabel: host.status === "ACTIVE" ? "online" : host.status,
    statLines: [], width: hostWidth, height: hostHeight, depth: hostDepth, raw: host,
    boxColor: host.role === "attacker" ? BOX_COLOR_ATTACKER : BOX_COLOR_DEFAULT,
    extraHtml: hostDetailExtraHtml(host),
    ringPct: completionPct(tools, (t) => t.inventory_status === "installed"),
    // The host's title card and its nested modules' cards would otherwise
    // both sit at the box center and collide -- push the host's card up
    // near the top of the glass box, like a label, and leave the interior
    // clear for the telemetry/tool/evidence modules it contains.
    cardOffsetY: hostHeight / 2 + 6,
  });
  hostBox.position.set(0, 0, 0);
  three.scene.add(hostBox);
  entityGroups.push(hostBox);

  // Three real, independent module rows -- telemetry, tools, evidence --
  // each its own set of small 3D boxes inside the host's volume (spec
  // section 6/9), not one flat panel. Evidence only appears for the one
  // host that was genuinely the acquisition target (see
  // buildHostEvidenceBoxes) -- most hosts will simply have no third row.
  const telemetryBoxes = buildTelemetryBoxes(host);
  const toolBoxes = tools.map((t) => createEntityBox({
    id: `tool:${host.instance_id}:${t.id}`, kind: "tool", title: t.display_name || t.id, subtitle: t.category,
    status: t.inventory_status, statusLabel: t.inventory_status,
    statLines: t.installed_at ? [`since ${t.installed_at.slice(0, 10)}`] : [],
    width: 5.5, height: 3.2, depth: 4, raw: { ...t, host },
  }));
  const evidenceBoxes = buildHostEvidenceBoxes(host);

  [...telemetryBoxes, ...toolBoxes, ...evidenceBoxes].forEach((b) => { entityGroups.push(b); three.scene.add(b); });

  // Same (x, z) center as the host, only smaller -- reads as "inside" the
  // glass volume. Three vertically-stacked bands, clear of the title card.
  if (telemetryBoxes.length) applyRowLayout(telemetryBoxes, { y: 3, spacing: 7, maxPerRow: 5, zOffset: -8 });
  applyRowLayout(toolBoxes, { y: -4, spacing: 10.5, maxPerRow: 3, zOffset: 1 });
  if (evidenceBoxes.length) applyRowLayout(evidenceBoxes, { y: -12, spacing: 8, maxPerRow: 4, zOffset: 8 });

  [...telemetryBoxes, ...toolBoxes, ...evidenceBoxes].forEach((b) => {
    b.position.x += hostBox.position.x;
    b.position.z += hostBox.position.z;
  });
}

function caseDetailExtraHtml(caseData) {
  const integ = caseData.integrity || {};
  const tiles = [
    metricTile("Artifacts", integ.available ? `${fmt(integ.artifacts_with_hash)}/${fmt(integ.artifacts_total)}` : "not available"),
    metricTile("Custody entries", fmt(integ.custody_entries)),
    metricTile("Manifest verified", integ.manifest_hash_verified_live ? "yes" : "no"),
    metricTile("Sealed", integ.case_sealed ? "yes" : "no"),
  ];
  const info = `<div class="info-panel">
    <div class="panel-title">Case information</div>
    <div class="panel-row"><span class="k">Case name</span><span class="v">${esc(fmt(caseData.case_real_name))}</span></div>
    <div class="panel-row"><span class="k">Manifest hash</span><span class="v" style="font-size:9px;">${esc((integ.manifest_hash || "").slice(0, 14))}&hellip;</span></div>
  </div>`;
  return `<div class="metric-grid">${tiles.join("")}</div>${info}`;
}

// The drilled-into case: the real Level B pipeline (attack -> detect ->
// acquire -> analyze -> seal, from campaign_repetitions' own stage list)
// and the real per-data-type preservation steps (Memory/Disk/Network/OT),
// both nested inside the case's own glass volume as their own boxes --
// this is the same real data the "Campaign Repetitions / Recent
// repetitions" tree already shows, just surfaced here as 3D boxes instead
// of text rows, per the user's explicit request to go one level deeper.
function renderDrilledCase(caseData, levelB) {
  const caseHeight = 32, caseWidth = 42, caseDepth = 36;

  // Faint Campaign context around the case (spec section 12).
  addGhostShell({
    id: "ghost:campaign", kind: "campaign", title: snapshot.job_id, subtitle: "campaign context",
    width: caseWidth * 1.5, height: caseHeight * 1.4, depth: caseDepth * 1.5, boxColor: BOX_COLOR_DEFAULT,
  });

  const caseBox = createEntityBox({
    id: `case:${caseData.case_id}`, kind: "case", title: caseData.case_id, subtitle: caseData.case_real_name,
    status: (caseData.integrity || {}).case_sealed ? "completed" : "pending",
    statusLabel: (caseData.integrity || {}).case_sealed ? "sealed" : "unsealed",
    statLines: [], width: caseWidth, height: caseHeight, depth: caseDepth, raw: caseData,
    extraHtml: caseDetailExtraHtml(caseData),
    cardOffsetY: caseHeight / 2 + 3,
  });
  caseBox.position.set(0, 0, 0);
  three.scene.add(caseBox);
  entityGroups.push(caseBox);

  const lbStages = (levelB || {}).stages || [];
  const stageBoxes = lbStages.map((s) => {
    const box = createEntityBox({
      id: `stage:${s.stage_key}`, kind: "stage", title: s.label,
      subtitle: s.elapsed_seconds != null ? fmtElapsed(s.elapsed_seconds) : null,
      status: s.status, statusLabel: s.status,
      statLines: s.detail ? [esc(s.detail)] : [],
      width: 6, height: 3.2, depth: 4, raw: s,
    });
    entityGroups.push(box);
    three.scene.add(box);
    return box;
  });
  applyRowLayout(stageBoxes, { y: 6, spacing: 9, maxPerRow: 5, zOffset: -13 });

  const evidenceSteps = caseData.evidence_pipeline || [];
  const evidenceBoxes = evidenceSteps.map((s) => {
    const box = createEntityBox({
      id: `evidence:${caseData.case_id}:${s.label}`, kind: "evidence", title: s.label,
      status: s.status, statusLabel: s.status,
      statLines: s.detail ? [esc(s.detail)] : [],
      width: 6.5, height: 3.5, depth: 4.5, raw: s,
    });
    entityGroups.push(box);
    three.scene.add(box);
    return box;
  });
  applyRowLayout(evidenceBoxes, { y: -11, spacing: 9.5, maxPerRow: 4, zOffset: 7 });

  [...stageBoxes, ...evidenceBoxes].forEach((b) => {
    b.position.x += caseBox.position.x;
    b.position.z += caseBox.position.z;
  });
}

function campaignDetailExtraHtml(snap) {
  const stages = snap.stages || [];
  const installs = snap.tool_installs || [];
  const syncs = snap.time_sync_checks || [];
  const tiles = [
    metricTile("Elapsed", fmtElapsed(snap.total_elapsed_seconds)),
    metricTile("Stages", `${stages.filter((s) => s.status === "completed").length}/${stages.length}`),
    metricTile("Tool installs", `${installs.filter((i) => i.status === "installed").length}/${installs.length}`),
    metricTile("Clocks synced", `${syncs.filter((s) => s.temporal_sync_status === "synchronized").length}/${syncs.length}`),
  ];
  const info = `<div class="info-panel">
    <div class="panel-title">Campaign information</div>
    <div class="panel-row"><span class="k">Phase</span><span class="v">${esc(fmt(snap.phase))}</span></div>
    <div class="panel-row"><span class="k">Repetition</span><span class="v">${snap.focus_repetition}/${snap.total_repetitions}</span></div>
  </div>`;
  return `<div class="metric-grid">${tiles.join("")}</div>${info}`;
}

// The drilled-into campaign: the real Level C orchestration loop (destroy
// -> deploy -> wait -> sync clocks -> install tools -> verify -> launch
// Level B -> wait -> snapshot) as its own nested boxes -- same real stage
// list already shown as text when clicking the campaign box, now also
// visible as the "cage" boxes inside the campaign's own glass volume.
function renderDrilledCampaign() {
  const campaignHeight = 26;
  const campaignBox = createEntityBox({
    id: `campaign:${snapshot.job_id}`, kind: "campaign", title: snapshot.job_id,
    subtitle: `Repetition ${snapshot.focus_repetition}/${snapshot.total_repetitions}`,
    status: snapshot.is_live ? "running" : snapshot.status, statusLabel: snapshot.is_live ? "running" : snapshot.status,
    statLines: [], width: 36, height: campaignHeight, depth: 26, raw: snapshot,
    extraHtml: campaignDetailExtraHtml(snapshot),
    cardOffsetY: campaignHeight / 2 + 3,
  });
  campaignBox.position.set(0, 0, 0);
  three.scene.add(campaignBox);
  entityGroups.push(campaignBox);

  const stages = snapshot.stages || [];
  const stageBoxes = stages.map((s) => {
    const box = createEntityBox({
      id: `stage:${s.stage_key}`, kind: "stage", title: s.label,
      subtitle: s.elapsed_seconds != null ? fmtElapsed(s.elapsed_seconds) : null,
      status: s.status, statusLabel: s.status,
      statLines: s.detail ? [esc(s.detail)] : [],
      width: 6, height: 3.2, depth: 4, raw: s,
    });
    entityGroups.push(box);
    three.scene.add(box);
    return box;
  });
  applyRowLayout(stageBoxes, { y: -3, spacing: 8.5, maxPerRow: 4, zOffset: -3 });
  stageBoxes.forEach((b) => {
    b.position.x += campaignBox.position.x;
    b.position.z += campaignBox.position.z;
  });
}

function rebuildScene() {
  clearScene();
  if (!snapshot) { updateBreadcrumb(); return; }

  const drilledHost = drilledHostId ? (snapshot.hosts || []).find((h) => h.instance_id === drilledHostId) : null;
  if (drilledHostId && !drilledHost) drilledHostId = null; // host vanished from a fresh snapshot -- fall back, don't dead-end
  if (drilledCase && !(repFocusOverride ? repFocusOverride.case : snapshot.case)) drilledCase = false; // case vanished (new repetition, not sealed yet) -- fall back

  if (drilledHost) {
    renderDrilledHost(drilledHost);
  } else if (drilledCase) {
    renderDrilledCase(repFocusOverride ? repFocusOverride.case : snapshot.case, repFocusOverride ? repFocusOverride.level_b : snapshot.level_b);
  } else if (drilledCampaign) {
    renderDrilledCampaign();
  } else {
    renderOverview();
  }

  refreshVisualState();
  document.getElementById("collapse-btn").style.display = (drilledHostId || drilledCase || drilledCampaign) ? "inline-block" : "none";
  updateBreadcrumb();
}

// True while a sibling full-scene mode (Live Attack View / Digital Twin
// View) owns the 3D view. The default overview's own navigation (drill-down,
// breadcrumb, back button, right-click) must no-op while one of these is
// active -- otherwise it silently rebuilds the default campaign/cases/hosts
// scene underneath a sibling mode that never got told to exit(), leaving
// its polling running invisibly and the view stuck showing the wrong scene.
function sideModeActive() {
  return liveAttack.isActive() || digitalTwin.isActive();
}

// The breadcrumb doubles as a level switcher: every level that currently
// exists (Overview, the campaign/Level C, the case/Level B if one exists,
// and a drilled host if any) is its own clickable segment, so jumping
// between levels never requires re-finding and double-clicking a 3D box.
function goToLevel(target) {
  if (sideModeActive()) return;
  drilledHostId = target.host ? drilledHostId : null;
  drilledCase = !!target.case;
  drilledCampaign = !!target.campaign;
  rebuildScene();
  three.focusOnGroups(allVisibleGroups());
}

function updateBreadcrumb() {
  const el = document.getElementById("breadcrumb-bar");
  if (!el) return;
  if (!snapshot) { el.innerHTML = ""; return; }
  const drilledHost = drilledHostId ? (snapshot.hosts || []).find((h) => h.instance_id === drilledHostId) : null;
  const atOverview = !drilledHost && !drilledCase && !drilledCampaign;

  const crumb = (id, text, active, clickable) =>
    `<span class="crumb${active ? " current" : ""}"${clickable ? ` id="${id}"` : ""}>${esc(text)}</span>`;

  const parts = [crumb("crumb-overview", "Overview", atOverview, !atOverview)];
  parts.push(`<span class="sep">&rsaquo;</span>`);
  parts.push(crumb("crumb-campaign", snapshot.job_id, drilledCampaign, !drilledCampaign));
  const breadcrumbCase = repFocusOverride ? repFocusOverride.case : snapshot.case;
  if (breadcrumbCase) {
    parts.push(`<span class="sep">&rsaquo;</span>`);
    parts.push(crumb("crumb-case", breadcrumbCase.case_id, drilledCase, !drilledCase));
  }
  if (drilledHost) {
    parts.push(`<span class="sep">&rsaquo;</span>`);
    parts.push(crumb("crumb-host", drilledHost.name, true, false));
  }
  el.innerHTML = parts.join("");

  document.getElementById("crumb-overview")?.addEventListener("click", () => goToLevel({}));
  document.getElementById("crumb-campaign")?.addEventListener("click", () => goToLevel({ campaign: true }));
  document.getElementById("crumb-case")?.addEventListener("click", () => goToLevel({ case: true }));
}

// ---------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------

function stagesHtml(stages, heading = "Stages") {
  let html = `<div style="margin-top:10px;font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;">${esc(heading)}</div>`;
  for (const s of stages || []) {
    html += `<div class="kv-row"><span class="k">${esc(s.label)}</span><span class="v">${badge(s.status)}</span></div>`;
  }
  return html;
}

function renderDetail(hit) {
  const body = document.getElementById("detail-body");
  if (!hit) { body.innerHTML = `<div class="detail-empty">Nothing selected yet.</div>`; return; }
  const { kind, title, raw } = hit;
  let html = `<div style="font-weight:700;font-size:13px;margin-bottom:6px;">${esc(title)}</div>`;

  if (kind === "campaign") {
    html += `<div class="kv-row"><span class="k">Status</span><span class="v">${badge(snapshot.is_live ? "running" : snapshot.status)}</span></div>`;
    html += `<div class="kv-row"><span class="k">Phase</span><span class="v">${esc(fmt(snapshot.phase))}</span></div>`;
    html += `<div class="kv-row"><span class="k">Elapsed</span><span class="v">${fmtElapsed(snapshot.total_elapsed_seconds)}</span></div>`;
    html += stagesHtml(snapshot.stages);
    html += `<button class="action-btn" id="expand-campaign-btn">${drilledCampaign ? "&larr; Back to overview" : "Drill into campaign"}</button>`;
  } else if (kind === "repetition") {
    html += `<div class="kv-row"><span class="k">Repetition</span><span class="v">${raw.repetition_number}/${raw.total_repetitions}</span></div>`;
    html += `<div class="kv-row"><span class="k">Status</span><span class="v">${badge(raw.status)}</span></div>`;
    if (raw.is_focus) {
      html += stagesHtml(snapshot.stages, "Stages (this is the focused repetition)");
    } else if (raw.status === "pending") {
      html += `<div class="detail-empty" style="margin-top:10px;">Not started yet.</div>`;
    } else {
      html += `<div id="rep-stage-detail" style="margin-top:8px;color:var(--text-dim);font-size:11px;">Loading stage detail&hellip;</div>`;
    }
  } else if (kind === "case") {
    const integ = raw.integrity || {};
    html += `<div class="kv-row"><span class="k">Sealed</span><span class="v">${integ.case_sealed ? "yes" : "no"}</span></div>`;
    html += `<div class="kv-row"><span class="k">Manifest hash</span><span class="v" style="font-size:9px;">${esc((integ.manifest_hash || "").slice(0, 14))}&hellip;</span></div>`;
    html += `<div class="kv-row"><span class="k">Verified live</span><span class="v">${integ.manifest_hash_verified_live ? "yes" : "no (changed)"}</span></div>`;
    html += `<div class="kv-row"><span class="k">Custody entries</span><span class="v">${fmt(integ.custody_entries)}</span></div>`;
    html += `<div style="margin-top:10px;font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;">Evidence pipeline</div>`;
    for (const s of raw.evidence_pipeline || []) {
      html += `<div class="kv-row"><span class="k">${esc(s.label)}</span><span class="v">${badge(s.status)}</span></div>`;
    }
    html += `<div style="margin-top:10px;font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;">Recent events</div>`;
    html += `<div class="events-list">`;
    for (const e of (raw.recent_events || []).slice(0, 8)) {
      html += `<div class="event-row"><b>${esc(e.event)}</b><br>${esc((e.ts_utc || "").replace("T", " ").replace("Z", ""))}</div>`;
    }
    html += `</div>`;
    html += `<button class="action-btn" id="expand-case-btn">${drilledCase ? "&larr; Back to overview" : "Drill into case"}</button>`;
  } else if (kind === "stage") {
    html += `<div class="kv-row"><span class="k">Status</span><span class="v">${badge(raw.status)}</span></div>`;
    if (raw.elapsed_seconds != null) html += `<div class="kv-row"><span class="k">Elapsed</span><span class="v">${fmtElapsed(raw.elapsed_seconds)}</span></div>`;
    if (raw.detail) html += `<div class="kv-row"><span class="k">Detail</span><span class="v">${esc(raw.detail)}</span></div>`;
    if (raw.error_detail) html += `<div class="kv-row"><span class="k">Error</span><span class="v" style="color:var(--red);">${esc(raw.error_detail)}</span></div>`;
  } else if (kind === "evidence") {
    html += `<div class="kv-row"><span class="k">Status</span><span class="v">${badge(raw.status)}</span></div>`;
    if (raw.detail) html += `<div class="kv-row"><span class="k">Detail</span><span class="v">${esc(raw.detail)}</span></div>`;
  } else if (kind === "telemetry") {
    html += `<div class="kv-row"><span class="k">Value</span><span class="v">${esc(raw.value)}</span></div>`;
    html += `<div class="kv-row"><span class="k">Host</span><span class="v">${esc(raw.host?.name)}</span></div>`;
  } else if (kind === "host") {
    const vitals = raw.vitals || {};
    html += `<div class="kv-row"><span class="k">Role</span><span class="v">${esc(raw.role)}</span></div>`;
    html += `<div class="kv-row"><span class="k">OS</span><span class="v">${esc(raw.os)}</span></div>`;
    html += `<div class="kv-row"><span class="k">Activity</span><span class="v">${badge(raw.current_activity?.state)}</span></div>`;
    html += `<div class="kv-row"><span class="k">Clock offset</span><span class="v">${raw.clock_offset_ms ?? "—"} ms</span></div>`;
    html += `<div style="margin-top:8px;font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;">Resources</div>`;
    html += resourceLine("CPU", vitals.cpu_usage_pct);
    html += resourceLine("Memory", vitals.memory_usage_pct);
    html += resourceLine("Disk", vitals.disk_root_use_pct);
    html += `<div class="kv-row"><span class="k">Network</span><span class="v">↓${fmtBytes(vitals.network?.rx_bytes)} ↑${fmtBytes(vitals.network?.tx_bytes)}</span></div>`;
    html += `<button class="action-btn" id="refresh-vitals-btn">&#8635; Refresh vitals now</button>`;
    html += `<button class="action-btn" id="expand-tools-btn">${drilledHostId === raw.instance_id ? "&larr; Back to overview" : "Drill into host"}</button>`;
  } else if (kind === "tool") {
    html += `<div class="kv-row"><span class="k">Category</span><span class="v">${esc(fmt(raw.category))}</span></div>`;
    html += `<div class="kv-row"><span class="k">Status</span><span class="v">${badge(raw.inventory_status)}</span></div>`;
    html += `<div class="kv-row"><span class="k">Installed at</span><span class="v" style="font-size:9.5px;">${esc(fmt(raw.installed_at))}</span></div>`;
    html += `<div class="kv-row"><span class="k">Host</span><span class="v">${esc(raw.host?.name)}</span></div>`;
  }
  body.innerHTML = html;

  document.getElementById("refresh-vitals-btn")?.addEventListener("click", async () => {
    const fresh = await fetchHostVitals(raw.instance_id, { refresh: true }).catch(() => null);
    if (fresh) { raw.vitals = fresh; renderDetail(hit); }
  });
  document.getElementById("expand-tools-btn")?.addEventListener("click", () => {
    drilledHostId = drilledHostId === raw.instance_id ? null : raw.instance_id;
    drilledCase = false;
    drilledCampaign = false;
    rebuildScene();
    three.focusOnGroups(allVisibleGroups());
  });
  document.getElementById("expand-case-btn")?.addEventListener("click", () => {
    drilledCase = !drilledCase;
    drilledHostId = null;
    drilledCampaign = false;
    rebuildScene();
    three.focusOnGroups(allVisibleGroups());
  });
  document.getElementById("expand-campaign-btn")?.addEventListener("click", () => {
    drilledCampaign = !drilledCampaign;
    drilledHostId = null;
    drilledCase = false;
    rebuildScene();
    three.focusOnGroups(allVisibleGroups());
  });

  if (kind === "repetition") {
    if (raw.is_focus) {
      // The focused repetition's data is already what snapshot.case/level_b
      // naturally holds -- clear any earlier override so the Case box goes
      // back to tracking the live snapshot instead of staying pinned to
      // whatever repetition was last clicked.
      if (repFocusOverride) { repFocusOverride = null; rebuildScene(); }
    } else if (raw.status !== "pending") {
      fetchRepetitionDetail(raw.repetition_number).then((detail) => {
        // The user may have clicked something else while this was in flight --
        // only apply it if this repetition is still what's selected.
        if (selectedId !== hit.id) return;
        const el = document.getElementById("rep-stage-detail");
        if (el) el.outerHTML = detail ? stagesHtml(detail.stages, "Stages") : `<div class="detail-empty">No stage detail available.</div>`;
        // Each repetition launches its own distinct Level B job/case -- swap
        // the Case box (and the security/evidence overlays, which read the
        // same level_b) to reflect THIS repetition instead of staying frozen
        // on the campaign's current/last one.
        if (detail && detail.case) {
          repFocusOverride = { repetition_number: raw.repetition_number, case: detail.case, level_b: detail.level_b, snapshot_infrastructure: detail.snapshot_infrastructure };
          rebuildScene();
        }
      }).catch(() => {
        if (selectedId !== hit.id) return;
        const el = document.getElementById("rep-stage-detail");
        if (el) el.textContent = "Could not load stage detail.";
      });
    }
  }
}

function resourceLine(label, pct) {
  if (pct === null || pct === undefined) return `<div class="kv-row"><span class="k">${esc(label)}</span><span class="v" style="color:var(--text-dim);">not probed</span></div>`;
  return `<div class="kv-row"><span class="k">${esc(label)}</span><span class="v">${pct}%</span></div>${bar(pct)}`;
}

// ---------------------------------------------------------------------
// Interaction wiring
// ---------------------------------------------------------------------

// A single click only selects a box and populates the right-hand detail
// panel -- it never navigates. Double-click on a host or the case drills
// INTO it: the overview (Campaign -> Repetitions -> Case -> Hosts) is
// replaced by that one box rendered large, with its real children as
// smaller boxes inside its own volume (a host's tools; a case's Level B
// pipeline stages and per-data-type evidence). Only one of host/case can be
// drilled into at a time. Double-clicking the same box again (or the
// breadcrumb/back button) returns to the overview.
attachInteraction(three.renderer.domElement, three.camera, () => (liveAttack.isActive() ? liveAttack.getAllRenderedGroups() : digitalTwin.isActive() ? digitalTwin.getAllRenderedGroups() : entityGroups), {
  onSelect(hit) {
    if (liveAttack.isActive()) { liveAttack.handleSelect(hit); return; }
    if (digitalTwin.isActive()) { digitalTwin.handleSelect(hit); return; }
    selectedId = hit.id;
    refreshVisualState();
    renderDetail(hit);
  },
  onDrillDown(hit) {
    if (sideModeActive()) return; // a sibling mode owns the scene -- never fall back to the default drill-down/overview underneath it
    if (hit.kind === "host") {
      const instanceId = hit.raw.instance_id;
      drilledHostId = drilledHostId === instanceId ? null : instanceId;
      drilledCase = false;
      drilledCampaign = false;
      rebuildScene();
      // Fit the WHOLE current level in view -- in a drilled view that's the
      // container box plus everything now nested inside it, so nothing ends
      // up clipped outside the frustum.
      three.focusOnGroups(allVisibleGroups());
      renderDetail(hit);
    } else if (hit.kind === "case") {
      drilledCase = !drilledCase;
      drilledHostId = null;
      drilledCampaign = false;
      rebuildScene();
      three.focusOnGroups(allVisibleGroups());
      renderDetail(hit);
    } else if (hit.kind === "campaign") {
      drilledCampaign = !drilledCampaign;
      drilledHostId = null;
      drilledCase = false;
      rebuildScene();
      three.focusOnGroups(allVisibleGroups());
      renderDetail(hit);
    } else {
      const box = entityGroups.find((g) => g.userData.id === hit.id);
      const dist = (hit.kind === "stage" || hit.kind === "evidence") ? 18 : 24;
      if (box) three.focusOn(box.position, dist);
    }
  },
  // "Where did this value come from?" (spec section 16) -- reuses the same
  // Data Sources match rules, so the provenance shown here is always
  // consistent with what clicking that same source in the sidebar filters.
  onHover(hit) {
    const el = document.getElementById("provenance-hint");
    if (!hit) { el.classList.remove("visible"); return; }
    const source = DATA_SOURCES.find((s) => s.match({ userData: hit }));
    el.innerHTML = `<b>${esc(hit.title)}</b> — Source: ${esc(source ? source.desc : "unknown")}`;
    el.classList.add("visible");
  },
});

document.getElementById("collapse-btn").addEventListener("click", () => {
  if (sideModeActive()) return;
  drilledHostId = null;
  drilledCase = false;
  drilledCampaign = false;
  rebuildScene();
  three.focusOnGroups(allVisibleGroups());
});

// Right-click = go up one level (spec section 11.3). The current model is
// flat (Host/Case/Campaign are mutually-exclusive drill states, not a real
// stack), so "up" from any of them lands on Overview -- the same place the
// breadcrumb's "Overview" segment and the back button already go. The
// browser's own context menu is suppressed on the canvas so this reads as
// a real navigation gesture rather than a broken right-click.
three.renderer.domElement.addEventListener("contextmenu", (event) => {
  event.preventDefault();
  if (!drilledHostId && !drilledCase && !drilledCampaign) return;
  goToLevel({});
});

// ---------------------------------------------------------------------
// Polling + render loop
// ---------------------------------------------------------------------

const connDot = document.getElementById("conn-dot");
const connText = document.getElementById("conn-text");

function startLivePolling() {
  startPolling(
    (data) => {
      // A poll that was already in flight when reconstruction mode cleared
      // the live scene can still resolve afterward -- without this guard its
      // callback would silently repaint live-mode boxes into what's supposed
      // to be an empty (or partially built) reconstruction scene.
      if (reconstruction.isReconstructionActive() || liveAttack.isActive() || digitalTwin.isActive()) return;
      if (data.unchanged) { connDot.className = "conn-dot"; connText.textContent = "live · no changes"; return; }
      if (repFocusOverride && data.campaign?.job_id !== snapshot?.job_id) repFocusOverride = null; // stale cross-campaign override
      snapshot = data.campaign;
      connDot.className = "conn-dot";
      connText.textContent = snapshot ? `live · ${snapshot.job_id}` : "live · no campaign found";
      rebuildScene();
    },
    (err) => { connDot.className = "conn-dot error"; connText.textContent = `error: ${err.message}`; },
    (syncing) => { connDot.classList.toggle("syncing", syncing); },
  );
}
startLivePolling();

// ---------------------------------------------------------------------
// Bridge for reconstruction.js (post-campaign replay mode) -- deliberately
// narrow: reconstruction.js never reaches into this module's state directly,
// it only goes through setState()/rebuildScene()/focus helpers below, so
// live mode's own state can never be corrupted by a replay bug. See
// reconstruction.js for how entry/exit save and restore state through this
// same surface.
// ---------------------------------------------------------------------
export const monitorBridge = {
  setState({ snapshot: s, repFocusOverride: r, drilledHostId: dh, drilledCase: dc, drilledCampaign: dcamp }) {
    if (s !== undefined) snapshot = s;
    if (r !== undefined) repFocusOverride = r;
    if (dh !== undefined) drilledHostId = dh;
    if (dc !== undefined) drilledCase = dc;
    if (dcamp !== undefined) drilledCampaign = dcamp;
  },
  getState: () => ({ snapshot, repFocusOverride, drilledHostId, drilledCase, drilledCampaign }),
  rebuildScene,
  focusOnGroups: (...args) => three.focusOnGroups(...args),
  focusOn: (...args) => three.focusOn(...args),
  resolveFocusIds: (ids) => allVisibleGroups().filter((g) => ids.includes(g.userData.id)),
  allVisibleGroups,
  stopLivePolling: stopPolling,
  startLivePolling,
  addObject: (obj) => three.scene.add(obj),
  removeObject: (obj) => three.scene.remove(obj),
  getCamera: () => three.camera,
  clearLiveScene: clearScene, // empties ONLY the live-mode arrays -- never touches snapshot/drill flags
  setConnStatus(text, { reconstructing = false, error = false } = {}) {
    connText.textContent = text;
    connDot.className = "conn-dot" + (reconstructing ? " reconstructing" : "") + (error ? " error" : "");
  },
};

// While reconstruction owns the viewport, its own boxes -- not live-mode's
// entityGroups (empty during a replay) -- are what needs CSS2D visibility
// culling; see scene.js's updateEntityVisibility().
three.setEntities(() => (reconstruction.isReconstructionActive() ? reconstruction.getAllRenderedGroups() : liveAttack.isActive() ? liveAttack.getAllRenderedGroups() : digitalTwin.isActive() ? digitalTwin.getAllRenderedGroups() : entityGroups));

function animate() {
  requestAnimationFrame(animate);
  three.render();
}
animate();

// ---------------------------------------------------------------------
// Fullscreen toggle -- a corner control living IN the viewport itself
// (YouTube-style), not a top-bar text button. Standard browser Fullscreen
// API on the whole document, so it works identically in live mode and
// reconstruction mode (both share the same page; this has no notion of
// which one is active).
// ---------------------------------------------------------------------
const fullscreenBtn = document.getElementById("fullscreen-toggle-btn");
const expandIcon = fullscreenBtn.querySelector(".icon-expand");
const compressIcon = fullscreenBtn.querySelector(".icon-compress");
function updateFullscreenIcon() {
  const active = !!document.fullscreenElement;
  // SVGElement doesn't reliably expose the `.hidden` IDL property the way
  // HTMLElement does (it reads back `undefined` even with the `hidden`
  // attribute present in markup) -- style.display works on any element
  // and is what actually toggles visibility here.
  expandIcon.style.display = active ? "none" : "";
  compressIcon.style.display = active ? "" : "none";
  fullscreenBtn.title = active ? "Exit fullscreen" : "Fullscreen";
  fullscreenBtn.setAttribute("aria-label", fullscreenBtn.title);
}
fullscreenBtn.addEventListener("click", () => {
  if (document.fullscreenElement) {
    document.exitFullscreen();
  } else {
    document.documentElement.requestFullscreen().catch(() => {});
  }
});
document.addEventListener("fullscreenchange", updateFullscreenIcon);
updateFullscreenIcon();

// ---------------------------------------------------------------------
// Reconstruction mode UI -- thin glue between the DOM controls and
// reconstruction.js's play/pause/reset/exit. All the actual replay logic
// (timeline fetch, beat scheduling, state save/restore) lives there; this
// only reflects button/select state and formats the current-beat readout.
// ---------------------------------------------------------------------
const reconToggleBtn = document.getElementById("reconstruction-toggle-btn");
const reconBar = document.getElementById("reconstruction-bar");
const reconSelect = document.getElementById("reconstruction-campaign-select");
const reconPlayBtn = document.getElementById("reconstruction-play-btn");
const reconPauseBtn = document.getElementById("reconstruction-pause-btn");
const reconStepBackBtn = document.getElementById("reconstruction-step-back-btn");
const reconStepFwdBtn = document.getElementById("reconstruction-step-fwd-btn");
const reconResetBtn = document.getElementById("reconstruction-reset-btn");
const reconExitBtn = document.getElementById("reconstruction-exit-btn");
const reconBeatLabel = document.getElementById("reconstruction-beat-label");
const reconProgress = document.getElementById("reconstruction-progress");
const reconSpeedInput = document.getElementById("reconstruction-speed");
const reconSpeedLabel = document.getElementById("reconstruction-speed-label");
const realityGapToggle = document.getElementById("reality-gap-toggle");

// The two side panels swap their whole content between live mode's own
// (unchanged) click-to-inspect behavior and reconstruction's own
// auto-updating summaries -- toggled by visibility, not by destroying/
// rebuilding either side, so live mode's DOM/listeners are never disturbed.
const liveSourcesPanel = document.getElementById("live-sources-panel");
const reconProgressPanel = document.getElementById("recon-progress-panel");
const reconFailurePanel = document.getElementById("recon-failure-panel");
const reconFailureBody = document.getElementById("recon-failure-body");
const liveDetailPanel = document.getElementById("live-detail-panel");
const reconStagePanel = document.getElementById("recon-stage-panel");
const reconProgressBody = document.getElementById("recon-progress-body");
const reconStageBody = document.getElementById("recon-stage-body");
const reconStageSubtitle = document.getElementById("recon-stage-subtitle");

const reconWatermark = document.getElementById("reconstruction-watermark");

function setReconPanelsVisible(active) {
  liveSourcesPanel.hidden = active;
  reconProgressPanel.hidden = !active;
  liveDetailPanel.hidden = active;
  reconStagePanel.hidden = !active;
  reconWatermark.classList.toggle("visible", active);
}

function setTransportEnabled(loaded) {
  reconPlayBtn.disabled = !loaded;
  reconPauseBtn.disabled = !loaded;
  reconStepBackBtn.disabled = !loaded;
  reconStepFwdBtn.disabled = !loaded;
  reconResetBtn.disabled = !loaded;
  reconExitBtn.disabled = !loaded;
}
setTransportEnabled(false);

function kv(k, v) {
  return `<div class="kv-row"><span class="k">${esc(k)}</span><span class="v">${v}</span></div>`;
}
function sectionHeading(text) {
  return `<div style="margin-top:10px;font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;">${esc(text)}</div>`;
}

// Plain-language reading of a raw result -- not just the number, what it
// means in practice, for a non-specialist. User's explicit, generalized
// request: every dashboard/mode, not just one. tone: "good"|"mixed"|"bad".
function interpretationBox(tone, text) {
  const colors = { good: "var(--green)", mixed: "var(--amber)", bad: "var(--red)" };
  const color = colors[tone] || "var(--text-dim)";
  return `<div style="margin-top:6px;padding:7px 9px;border-radius:6px;border-left:3px solid ${color};color:${color};background:rgba(255,255,255,0.03);font-size:11px;line-height:1.4;">${esc(text)}</div>`;
}

function interpretCpr(cpr) {
  if (cpr == null) return null;
  if (cpr >= 0.9) return { tone: "good", text: "Almost the entire real attack chain could be rebuilt from evidence after the fact -- strong forensic reconstruction." };
  if (cpr >= 0.6) return { tone: "mixed", text: "Most of the real attack chain could be rebuilt, but real gaps remain -- some steps couldn't be proven from evidence alone." };
  return { tone: "bad", text: "Only a small part of the real attack chain could be rebuilt from evidence -- most of what happened can't be proven forensically from this case." };
}

// Left panel: cumulative, campaign-wide counters -- "how far has this whole
// replay gotten", not tied to whatever beat happens to be on screen right
// now. Every number comes straight from reconstruction.getProgressSummary(),
// itself a running tally of real beats that have actually fired.
function renderReconProgress() {
  const s = reconstruction.getProgressSummary();
  const repPct = s.totalRepetitions ? Math.round((s.repetitionsCompleted / s.totalRepetitions) * 100) : 0;
  const beatPct = s.totalBeats ? Math.round(((s.beatIndex + 1) / s.totalBeats) * 100) : 0;
  let html = "";
  html += kv("Repetition", `${s.currentRepetition ?? "—"} / ${s.totalRepetitions || "—"}`);
  html += kv("Repetitions completed", `${s.repetitionsCompleted} (${repPct}%)`);
  html += kv("Overall beat progress", `${s.beatIndex + 1} / ${s.totalBeats} (${beatPct}%)`);
  // Alert Center -- the real events worth emphasizing (attacks, detections,
  // fault-injection outcomes, computed metrics), newest first, each one the
  // SAME real data the 3D callout/camera spotlight just showed (see
  // reconstruction.js::triggerAlert) -- kept here too since a held camera
  // shot is transient but this list stays scrollable/reviewable at any pace.
  if (s.alertFeed?.length) {
    html += sectionHeading("Alert center");
    html += `<div class="events-list">`;
    for (const a of [...s.alertFeed].reverse()) {
      html += `<div class="alert-feed-row sev-${esc(a.severity)}">` +
        `<div class="afr-kind">${esc(a.kind)}</div>` +
        `<div class="afr-title">${esc(a.title)}</div>` +
        (a.detail ? `<div class="afr-detail">${esc(a.detail)}</div>` : "") +
        `</div>`;
    }
    html += `</div>`;
  }
  html += sectionHeading("Construction");
  html += kv("Hosts deployed", s.hostsDeployed);
  html += kv("Tools installed", s.toolsInstalled);
  html += sectionHeading("Attack & detection");
  html += kv("Attacks executed", s.attacksExecuted);
  html += kv("Detections", `${s.detectionsTriggered} detected / ${s.detectionsMissed} missed`);
  if (s.interventionsReplayed) html += kv("Real interventions (Ledger)", s.interventionsReplayed);
  html += sectionHeading("Forensics");
  html += kv("Cases created", s.casesCreated);
  html += kv("Cases sealed", s.casesSealed);
  // "This case" (resets every case_created, grows artifact by artifact as
  // that case's own preservation_step beats fire) vs. the campaign-wide
  // running total across every repetition's case so far -- two different
  // real numbers that were previously collapsed into one, reading as
  // "stuck" once a case finished and the next repetition's own count
  // hadn't caught up to the same total yet.
  if (s.currentCaseId) {
    html += kv("This case's artifacts", s.currentCaseArtifacts);
    html += kv("This case's volume", fmtBytes(s.currentCaseBytes));
    if (s.lastArtifactLabel) {
      html += kv("Last artifact preserved", `${esc(s.lastArtifactLabel)}${s.lastArtifactBytes != null ? ` (${fmtBytes(s.lastArtifactBytes)})` : ""}`);
    }
  }
  html += kv("Artifacts preserved (campaign)", s.artifactsPreserved);
  html += kv("Evidence volume (campaign)", fmtBytes(s.artifactBytesTotal));
  html += kv("Analysis phases done", s.analysisPhasesCompleted);
  html += kv("Avg. CPR so far", s.avgCpr != null ? s.avgCpr.toFixed(3) : "—");
  // CPR per repetition, in order -- the actual number this whole platform's
  // reproducibility question hinges on. A flat trend across many reps is
  // itself a real finding; a sudden drop stands out immediately here
  // instead of needing to remember and compare each repetition beat by
  // beat.
  if (s.cprValues?.length) {
    html += sectionHeading("CPR per repetition");
    for (const v of s.cprValues) html += kv(`Rep ${v.rep}`, v.cpr.toFixed(3));
  }
  // Short scrollback of what just happened -- independent of whatever beat
  // the Stage Detail panel is showing right now, useful once played past
  // it or after jumping around.
  if (s.recentBeats?.length) {
    html += sectionHeading("Recent beats");
    html += `<div class="events-list">`;
    for (const b of [...s.recentBeats].reverse()) {
      const ts = b.started_at ? esc(fmt(b.started_at)) : "";
      html += `<div class="event-row"><b>${esc(b.title)}</b>${b.repetition_number ? ` · Rep ${b.repetition_number}` : ""}${ts ? `<br>${ts}` : ""}</div>`;
    }
    html += `</div>`;
  }
  reconProgressBody.innerHTML = html;
}

// Right panel: deep, real detail for whatever beat is CURRENTLY on screen --
// same real payload fields already fetched for the 3D boxes, just laid out
// as readable rows here too.
function renderReconStageDetail(beat) {
  reconStageSubtitle.textContent = beat.available ? esc(beat.title) : `${esc(beat.title)} (not available)`;
  const p = beat.payload || {};
  let html = "";
  if (beat.kind === "deployment") {
    const inst = p.instance || {};
    const installed = (inst.tools || []).filter((t) => String(t.status).toUpperCase() === "INSTALLED").length;
    html += kv("Instance", esc(inst.name));
    html += kv("Flavor", esc(inst.flavor_id));
    html += kv("Private IP", esc(inst.ip_private));
    html += kv("Floating IP", esc(inst.ip_floating));
    html += kv("Created", esc(fmt(inst.created_at)));
    html += kv("Tools installed", `${installed} / ${(inst.tools || []).length}`);
  } else if (beat.kind === "tool_install") {
    const tool = p.tool || {};
    html += kv("Tool", esc(tool.tool_name));
    html += kv("Host", esc(p.instance?.name));
    html += kv("Installed at", esc(fmt(tool.installed_at)));
    if (beat.real_duration_seconds != null) html += kv("Install duration", fmtElapsed(beat.real_duration_seconds));
  } else if (beat.kind === "attack") {
    const a = p.attack || {};
    html += kv("Attack", esc(a.attack_name));
    html += kv("Catalog ID (MITRE-aligned)", esc(a.attack_profile_id));
    html += kv("Protocol", esc(a.protocol));
    html += kv("Function code", esc(a.function_code));
    html += kv("Register", esc(a.register));
    html += kv("Value written", esc(a.value));
    html += kv("Target", esc(a.target_node));
    // Real absolute timestamps, not just the elapsed duration -- the user
    // explicitly asked for "the times of each thing, when it happened", not
    // just a summary number.
    html += kv("Started (real)", esc(fmt(a.started_at)));
    html += kv("Completed (real)", esc(fmt(a.completed_at)));
    if (beat.real_duration_seconds != null) html += kv("Duration", fmtElapsed(beat.real_duration_seconds));
    html += interpretationBox("mixed", "This is the real command sent to the industrial process -- the next beat (Detection) shows whether the security monitoring actually caught it, and the full real history of every attempt it took to get a reliable alert match, not just the final outcome.");
  } else if (beat.kind === "intervention") {
    // Explicit "did this fault injection actually work, and was it
    // detected" callout -- user feedback 2026-10-14: this real data was
    // already flowing in (effect_verified's status/detail IS fault_injection's
    // own measure_effectiveness() result, twin_observed IS the digital twin
    // genuinely noticing it) but was only visible buried inside the generic
    // 6-phase strip below, with no explicit success/detection verdict. Reads
    // directly from the SAME phase_timeline the strip below also renders --
    // nothing new fetched, just surfaced plainly before it.
    const pt = p.phase_timeline || {};
    const phases = pt.phases || [];
    const findPhase = (name) => phases.find((ph) => ph.phase === name);
    const effectPhase = findPhase("effect_verified");
    const twinPhase = findPhase("twin_observed");
    html += kv("Fault injection", esc(pt.type || "intervention"));
    html += kv("Target", esc(pt.target_node_name || pt.target_node_id));
    if (effectPhase) {
      const effBadge = effectPhase.status === "done" ? badge("ok", "Effective -- yes")
        : effectPhase.status === "failed" ? badge("failed", "Effective -- no")
        : badge("pending", "Effect not yet measured");
      html += kv("Did it succeed?", effBadge);
      if (effectPhase.detail) html += kv("Effect evidence (real)", esc(effectPhase.detail));
    }
    if (twinPhase) {
      const detBadge = twinPhase.status === "done" ? badge("ok", "Detected by digital twin") : badge("pending", "Not detected yet");
      html += kv("Was it detected?", detBadge);
    }
    let interpTone = "mixed", interpText;
    if (effectPhase?.status === "failed") {
      interpTone = "bad";
      interpText = "This fault injection did not actually take hold on the real machine -- the measured effect never matched what was expected.";
    } else if (effectPhase?.status !== "done") {
      interpText = "This fault injection's real effect has not been measured yet at this point in the replay." +
        (twinPhase?.status === "done" ? " The digital twin has already recorded noticing something on this node independently of that measurement." : "");
    } else if (twinPhase?.status === "done") {
      interpTone = "good";
      interpText = "This fault injection took real effect AND the digital twin genuinely noticed the resulting divergence -- both the injection and the detection mechanism worked as intended.";
    } else {
      interpText = "This fault injection took real effect, but the digital twin has not (yet, at this point in the replay) recorded noticing a divergence from it.";
    }
    html += interpretationBox(interpTone, interpText);
    // Same real phase-timeline widget already verified live in Digital Twin
    // View's node panel -- reused unchanged here, fed from this beat's own
    // already-fetched payload instead of a fresh API call, since the whole
    // point of reconstruction mode is replaying data already on disk.
    html += renderPhaseTimelineHtml(p.phase_timeline);
  } else if (beat.kind === "detection") {
    const d = p.detection || {};
    html += interpretationBox(
      d.outcome === "detected" ? "good" : "bad",
      d.outcome === "detected"
        ? "The security monitoring (Suricata/Wazuh) caught this real attack on its own, in time to trigger evidence preservation."
        : "The security monitoring did NOT catch this real attack -- it happened without raising an alert, so nothing automatically preserved evidence for it."
    );
    html += kv("Historical outcome", badge(d.outcome));
    html += kv("Matched alert rule", esc(d.trigger_alert_rule));
    html += kv("Severity", severityBadge(d.trigger_alert_severity));
    html += kv("Alert timestamp (real)", esc(fmt(d.trigger_alert_timestamp)));
    // trigger_alert_mitre is the SIEM/IDS's OWN real-time technique tag on
    // the matched alert (Wazuh/Suricata's own mitre_mapping field) -- a
    // DIFFERENT real evidence trail than the attack's own catalog ID above
    // or forensic_twin's post-hoc mapping (see digital_twin_view.js /
    // forensic_twin's own MITRE badges) -- shown distinctly so it reads as
    // "what the detector itself concluded", not a duplicate of the other two.
    if (d.trigger_alert_mitre?.length) {
      html += kv("MITRE technique (SIEM-detected)", d.trigger_alert_mitre.map((t) => `<span style="display:inline-block;margin-right:4px;padding:1px 7px;border-radius:999px;font-size:10px;font-weight:700;color:var(--cyan);border:1px solid var(--cyan);">${esc(t)}</span>`).join(""));
    }
    html += kv("Trigger attempts (real)", esc(d.trigger_attempts_total));

    // Full real history of every attempt it took to get a reliable alert
    // match -- not just the final outcome. Each attempt already carries its
    // OWN real attack window and its own detection result; user explicitly
    // asked for "the complete history including the times of each thing,
    // when it happened", since a campaign that needed 3 retries to get a
    // clean alert match is itself an important real finding this view was
    // previously hiding.
    const trace = d.trigger_attempt_trace || [];
    if (trace.length) {
      html += sectionHeading(`Full detection history -- ${trace.length} real attempt(s)`);
      if (trace.length > 1) {
        html += interpretationBox("mixed", `Detection did not succeed on the first try -- it took ${trace.length} real attempts before a reliable alert match was found. Each attempt below re-launched the real attack and re-waited for a real Wazuh/Suricata alert.`);
      }
      trace.forEach((t) => {
        const detected = !!t.trigger_alert_detected;
        html += `<div class="event-row" style="border-left:3px solid ${detected ? "var(--green)" : "var(--red)"};padding-left:9px;margin:4px 0 10px;">`;
        html += `<div><b>Attempt ${esc(t.attempt_number)}</b> -- attack ${esc(t.attack_status)}</div>`;
        html += `<div style="font-size:11px;opacity:0.85;">Attack window (real): ${esc(fmt(t.attack_started_at))} &rarr; ${esc(fmt(t.attack_completed_at))}</div>`;
        if (detected) {
          html += `<div style="font-size:11px;margin-top:3px;">Alert matched: <b>${esc(t.trigger_alert_rule || "n/a")}</b> (severity ${severityBadge(t.trigger_alert_severity)}, id ${esc(t.trigger_alert_id || "n/a")})</div>`;
        } else {
          html += `<div style="font-size:11px;margin-top:3px;color:var(--red);">No alert matched -- ${esc(t.observed_alerts_count ?? 0)} real alert(s) observed in this window, none matched this attack</div>`;
        }
        html += `<div style="font-size:11px;opacity:0.85;">Eligible for forensic intervention: ${t.forensic_intervention_eligible ? "yes" : "no"}${t.eligibility_reason ? " -- " + esc(t.eligibility_reason) : ""}</div>`;
        if (t.automatic_preservation_armed) html += `<div style="font-size:11px;color:var(--green);">Automatic evidence preservation armed</div>`;
        if (t.fallback_reasons?.length) html += `<div style="font-size:11px;opacity:0.7;">Fallback: ${esc(t.fallback_reasons.join("; "))}</div>`;
        if (t.background_case_detected) html += `<div style="font-size:11px;opacity:0.7;">Adopted background case: ${esc(t.background_case_detected.case_id || "n/a")}</div>`;
        html += `</div>`;
      });
    }
  } else if (beat.kind === "case_created") {
    const c = p.case || {};
    html += kv("Case ID", esc(c.case_real_name || c.case_id));
    html += sectionHeading("Evidence pipeline");
    for (const step of c.evidence_pipeline || []) {
      html += kv(step.label, badge(step.status));
      // The actual reason a step is "partial"/"blocked" (real text, e.g.
      // "forensic analysis has not been generated for this case") -- this
      // is the concrete answer to "why isn't this at 100%", not just the
      // status color.
      if (step.detail && step.status !== "completed") {
        html += `<div class="event-row" style="margin-top:-2px;margin-bottom:4px;">${esc(step.detail)}</div>`;
      }
    }
    // Real TOTAL per acquisition phase, summed across every host that went
    // through it -- each later preservation_step beat only shows ONE host's
    // own slice (e.g. "Memory acquisition: 3m 3s"), which is accurate but
    // reads as short in isolation when a case has 3+ hosts. User explicitly
    // asked (2026-10-11) to re-verify these durations; this total was the
    // real number missing, not a correction of a wrong one -- see
    // monitor3d/README.md for the verification this came from.
    const totals = p.phase_totals || [];
    if (totals.length) {
      html += sectionHeading("Real totals across all hosts (not just one)");
      totals.forEach((t) => {
        const spanNote = t.span_seconds != null && Math.abs(t.span_seconds - t.total_elapsed_seconds) > 5
          ? ` (wall-clock span ${fmtElapsed(t.span_seconds)} -- hosts ran one after another, not in parallel)`
          : "";
        html += kv(`${t.label} (${t.host_count} host${t.host_count === 1 ? "" : "s"})`, `${fmtElapsed(t.total_elapsed_seconds)}${spanNote}`);
      });
    }
    // Reality Gap (hueco #5, "contextual reality gap") -- opt-in only
    // (#reality-gap-toggle), never computed by default: each check below
    // triggers a real, fresh SSH probe per host, same cost tier as
    // forensic_twin.html's own "Check a Node" button. Filled in
    // asynchronously by loadRealityGap() right after this beat's main HTML
    // is already on screen -- see its call site at the end of
    // renderReconStageDetail.
    if (realityGapToggle?.checked) {
      html += sectionHeading("Reality Gap vs. current twin");
      html += `<div id="reality-gap-mount"><div class="detail-empty">Checking the twin's current reference model against what it really was for this case (real SSH probe, a few seconds per host)&hellip;</div></div>`;
    }
  } else if (beat.kind === "preservation_step" || beat.kind === "analysis_phase") {
    const e = p.stage_timeline_entry || {};
    html += kv("Stage", esc(e.label));
    html += kv("Status", badge(e.status));
    if (e.elapsed_seconds != null) html += kv("Real elapsed", fmtElapsed(e.elapsed_seconds));
    if (e.target_ip) html += kv("Target IP", esc(e.target_ip));
    if (e.size_bytes != null) html += kv("Size", fmtBytes(e.size_bytes));
    if (e.sha256) html += kv("SHA-256", `<span style="font-size:9px;">${esc(e.sha256.slice(0, 20))}&hellip;</span>`);
    if (e.rel_path) html += kv("Path", `<span style="font-size:9px;word-break:break-all;">${esc(e.rel_path)}</span>`);
    if (e.error_detail) html += kv("Error", `<span style="color:var(--red);">${esc(e.error_detail)}</span>`);
  } else if (beat.kind === "reconstruction") {
    const status = p.causal_status || {};
    const metrics = status.metrics_preview || {};
    html += kv("CPR (C0 — forensic attestation)", metrics.causal_path_recoverability ?? "—");
    html += kv("Analysis coverage", metrics.analysis_coverage_ratio != null ? `${Math.round(metrics.analysis_coverage_ratio * 100)}%` : "—");
    html += kv("Ambiguous edges", metrics.ambiguous_edges ?? "—");
    html += kv("Ground truth", esc(status.ground_truth_summary?.ground_truth_status));
    const cprVerdict = interpretCpr(metrics.causal_path_recoverability);
    if (cprVerdict) html += interpretationBox(cprVerdict.tone, cprVerdict.text);
    // Evidence strength per edge (foc_causal_reconstruction, 2026-10-10):
    // how each recovered edge was actually proven -- a "causal" edge has a
    // confirmed cause-before-effect order, a "co_occurrence" edge only shows
    // both things happened without proving one caused the other. Purely a
    // read of the already-computed `evidence_strength` field on each edge
    // in this beat's own payload -- never recomputed here.
    const edges = p.edges || [];
    if (edges.length) {
      const counts = { causal: 0, temporal: 0, co_occurrence: 0, unclassified: 0 };
      for (const e of edges) counts[e.evidence_strength || "unclassified"] = (counts[e.evidence_strength || "unclassified"] || 0) + 1;
      html += sectionHeading("Evidence strength per edge");
      html += kv("Causal (cause confirmed before effect)", counts.causal);
      html += kv("Temporal (order unconfirmed)", counts.temporal);
      html += kv("Co-occurrence only (not proven causal)", counts.co_occurrence);
      html += kv("Unclassified (missing evidence)", counts.unclassified);
      html += interpretationBox(
        counts.causal >= counts.co_occurrence + counts.unclassified ? "good" : "mixed",
        "\"Causal\" means this edge's evidence proves the cause really happened before its effect, in order -- the strongest kind of forensic proof. \"Co-occurrence\" means the evidence only shows two things happened near each other in time, not that one caused the other."
      );
    }
    // C3 CPR (forge_dt_metrics, 2026-10-10): the SAME edges re-checked
    // against an independent evidence path (Intervention Ledger + post-hoc
    // Linker + Evidence Bridge) instead of foc_causal_reconstruction's own
    // attestation chain -- a real, substantive "second opinion" on the
    // exact same case. Only ever moves CPR up from C0, never down.
    const c3 = p.c3;
    if (c3 && c3.ok) {
      html += sectionHeading("CPR (C3 — independent twin corroboration)");
      html += kv("C3 CPR", c3.c3_cpr ?? "—");
      html += kv("Independently confirmed", c3.independently_confirmed ? "yes" : "no");
      if (c3.independently_confirmed) html += kv("Confirming intervention", esc(c3.confirming_intervention_id));
      if (c3.c3_cpr != null && c3.c0_cpr != null && c3.c3_cpr > c3.c0_cpr) {
        html += interpretationBox("good", `Independent confirmation from the digital twin raised this case's recoverability from ${c3.c0_cpr} to ${c3.c3_cpr} -- real intervention data the twin itself observed proved a step the forensic attestation chain alone could not.`);
      } else if (c3.independently_confirmed === false) {
        html += interpretationBox("mixed", "Nothing new to confirm here independently -- either no real intervention was applied against this case's host, or C0's own attestation already covered everything.");
      }
    }
    html += sectionHeading("Execution");
    html += kv("Execution status", esc(status.execution_status));
    html += kv("Degraded OK", status.degraded_ok ? "yes" : "no");
    html += kv("Stale", status.is_stale ? "yes" : "no");
    if (status.errors?.length) html += kv("Errors", `<span style="color:var(--red);">${esc(status.errors.join("; "))}</span>`);
  } else if (beat.kind === "seal") {
    const integ = p.integrity || {};
    html += interpretationBox(
      integ.case_sealed ? "good" : "bad",
      integ.case_sealed
        ? "This case's evidence is locked and fingerprinted -- if anyone tampers with a file afterward, that change would be detectable."
        : "This case was never sealed -- its evidence has no tamper-evidence guarantee, so a later change to a file couldn't be proven to have happened."
    );
    html += kv("Sealed", integ.case_sealed ? "yes" : "no");
    html += kv("Artifacts", `${fmt(integ.artifacts_with_hash)} / ${fmt(integ.artifacts_total)} hashed`);
    html += kv("Manifest present", integ.manifest_present ? "yes" : "no");
    if (integ.manifest_hash) html += kv("Manifest hash", `<span style="font-size:9px;">${esc(integ.manifest_hash.slice(0, 20))}&hellip;</span>`);
    html += kv("Manifest verified live", integ.manifest_hash_verified_live ? "yes" : "no");
    html += kv("Custody present", integ.custody_present ? "yes" : "no");
    html += kv("Custody entries", fmt(integ.custody_entries));
    html += kv("Last custody action", esc(fmt(integ.last_custody_action)));
  } else if (beat.kind === "repetition_summary") {
    html += p.narrative
      ? kv("Narrative", esc(String(p.narrative).slice(0, 200)))
      : `<div class="detail-empty">No narrative report available for this repetition.</div>`;
  } else if (beat.kind === "campaign_finale") {
    const report = p.comparison_report || {};
    if (report.verdict) html += interpretationBox(report.all_delta_wcpr_acceptable ? "good" : "bad", report.verdict);
    html += kv("All Δwcpr acceptable", report.all_delta_wcpr_acceptable ? "yes" : "no");
    for (const c of report.comparisons || []) {
      html += sectionHeading(`CPR A/B`);
      html += kv("CPR A", c.cpr_a);
      html += kv("CPR B", c.cpr_b);
      html += kv("ΔCPR", c.delta_cpr);
      html += kv("Δwcpr acceptable", c.delta_wcpr_acceptable ? "yes" : "no");
      // Real reproducibility diff between the two repetitions being
      // compared -- exactly what "is this campaign reproducible" is
      // actually checking, not just the headline CPR numbers.
      const diff = c.diff_summary || {};
      if (Object.keys(diff).length) {
        html += sectionHeading("Reproducibility diff (A vs B)");
        for (const [field, pair] of Object.entries(diff)) {
          const same = JSON.stringify(pair?.a) === JSON.stringify(pair?.b);
          html += kv(field.replace(/_/g, " "), same ? esc(fmt(pair?.a)) : `<span style="color:var(--amber);">${esc(fmt(pair?.a))} → ${esc(fmt(pair?.b))}</span>`);
        }
      }
    }
  } else if (beat.kind === "campaign_failed") {
    // The chronologically-correct "here it stopped" moment -- reuses the
    // exact same renderFailureForensics() already built for
    // campaign_failure_forensics, just reached through normal playback
    // instead of shown up front. See renderFailureForensics's own comment
    // for the full design history.
    html += renderFailureForensics(beat.payload?.failure_report);
  } else {
    html = `<div class="detail-empty">No detail available for this beat.</div>`;
  }
  if (beat.detail_lines?.length) {
    html += sectionHeading("Summary");
    html += beat.detail_lines.map((l) => `<div class="event-row">${esc(l)}</div>`).join("");
  }
  reconStageBody.innerHTML = html;
  if (beat.kind === "case_created" && realityGapToggle?.checked) loadRealityGap(beat);
}

// Reality Gap vs. current twin (hueco #5, Sammartino & Pasquini's
// "contextual reality gap") -- queries, per real host in this case, whether
// the twin's CURRENT Suricata/Wazuh config + expected-ports reference model
// still matches what it really was when this case was built, or has
// silently drifted since. One real SSH probe per host via
// forensic_twin.compute_reality_gap -- never automatic, only when the
// toggle is on, since it is genuinely not free. `as_of` is the case's own
// real `case_created_utc`, not "now".
function renderRealityGapKind(label, g) {
  if (!g) return "";
  if (!g.comparable) {
    return `<div class="event-row" style="opacity:0.7;">${esc(label)}: ${esc(g.reason)}</div>`;
  }
  if (g.same_baseline) {
    return `<div class="event-row" style="color:var(--green);">${esc(label)}: same reference model used then and now -- no drift.</div>`;
  }
  const note = g.drifted
    ? `<span style="color:var(--amber);">drifted since then -- ${g.changed.length} changed, ${g.added.length} added, ${g.removed.length} removed vs. the reference that was really in effect for this case</span>`
    : `<span style="color:var(--green);">reference was recaptured since, but the real content is unchanged -- no drift</span>`;
  return `<div class="event-row">${esc(label)}: ${note}</div>`;
}

function renderRealityGapHost(hostName, data) {
  if (!data || !data.ok) {
    return `<div class="event-row" style="opacity:0.6;">${esc(hostName)}: ${esc((data && data.error) || "not reachable right now")}</div>`;
  }
  return `<div class="kv-row" style="flex-direction:column;align-items:flex-start;gap:2px;"><div class="k">${esc(hostName)}</div>${renderRealityGapKind("Config baseline", data.config)}${renderRealityGapKind("Network baseline", data.network)}</div>`;
}

async function loadRealityGap(beat) {
  const mount = document.getElementById("reality-gap-mount");
  if (!mount) return;
  const hosts = (beat.payload?.hosts || []).filter((h) => h.name);
  const asOf = beat.payload?.case?.case_created_utc;
  if (!hosts.length || !asOf) {
    mount.innerHTML = `<div class="detail-empty">No case/host data available to compare for this repetition.</div>`;
    return;
  }
  const rows = [];
  for (const h of hosts) {
    try {
      const res = await fetch(`/api/forensic-twin/reality-gap/${encodeURIComponent(h.name)}?as_of=${encodeURIComponent(asOf)}`, { method: "POST" });
      rows.push(renderRealityGapHost(h.name, await res.json()));
    } catch (e) {
      rows.push(renderRealityGapHost(h.name, { ok: false, error: String(e) }));
    }
    // Re-check the mount still exists and the toggle is still on after each
    // await -- the user may have navigated to a different beat or turned
    // the toggle off mid-flight (several real SSH probes in sequence can
    // take a while); stop silently instead of overwriting newer content.
    if (!document.getElementById("reality-gap-mount") || !realityGapToggle?.checked) return;
  }
  mount.innerHTML = rows.join("") || `<div class="detail-empty">No comparable hosts for this case.</div>`;
}

let lastRenderedBeat = null;

reconstruction.onBeatChange((beat, index, total) => {
  const ts = beat.started_at ? esc(beat.started_at) : "";
  reconBeatLabel.textContent = beat.available ? esc(beat.title) : `${esc(beat.title)} (not available)`;
  reconProgress.textContent = `Rep ${beat.repetition_number ?? "—"} · beat ${index + 1}/${total}${ts ? " · " + ts : ""}`;
  renderReconProgress();
  lastRenderedBeat = beat;
  renderReconStageDetail(beat);
  // The moment playback genuinely reaches the real failure beat (never
  // before), pin a persistent copy of the same account into the always-on
  // left panel -- so it stays available for further inspection even if the
  // user later scrubs back to an earlier beat and Stage Detail (right
  // panel) moves on to show that instead.
  if (beat.kind === "campaign_failed") {
    reconFailurePanel.hidden = false;
    reconFailureBody.innerHTML = renderFailureForensics(beat.payload?.failure_report);
  }
});

// Flipping the toggle while already looking at a case_created beat
// re-renders immediately -- otherwise it would only take effect the next
// time playback happens to land on a case_created beat again.
realityGapToggle?.addEventListener("change", () => {
  if (lastRenderedBeat?.kind === "case_created") renderReconStageDetail(lastRenderedBeat);
});

const forensicTwinWatcherToggle = document.getElementById("forensic-twin-watcher-toggle");
forensicTwinWatcherToggle?.addEventListener("change", () => {
  reconstruction.setTwinWatcherEnabled(forensicTwinWatcherToggle.checked);
});

reconToggleBtn.addEventListener("click", async () => {
  const willShow = !reconBar.classList.contains("visible");
  reconBar.classList.toggle("visible", willShow);
  reconToggleBtn.classList.toggle("active", willShow);
  if (willShow) {
    if (liveAttackToggleBtn.classList.contains("active")) liveAttackToggleBtn.click(); // mutually exclusive
    if (digitalTwinToggleBtn.classList.contains("active")) digitalTwinToggleBtn.click(); // mutually exclusive
    // Opening the panel is what enters reconstruction mode now -- the live
    // scene is cleared right here, not only once Play is first pressed.
    reconstruction.enter();
    setReconPanelsVisible(true);
    renderReconProgress();
    if (!reconSelect.dataset.loaded) {
      try {
        const res = await fetch("/api/level-c/jobs", { cache: "no-store" });
        const data = await res.json();
        const jobs = data.jobs || [];
        reconSelect.innerHTML = `<option value="">Select a campaign&hellip;</option>` + jobs.map(
          (j) => `<option value="${esc(j.job_id)}" data-status="${esc(j.status)}">${esc(j.job_id)} · ${esc(j.status)} · ${esc(fmt(j.created_at))}</option>`
        ).join("");
        reconSelect.dataset.loaded = "1";
      } catch (err) {
        reconBeatLabel.textContent = `Could not load campaign list: ${err.message}`;
      }
    }
  } else {
    // Closing the panel is equivalent to Exit -- avoids a dead-end state
    // with the transport controls hidden and no visible way back to live.
    reconstruction.exitReconstruction();
    reconBeatLabel.textContent = "";
    reconProgress.textContent = "";
    setReconPanelsVisible(false);
  }
});

const liveAttackToggleBtn = document.getElementById("live-attack-toggle-btn");
liveAttackToggleBtn.addEventListener("click", async () => {
  const willShow = !liveAttackToggleBtn.classList.contains("active");
  liveAttackToggleBtn.classList.toggle("active", willShow);
  if (willShow) {
    if (reconBar.classList.contains("visible")) reconToggleBtn.click(); // mutually exclusive with reconstruction mode
    if (digitalTwinToggleBtn.classList.contains("active")) digitalTwinToggleBtn.click(); // mutually exclusive with digital twin view
    await liveAttack.enter();
  } else {
    liveAttack.exit();
  }
});

const digitalTwinToggleBtn = document.getElementById("digital-twin-toggle-btn");
digitalTwinToggleBtn.addEventListener("click", async () => {
  const willShow = !digitalTwinToggleBtn.classList.contains("active");
  digitalTwinToggleBtn.classList.toggle("active", willShow);
  if (willShow) {
    if (reconBar.classList.contains("visible")) reconToggleBtn.click(); // mutually exclusive with reconstruction mode
    if (liveAttackToggleBtn.classList.contains("active")) liveAttackToggleBtn.click(); // mutually exclusive with live attack view
    await digitalTwin.enter();
  } else {
    digitalTwin.exit();
  }
});

// Deep link from forensic_twin.html's "Open 3D Digital Twin View" button
// (?view=digital-twin) -- lets that 2D control panel jump straight into this
// mode instead of requiring a manual click here every time.
if (new URLSearchParams(window.location.search).get("view") === "digital-twin") {
  digitalTwinToggleBtn.click();
}

// Campaign Failure Forensics (2026-10-11) -- a FAILED job rarely has a
// clean, fully-played-out beat timeline to replay (that's the whole point:
// it died partway through), so instead of forcing it through the normal
// playback UI, picking one in this same dropdown shows a real,
// evidence-grounded account of why it actually stopped -- reusing data
// this platform already records (the job's own log, including real
// load/mem/swap readings, and the orchestrator server's own independent
// memory watchdog), never a guess. See
// campaign_failure_forensics/README.md for the full design and the real
// false-positive it was caught and fixed against before shipping.
function renderFailureForensics(r) {
  if (!r || !r.ok) {
    return `<div class="detail-empty">${esc((r && r.error) || "Could not load failure forensics for this job.")}</div>`;
  }
  const toneByCause = {
    undetermined: "mixed",
    scenario_vm_resource_exhaustion: "mixed",
    server_resource_exhaustion: "bad",
    host_and_server_resource_exhaustion: "bad",
  };
  let html = "";
  html += kv("Phase at failure", esc(r.phase_at_failure));
  html += kv("Declared error (the watchdog's own symptom message)", esc(r.declared_error));
  html += sectionHeading("Real timeline reconstructed from this job's own log");
  html += kv("Last real activity", `${esc(fmt(r.last_real_activity?.ts))} -- ${esc(r.last_real_activity?.msg)}`);
  html += kv("Declared failed at", esc(fmt(r.declared_failed_at)));
  html += kv("Silence before being declared dead", r.silence_seconds != null ? fmtElapsed(r.silence_seconds) : "—");
  const snap = r.scenario_vm_host_snapshot;
  if (snap) {
    html += sectionHeading("Scenario VM's own last resource reading before the silence");
    html += kv("Load", `${esc(fmt(snap.load_1m))} / ${esc(fmt(snap.cpu_count))} cores (ratio ${esc(fmt(snap.load_ratio))}) -- ${severityBadge(snap.load_severity)}`);
    html += kv("Memory used", `${esc(fmt(snap.mem_used_pct))}% -- ${severityBadge(snap.mem_severity)}`);
    html += kv("Swap used", `${esc(fmt(snap.swap_used_pct))}% -- ${severityBadge(snap.swap_severity)}`);
  }
  const mw = r.server_memory_watchdog;
  if (mw) {
    html += sectionHeading("Orchestrator server's own independent memory watchdog, same window");
    html += kv("Events in this window", `${mw.events?.length ?? 0} (${esc(fmt(mw.window_rate_per_min))}/min)`);
    html += kv("Baseline rate (preceding 3h)", `${esc(fmt(mw.baseline_rate_per_min))}/min`);
    html += kv("Assessment", mw.is_spike
      ? `<span style="color:var(--red);">real spike -- meaningfully above the baseline rate</span>`
      : mw.chronic
        ? `<span style="color:var(--text-dim);">chronic background rate -- NOT a spike tied to this failure, weak evidence</span>`
        : `<span style="color:var(--green);">no unusual activity</span>`);
  }
  html += interpretationBox(
    toneByCause[r.probable_cause] || "mixed",
    `Probable cause: ${(r.probable_cause || "undetermined").replace(/_/g, " ")} (confidence: ${r.confidence}). ${r.explanation}`
  );
  return html;
}

// Real data-loss bug found 2026-10-11: a failed campaign that completed
// some repetitions before dying can have real scenario snapshots on disk
// (proven by its own log: "Snapshot captured: SS-...") that never got
// linked into job_state.json's level_c_snapshot_ids -- without them,
// monitor3d has no host/machine data to draw at all for those repetitions,
// which is exactly what looked like "no reconstruye nada visualmente" to
// the user. Narrow, evidence-based, one-field repair -- see
// recover_missing_snapshot_ids's own docstring in service.py. Tried
// silently before every timeline load for a failed job; a no-op (and
// invisible) when there's nothing to repair.
async function tryRecoverSnapshotIds(jobId) {
  try {
    const res = await fetch(`/api/campaign-failure-forensics/${encodeURIComponent(jobId)}/recover-snapshot-ids`, { method: "POST" });
    return await res.json();
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

reconSelect.addEventListener("change", async () => {
  const jobId = reconSelect.value;
  const status = reconSelect.selectedOptions[0]?.dataset.status;
  setTransportEnabled(false);
  reconBeatLabel.textContent = "";
  reconProgress.textContent = "";
  reconStageBody.innerHTML = `<div class="detail-empty">Nothing played yet.</div>`;
  reconStageSubtitle.textContent = "Current beat";
  // Deliberately NOT shown immediately on selection, even for a failed
  // campaign -- user's own correction, 2026-10-12: the real "why it failed"
  // account should appear exactly when playback reaches that moment (its
  // own real "campaign_failed" beat, see reconstruction.js::handleCampaignFailed
  // and this file's own "campaign_failed" branch in renderReconStageDetail),
  // not as a spoiler shown before pressing Play. This panel only gets
  // un-hidden and filled in, as a persistent pinned copy, once that beat is
  // actually reached -- see the onBeatChange callback below.
  reconFailurePanel.hidden = true;
  if (!jobId) return;
  // Silent, invisible data repair (see tryRecoverSnapshotIds's own comment)
  // -- never shown as a message, since even announcing "real data was
  // recovered for this campaign" would itself hint that it's the failed
  // one before the user has pressed Play.
  if (status === "failed") await tryRecoverSnapshotIds(jobId);
  // Timeline loading is identical for every job regardless of status -- a
  // failed campaign still has real beats for whatever it completed before
  // dying (deployment, maybe an attack/detection), and plays back through
  // this exact same flow, Stage Detail panel included.
  reconBeatLabel.textContent = "Loading timeline…";
  try {
    const { totalBeats } = await reconstruction.loadTimeline(jobId);
    reconBeatLabel.textContent = `Loaded ${totalBeats} beats — press Play`;
    setTransportEnabled(true);
    renderReconProgress();
  } catch (err) {
    reconBeatLabel.textContent = `Could not load reconstruction timeline: ${err.message}`;
  }
});

reconSpeedInput.addEventListener("input", () => {
  const v = parseFloat(reconSpeedInput.value) || 1;
  reconstruction.setSpeed(v);
  reconSpeedLabel.textContent = `${v}x`;
});

reconPlayBtn.addEventListener("click", () => reconstruction.play());
reconPauseBtn.addEventListener("click", () => reconstruction.pause());
// VCR-style scrubbing (2026-10-12): pause-and-go-back for investigating a
// moment just before something, without losing the whole replay position
// the way Reset would. reconstruction.stepBack/stepForward already pause
// and rebuild the scene up to the exact target beat; onBeatChange (already
// wired) re-renders Stage Detail/the left progress panel for wherever it
// lands, same as normal playback.
reconStepBackBtn.addEventListener("click", () => reconstruction.stepBack());
reconStepFwdBtn.addEventListener("click", () => reconstruction.stepForward());
reconResetBtn.addEventListener("click", () => {
  reconstruction.reset();
  renderReconProgress();
  reconStageBody.innerHTML = `<div class="detail-empty">Nothing played yet.</div>`;
  reconStageSubtitle.textContent = "Current beat";
});
reconExitBtn.addEventListener("click", () => {
  reconstruction.exitReconstruction();
  reconBeatLabel.textContent = "";
  reconProgress.textContent = "";
  reconBar.classList.remove("visible");
  reconToggleBtn.classList.remove("active");
  setReconPanelsVisible(false);
  reconFailurePanel.hidden = true;
});
