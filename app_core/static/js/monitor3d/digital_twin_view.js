import { createEntityBox, createFloatingLabel, disposeEntity, recolorEntity, setSelected, statusColor, updateBadge, updateStatLines, BOX_COLOR_DEFAULT } from "./entities.js";
import { applyRowLayout } from "./layout.js";
import { buildHostVisual } from "./host-visuals.js";
import { monitorBridge } from "./app.js";
import * as faultDrawer from "./digital_twin_fault_drawer.js";
import { renderNodeTimelineInto } from "./phase_timeline.js";

// Digital Twin View -- a sibling mode to Live Attack View, reusing the same
// node-only 3D layout and entity primitives (createEntityBox,
// createFloatingLabel, applyRowLayout, buildHostVisual, monitorBridge; same
// pattern live_attack.js already established for a dedicated, campaign-free
// mode). Colors each real scenario node by its LAST already-computed
// forensic_twin state (app_core/infrastructure/forensic_twin):
//   GET /api/forensic-twin/state/<id>   (per-node last check)
//   GET /api/forensic-twin/events       (divergence events, polled for new ones)
//   GET /api/forensic-twin/continuous/status  (best-effort "next check" estimate)
// Mostly read-only, with one deliberate exception: if a node's last state is
// missing or only "light tier" (no live clock/PLC reading -- see
// checkOneNode below), this view triggers ONE real on-demand check per node
// per view-entry (POST /api/forensic-twin/check/<id>) so the real-vs-expected
// comparison the dashboard exists to show is actually populated, not just a
// gray "not checked yet" box.
// A node is green once it has been checked at least once with no open
// divergence; it turns red the instant a real divergence event naming that
// node is seen here for the first time, with a transient floating label
// showing the event type and evidence -- gray/"unknown" until its first
// real check comes back, never invented as healthy by default. Clicking a
// node shows its full real-vs-expected state in the right-hand detail panel
// (see handleSelect/renderNodeDetail).

const POLL_MS = 15000; // cheap: only reads forensic_twin's own already-computed state/events, never a live SSH/Modbus check itself
const EVENT_FLASH_MS = 12000;

let active = false;
let pollTimer = null;
let savedState = null;
let nodeBoxes = new Map(); // instance_id -> box group
let liveObjects = [];
let transientTimers = [];
let seenEventKeys = new Set();
// Per-node recent divergence events, rebuilt fresh every pollEvents() tick
// (not accumulated) -- feeds renderNodeDetail's "Recent divergence events"
// section, which needs the real mitre_attck_ics field already written by
// forensic_twin.service._record_event, not just the transient flash labels
// spawnEventFlash already shows.
let recentEventsByNode = new Map();
let feedItems = [];
let feedIdSeq = 0;
// Best last_tick_at/interval_seconds ever seen across polls. Necessary
// because gunicorn runs several worker processes and only the one holding
// forensic_twin's leader lock has real tick data (see
// app_core/infrastructure/forensic_twin/README.md, "Concurrency and
// resource footprint") -- most polls land on a non-leader worker and come
// back empty, so the countdown shown here is a best-effort estimate, never
// a precise live value, and is labeled as such.
let bestKnownTick = null;
// nodeId -> last time (ms) we asked forensic_twin for a real on-demand
// check, so a node that's genuinely unreachable doesn't get re-POSTed every
// 15s. NOT a one-shot "never again" flag (an earlier version was) -- a real
// bug found live: forensic_twin's own continuous monitor runs its cheap
// "light" tier tick independently (tools/services only, clock/plc always
// null) on its own 1800s timer, and its first tick right after a gunicorn
// restart can land just after this view's own one-time bootstrap check,
// silently overwriting the richer on-demand data with the lighter one --
// with no further bootstrap left to restore it, since it had already fired
// once. Nodes ended up looking genuinely unequal (only whichever node a
// human happened to separately fault-test afterward still showed full
// data) even though every node runs the exact same check. A bounded
// cooldown instead of a one-shot flag lets this view keep re-asserting the
// full picture for every node, not just the one somebody happened to poke.
let lastCheckTriggeredAt = new Map();
const BOOTSTRAP_RECHECK_COOLDOWN_MS = 60000;
// Last real state seen per node, for the detail panel -- kept separate from
// what's painted on each box (which only has room for a few short lines).
let lastStateById = new Map();
let selectedNodeId = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmt(v) {
  return v === null || v === undefined ? "n/a" : String(v);
}

// The real/expected counterpart this whole module is meant to show --
// Grieves/IBM's "two sides" of a digital twin, not just a single color.
// Built straight from forensic_twin's own already-computed state (tools,
// clock, plc.control_law/comparison), never re-derived or guessed here.
function buildStatLines(state) {
  const lines = [];
  const tools = state.tools || {};
  const expectedCount = (tools.expected_tools || []).length;
  const installedCount = (tools.installed_tools || []).length;
  const missing = tools.missing_tools || [];
  lines.push(`Tools: ${installedCount}/${expectedCount} installed${missing.length ? ` <span style="color:#ef4444">(missing: ${esc(missing.join(", "))})</span>` : ""}`);

  const services = state.services || {};
  if ((services.down || []).length) {
    lines.push(`<span style="color:#ef4444">Services down: ${esc(services.down.join(", "))}</span>`);
  }

  if (state.clock) {
    const deg = state.clock.degraded;
    lines.push(`Clock offset: ${fmt(state.clock.offset_ms)}ms${deg ? ` <span style="color:#ef4444">(degraded)</span>` : ""}`);
  }

  const plc = state.plc;
  if (plc && plc.available) {
    const cl = plc.control_law || {};
    // Level/level_max/air_valve_open ARE the real physical readings this
    // whole comparison is built on -- always shown, not just when something
    // diverges, otherwise a healthy PLC never actually shows "the real part"
    // at all (only a reassuring "matches expected" string with no numbers).
    if (cl.applicable !== false) {
      lines.push(`Tank level (real): ${esc(fmt(cl.level))} / max ${esc(fmt(cl.level_max))} &middot; branch: ${esc(cl.branch || "n/a")} &middot; air valve: ${cl.air_valve_open ? "open" : "closed"}`);
    }
    if (cl.diverged && (cl.differences || []).length) {
      cl.differences.forEach((d) => {
        lines.push(`<span style="color:#ef4444">${esc(d.canonical_name)}: real=${esc(fmt(d.observed_value))} expected=${esc(fmt(d.expected_value))}</span>`);
      });
    } else if (cl.applicable !== false) {
      lines.push(`Valves: real matches control law`);
    }
    if (plc.baseline_present) {
      const cmp = plc.comparison || {};
      // No raw per-variable values are kept once a comparison matches (only
      // a hash of each full state) -- showing both hashes always, not just
      // on divergence, is the same "hasStateHash/expectedStateHash" pattern
      // the ForensicTwin literature this module is based on uses.
      const obsHash = (cmp.observed_state_hash || "").slice(0, 12);
      const expHash = (cmp.expected_state_hash || "").slice(0, 12);
      if (cmp.diverged && (cmp.differences || []).length) {
        cmp.differences.forEach((d) => {
          lines.push(`<span style="color:#ef4444">${esc(d.canonical_name)}: real=${esc(fmt(d.observed_value))} expected=${esc(fmt(d.expected_value))}</span>`);
        });
      } else {
        lines.push(`Baseline: real matches expected`);
      }
      lines.push(`State hash (real): ${esc(obsHash)}... vs baseline: ${esc(expHash)}...`);
    } else {
      lines.push(`Baseline: not captured yet`);
    }
  }

  const configIntegrity = state.config_integrity;
  if (configIntegrity) {
    lines.push(configIntegrity.diverged
      ? `<span style="color:#ef4444">Config integrity: ${esc((configIntegrity.differences || []).length)} file(s) changed</span>`
      : `Config integrity: matches baseline`);
  }
  const networkExposure = state.network_exposure;
  if (networkExposure) {
    lines.push(networkExposure.diverged
      ? `<span style="color:#ef4444">Network: ${esc((networkExposure.new_listening_ports || []).join(", "))} (new)</span>`
      : `Network: no new listening ports`);
  }
  const resourceUsage = state.resource_usage;
  if (resourceUsage) {
    lines.push(resourceUsage.diverged
      ? `<span style="color:#ef4444">Resources: CPU ${esc(fmt(resourceUsage.cpu_usage_pct))}% &middot; Mem ${esc(fmt(resourceUsage.memory_usage_pct))}% &middot; Disk ${esc(fmt(resourceUsage.disk_root_use_pct))}%</span>`
      : `Resources: CPU ${esc(fmt(resourceUsage.cpu_usage_pct))}% &middot; Mem ${esc(fmt(resourceUsage.memory_usage_pct))}% &middot; Disk ${esc(fmt(resourceUsage.disk_root_use_pct))}%`);
  }
  const networkLatency = state.network_latency;
  if (networkLatency) {
    lines.push(networkLatency.diverged
      ? `<span style="color:#ef4444">Network RTT: ${esc(fmt(networkLatency.ping_avg_ms))}ms (floor ${esc(fmt(networkLatency.floor_ms))}ms)</span>`
      : `Network RTT: ${esc(fmt(networkLatency.ping_avg_ms))}ms`);
  }
  return lines;
}

// A node's lamp color must reflect its CURRENT divergence flags, not just
// "did the /state fetch succeed" -- an earlier version of this module
// conflated the two (any successful fetch painted the node green even with
// an open divergence already recorded in that same response).
function computeNodeHealth(state) {
  const tools = state.tools || {};
  const services = state.services || {};
  const plc = state.plc;
  // config_integrity/network_exposure are on-demand-only sensors (never run
  // by the continuous monitor, see forensic_twin.service -- a full SSH
  // probe each), so these fields are only ever populated once a human (or a
  // fault lifecycle hook, see FAULT_RELEVANT_CHECKS in that same module) has
  // actually triggered a check for this node at least once; until then they
  // stay null/undefined here and simply don't affect health, same as `plc`
  // already does for a non-PLC node.
  const configIntegrity = state.config_integrity;
  const networkExposure = state.network_exposure;
  const resourceUsage = state.resource_usage;
  const networkLatency = state.network_latency;
  const problems = [];
  if ((tools.missing_tools || []).length) problems.push("missing tools");
  if ((services.down || []).length) problems.push("service down");
  if (state.clock && state.clock.degraded) problems.push("clock degraded");
  if (plc && plc.control_law && plc.control_law.diverged) problems.push("control law diverged");
  if (plc && plc.comparison && plc.comparison.diverged) problems.push("baseline diverged");
  if (configIntegrity && configIntegrity.diverged) problems.push("config tampered");
  if (networkExposure && networkExposure.diverged) problems.push("rogue port open");
  if (resourceUsage && resourceUsage.diverged) problems.push("resource exhaustion");
  if (networkLatency && networkLatency.diverged) problems.push("network latency degraded");
  return { healthy: problems.length === 0, label: problems.length ? problems.join(", ") : "healthy" };
}

export function isActive() {
  return active;
}

async function fetchSnapshotOnce() {
  const r = await fetch("/api/monitor3d/snapshot", { cache: "no-store" });
  return r.json();
}

function buildNodesOnlyScene(hosts) {
  nodeBoxes.clear();
  const boxes = (hosts || []).map((h) => {
    const box = createEntityBox({
      id: `twinnode:${h.instance_id}`, kind: "host", title: h.name, subtitle: h.ip_floating || h.ip_private,
      status: "unknown", statusLabel: "checking...",
      statLines: [], width: 10, height: 5.5, depth: 7, raw: h,
      boxColor: BOX_COLOR_DEFAULT,
      visualModel: buildHostVisual(h.role, 10, 5.5, 7),
      // Was centered at the box's own origin by default (cardOffsetY=0),
      // visually sitting ON TOP of / inside the wireframe box underneath --
      // same fix already used for host boxes in the main overview scene
      // (app.js:507): float the card clear above the box instead.
      cardOffsetY: 5.5 / 2 + 6,
    });
    monitorBridge.addObject(box);
    liveObjects.push(box);
    nodeBoxes.set(h.instance_id, box);
    return box;
  });
  applyRowLayout(boxes, { y: 10, spacing: 13, maxPerRow: 5 });
}

// The floating card has no height cap (.ent-stat lines just stack), so a
// PLC node -- which has real extra lines no other role has (tank level,
// valves, baseline comparison) on top of the same tools/services/clock/
// config/network/resources lines every node gets -- rendered visibly
// taller than every other node's card. Capped here, in the CARD only
// (never in buildStatLines/renderNodeDetail themselves, which still show
// everything real): every node's floating card now shows at most the same
// number of lines, with a "+N more" hint pointing at the right-hand detail
// panel (clicking the node) for the full, uncapped picture.
const MAX_CARD_STAT_LINES = 6;
function capStatLines(lines) {
  if (lines.length <= MAX_CARD_STAT_LINES) return lines;
  const shown = lines.slice(0, MAX_CARD_STAT_LINES);
  shown.push(`<span style="opacity:0.7">+${lines.length - MAX_CARD_STAT_LINES} more -- click for details</span>`);
  return shown;
}

function markNodeHealthy(nodeId, state) {
  const box = nodeBoxes.get(nodeId);
  if (!box) return;
  recolorEntity(box, statusColor("ok"));
  updateBadge(box.userData.card, "ok", "healthy");
  if (state) updateStatLines(box.userData.card, capStatLines(buildStatLines(state)));
}

function markNodeDiverged(nodeId, label, state) {
  const box = nodeBoxes.get(nodeId);
  if (!box) return;
  recolorEntity(box, statusColor("error"));
  updateBadge(box.userData.card, "error", label || "divergence");
  if (state) updateStatLines(box.userData.card, capStatLines(buildStatLines(state)));
}

function markNodeUnknown(nodeId) {
  const box = nodeBoxes.get(nodeId);
  if (!box) return;
  recolorEntity(box, statusColor("unknown"));
  updateBadge(box.userData.card, "unknown", "not checked yet");
  updateStatLines(box.userData.card, ["Waiting for first real check..."]);
}

function scheduleTransient(fn, ms) {
  const t = setTimeout(fn, ms);
  transientTimers.push(t);
}

function pushFeedItem(item) {
  feedItems.unshift({ id: ++feedIdSeq, ts: Date.now(), ...item });
  feedItems = feedItems.slice(0, 60);
  renderFeed();
}

// fault_injection_applied/fault_injection_reverted (see forensic_twin's
// record_fault_injection_lifecycle) are deliberately a separate event
// family from a real divergence: applying a fault on purpose during an
// experiment is not evidence of an anomaly, so it must never paint a node's
// persistent lamp red the way tool_regression/clock_offset_degraded/etc.
// do -- only a neutral, transient marker. The persistent lamp itself still
// updates correctly on the NEXT poll via computeNodeHealth, if this fault
// actually tripped a real sensor (plc_io_manipulation, or config_tamper/
// rogue_port when a baseline exists).
const FAULT_EVENT_PREFIX = "fault_injection_";

function spawnEventFlash(nodeId, ev) {
  const isFaultLifecycle = (ev.event_type || "").startsWith(FAULT_EVENT_PREFIX);
  const box = nodeBoxes.get(nodeId);
  if (box) {
    const pos = box.position.clone();
    // Above the card's own float height (cardOffsetY = 5.5/2 + 6 = 8.75),
    // not just above the box itself -- otherwise this transient label would
    // render behind/through the now-higher persistent card.
    pos.y += 12;
    if (isFaultLifecycle) {
      const phase = ev.event_type.endsWith("_reverted") ? "reverted" : "applied";
      const label = createFloatingLabel(pos, `${esc(ev.fault_id || "fault")} ${phase}<br>${esc(ev.evidence || "")}`, "fault");
      monitorBridge.addObject(label);
      scheduleTransient(() => { monitorBridge.removeObject(label); disposeEntity(label); }, EVENT_FLASH_MS);
    } else {
      markNodeDiverged(nodeId, ev.event_type);
      const label = createFloatingLabel(pos, `${esc(ev.event_type)}<br>${esc(ev.evidence || "")}`, "security");
      monitorBridge.addObject(label);
      scheduleTransient(() => { monitorBridge.removeObject(label); disposeEntity(label); }, EVENT_FLASH_MS);
    }
  }
  pushFeedItem({ title: ev.event_type, detail: `${esc(ev.scope_id || "")} -- ${esc(ev.evidence || "")}` });
}

function renderFeed() {
  const el = document.getElementById("digital-twin-feed-list");
  if (!el) return;
  el.innerHTML = feedItems.length
    ? feedItems.map((it) => {
        const time = new Date(it.ts).toLocaleTimeString();
        return `<div class="live-feed-item" style="border-left:3px solid #ef4444">
          <div class="live-feed-time">${time}</div>
          <div class="live-feed-title">${esc(it.title)}</div>
          <div class="live-feed-detail">${it.detail}</div>
        </div>`;
      }).join("")
    : `<div class="detail-empty">No divergence events yet -- everything checked so far is healthy.</div>`;
}

function renderTickStatus() {
  const el = document.getElementById("digital-twin-tick-status");
  if (!el) return;
  if (!bestKnownTick || !bestKnownTick.last_tick_at) {
    el.textContent = "Continuous monitor: waiting for a status reading from its worker...";
    return;
  }
  const lastAt = new Date(bestKnownTick.last_tick_at).getTime();
  const nextAt = lastAt + bestKnownTick.interval_seconds * 1000;
  const remainingMin = Math.max(0, Math.round((nextAt - Date.now()) / 60000));
  el.textContent = `Continuous monitor -- last automatic check ${new Date(bestKnownTick.last_tick_at).toLocaleTimeString()}, next in ~${remainingMin} min (approximate)`;
}

async function checkOneNode(nodeId) {
  try {
    let res = await fetch(`/api/forensic-twin/state/${encodeURIComponent(nodeId)}`, { cache: "no-store" });
    let data = await res.json();
    // A state can exist (ok:true) and still be missing the real-vs-expected
    // picture: forensic_twin's own continuous monitor runs a cheap "light"
    // tick (tools + services only, clock/plc skipped) most of the time,
    // only doing the expensive live clock/PLC read once every
    // HEAVY_CHECK_EVERY_N_TICKS ticks (service.py's own documented
    // resource-saving design) -- `source: "continuous"` on the state names
    // this directly. `clock == null` catches the same thing for any state
    // that somehow lacks a source label. Either one means "light-tier data
    // only, not the full real-vs-expected picture this view exists to show".
    const isLightTierOnly = data.ok && data.state && (data.state.clock == null || data.state.source === "continuous");
    const lastTriggered = lastCheckTriggeredAt.get(nodeId) || 0;
    const cooledDown = (Date.now() - lastTriggered) >= BOOTSTRAP_RECHECK_COOLDOWN_MS;
    if ((!data.ok || isLightTierOnly) && cooledDown) {
      // Surfacing only tool counts when the user explicitly asked to see the
      // real vs. expected PLC/clock comparison isn't useful -- so trigger a
      // real, full on-demand check ourselves (same endpoint forensic_twin.html's
      // own "Check a Node" button uses, which defaults to
      // include_clock=True/include_plc=True), then re-read the result.
      // Measured live against this scenario's real hosts: ~23-30s per node,
      // almost entirely the live SSH clock preflight (time_sync_preflight.sh),
      // not Modbus -- so all 5 nodes are run CONCURRENTLY (Promise.all in
      // pollNodeStates below), ~25-30s total instead of ~2 minutes serial.
      // Bounded by BOOTSTRAP_RECHECK_COOLDOWN_MS, not "only once ever per
      // view-entry" -- see lastCheckTriggeredAt's own comment for why.
      lastCheckTriggeredAt.set(nodeId, Date.now());
      try {
        await fetch(`/api/forensic-twin/check/${encodeURIComponent(nodeId)}`, { method: "POST" });
        res = await fetch(`/api/forensic-twin/state/${encodeURIComponent(nodeId)}`, { cache: "no-store" });
        data = await res.json();
      } catch (e) { /* bootstrap check failed -- falls through to markNodeUnknown below */ }
    }
    if (data.ok && data.state) {
      lastStateById.set(nodeId, data.state);
      const health = computeNodeHealth(data.state);
      if (health.healthy) markNodeHealthy(nodeId, data.state);
      else markNodeDiverged(nodeId, health.label, data.state);
      if (selectedNodeId === nodeId) renderNodeDetail(nodeId);
    } else {
      markNodeUnknown(nodeId);
    }
  } catch (e) { /* transient network hiccup -- leave the node's current color */ }
}

async function pollNodeStates() {
  await Promise.all(Array.from(nodeBoxes.keys()).map(checkOneNode));
}

// Full real-vs-expected state for the selected node, written into the same
// right-hand #detail-body panel the default overview uses -- a richer
// version of buildStatLines' box lines (which have room for only a few
// short ones), always showing the real values, not just "matches expected".
// Section header + a one-line plain-language explanation of what the
// numbers under it mean and why they're being compared -- the user
// explicitly asked for "más detalles explicativos", not just raw field
// dumps, matching the same plain-language approach as the simplified guide
// already built into forensic_twin.html.
function sectionHeader(title, help) {
  return `<div class="section-title">${esc(title)}</div><div class="section-help">${esc(help)}</div>`;
}

// Each real divergence event this node triggered recently, tagged with the
// real MITRE ATT&CK for ICS technique forensic_twin.service already mapped
// it to (service.py::MITRE_ATTCK_ICS_MAPPING, 2026-10-09) -- a plain-language
// "this looks like <real adversary technique>" reading for every event name,
// not just raw JSON fields. Some event types (reproducibility_degraded,
// scenario_validation_degraded) are meta-signals about the experiment itself,
// not adversary behavior -- those are honestly shown as "no ATT&CK mapping",
// never forced into a technique that doesn't fit.
function renderMitreEventsSection(nodeId) {
  const events = recentEventsByNode.get(nodeId) || [];
  if (!events.length) return "";
  let html = sectionHeader(
    "Recent divergence events (real) -- MITRE ATT&CK for ICS",
    "Each real divergence this node triggered recently, matched to the real adversary technique it looks like -- so this reads as 'what an attacker would be doing', not just an internal event name."
  );
  const sorted = [...events].sort((a, b) => String(b.generated_at_utc || "").localeCompare(String(a.generated_at_utc || "")));
  sorted.slice(0, 8).forEach((ev) => {
    const m = ev.mitre_attck_ics;
    const badge = m
      ? `<span style="display:inline-block;margin-left:8px;padding:1px 7px;border-radius:999px;font-size:10px;font-weight:700;color:var(--cyan);border:1px solid var(--cyan);background:var(--cyan-glow);">${esc(m.technique_id)} &middot; ${esc(m.technique_name)}</span>`
      : `<span style="display:inline-block;margin-left:8px;padding:1px 7px;border-radius:999px;font-size:10px;color:var(--text-dim);border:1px dashed var(--text-dim);">no ATT&amp;CK mapping (experiment meta-signal)</span>`;
    html += `<div class="kv-row" style="flex-direction:column;align-items:flex-start;gap:2px;">`;
    html += `<div><span class="k">${esc(ev.event_type)}</span>${badge}</div>`;
    if (m?.tactic) html += `<div class="v" style="font-size:11px;opacity:0.7;">Tactic: ${esc(m.tactic)}${m.note ? ` -- ${esc(m.note)}` : ""}</div>`;
    html += `<div class="v" style="font-size:11px;opacity:0.85;">${esc(ev.evidence || "")} -- ${esc(ev.generated_at_utc || "")}</div>`;
    html += `</div>`;
  });
  return html;
}

function renderNodeDetail(nodeId) {
  const body = document.getElementById("detail-body");
  if (!body) return;
  const box = nodeBoxes.get(nodeId);
  const state = lastStateById.get(nodeId);
  const title = box ? esc(box.userData.title) : esc(nodeId);
  const raw = box ? box.userData.raw || {} : {};
  let html = `<div class="dt-detail">`;
  html += `<div style="font-weight:700;font-size:15px;margin-bottom:8px;">${title}</div>`;
  html += `<div class="kv-row"><span class="k">Role</span><span class="v">${esc(raw.role || "n/a")}</span></div>`;
  html += `<div class="kv-row"><span class="k">IP</span><span class="v">${esc(raw.ip_floating || raw.ip_private || "n/a")}</span></div>`;

  html += sectionHeader("Intervention history (real)", "The real lifecycle of the most recent fault/attack applied to this node, end to end: when it was requested, when it really took effect, when the digital twin noticed it on its own, and when that alert got real proof attached -- built from the Intervention Ledger, the post-hoc linker, and the Evidence Bridge, never guessed.");
  html += `<div class="pt-mount" id="pt-mount-${esc(nodeId)}"><div class="pt-empty">Loading real intervention history...</div></div>`;

  html += renderMitreEventsSection(nodeId);

  if (!state) {
    html += `<div class="detail-empty" style="margin-top:10px;">Not checked yet -- waiting for this node's first real forensic_twin check.</div></div>`;
    body.innerHTML = html;
    renderNodeTimelineInto(document.getElementById(`pt-mount-${nodeId}`), nodeId);
    return;
  }

  html += `<div class="kv-row"><span class="k">Last checked</span><span class="v">${esc(state.checked_at || "n/a")} (${esc(state.source || "n/a")})</span></div>`;

  const tools = state.tools || {};
  html += sectionHeader("Tools (real)", "Which forensic/monitoring tools this node's scenario profile expects, and whether they're still really installed on the live VM right now.");
  html += `<div class="kv-row"><span class="k">Installed</span><span class="v">${(tools.installed_tools || []).map(esc).join(", ") || "none"}</span></div>`;
  if ((tools.missing_tools || []).length) {
    html += `<div class="kv-row"><span class="k">Missing</span><span class="v" style="color:#ef4444">${tools.missing_tools.map(esc).join(", ")}</span></div>`;
  }

  const services = state.services || {};
  if ((services.checked || []).length) {
    html += sectionHeader("Services (real)", "Whether the real security services (Suricata/Wazuh) that should be running on this node are actually active right now.");
    html += `<div class="kv-row"><span class="k">Checked</span><span class="v">${services.checked.map((s) => `${esc(s.unit)}: ${esc(s.status)}`).join(", ")}</span></div>`;
    if ((services.down || []).length) {
      html += `<div class="kv-row"><span class="k">Down</span><span class="v" style="color:#ef4444">${services.down.map(esc).join(", ")}</span></div>`;
    }
  }

  if (state.clock) {
    html += sectionHeader("Clock (live reading)", "A live SSH-based clock-skew measurement against this node, taken right now -- a sudden large offset can be a sign of anti-forensic timestamp tampering.");
    html += `<div class="kv-row"><span class="k">Offset (real)</span><span class="v"${state.clock.degraded ? ' style="color:#ef4444"' : ""}>${esc(fmt(state.clock.offset_ms))}ms</span></div>`;
    html += `<div class="kv-row"><span class="k">Sync status</span><span class="v">${esc(state.clock.temporal_sync_status || "n/a")}</span></div>`;
  }

  const plc = state.plc;
  if (plc && plc.available) {
    const cl = plc.control_law || {};
    html += sectionHeader("PLC control law (real vs. expected)", "Compares the real valve positions right now against what the PLC's own real control program (TankControl.st) says they should be, given the current tank level -- a mismatch here means the PLC did something its own code would never produce by itself.");
    html += `<div class="kv-row"><span class="k">Tank level (real)</span><span class="v">${esc(fmt(cl.level))} / max ${esc(fmt(cl.level_max))}</span></div>`;
    html += `<div class="kv-row"><span class="k">Branch (expected from level)</span><span class="v">${esc(cl.branch || "n/a")}</span></div>`;
    html += `<div class="kv-row"><span class="k">Air valve (real)</span><span class="v">${cl.air_valve_open ? "open" : "closed"}</span></div>`;
    if ((cl.differences || []).length) {
      cl.differences.forEach((d) => {
        html += `<div class="kv-row"><span class="k">${esc(d.canonical_name)}</span><span class="v" style="color:#ef4444">real=${esc(fmt(d.observed_value))} / expected=${esc(fmt(d.expected_value))}</span></div>`;
      });
    } else {
      html += `<div class="kv-row"><span class="k">Valves</span><span class="v">real matches control law</span></div>`;
    }

    if (plc.baseline_present) {
      const cmp = plc.comparison || {};
      html += sectionHeader("Baseline comparison (real vs. expected)", "Compares today's full PLC state against a frozen snapshot (baseline) captured earlier -- any difference means the PLC's static configuration changed since then, outside of normal tank-level/valve cycling.");
      html += `<div class="kv-row"><span class="k">State hash (real)</span><span class="v">${esc((cmp.observed_state_hash || "n/a").slice(0, 16))}...</span></div>`;
      html += `<div class="kv-row"><span class="k">State hash (baseline)</span><span class="v">${esc((cmp.expected_state_hash || "n/a").slice(0, 16))}...</span></div>`;
      if ((cmp.differences || []).length) {
        cmp.differences.forEach((d) => {
          html += `<div class="kv-row"><span class="k">${esc(d.canonical_name)}</span><span class="v" style="color:#ef4444">real=${esc(fmt(d.observed_value))} / expected=${esc(fmt(d.expected_value))}</span></div>`;
        });
      } else {
        html += `<div class="kv-row"><span class="k">Static variables</span><span class="v">real matches baseline</span></div>`;
      }
    } else {
      html += `<div class="kv-row" style="margin-top:10px;"><span class="k">Baseline</span><span class="v">not captured yet</span></div>`;
    }
  }

  const configIntegrity = state.config_integrity;
  if (configIntegrity) {
    html += sectionHeader("Config integrity (real vs. baseline)", "Compares a SHA-256 hash of the real Suricata/Wazuh config and rule files on this node right now against a baseline captured earlier -- any mismatch means one of those files was edited or replaced since then, outside of a routine rule update.");
    html += `<div class="kv-row"><span class="k">Baseline captured</span><span class="v">${esc(configIntegrity.baseline_captured_at_utc || "n/a")}</span></div>`;
    if ((configIntegrity.differences || []).length) {
      configIntegrity.differences.forEach((d) => {
        html += `<div class="kv-row"><span class="k">${esc(d.path)}</span><span class="v" style="color:#ef4444">${esc(d.reason)}</span></div>`;
      });
    } else {
      html += `<div class="kv-row"><span class="k">Files tracked</span><span class="v">${esc(fmt(configIntegrity.files_tracked))}, all matching baseline</span></div>`;
    }
  }

  const networkExposure = state.network_exposure;
  if (networkExposure) {
    html += sectionHeader("Network exposure (real vs. baseline)", "Compares real listening TCP/UDP ports on this node right now (ss -tulwn) against a baseline captured earlier -- a NEW port is a classic backdoor/persistence indicator. Login sessions (who) are shown as real context only, never auto-flagged as a divergence.");
    html += `<div class="kv-row"><span class="k">Listening ports (real)</span><span class="v">${(networkExposure.listening_ports || []).map(esc).join(", ") || "none"}</span></div>`;
    if ((networkExposure.new_listening_ports || []).length) {
      html += `<div class="kv-row"><span class="k">New vs. baseline</span><span class="v" style="color:#ef4444">${networkExposure.new_listening_ports.map(esc).join(", ")}</span></div>`;
    }
    if ((networkExposure.login_sessions || []).length) {
      html += `<div class="kv-row"><span class="k">Login sessions (real)</span><span class="v">${networkExposure.login_sessions.map(esc).join(" | ")}</span></div>`;
    }
  }

  const resourceUsage = state.resource_usage;
  if (resourceUsage) {
    html += sectionHeader("Resource usage (live reading)", "A live CPU/RAM/disk read taken right now (same severity thresholds node_health's own alerts use: ok below 85%, warning 85-95%, critical at/above 95%) -- this is what actually shows a real cpu_ram_stress/disk_fill fault's effect, not just a neutral marker that something was applied.");
    html += `<div class="kv-row"><span class="k">CPU (real)</span><span class="v"${resourceUsage.cpu_severity !== "ok" ? ' style="color:#ef4444"' : ""}>${esc(fmt(resourceUsage.cpu_usage_pct))}% (${esc(resourceUsage.cpu_severity)})</span></div>`;
    html += `<div class="kv-row"><span class="k">Memory (real)</span><span class="v"${resourceUsage.memory_severity !== "ok" ? ' style="color:#ef4444"' : ""}>${esc(fmt(resourceUsage.memory_usage_pct))}% (${esc(resourceUsage.memory_severity)})</span></div>`;
    html += `<div class="kv-row"><span class="k">Disk root (real)</span><span class="v"${resourceUsage.disk_severity !== "ok" ? ' style="color:#ef4444"' : ""}>${esc(fmt(resourceUsage.disk_root_use_pct))}% (${esc(resourceUsage.disk_severity)})</span></div>`;
  }

  const networkLatency = state.network_latency;
  if (networkLatency) {
    html += sectionHeader("Network latency (live reading)", "A live ping RTT taken right now, compared against the lowest RTT ever seen healthy for this node (its own floor, not a fixed number) -- this is what actually shows a real network_fault's effect.");
    html += `<div class="kv-row"><span class="k">RTT (real)</span><span class="v"${networkLatency.diverged ? ' style="color:#ef4444"' : ""}>${esc(fmt(networkLatency.ping_avg_ms))}ms</span></div>`;
    html += `<div class="kv-row"><span class="k">Floor (healthy)</span><span class="v">${esc(fmt(networkLatency.floor_ms))}ms</span></div>`;
  }

  html += `</div>`;
  body.innerHTML = html;
  renderNodeTimelineInto(document.getElementById(`pt-mount-${nodeId}`), nodeId);
}

export function handleSelect(hit) {
  if (hit.kind !== "host") return;
  const nodeId = hit.raw.instance_id;
  const box = nodeBoxes.get(nodeId);
  if (!box) return;
  const prevBox = selectedNodeId ? nodeBoxes.get(selectedNodeId) : null;
  if (prevBox && prevBox !== box) setSelected(prevBox, false);
  setSelected(box, true);
  selectedNodeId = nodeId;
  renderNodeDetail(nodeId);
  faultDrawer.setSelectedNode(nodeId, box.userData.title);
}

async function pollEvents() {
  try {
    const res = await fetch("/api/forensic-twin/events?limit=30", { cache: "no-store" });
    const data = await res.json();
    const byNode = new Map();
    for (const ev of data.events || []) {
      const nodeId = (ev.scope_id || "").startsWith("node:") ? ev.scope_id.slice(5) : null;
      if (nodeId) {
        if (!byNode.has(nodeId)) byNode.set(nodeId, []);
        byNode.get(nodeId).push(ev);
      }
      const key = `${ev.scope_id}|${ev.generated_at_utc}|${ev.event_type}`;
      if (seenEventKeys.has(key)) continue;
      seenEventKeys.add(key);
      if (nodeId && nodeBoxes.has(nodeId)) spawnEventFlash(nodeId, ev);
      else pushFeedItem({ title: ev.event_type, detail: `${esc(ev.scope_id || "")} -- ${esc(ev.evidence || "")}` });
    }
    recentEventsByNode = byNode;
    if (selectedNodeId) renderNodeDetail(selectedNodeId);
  } catch (e) { /* transient */ }
}

// Called by digital_twin_fault_drawer.js right after a real apply/revert
// HTTP call returns, so the quick-injection panel's effect shows up here
// immediately instead of waiting up to POLL_MS for the next scheduled tick
// -- the event this triggers is already written server-side by the time
// that response comes back (fault_injection.apply_fault/revert_fault call
// forensic_twin's lifecycle hook synchronously before returning).
export async function refreshNow() {
  if (!active) return;
  await pollNodeStates();
  await pollEvents();
}

async function pollContinuousStatus() {
  try {
    const res = await fetch("/api/forensic-twin/continuous/status", { cache: "no-store" });
    const data = await res.json();
    if (data.last_tick_at) bestKnownTick = { last_tick_at: data.last_tick_at, interval_seconds: data.interval_seconds || 1800 };
    renderTickStatus();
  } catch (e) { /* transient */ }
}

function schedulePoll() {
  pollTimer = setTimeout(async () => {
    if (!active) return;
    await pollNodeStates();
    await pollEvents();
    await pollContinuousStatus();
    if (active) schedulePoll();
  }, POLL_MS);
}

export async function enter() {
  if (active) return;
  active = true;
  savedState = monitorBridge.getState();
  monitorBridge.stopLivePolling();
  monitorBridge.clearLiveScene();
  monitorBridge.setConnStatus("digital twin view · loading nodes…");
  feedItems = [];
  seenEventKeys = new Set();
  bestKnownTick = null;
  lastCheckTriggeredAt = new Map();
  lastStateById = new Map();
  selectedNodeId = null;
  renderFeed();
  renderTickStatus();
  const panel = document.getElementById("digital-twin-panel");
  const sourcesPanel = document.getElementById("live-sources-panel");
  if (panel) panel.hidden = false;
  if (sourcesPanel) sourcesPanel.hidden = true;
  const detailBody = document.getElementById("detail-body");
  if (detailBody) detailBody.innerHTML = `<div class="detail-empty">Click any node to see its digital twin state (real vs. expected).</div>`;
  try {
    const snap = await fetchSnapshotOnce();
    const hosts = snap.campaign?.hosts || [];
    buildNodesOnlyScene(hosts);
    for (const nodeId of nodeBoxes.keys()) markNodeUnknown(nodeId);
    monitorBridge.setConnStatus(`digital twin view · ${nodeBoxes.size} node(s)`);
    faultDrawer.show(hosts.map((h) => ({ instance_id: h.instance_id, name: h.name })));
  } catch (e) {
    monitorBridge.setConnStatus("digital twin view · failed to load nodes", { error: true });
  }
  await pollNodeStates();
  await pollEvents();
  await pollContinuousStatus();
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
  lastStateById = new Map();
  selectedNodeId = null;
  faultDrawer.hide();
  const panel = document.getElementById("digital-twin-panel");
  const sourcesPanel = document.getElementById("live-sources-panel");
  if (panel) panel.hidden = true;
  if (sourcesPanel) sourcesPanel.hidden = false;
  if (savedState) monitorBridge.setState(savedState);
  monitorBridge.rebuildScene();
  monitorBridge.startLivePolling();
}

export function getAllRenderedGroups() {
  return liveObjects;
}
