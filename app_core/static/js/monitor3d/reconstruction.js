// Post-campaign reconstruction ("replay") mode -- a self-contained 3D scene
// composer that builds a completed campaign's real history progressively,
// piece by piece ("like a mason building a house"), instead of swapping the
// whole scene per beat. Purely reads an already-assembled timeline from the
// backend (GET /api/monitor3d/reconstruction/<job_id>, itself built entirely
// from files that already exist on disk, see monitor3d/service.py) -- never
// issues anything but GET requests, so it cannot create or modify any
// artifact, by construction.
//
// State isolation: this module owns its OWN set of Three.js objects
// (persistentObjects/repScopedObjects/reconObjects below), separate from
// app.js's live-mode entityGroups/ghostShells/connectors/relationObjects.
// It never calls app.js's rebuildScene()/setState() during playback -- only
// on enter()/exitReconstruction() to save and restore the live view exactly.
// This means a bug here can never corrupt live mode's own state.

import * as THREE from "three";
import {
  createEntityBox, createConnector, createRelationLine, createSaggingCable, createFloatingLabel,
  disposeEntity, updateRing, updateBadge, recolorEntity, spawnPhoton,
  BOX_COLOR_ATTACKER, statusColor,
} from "./entities.js";
import { applyRowLayout } from "./layout.js";
import { buildHostVisual } from "./host-visuals.js";
import { buildCaseVisual } from "./case-visuals.js";
import { buildVigia } from "./forensic_twin_watcher.js";
import { monitorBridge } from "./app.js";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtSeconds(s) {
  if (s == null) return "—";
  const v = Math.max(0, Math.round(s));
  const m = Math.floor(v / 60), sec = v % 60;
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}
function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}
// A real, readable "report card" -- see monitor3d.html's .report-card CSS.
// `rows` is [[label, value], ...], value already formatted as a plain
// string; a falsy value is skipped (lets callers pass rows unconditionally
// from data that may or may not be available, without littering every call
// site with its own filter).
function buildReportCardHtml(title, rows, note) {
  const body = rows
    .filter(([, v]) => v != null && v !== "")
    .map(([k, v]) => `<div class="rc-row"><span class="rc-k">${esc(k)}</span><span class="rc-v">${esc(v)}</span></div>`)
    .join("");
  return `<div class="rc-title">${esc(title)}</div>${body}` + (note ? `<div class="rc-note">${esc(note)}</div>` : "");
}
function fmtBytes(bytes) {
  if (bytes == null) return null;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(bytes), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

const MIN_BEAT_MS = 2000;
const MAX_BEAT_MS = 6000;
const BASE_MS_PER_REAL_HOUR = 2500;
// The attacker->PLC red thread is the single most important visual beat of
// the whole replay -- explicitly called out TWICE as too fast to read at the
// normal compression rate (bumped again 2026-10-11, still felt short even
// at 5x). Kept as a dedicated multiplier (not a change to the shared
// floor/ceiling) so only the attack beat itself gets slower.
const ATTACK_SLOWDOWN_FACTOR = 8;

// User-controlled playback speed (the reconstruction-bar slider) -- a plain
// divisor on top of the already-compressed duration. Takes effect from the
// NEXT beat scheduled onward (matching the existing Pause behaviour of
// letting whatever's already running finish, rather than yanking a running
// timer/animation mid-flight).
const MIN_SPEED = 0.25;
const MAX_SPEED = 4;
let speedMultiplier = 1;

export function setSpeed(multiplier) {
  const v = Number(multiplier);
  speedMultiplier = Number.isFinite(v) ? clamp(v, MIN_SPEED, MAX_SPEED) : 1;
}
export function getSpeed() {
  return speedMultiplier;
}

// "Thousands of times faster than real time", with floors/ceilings so a
// beat is never too fast to read or so slow it stalls playback -- a 3-hour
// real stage (e.g. a long memory analysis) still only takes 6s on screen.
// `kind` is optional; only "attack" gets the extra slowdown. The user-facing
// speed slider (speedMultiplier) is applied last, on top of everything else.
export function compressedDurationMs(realSeconds, kind) {
  const base = realSeconds == null || realSeconds <= 0
    ? MIN_BEAT_MS
    : clamp((realSeconds / 3600) * BASE_MS_PER_REAL_HOUR, MIN_BEAT_MS, MAX_BEAT_MS);
  const withKind = kind === "attack" ? base * ATTACK_SLOWDOWN_FACTOR : base;
  return withKind / speedMultiplier;
}

// ---------------------------------------------------------------------
// Module state -- entirely reconstruction's own, never shared with app.js.
// ---------------------------------------------------------------------
let beats = [];
let totalRepetitions = 0;
let currentIndex = 0;
let isActive = false;
let isPlaying = false;
let foundationBuilt = false;
let timerId = null;
let pendingTimers = []; // every staggered setTimeout handle, cancellable on Reset/Exit
let persistentObjects = []; // campaign box + repetition-row boxes/connectors -- survive the whole run
let repScopedObjects = []; // current repetition's case/hosts/artifacts/relations -- torn down each handoff
let reconObjects = []; // superset of both, for full teardown
let savedState = null;
// Supplementary, read-only metrics for the 3D "report card" (see
// buildReportCardHtml/handleCampaignFinale/handleRepetitionSummary) -- real
// numbers from forge_dt_metrics, fetched once in loadTimeline() alongside
// the main timeline. Never required: every report card renders with
// whatever rows it actually has data for, never blocking on these.
let forgeMetrics = null;
// Per-repetition case metrics, stashed in handleReconstruction and read
// back by handleRepetitionSummary to build that repetition's own report
// card -- avoids a second fetch, reuses data already real and on-hand.
let repCaseMetrics = new Map();
// Dedicated "report row" -- a fixed, separate area well below every other
// level of the real hierarchy (hosts/case/artifacts), reserved purely for
// report cards. User's explicit correction 2026-10-15: the first version
// parked each card right next to its own box, which visually collided with
// that box's own labels (e.g. a rep's card landing under the attacker
// host's label) -- report cards never share space with the 3D hierarchy
// again. repNum -> cardLabel, so the campaign finale can gather every
// repetition's own card into one combined closing shot.
const REPORT_ROW_Y = -24;
let reportCardsByRep = new Map();
let onTick = null;
// Extra pause time (ms) the CURRENT beat's own alert wants before advancing
// to the next one -- set by triggerAlert(), consumed once by scheduleNext()
// then reset. Lives per-beat, not accumulated: applyBeat() resets it to 0
// before dispatching, so an instant bulk replay (seekTo's own 0..target
// loop, every beat applied synchronously with isPlaying still false) can
// never stack up dozens of alerts' hold times into one giant stall the
// moment playback actually resumes.
let extraHoldMs = 0;
// Running log of "important, worth emphasizing" real events (attacks,
// detections, fault-injection outcomes, computed metrics) -- read by app.js
// via getProgressSummary()'s own alertFeed field for the Alert Center list.
// Rebuilt from scratch on every reset()/seekTo() (cleared in
// _teardownScene(), same as every other derived replay state), so it always
// matches the real history up to wherever playback currently is.
let alertFeed = [];

// ---------------------------------------------------------------------
// Digital twin "watcher" (vigía forense) -- a single persistent object for
// the whole reconstruction SESSION, deliberately NOT added via track()/
// reconObjects: every one of this module's own objects gets torn down and
// rebuilt on every seek/step/reset (see _teardownScene's own comment), but
// this one must survive that, the same way a real investigator watching a
// video doesn't blink out of existence every time you scrub the timeline.
// Lives outside this module's teardown cycle on purpose; only created in
// enter() and destroyed in exitReconstruction().
let twinWatcher = null; // { group, cono, api }
let twinWatcherEnabled = true;
let twinWatcherRafId = null;
let twinWatcherT0 = 0;
// Per-entity (any real thing the digital twin reports on -- a host node,
// a case, the campaign itself, keyed "host:<id>"/"case:<id>"/"campaign:<id>")
// latest known severity, so several real observations can coexist honestly
// -- the watcher always shows the WORST currently-unresolved state across
// everything it has observed so far in this playback, never just the most
// recent one. Originally host-only (intervention beats); generalized
// 2026-10-15 so a case's own reconstruction-confidence metric or the
// campaign's own final reproducibility verdict feed the SAME watcher, the
// same honest way, per explicit user request.
let twinSeverityByEntity = new Map();
const TWIN_SEVERITY_RANK = { match: 0, deviation: 1, discrepancy: 2 };
// Same worst-case-wins data, but keyed with enough detail (entity name, real
// observed timestamp/detail) to drive the always-on-screen HUD -- the 3D
// object's own position/color can be out of the camera's frame at any given
// moment, so the real comparison it's making must not depend on the 3D
// object being visible at all.
let twinObservationByEntity = new Map();
// One observation label per entity at a time -- a host hit by several real
// interventions in a row (common: several fault types tried against the
// same PLC) would otherwise stack a new floating label directly on top of
// the still-fading previous one, at the exact same offset, into unreadable
// overlapping text.
let twinLabelByEntity = new Map();
// The single most recent real observation across every entity, regardless
// of severity -- Map iteration/insertion order does NOT reflect "most
// recently updated" (re-`.set()`-ing an existing key doesn't move it), and
// a HUD that only ever shows the worst UNRESOLVED thing would otherwise
// fall back to a generic "nothing yet" placeholder forever once every real
// observation so far happens to be good news (e.g. a `mostly_recoverable`
// CPR) -- which is a real, true thing that just happened and should say so.
let lastTwinObservation = null;

let campaignBox = null;
let repBoxes = new Map(); // repetition_number -> box
let caseBox = null;
let hostBoxes = new Map(); // instance_id -> box
let hostToolBoxes = new Map(); // instance_id -> [tool box, ...]
let lastHostBeatIds = new Set(); // beat_id of the LAST deployment/tool_install beat per host, for the "leaving this machine" camera cue
let caseFocusedForRep = null; // repetition_number already given its one-time "enter the case" camera focus

// Cumulative, campaign-wide counters -- "progress since the first machine of
// repetition 1" for the left-side panel. Every field is a running count of
// beats that have genuinely fired, never a fabricated estimate; reset only
// on loadTimeline()/reset()/exitReconstruction().
function freshProgressStats() {
  return {
    hostsDeployed: 0,
    toolsInstalled: 0,
    attacksExecuted: 0,
    interventionsReplayed: 0,
    detectionsTriggered: 0,
    detectionsMissed: 0,
    artifactsPreserved: 0,
    artifactBytesTotal: 0,
    // Per-CASE, not campaign-wide -- reset every time a new case_created
    // beat fires, so this always reads "how much this one case's evidence
    // adds up to so far", not a running total across all 10 repetitions'
    // cases mixed together.
    currentCaseId: null,
    currentCaseArtifacts: 0,
    currentCaseBytes: 0,
    lastArtifactLabel: null,
    lastArtifactBytes: null,
    analysisPhasesCompleted: 0,
    casesCreated: 0,
    casesSealed: 0,
    cprValues: [], // [{rep, cpr}, ...] one per repetition that reached a reconstruction beat
    repetitionsCompleted: 0,
  };
}
let progressStats = freshProgressStats();

// Called once per beat from applyBeat(), independent of the visual
// handlers -- so the counters stay accurate even if a handler bails early
// (e.g. a missing box reference) and reflect exactly what the backend's
// real timeline recorded.
function bumpProgress(beat) {
  switch (beat.kind) {
    case "deployment":
      progressStats.hostsDeployed += 1;
      break;
    case "tool_install":
      progressStats.toolsInstalled += 1;
      break;
    case "attack":
      progressStats.attacksExecuted += 1;
      break;
    case "intervention":
      progressStats.interventionsReplayed += 1;
      break;
    case "detection":
      if (beat.payload?.detection?.outcome === "detected") progressStats.detectionsTriggered += 1;
      else progressStats.detectionsMissed += 1;
      break;
    case "case_created":
      progressStats.casesCreated += 1;
      // A new case starts its own volume count at zero -- this is the
      // "this case's evidence so far" number, not a running total mixed
      // across every repetition's case.
      progressStats.currentCaseId = beat.payload?.case?.case_id ?? null;
      progressStats.currentCaseArtifacts = 0;
      progressStats.currentCaseBytes = 0;
      break;
    case "preservation_step": {
      progressStats.artifactsPreserved += 1;
      progressStats.currentCaseArtifacts += 1;
      const entry = beat.payload?.stage_timeline_entry;
      const size = entry?.size_bytes;
      if (typeof size === "number") {
        progressStats.artifactBytesTotal += size;
        progressStats.currentCaseBytes += size;
      }
      progressStats.lastArtifactLabel = entry?.label ?? beat.title ?? null;
      progressStats.lastArtifactBytes = typeof size === "number" ? size : null;
      break;
    }
    case "analysis_phase":
      progressStats.analysisPhasesCompleted += 1;
      break;
    case "reconstruction": {
      const cpr = beat.payload?.causal_status?.metrics_preview?.causal_path_recoverability;
      if (typeof cpr === "number") progressStats.cprValues.push({ rep: beat.repetition_number, cpr });
      break;
    }
    case "seal":
      if (beat.payload?.integrity?.case_sealed) progressStats.casesSealed += 1;
      break;
    case "repetition_summary":
      progressStats.repetitionsCompleted += 1;
      break;
  }
}

// Read by app.js to render the left-side "Reconstruction progress" panel.
export function getProgressSummary() {
  const avgCpr = progressStats.cprValues.length
    ? progressStats.cprValues.reduce((a, v) => a + v.cpr, 0) / progressStats.cprValues.length
    : null;
  // Last few real beats already played, oldest first -- a short scrollback
  // for orientation ("what just happened") independent of whatever the
  // Stage Detail panel is showing for the CURRENT beat.
  const recentBeats = beats.slice(Math.max(0, currentIndex - 7), currentIndex + 1).map((b) => ({
    title: b.title, kind: b.kind, repetition_number: b.repetition_number, started_at: b.started_at,
  }));
  return {
    ...progressStats,
    avgCpr,
    recentBeats,
    alertFeed: [...alertFeed],
    currentRepetition: beats[currentIndex]?.repetition_number ?? null,
    totalRepetitions,
    beatIndex: currentIndex,
    totalBeats: beats.length,
  };
}

export function onBeatChange(cb) {
  onTick = cb;
}
export function isReconstructionActive() {
  return isActive;
}
export function getAllRenderedGroups() {
  return reconObjects.filter((o) => o.isGroup);
}

// ---------------------------------------------------------------------
// Timeline fetch
// ---------------------------------------------------------------------
export async function loadTimeline(jobId) {
  const res = await fetch(`/api/monitor3d/reconstruction/${encodeURIComponent(jobId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`reconstruction HTTP ${res.status}`);
  const data = await res.json();

  const flat = [];
  for (const rep of data.repetitions || []) {
    for (const beat of rep.beats || []) flat.push({ ...beat, _rep: rep });
  }
  if (data.finale_beat) flat.push({ ...data.finale_beat, _rep: null });

  beats = flat;
  totalRepetitions = data.total_repetitions || 0;
  currentIndex = 0;
  foundationBuilt = false;
  progressStats = freshProgressStats();

  // One more real, read-only GET -- still never anything but GET, so the
  // "reconstruction mode cannot affect any real machine" guarantee holds;
  // just no longer literally the ONE fetch in this path. Deliberately NOT
  // awaited here -- a real bug caught live: an earlier version of this also
  // awaited `/forge-dt-metrics/ablation/<job_id>`, measured at 60s+ for a
  // real campaign (an expensive, uncached computation, not a fluke -- timed
  // twice), which stalled the ENTIRE reconstruction panel from ever
  // becoming interactive, since app.js only enables the transport controls
  // after this function's promise resolves. That ablation fetch was DROPPED
  // entirely rather than merely made non-blocking -- tying up a worker for
  // a full minute on every campaign load, out of only 4 gunicorn workers
  // total, isn't an acceptable cost for a supplementary report-card row,
  // background or not. `/forge-dt-metrics/report` alone is fast (tens of
  // ms, measured) and still carries real IRR/TOR/IER/ESR numbers plus the
  // honest `unavailable_metrics` list -- fired off here without awaiting;
  // `forgeMetrics` populates whenever it resolves, and every report card
  // already tolerates missing data (buildReportCardHtml skips any row it
  // doesn't have), so a user reaching a report-card moment before this
  // lands just sees fewer rows, never a block.
  forgeMetrics = null;
  // The reconstruction endpoint's own TOP-LEVEL `campaign_id` is always
  // null (confirmed against a real response) -- the real value only lives
  // nested in a repetition's own `snapshot.campaign_id`.
  const campaignId = data.repetitions?.[0]?.snapshot?.campaign_id;
  if (campaignId) {
    fetch(`/api/forge-dt-metrics/report?campaign_id=${encodeURIComponent(campaignId)}`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null)).then((j) => { if (j) forgeMetrics = j; }).catch(() => {});
  }

  return { jobId, totalBeats: beats.length, campaignId: data.campaign_id, totalRepetitions };
}

// ---------------------------------------------------------------------
// Tracking / teardown helpers
// ---------------------------------------------------------------------
function track(obj, { persistent = false } = {}) {
  reconObjects.push(obj);
  (persistent ? persistentObjects : repScopedObjects).push(obj);
  monitorBridge.addObject(obj);
  return obj;
}

function disposeNow(obj) {
  monitorBridge.removeObject(obj);
  disposeEntity(obj);
}

// Removes `obj` from every one of this module's tracking arrays BEFORE
// disposing it -- for the rare object (a photon, a short-lived observation
// beam) that disposes itself early, on its own timer, instead of waiting
// for the next full teardown. Without this, the object would stay listed
// in reconObjects/repScopedObjects after already being disposed, and a
// later teardown would try to dispose it a second time (harmless in
// practice -- Three.js dispose()/scene.remove() both no-op gracefully on
// an already-removed object -- but untidy bookkeeping, avoided on purpose).
function untrackAndDispose(obj) {
  reconObjects = reconObjects.filter((o) => o !== obj);
  persistentObjects = persistentObjects.filter((o) => o !== obj);
  repScopedObjects = repScopedObjects.filter((o) => o !== obj);
  disposeNow(obj);
}

function untrackAndFade(obj, duration = 400) {
  reconObjects = reconObjects.filter((o) => o !== obj);
  persistentObjects = persistentObjects.filter((o) => o !== obj);
  repScopedObjects = repScopedObjects.filter((o) => o !== obj);
  fadeAndDispose(obj, duration);
}

// Reverse-materialize (shrink/fade) then dispose -- the repetition-handoff
// "unbuild this room before starting the next one" effect.
function fadeAndDispose(obj, duration = 350) {
  const card = obj.isGroup ? obj.userData?.card : null;
  const domEl = obj.isCSS2DObject ? obj.element : null;
  const startScale = obj.isGroup ? obj.scale.x : null;
  const startOpacity = obj.material ? obj.material.opacity : null;
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / duration);
    const k = 1 - t;
    if (obj.isGroup) {
      obj.scale.setScalar(Math.max(0.05, startScale * k));
      if (card) card.style.opacity = String(k);
    }
    if (startOpacity != null) obj.material.opacity = startOpacity * k;
    if (domEl) domEl.style.opacity = String(k);
    if (t < 1) requestAnimationFrame(step);
    else disposeNow(obj);
  }
  step();
}

// ---------------------------------------------------------------------
// Alert / spotlight center -- emphasizes the real events worth noticing
// (attack launched/detected, a fault injection's real outcome, a computed
// metric like CPR) with a 3D callout + a brief camera detour + an Alert
// Center entry (app.js renders getProgressSummary().alertFeed). User's own
// words, 2026-10-14: "cada vez que se calcula una métrica importante...
// la cámara tiene que ir hacia esta métrica, enfocarla, y luego volver a lo
// que estaba haciendo" -- for attacks/detections specifically, ~3s; for
// metrics/fault injections generally, ~2s.
// ---------------------------------------------------------------------
const ALERT_SEV_CLASS = { critical: "sev-critical", warning: "sev-warning", good: "sev-good", info: "sev-info" };

// Camera "punch in, hold, return" primitive -- shared by triggerAlert()
// below and the dedicated report-row camera visits (handleRepetitionSummary/
// handleCampaignFinale). `holdMs` here is ALREADY speed-scaled by the
// caller (each call site knows its own context for when to apply
// speedMultiplier), so this stays a plain, reusable mechanism.
function spotlightCamera(groups, holdMs, { revertGroups, focusOpts = {}, revertOpts = {} } = {}) {
  if (!groups?.length) return;
  monitorBridge.focusOnGroups(groups, { duration: 450, ...focusOpts });
  if (revertGroups?.length) {
    const revertHandle = setTimeout(() => monitorBridge.focusOnGroups(revertGroups, { duration: 600, ...revertOpts }), holdMs);
    pendingTimers.push(revertHandle);
  }
}

function triggerAlert({ kind, title, detail, severity = "info", anchorBox, holdMs = 2000, revertFocus, cameraPunch = true, showCallout = true }) {
  // Scaled by the same playback-speed slider everything else already
  // respects (compressedDurationMs) -- at 4x speed a hold should shrink
  // along with every other beat, not stay a fixed real-world 2-3s and
  // silently stretch the whole replay's actual wall-clock length well
  // beyond what the speed control promises.
  holdMs = holdMs / speedMultiplier;
  if (anchorBox && showCallout) {
    const pos = anchorBox.position.clone();
    pos.y += (anchorBox.userData?.height || 8) / 2 + 7;
    const html = `<div class="alert-kicker">${esc(kind)}</div><div class="alert-title">${esc(title)}</div>` +
      (detail ? `<div class="alert-detail">${esc(detail)}</div>` : "");
    const callout = createFloatingLabel(pos, html, `alert-callout ${ALERT_SEV_CLASS[severity] || ALERT_SEV_CLASS.info}`);
    track(callout);
    const fadeHandle = setTimeout(() => untrackAndFade(callout, 500), holdMs);
    pendingTimers.push(fadeHandle);
  }
  if (anchorBox && cameraPunch) {
    spotlightCamera([anchorBox], holdMs, { revertGroups: revertFocus?.groups, focusOpts: { paddingFactor: 1.15 }, revertOpts: revertFocus?.opts });
  }
  extraHoldMs += holdMs;
  alertFeed.push({ kind, title, detail, severity, at: beats[currentIndex]?.started_at || null });
  if (alertFeed.length > 30) alertFeed.shift();
}

// ---------------------------------------------------------------------
// Digital twin watcher -- lifecycle (create once per session / destroy on
// exit), independent of every other object's per-beat teardown cycle.
// ---------------------------------------------------------------------

// The watcher is a HUD prop, not a scene object -- user feedback 2026-10-14
// after the first version (parked at a fixed world position above the
// campaign) came across as "just one more decorative extra object" that was
// also out of frame most of the time and much bigger than everything else.
// It's now re-anchored every tick to a fixed offset from the CAMERA itself
// (position + forward*distance + right*rightOffset + up*upOffset, all in
// world space, recomputed from the camera's real live transform) -- the
// same trick used for a first-person HUD icon: this keeps it pinned to the
// same spot on screen (far right) no matter how the user orbits/zooms the
// real scene, and a FIXED anchor distance means its apparent screen size
// never changes either, so TWIN_WATCHER_SCALE only has to look right once.
const TWIN_WATCHER_SCALE = 2.2; // was 6 -- far too large next to everything else once directly compared
const TWIN_ANCHOR_DISTANCE = 55; // world units in front of the camera
const TWIN_ANCHOR_RIGHT_FRAC = 0.74; // fraction of the half-frustum-width at that distance
const TWIN_ANCHOR_UP_FRAC = 0.48; // fraction of the half-frustum-height, above center -- generous margin so the attached label (below it) still clears the bottom edge across every real focus shot's distance/FOV combination

function createTwinWatcherIfNeeded() {
  if (twinWatcher) return;
  const group = buildVigia();
  group.scale.setScalar(TWIN_WATCHER_SCALE);
  const api = group.userData;
  group.visible = twinWatcherEnabled;
  api.cono.visible = twinWatcherEnabled;
  // Permanent label attached directly under the object -- this IS the
  // watcher's real output, not a separate decorative panel elsewhere; shows
  // whatever the real comparison currently is, continuously, not just for a
  // few seconds after an observation.
  const hudLabel = createFloatingLabel(new THREE.Vector3(), "", "twin-hud");
  // Added directly via monitorBridge, NOT track() -- see this module's own
  // declaration comment on twinWatcher for why it must outlive every
  // seek/step/reset's full scene teardown.
  monitorBridge.addObject(group);
  monitorBridge.addObject(api.cono);
  monitorBridge.addObject(hudLabel);
  twinWatcher = { group, cono: api.cono, api, hudLabel };
  twinSeverityByEntity = new Map();
  twinObservationByEntity = new Map();
  lastTwinObservation = null;
  twinWatcherT0 = performance.now();
  const _fwd = new THREE.Vector3(), _right = new THREE.Vector3(), _up = new THREE.Vector3(), _anchor = new THREE.Vector3();
  const loop = () => {
    if (!twinWatcher) return;
    const camera = monitorBridge.getCamera?.();
    if (camera) {
      camera.getWorldDirection(_fwd);
      _right.crossVectors(_fwd, camera.up).normalize();
      _up.crossVectors(_right, _fwd).normalize();
      const halfH = TWIN_ANCHOR_DISTANCE * Math.tan(THREE.MathUtils.degToRad(camera.fov) / 2);
      const halfW = halfH * camera.aspect;
      _anchor.copy(camera.position)
        .addScaledVector(_fwd, TWIN_ANCHOR_DISTANCE)
        .addScaledVector(_right, halfW * TWIN_ANCHOR_RIGHT_FRAC)
        .addScaledVector(_up, halfH * TWIN_ANCHOR_UP_FRAC);
      twinWatcher.group.position.copy(_anchor);
      twinWatcher.hudLabel.position.copy(_anchor).addScaledVector(_up, -halfH * 0.22);
      // Billboard toward the camera -- the model's own "face" (eye/visor/
      // vision cone) points along its local +Z, but Object3D.lookAt() aims
      // local -Z at the target (the standard camera convention), so an
      // extra 180 degree yaw is needed to actually turn the face toward the
      // viewer instead of the back of the head.
      twinWatcher.group.lookAt(camera.position);
      twinWatcher.group.rotateY(Math.PI);
    }
    twinWatcher.api.tick((performance.now() - twinWatcherT0) / 1000, true);
    twinWatcherRafId = requestAnimationFrame(loop);
  };
  loop();
  renderTwinHud();
}

function destroyTwinWatcher() {
  if (twinWatcherRafId != null) cancelAnimationFrame(twinWatcherRafId);
  twinWatcherRafId = null;
  if (twinWatcher) {
    monitorBridge.removeObject(twinWatcher.group);
    monitorBridge.removeObject(twinWatcher.cono);
    monitorBridge.removeObject(twinWatcher.hudLabel);
    disposeEntity(twinWatcher.group);
    disposeEntity(twinWatcher.cono);
    disposeEntity(twinWatcher.hudLabel);
    twinWatcher = null;
  }
  twinSeverityByEntity = new Map();
  twinObservationByEntity = new Map();
  lastTwinObservation = null;
}

// Resets the watcher's own state (never the object itself) back to the
// honest "nothing observed yet" baseline -- called from inside
// _teardownScene(), the one place shared by both reset() (rewind to start)
// and seekTo() (jump anywhere, then instantly replay 0..target) -- so a
// fresh, correct severity gets rebuilt by the real replay either way,
// never left showing a stale state from before the jump.
function resetTwinWatcherState() {
  twinSeverityByEntity = new Map();
  twinLabelByEntity = new Map();
  twinObservationByEntity = new Map();
  lastTwinObservation = null;
  if (twinWatcher) twinWatcher.api.setState("match");
  renderTwinHud();
}

// The watcher's real, continuous output -- a permanent label attached
// directly under the 3D object itself (not a separate panel elsewhere),
// always showing the same worst-case-wins verdict driving its color, PLUS
// the actual comparison text (which node, what was really observed, when,
// resolved or not) -- user feedback 2026-10-14: the object alone, even once
// correctly visible, conveyed no information by itself.
const TWIN_HUD_COPY = {
  match: { color: "#2fbf71", word: "Match", meaning: "the real expected machine state still matches what the twin has recorded -- nothing to flag so far in this replay." },
  deviation: { color: "#f2a516", word: "Deviation (resolved)", meaning: "a real divergence was observed on this node, and the real rollback/revert for it was later confirmed -- resolved, not currently a problem." },
  discrepancy: { color: "#e5484d", word: "Discrepancy (unresolved)", meaning: "a real divergence was observed on this node and no confirmed revert/rollback has been recorded for it yet at this point in the replay." },
};
function renderTwinHud() {
  if (!twinWatcher?.hudLabel) return;
  let worst = "match", worstEntry = null;
  for (const entry of twinObservationByEntity.values()) {
    if (TWIN_SEVERITY_RANK[entry.severity] > TWIN_SEVERITY_RANK[worst]) { worst = entry.severity; worstEntry = entry; }
  }
  // Nothing outranks "match" (either truly nothing observed yet, or every
  // real observation so far happens to be good news) -- in the latter case
  // still report the real most recent one rather than a blanket "nothing
  // yet" placeholder that would otherwise hide genuinely good real news.
  if (!worstEntry && lastTwinObservation) worstEntry = lastTwinObservation;
  const copy = TWIN_HUD_COPY[worst];
  let obsLine = "No divergence observed yet";
  if (worstEntry) {
    let tsLabel = "—";
    if (worstEntry.at) {
      try { tsLabel = new Date(worstEntry.at).toLocaleTimeString("en-GB", { hour12: false, timeZone: "UTC" }) + " UTC"; } catch (e) { /* leave em dash */ }
    }
    obsLine = `${esc(worstEntry.nodeName)} -- observed ${esc(tsLabel)}` + (worstEntry.detail ? `<br/>${esc(worstEntry.detail)}` : "");
  }
  twinWatcher.hudLabel.element.innerHTML =
    `<b style="color:${copy.color}">Digital twin -- ${copy.word}</b><br/>` +
    `<span style="font-weight:400">${obsLine}</span><br/>` +
    `<span style="font-weight:400;font-size:9px;opacity:0.85">${esc(copy.meaning)}</span>`;
}

// Exported so app.js can wire a real checkbox to it (see monitor3d.html's
// #forensic-twin-watcher-toggle) -- toggles visibility only, never touches
// the object's state/animation, so re-enabling it mid-session shows
// whatever is honestly true right now, not a reset.
export function setTwinWatcherEnabled(on) {
  twinWatcherEnabled = !!on;
  if (twinWatcher) {
    twinWatcher.group.visible = twinWatcherEnabled;
    twinWatcher.cono.visible = twinWatcherEnabled;
    twinWatcher.hudLabel.visible = twinWatcherEnabled;
  }
}
export function isTwinWatcherEnabled() {
  return twinWatcherEnabled;
}

// ---------------------------------------------------------------------
// Animation primitives -- same hand-rolled rAF + cubic-ease style already
// used by scene.js's focusOn/focusOnGroups, kept consistent on purpose.
// ---------------------------------------------------------------------
function materialize(group, { duration = 700 } = {}) {
  const card = group.userData?.card;
  group.scale.setScalar(0.05);
  if (card) card.style.opacity = "0";
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / duration);
    const ease = 1 - Math.pow(1 - t, 3);
    group.scale.setScalar(0.05 + 0.95 * ease);
    if (card) card.style.opacity = String(ease);
    if (t < 1) requestAnimationFrame(step);
  }
  step();
}

function materializeLine(line, { duration = 700 } = {}) {
  const targetOpacity = line.material.opacity;
  line.material.opacity = 0;
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / duration);
    line.material.opacity = targetOpacity * (1 - Math.pow(1 - t, 3));
    if (t < 1) requestAnimationFrame(step);
  }
  step();
}

function stagger(items, gap, fn) {
  items.forEach((item, i) => {
    const handle = setTimeout(() => fn(item, i), i * gap);
    pendingTimers.push(handle);
  });
}

// Only beats with a real recorded duration (attack/preservation_step/
// analysis_phase) get this numeric readout -- everything else would be a
// fabricated number, which this codebase never does (see service.py's own
// "never invent a value that doesn't exist" rule).
function runProgressBar(container, durationMs, realSeconds) {
  const fill = container?.querySelector(".bar-fill");
  const timer = container?.querySelector(".beat-timer");
  if (!fill && !timer) return;
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / durationMs);
    if (fill) fill.style.width = `${Math.round(t * 100)}%`;
    if (timer && realSeconds != null) {
      timer.textContent = `${fmtSeconds(realSeconds * t)} / ${fmtSeconds(realSeconds)} (${Math.round(t * 100)}%)`;
    }
    if (t < 1) requestAnimationFrame(step);
  }
  step();
}

// ---------------------------------------------------------------------
// Foundation -- campaign box + repetition row. Built once per Play (from
// empty), persists across the whole run, only cleared by Reset/Exit.
// ---------------------------------------------------------------------
function buildFoundation() {
  if (foundationBuilt) return;
  foundationBuilt = true;
  const firstSnapshot = beats[0]?._rep?.snapshot;
  if (!firstSnapshot) return;

  campaignBox = createEntityBox({
    id: `campaign:${firstSnapshot.job_id}`, kind: "campaign", title: firstSnapshot.job_id,
    subtitle: `${totalRepetitions} repetition(s)`,
    status: "pending", statusLabel: "constructing", statLines: [],
    ringPct: 0, width: 14, height: 7, depth: 10,
  });
  campaignBox.position.set(0, 26, 0);
  track(campaignBox, { persistent: true });

  const repEntries = firstSnapshot.repetitions || [];
  const repBoxList = repEntries.map((r) => {
    const box = createEntityBox({
      id: `rep:${r.repetition_number}`, kind: "repetition", title: `Rep ${r.repetition_number}`,
      status: "pending", statusLabel: "pending", statLines: [],
      width: 4.5, height: 3.5, depth: 3.5,
    });
    box.scale.setScalar(0.05);
    box.userData.card.style.opacity = "0";
    track(box, { persistent: true });
    repBoxes.set(r.repetition_number, box);
    return box;
  });
  applyRowLayout(repBoxList, { y: 18, spacing: 6, maxPerRow: 10 });

  materialize(campaignBox);
  // Deliberately does NOT include the digital twin watcher here -- it's a
  // camera-anchored HUD prop now (re-positioned every frame relative to the
  // camera itself, see createTwinWatcherIfNeeded), always on screen by
  // construction; including it in this bounding-box-based focus calculation
  // would feed the camera's own position back into what the camera is being
  // moved to frame.
  monitorBridge.focusOnGroups([campaignBox, ...repBoxList]);
  stagger(repBoxList, 120, (box) => {
    materialize(box);
    const conn = createConnector(campaignBox, box);
    track(conn, { persistent: true });
    materializeLine(conn);
  });
}

// ---------------------------------------------------------------------
// Per-repetition skeleton -- pre-computes and finalizes every row position
// for this repetition's hosts and preservation/analysis artifacts BEFORE
// any of them is revealed, since the full beat list (and therefore every
// row's final size) is already known before Play. This guarantees
// connectors are always drawn against a box's true, final position, never
// a stale one that a later re-layout would silently invalidate.
// ---------------------------------------------------------------------
const builtRepetitions = new Set();

function beatsForRep(repNum) {
  return beats.filter((b) => b.repetition_number === repNum);
}

function prepareRepetitionSkeleton(repNum) {
  if (builtRepetitions.has(repNum)) return;
  builtRepetitions.add(repNum);
  const repBeats = beatsForRep(repNum);
  const snapshot = repBeats[0]?._rep?.snapshot;
  if (!snapshot) return;

  const roleByName = new Map((snapshot.hosts || []).map((h) => [h.name, h.role]));
  const hostsSeen = new Map();
  const hostBeatsById = new Map();
  for (const b of repBeats) {
    if (b.kind !== "deployment" && b.kind !== "tool_install") continue;
    const inst = b.payload?.instance;
    if (!inst) continue;
    if (b.kind === "deployment" && !hostsSeen.has(inst.instance_id)) hostsSeen.set(inst.instance_id, inst);
    if (!hostBeatsById.has(inst.instance_id)) hostBeatsById.set(inst.instance_id, []);
    hostBeatsById.get(inst.instance_id).push(b);
  }
  // The last deployment/tool_install beat seen for each host is the cue to
  // pull the camera back out to the campaign-wide view ("sale de la máquina
  // y centraliza la vista") before moving on to whatever comes next.
  for (const list of hostBeatsById.values()) {
    lastHostBeatIds.add(list[list.length - 1].beat_id);
  }
  const hostBoxList = [...hostsSeen.values()].map((inst) => {
    const box = createEntityBox({
      id: `host:${inst.instance_id}`, kind: "host", title: inst.name,
      subtitle: inst.ip_floating || inst.ip_private,
      status: "pending", statusLabel: "constructing", statLines: [],
      width: 10, height: 5.5, depth: 7,
      raw: { ...inst, role: roleByName.get(inst.name) },
      boxColor: roleByName.get(inst.name) === "attacker" ? BOX_COLOR_ATTACKER : undefined,
      visualModel: buildHostVisual(roleByName.get(inst.name), 10, 5.5, 7),
    });
    box.scale.setScalar(0.05);
    box.userData.card.style.opacity = "0";
    track(box);
    hostBoxes.set(inst.instance_id, box);
    return box;
  });
  applyRowLayout(hostBoxList, { y: 10, spacing: 13, maxPerRow: 5 });

  const artifactBeats = repBeats.filter((b) => b.kind === "preservation_step" || b.kind === "analysis_phase");
  const artifactBoxList = artifactBeats.map((b) => {
    // Real per-artifact detail (memory/disk size, first hash characters) --
    // stage_timing_service now surfaces sha256/size_bytes on exactly the
    // entries that have them (memory/disk acquisition); every other stage
    // (network import, each analysis phase) simply omits the line rather
    // than showing a fabricated size/hash.
    const entry = b.payload?.stage_timeline_entry;
    const detailBits = [];
    const size = fmtBytes(entry?.size_bytes);
    if (size) detailBits.push(size);
    if (entry?.sha256) detailBits.push(`sha256 ${entry.sha256.slice(0, 12)}…`);
    const detailHtml = detailBits.length ? `<div class="ent-stat">${esc(detailBits.join(" · "))}</div>` : "";
    const box = createEntityBox({
      id: b.beat_id, kind: "evidence", title: b.title,
      status: "pending", statusLabel: "constructing", statLines: [],
      width: 6, height: 3.2, depth: 4,
      extraHtml: `${detailHtml}<div class="bar-track"><div class="bar-fill" style="width:0%"></div></div><div class="beat-timer"></div>`,
    });
    box.scale.setScalar(0.05);
    box.userData.card.style.opacity = "0";
    track(box);
    b._box = box;
    return box;
  });
  applyRowLayout(artifactBoxList, { y: -14, spacing: 8, maxPerRow: 6, zOffset: 6 });
}

// ---------------------------------------------------------------------
// Per-repetition "replay progress" ring for the case box (see plan finding:
// evidence_pipeline arrives already-frozen/complete from a historical
// repetition, so it can't be used as an incremental ring -- this counts
// real beats of THIS repetition that have actually played instead, which
// genuinely does move as the repetition's story advances).
// ---------------------------------------------------------------------
function updateCaseReplayRing(beat) {
  if (!caseBox) return;
  const repBeats = beatsForRep(beat.repetition_number);
  const idx = repBeats.indexOf(beat);
  const pct = repBeats.length ? Math.round(((idx + 1) / repBeats.length) * 100) : 0;
  updateRing(caseBox.userData.card, pct, "#22d3ee");
}

// ---------------------------------------------------------------------
// Beat handlers
// ---------------------------------------------------------------------
function handleDeployment(beat) {
  prepareRepetitionSkeleton(beat.repetition_number);
  const inst = beat.payload?.instance;
  if (!inst) return;
  const box = hostBoxes.get(inst.instance_id);
  if (!box || box.userData._revealed) return;
  box.userData._revealed = true;
  materialize(box);
  // Case is never the parent here in practice -- it never exists yet at
  // deployment time (case_created always comes after every host in the
  // real beat order) -- and shouldn't be even if it did, now that it sits
  // BELOW the host row rather than above it.
  const parent = repBoxes.get(beat.repetition_number) || campaignBox;
  if (parent) {
    const conn = createConnector(parent, box);
    track(conn);
    materializeLine(conn);
    // Real data flowing to build this machine, right when it's actually
    // happening -- one photon along the exact cable just drawn, never a
    // decorative loop (2026-10-14, user's own request to see information or
    // energy moving through the cables that already connect everything).
    spawnPhoton(conn.userData.cableCurve, 0x22d3ee, (o) => track(o), (o) => untrackAndDispose(o));
  }
  // Camera enters exactly this machine's box while it's being built --
  // "entra en la caja de la máquina" -- instead of staying on the wide shot.
  monitorBridge.focusOnGroups([box]);
}

// One small box per tool, materializing next to the host it's installed on
// -- same visual pattern app.js's renderDrilledHost() already uses for its
// (live-mode) tool boxes, at a smaller scale since reconstruction's hosts
// sit at overview scale, not the large "drilled" scale. Camera stays framed
// on the host + all its tool boxes revealed so far while this plays out.
function handleToolInstall(beat) {
  const inst = beat.payload?.instance;
  const tool = beat.payload?.tool;
  const hostBox = inst ? hostBoxes.get(inst.instance_id) : null;
  if (!inst || !tool || !hostBox) return;

  let toolList = hostToolBoxes.get(inst.instance_id);
  if (!toolList) {
    toolList = [];
    hostToolBoxes.set(inst.instance_id, toolList);
  }
  const box = createEntityBox({
    id: beat.beat_id, kind: "tool", title: tool.tool_name, subtitle: inst.name,
    status: "pending", statusLabel: "installing", statLines: [],
    width: 3, height: 1.8, depth: 2.2,
    extraHtml: `<div class="bar-track"><div class="bar-fill" style="width:0%"></div></div><div class="beat-timer"></div>`,
  });
  toolList.push(box);
  track(box);
  // Same-center, smaller-scale placement as renderDrilledHost's tool row --
  // reads as "inside" the host's own volume. Tool boxes have no connectors
  // (mirroring the live-mode pattern), so re-laying out the growing row on
  // every new arrival is safe here.
  applyRowLayout(toolList, { y: -4, spacing: 3.6, maxPerRow: 3, zOffset: 1 });
  for (const b of toolList) {
    b.position.x += hostBox.position.x;
    b.position.y += hostBox.position.y;
    b.position.z += hostBox.position.z;
  }
  materialize(box);
  runProgressBar(box.userData.card, compressedDurationMs(beat.real_duration_seconds, beat.kind), beat.real_duration_seconds);
  monitorBridge.focusOnGroups([hostBox, ...toolList]);
}

// The last deployment/tool_install beat for a given machine is the cue to
// pull back out to a campaign-wide view before the story moves on --
// "sale de la máquina y centraliza la vista global" -- with a slightly
// longer, more deliberate camera move than the tight per-box focuses.
function maybeReturnToGlobalView(beat) {
  if (!lastHostBeatIds.has(beat.beat_id)) return;
  const groups = [campaignBox, ...repBoxes.values(), caseBox, ...hostBoxes.values()].filter(Boolean);
  monitorBridge.focusOnGroups(groups, { duration: 1100 });
}

// Real alert severity, color-coded -- same mapping as app.js's
// severityBadge (duplicated, not imported: reconstruction.js and app.js
// are independent modules with no shared helper file for this).
const SEVERITY_COLORS = { critical: "#ef4444", high: "#ef4444", medium: "#f59e0b", low: "#22d3ee" };
function severityLabelHtml(sev) {
  if (!sev) return "";
  const s = String(sev).toLowerCase();
  const color = SEVERITY_COLORS[s] || "#7c93a0";
  return `<span style="display:block;margin-top:3px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:${color};">severity: ${esc(s)}</span>`;
}

function handleAttack(beat) {
  const attack = beat.payload?.attack;
  if (!attack) return;
  const attackerBox = [...hostBoxes.values()].find((b) => b.userData.raw?.role === "attacker");
  const targetBox = [...hostBoxes.values()].find((b) => b.userData.raw?.name === attack.target_node);
  if (!attackerBox || !targetBox || attackerBox === targetBox) return;
  const line = createRelationLine(attackerBox, targetBox, 0xef4444, { bow: 8, radius: 0.22 });
  track(line);
  materializeLine(line);
  spawnPhoton(line.userData.cableCurve, 0xef4444, (o) => track(o), (o) => untrackAndDispose(o), { travelMs: 900 });
  const midpoint = attackerBox.position.clone().lerp(targetBox.position, 0.5);
  midpoint.y += 10.5;
  // Real severity of the alert this attack went on to trigger -- shown
  // directly above the red arc/arrow itself, not buried in a side panel,
  // per explicit request. Reconstruction mode replays already-known
  // history, so surfacing the real outcome here is honest, not invented.
  const html = `${esc(attack.attack_name || "Attack")}${attack.protocol ? ` (${esc(attack.protocol)})` : ""}` +
    severityLabelHtml(beat.payload?.known_severity) +
    `<div class="bar-track"><div class="bar-fill" style="width:0%"></div></div><div class="beat-timer"></div>`;
  const label = createFloatingLabel(midpoint, html, "security");
  track(label);
  monitorBridge.focusOnGroups([attackerBox, targetBox]);
  runProgressBar(label.element, compressedDurationMs(beat.real_duration_seconds, beat.kind), beat.real_duration_seconds);
  // Alert Center entry only here (no extra 3D callout/camera punch, no pacing
  // hold) -- the red ray + label above is already this beat's own dedicated
  // visual; the real verdict worth pausing and emphasizing for is the
  // DETECTION beat that follows (handleDetection), not the launch itself.
  triggerAlert({
    kind: "ATTACK", title: `${attack.attack_name || "Attack"} launched`,
    detail: `${attack.target_node || "target"}${attack.protocol ? ` · ${attack.protocol}` : ""}`,
    severity: "warning", holdMs: 0, cameraPunch: false,
  });
}

// Real intervention (Intervention Ledger, M1-M5) replayed against the host
// it was really applied to -- same `phase_timeline` payload shape Digital
// Twin View's node panel already renders, just surfaced here as a beat
// instead of on-demand. Keeps the 3D cue lightweight (badge + floating
// label on the real target box); the full 6-phase chain itself is shown in
// the Stage Detail panel via renderPhaseTimelineHtml (see app.js), so the
// SAME widget is reused rather than redrawn as a second 3D visual.
function handleIntervention(beat) {
  const timeline = beat.payload?.phase_timeline;
  if (!timeline || !timeline.ok) return;
  const targetBox = hostBoxes.get(timeline.target_node_id);
  if (!targetBox) return;
  const donePhases = (timeline.phases || []).filter((p) => p.status === "done").length;
  const totalPhases = (timeline.phases || []).length;
  const fullyComplete = donePhases === totalPhases;
  updateBadge(targetBox.userData.card, fullyComplete ? "completed" : "live", `intervention: ${donePhases}/${totalPhases}`);
  const pos = targetBox.position.clone();
  pos.y += 9;
  const label = createFloatingLabel(pos, esc(timeline.type || "intervention"), "security");
  track(label);
  // No longer widened to include the twin watcher -- it's a camera-anchored
  // HUD prop now (see createTwinWatcherIfNeeded), always on screen by
  // construction regardless of what this focuses on; including it here
  // would feed the camera's own position back into its own focus target.
  monitorBridge.focusOnGroups([targetBox]);
  updateTwinWatcherForIntervention(timeline, targetBox);
}

// Drives the digital twin watcher from the EXACT same phase_timeline data
// the badge/label above already read -- nothing new fetched, nothing
// invented. "twin_observed" done = the real digital twin genuinely
// noticed something about this intervention (intervention_ledger/
// timeline.py's own build_phase_timeline, already real and verified
// elsewhere in this platform); "reverted" done on top of that = it was
// since corrected/resolved. Several real interventions can be live in the
// replay at once (different hosts, overlapping repetitions) -- the watcher
// always shows the WORST currently-unresolved one, never just the latest.
function phaseByName(timeline, name) {
  return (timeline.phases || []).find((p) => p.phase === name);
}

// The generic "the digital twin reports something about a real entity"
// pipeline -- originally written for host interventions only, generalized
// 2026-10-15 so a case's own reconstruction-confidence metric or the
// campaign's own final reproducibility verdict drive the EXACT same
// mechanism: worst-case-wins color on the watcher, its attached HUD label,
// a short-lived observation label near the reporting entity, and a real
// "information traveling to the twin" beam+photon along a cable reused from
// the SAME `createSaggingCable` helper every other cable in this file uses
// -- never a second, special-cased visual per entity type.
function feedTwinObservation({ entityKey, entityName, anchorBox, severity, detail, at, alertKind, alertTitle, alertHoldMs = 2000, alertCameraPunch = false, alertRevertFocus, alertAnchorBox }) {
  if (!twinWatcher || !anchorBox) return;

  twinSeverityByEntity.set(entityKey, severity);
  let worst = "match";
  for (const sev of twinSeverityByEntity.values()) {
    if (TWIN_SEVERITY_RANK[sev] > TWIN_SEVERITY_RANK[worst]) worst = sev;
  }
  twinWatcher.api.setState(worst);

  lastTwinObservation = { severity, nodeName: entityName, at, detail: detail || "" };
  twinObservationByEntity.set(entityKey, lastTwinObservation);
  renderTwinHud();

  // No lookAt() here anymore -- now that the watcher is camera-anchored
  // (re-positioned every frame, see createTwinWatcherIfNeeded), a one-time
  // "face this world position" computation would go stale the instant the
  // camera moves again, since it was expressed relative to the watcher's
  // own position at the moment of the call. The idle scan animation alone
  // is enough motion for a HUD prop; the beam + HUD label below are what
  // actually convey which entity this observation is about.
  const sevColorHex = severity === "discrepancy" ? 0xe5484d : severity === "deviation" ? 0xf2a516 : 0x2fbf71;
  const sevColor = `#${sevColorHex.toString(16).padStart(6, "0")}`;
  let tsLabel = "—";
  if (at) {
    try { tsLabel = new Date(at).toLocaleTimeString("en-GB", { hour12: false, timeZone: "UTC" }) + " UTC"; } catch (e) { /* leave em dash */ }
  }
  const html = `<b style="color:${sevColor}">Digital twin</b><br/>` +
    `<span style="font-weight:400">observed ${esc(tsLabel)}</span>` +
    (detail ? `<br/><span style="font-weight:400;font-size:10px">${esc(detail)}</span>` : "");
  // Replace (not stack) any still-visible label for this same entity -- see
  // twinLabelByEntity's own declaration comment.
  const previousLabel = twinLabelByEntity.get(entityKey);
  if (previousLabel) untrackAndFade(previousLabel, 200);
  const labelPos = anchorBox.position.clone();
  labelPos.y += (anchorBox.userData?.height || 8) / 2 + 6;
  const twinLabel = createFloatingLabel(labelPos, html, severity === "discrepancy" ? "critical" : "security");
  track(twinLabel);
  twinLabelByEntity.set(entityKey, twinLabel);
  // Faded out a few seconds later, same as the beam below. This is a flash
  // tied to one specific observation, not a permanent record of it -- the
  // real history is already in the Stage Detail panel.
  const labelFadeHandle = setTimeout(() => {
    if (twinLabelByEntity.get(entityKey) === twinLabel) twinLabelByEntity.delete(entityKey);
    untrackAndFade(twinLabel, 600);
  }, 4200);
  pendingTimers.push(labelFadeHandle);

  // A short-lived observation beam -- real information traveling toward the
  // twin -- one real photon, then the beam itself fades a moment later.
  // Never a permanent structural cable (that would clutter the scene with
  // one per entity); this is a flash tied to a real, specific observation.
  // Reuses the exact same cable/photon primitives every other real-data
  // link in this file already uses (createSaggingCable/spawnPhoton) -- the
  // twin is just one more real endpoint, not a special case.
  const beam = createSaggingCable(anchorBox, twinWatcher.group, sevColorHex, { opacity: 0.55, radius: 0.08 });
  track(beam);
  spawnPhoton(beam.userData.cableCurve, sevColorHex, (o) => track(o), (o) => untrackAndDispose(o), { travelMs: 1400 });
  const beamFadeHandle = setTimeout(() => untrackAndFade(beam, 500), 1700);
  pendingTimers.push(beamFadeHandle);

  if (alertKind) {
    triggerAlert({
      kind: alertKind, title: alertTitle || entityName,
      detail: detail || "",
      severity: severity === "discrepancy" ? "critical" : severity === "deviation" ? "warning" : "good",
      holdMs: alertHoldMs, anchorBox: alertAnchorBox || anchorBox, cameraPunch: alertCameraPunch, revertFocus: alertRevertFocus,
      showCallout: false, // the 3D label this function already drew above IS this observation's own callout
    });
  }
}

function updateTwinWatcherForIntervention(timeline, targetBox) {
  const observed = phaseByName(timeline, "twin_observed");
  if (!observed || observed.status !== "done") return; // nothing real to react to yet
  const reverted = phaseByName(timeline, "reverted");
  const severity = reverted?.status === "done" ? "deviation" : "discrepancy";
  const entityName = timeline.target_node_name || timeline.target_node_id;
  feedTwinObservation({
    entityKey: `host:${timeline.target_node_id}`, entityName, anchorBox: targetBox,
    severity, detail: observed.detail || "", at: observed.at,
    alertKind: "FAULT INJECTION", alertTitle: `${timeline.type || "intervention"} on ${entityName}`,
  });
}

function handleDetection(beat) {
  const detection = beat.payload?.detection;
  const attackBeat = beatsForRep(beat.repetition_number).find((b) => b.kind === "attack");
  const targetName = attackBeat?.payload?.attack?.target_node;
  const targetBox = targetName ? [...hostBoxes.values()].find((b) => b.userData.raw?.name === targetName) : null;
  if (!targetBox) return;
  const detected = detection?.outcome === "detected";
  // "historical:" prefix is deliberate -- this badge replays a real detection
  // from an already-completed campaign (days/weeks old), not a live alert on
  // the real scenario machines. User reported reading this as a live alert
  // twice; the label itself now says otherwise rather than relying on the
  // small top-bar "reconstruction mode" text to carry that distinction.
  updateBadge(targetBox.userData.card, detected ? "under_attack" : "warning", `historical: ${detection?.outcome || "unknown"}`);
  // The real "news" moment this user feedback (2026-10-14) was specifically
  // about: a dedicated, un-missable callout + a brief camera punch onto the
  // target, held ~3s (user's own number for attacks) before returning to
  // wherever the replay was framing before this beat (here, the same
  // attacker+target pair the attack beat itself already focused on).
  const ts = detection?.trigger_alert_timestamp ? String(detection.trigger_alert_timestamp).slice(0, 16).replace("T", " ") : null;
  const attackerBox = [...hostBoxes.values()].find((b) => b.userData.raw?.role === "attacker");
  triggerAlert({
    kind: "DETECTION",
    title: detected ? "Attack detected" : "Attack NOT detected",
    detail: detected
      ? `${detection.trigger_alert_rule || "matched rule n/a"}${detection.trigger_alert_severity ? ` · ${detection.trigger_alert_severity}` : ""}${ts ? ` · ${ts}` : ""}`
      : `${detection?.trigger_attempts_total || 0} real attempt(s), no reliable alert match`,
    severity: detected ? "good" : "critical",
    anchorBox: targetBox,
    holdMs: 3000,
    revertFocus: attackerBox ? { groups: [attackerBox, targetBox] } : { groups: [targetBox] },
  });
}

function handleCaseCreated(beat) {
  const repNum = beat.repetition_number;
  const caseData = beat.payload?.case;
  caseBox = createEntityBox({
    id: `case:${caseData?.case_id || "rep" + repNum}`, kind: "case",
    title: caseData?.case_id || "Case (not available)",
    subtitle: caseData?.case_real_name,
    status: "pending", statusLabel: "constructing", statLines: [],
    ringPct: 0, width: 12, height: 6, depth: 8, raw: caseData,
    visualModel: buildCaseVisual(12, 6, 8),
  });
  // Below the host row, not above it -- matches the real chronological
  // order (machines exist first, the case only gets created once an
  // attack is detected) and gives every host a real, unobstructed cable
  // straight down into it instead of one single link crossing back up
  // through the host row from the repetition box.
  caseBox.position.set(0, -6, 0);
  track(caseBox);
  materialize(caseBox);
  // One evidentiary cable per host, all real (every host that's been
  // deployed by this point in the timeline) -- not a single structural
  // link from the repetition box. Violet tint (matches this dashboard's
  // existing "evidence source link" color) distinguishes these from the
  // structural campaign/repetition/host cables above.
  for (const hostBox of hostBoxes.values()) {
    const conn = createConnector(hostBox, caseBox, { colorHex: 0x6366f1 });
    track(conn);
    materializeLine(conn);
    // Real evidence flowing in from this host, right as the case is built.
    spawnPhoton(conn.userData.cableCurve, 0x6366f1, (o) => track(o), (o) => untrackAndDispose(o));
  }
  // Evidence source link -- same real relationship live mode already draws
  // (Case -> the specific host it was acquired from, "evidence" in the live
  // sensor-coverage panel), missing from reconstruction until now.
  const attackBeat = beatsForRep(repNum).find((b) => b.kind === "attack");
  const targetName = attackBeat?.payload?.attack?.target_node;
  const targetBox = targetName ? [...hostBoxes.values()].find((b) => b.userData.raw?.name === targetName) : null;
  if (targetBox) {
    const link = createRelationLine(caseBox, targetBox, 0x6366f1, { bow: 3, radius: 0.16 });
    track(link);
    materializeLine(link);
    const midpoint = caseBox.position.clone().lerp(targetBox.position, 0.5);
    midpoint.y += 5;
    track(createFloatingLabel(midpoint, `Acquired from ${esc(targetName)}`, "evidence"));
  }
  monitorBridge.focusOnGroups([...hostBoxes.values(), caseBox].filter(Boolean));
}

// One-time "enter the case" camera move for a repetition -- frames the case
// box together with every artifact/analysis box it will show, ONCE, so the
// camera doesn't jump for every single artifact that materializes inside
// that already-fixed framing afterward.
function maybeFocusCaseArea(beat) {
  if (caseFocusedForRep === beat.repetition_number || !caseBox) return;
  caseFocusedForRep = beat.repetition_number;
  const artifactBoxes = beatsForRep(beat.repetition_number)
    .filter((b) => (b.kind === "preservation_step" || b.kind === "analysis_phase") && b._box)
    .map((b) => b._box);
  monitorBridge.focusOnGroups([caseBox, ...artifactBoxes], { duration: 1000 });
}

function handleArtifact(beat) {
  prepareRepetitionSkeleton(beat.repetition_number);
  maybeFocusCaseArea(beat);
  const box = beat._box;
  if (!box || box.userData._revealed) return;
  box.userData._revealed = true;
  materialize(box);
  if (caseBox) {
    const conn = createConnector(caseBox, box);
    track(conn);
    materializeLine(conn);
    spawnPhoton(conn.userData.cableCurve, 0x22d3ee, (o) => track(o), (o) => untrackAndDispose(o));
  }
  updateBadge(box.userData.card, "running", "constructing");
  runProgressBar(box.userData.card, compressedDurationMs(beat.real_duration_seconds, beat.kind), beat.real_duration_seconds);
  updateCaseReplayRing(beat);
}

// Real backend-computed label -> this module's severity vocabulary -- the
// thresholds themselves belong to foc_causal_reconstruction/config.py's own
// CPR_LABEL_THRESHOLDS (0.80/0.50/0.25), never re-decided here; this just
// reads the label the backend already assigned.
const CPR_LABEL_SEVERITY = {
  mostly_recoverable: "match", partially_recoverable: "deviation",
  weak_recoverability: "discrepancy", low_recoverability: "discrepancy", unknown: "match",
};

function handleReconstruction(beat) {
  if (!caseBox) return;
  const status = beat.payload?.causal_status || {};
  const metrics = status.metrics_preview;
  const cpr = metrics?.causal_path_recoverability;
  updateBadge(caseBox.userData.card, "info", cpr != null ? `CPR ${cpr}` : "reconstruction n/a");
  updateCaseReplayRing(beat);
  // A real computed metric previously had NO visual emphasis at all beyond
  // this small badge text change -- user feedback 2026-10-14/15: "cada vez
  // que se calcula una métrica importante" the camera should go to it, hold
  // ~2s, then return; and when the digital twin reports on a real entity
  // (the case, not just a host) a cable+photon should feed it, same as a
  // host intervention already does. CPR (Causal Path Recoverability) is
  // exactly that kind of metric -- the real number this platform's
  // reconstruction-confidence question hinges on. A real execution problem
  // (errors[], is_stale, degraded_ok=false) overrides the label-based
  // severity -- something actually going wrong in the computation itself
  // matters more than a merely-partial recoverability score.
  if (cpr != null) {
    const hasExecutionProblem = (status.errors?.length > 0) || status.is_stale || status.degraded_ok === false;
    const severity = hasExecutionProblem ? "discrepancy" : (CPR_LABEL_SEVERITY[metrics.recoverability_label] || "match");
    // The REAL plain-language sentences this platform's own backend already
    // writes (foc_causal_reconstruction/service.py's _cpr_interpretation /
    // main_limitation) -- never a number restated without the caveat that
    // explains it.
    const detailParts = [
      `CPR ${cpr}${metrics.reconstruction_confidence != null ? ` · reconstruction confidence ${metrics.reconstruction_confidence}` : ""}`,
      metrics.interpretation,
      status.main_limitation,
    ].filter(Boolean);
    feedTwinObservation({
      entityKey: caseBox.userData.id || `case:${status.case_id}`,
      entityName: status.case_id || caseBox.userData.title || "case",
      anchorBox: caseBox, severity, detail: detailParts.join(" -- "), at: metrics.generated_at,
      alertKind: "METRIC", alertTitle: `CPR calculated: ${cpr}`,
      alertCameraPunch: true, alertRevertFocus: { groups: [caseBox] },
    });
    repCaseMetrics.set(beat.repetition_number, {
      caseId: status.case_id, cpr, reconstructionConfidence: metrics.reconstruction_confidence,
      recoverabilityLabel: metrics.recoverability_label,
    });
  }
}

function handleSeal(beat) {
  if (!caseBox) return;
  const sealed = !!beat.available;
  recolorEntity(caseBox, statusColor(sealed ? "completed" : "pending"));
  updateBadge(caseBox.userData.card, sealed ? "completed" : "pending", sealed ? "sealed" : "unsealed");
  updateCaseReplayRing(beat);
  // Feed-only (no camera punch, no twin beam) -- this is a real custody
  // milestone worth a line in the Alert Center, but not an analytical
  // "observation" the digital twin itself is making the way CPR or a
  // reproducibility verdict is.
  if (sealed) {
    const integrity = beat.payload?.integrity || {};
    triggerAlert({
      kind: "FORENSICS", title: "Case sealed",
      detail: `manifest ${integrity.manifest_present ? "present" : "MISSING"} · custody ${integrity.custody_present ? "present" : "MISSING"}`,
      severity: (integrity.manifest_present && integrity.custody_present) ? "good" : "warning",
      holdMs: 0, cameraPunch: false,
    });
  }
}

function handleRepetitionSummary(beat) {
  const repNum = beat.repetition_number;
  const rBox = repBoxes.get(repNum);
  if (rBox) {
    recolorEntity(rBox, statusColor("completed"));
    updateBadge(rBox.userData.card, "completed", "completed");
  }
  if (campaignBox) {
    updateRing(campaignBox.userData.card, Math.round((repNum / (totalRepetitions || repNum)) * 100), "#22d3ee");
  }
  // A real per-repetition report card -- same request as the campaign one,
  // "y cada rep". Built from data already real and on-hand (repCaseMetrics,
  // stashed by handleReconstruction above; progressStats' own per-case
  // tallies) -- no new fetch needed. Lives in the dedicated report row
  // (REPORT_ROW_Y), never near the 3D hierarchy itself -- user's explicit
  // correction 2026-10-15 after the first version collided with a host's
  // own label. `persistent: true` because teardownRepetitionScoped() right
  // below would otherwise fade/dispose it immediately.
  const m = repCaseMetrics.get(repNum);
  const card = buildReportCardHtml(
    `Repetition ${repNum} report`,
    [
      ["Case", m?.caseId || progressStats.currentCaseId],
      ["CPR", m?.cpr],
      ["Reconstruction confidence", m?.reconstructionConfidence],
      ["Recoverability", m?.recoverabilityLabel ? String(m.recoverabilityLabel).replace(/_/g, " ") : null],
      ["Artifacts preserved", progressStats.currentCaseArtifacts || null],
      ["Evidence volume", progressStats.currentCaseBytes ? fmtBytes(progressStats.currentCaseBytes) : null],
    ],
  );
  const cardPos = new THREE.Vector3((repNum - 1) * 28, REPORT_ROW_Y, 0);
  const cardLabel = createFloatingLabel(cardPos, card, "report-card");
  track(cardLabel, { persistent: true });
  reportCardsByRep.set(repNum, cardLabel);

  // A deliberate camera visit -- user's explicit requirement: whatever the
  // replay is doing right now must always be in frame, never built
  // off-screen. The camera dips down to the report row, holds ~5s (scaled
  // by playback speed like everything else), then returns to a neutral
  // overview ready for the next repetition's own construction to pick up
  // from (NOT including caseBox/hostBoxes -- those are about to be torn
  // down by teardownRepetitionScoped() below, already-faded objects would
  // make a stale revert target).
  const repHoldMs = 5000 / speedMultiplier;
  const overviewGroups = [campaignBox, ...repBoxes.values()].filter(Boolean);
  spotlightCamera([cardLabel], repHoldMs, { revertGroups: overviewGroups, focusOpts: { paddingFactor: 2.2 }, revertOpts: { duration: 900 } });
  extraHoldMs += repHoldMs;

  teardownRepetitionScoped();
}

// The chronologically-correct "here it stopped" moment for a failed
// campaign (campaign_failure_forensics.reconstruct_failure(), reused
// unchanged) -- deliberately the LAST beat of the repetition that was
// actually running when the job died, so it only appears once playback
// genuinely reaches that point, never shown up front as a spoiler. User's
// own words, 2026-10-12: watching the replay should build up normally,
// phase by phase, and only when it reaches the real failure moment should
// something dramatic and red mark it, with the real explanation alongside.
function handleCampaignFailed(beat) {
  const repNum = beat.repetition_number;
  const rBox = repBoxes.get(repNum);
  if (rBox) {
    recolorEntity(rBox, statusColor("failed"));
    updateBadge(rBox.userData.card, "failed", "FAILED HERE");
  }
  const anchor = rBox || campaignBox;
  if (!anchor) return;
  const pos = anchor.position.clone();
  pos.y += 13;
  const report = beat.payload?.failure_report || {};
  const cause = (report.probable_cause || "undetermined").replace(/_/g, " ");
  const label = createFloatingLabel(pos, `CAMPAIGN FAILED HERE<br><span style="font-weight:400;text-transform:none;font-size:11px;">${esc(cause)} (confidence: ${esc(report.confidence)})</span>`, "critical");
  track(label, { persistent: true });
  monitorBridge.focusOnGroups([anchor, label].filter(Boolean), { paddingFactor: 1.5, duration: 1200 });
  // This was previously the one genuinely dramatic real event with NO Alert
  // Center presence at all -- its own label+focus above are already its
  // dedicated visual (showCallout/cameraPunch both skipped here), just a
  // real feed entry so it's not invisible to anyone scrolling that list.
  triggerAlert({
    kind: "CAMPAIGN FAILED", title: cause,
    detail: `confidence: ${report.confidence ?? "n/a"}`,
    severity: "critical", holdMs: 1500, cameraPunch: false,
  });
}

function handleCampaignFinale(beat) {
  if (!campaignBox) return;
  updateRing(campaignBox.userData.card, 100, "#34d399");
  updateBadge(campaignBox.userData.card, "completed", "completed");

  const report = beat.payload?.comparison_report;
  let label = null;
  if (report) {
    const pos = campaignBox.position.clone();
    pos.y += 10;
    label = createFloatingLabel(pos, esc(report.verdict || "Campaign finished"), "security");
    track(label, { persistent: true });
  }
  // Closing shot: pull all the way back to the entire real hierarchy still
  // standing (campaign + every repetition box) in one frame -- a longer,
  // more deliberate move and extra padding than the per-stage focuses, plus
  // the same fixed oblique `dir` focusOnGroups already frames from, so it
  // reads unmistakably as a 3D scene rather than a flat top-down grid. The
  // digital twin watcher is deliberately NOT included -- it's a
  // camera-anchored HUD prop (see createTwinWatcherIfNeeded), always on
  // screen regardless of what this focuses on.
  const everything = [campaignBox, ...repBoxes.values(), label].filter(Boolean);
  monitorBridge.focusOnGroups(everything, { paddingFactor: 1.6, duration: 1800 });

  // A real, readable campaign report card -- user's own request to see the
  // important metrics "nicely" in the 3D background. Combines what was
  // already computed here (ΔCPR/reproducibility) with the forge_dt_metrics
  // bundle fetched once in loadTimeline() -- every row degrades gracefully
  // (just omitted) if that fetch didn't succeed. Lives in the SAME
  // dedicated report row as every repetition's own card (never near the 3D
  // hierarchy -- user's explicit correction 2026-10-15), placed after the
  // last repetition's card so the row reads left-to-right as "each
  // repetition, then the overall campaign verdict".
  let campaignCardLabel = null;
  if (report) {
    const cmp = (report.comparisons || [])[0];
    const card = buildReportCardHtml(
      "Campaign report",
      [
        ["Reproducibility", report.reproducibility_index != null ? `index ${report.reproducibility_index}` : null],
        ["ΔCPR (A vs B)", cmp ? `${cmp.delta_cpr} (${cmp.cpr_a} → ${cmp.cpr_b})` : null],
        ["Δwcpr", cmp ? (cmp.delta_wcpr_acceptable ? "acceptable" : "NOT acceptable") : null],
        ["Fault realized (IRR)", forgeMetrics?.irr ? `${Math.round(forgeMetrics.irr.irr * 100)}% (${forgeMetrics.irr.n_realized}/${forgeMetrics.irr.n_attempts})` : null],
        ["Seen by twin (TOR)", forgeMetrics?.tor ? `${Math.round(forgeMetrics.tor.tor * 100)}% · median ${forgeMetrics.tor.median_latency_seconds?.toFixed(2)}s` : null],
        ["Evidence-confirmed (IER)", forgeMetrics?.ier ? `${Math.round(forgeMetrics.ier.ier * 100)}% (${forgeMetrics.ier.n_with_evidence}/${forgeMetrics.ier.n_realized})` : null],
        ["Evidence support (ESR)", forgeMetrics?.esr ? `${Math.round(forgeMetrics.esr.esr * 100)}% (${forgeMetrics.esr.n_supported}/${forgeMetrics.esr.n_links})` : null],
        ["Monitoring overhead", forgeMetrics?.monitoring_overhead ? `${forgeMetrics.monitoring_overhead.mean_seconds_per_tick}s/tick avg` : null],
      ],
      forgeMetrics?.unavailable_metrics
        ? `${Object.keys(forgeMetrics.unavailable_metrics).length} further metrics not yet measurable with current real data.`
        : null
    );
    const cardPos = new THREE.Vector3(totalRepetitions * 28, REPORT_ROW_Y, 0);
    campaignCardLabel = createFloatingLabel(cardPos, card, "report-card");
    track(campaignCardLabel, { persistent: true });
  }

  // The final real metric this whole campaign was run to answer -- feeds
  // the SAME digital-twin-observation pipeline a host intervention or a
  // case's CPR already does (beam from the real campaign box to the
  // watcher, its HUD label, worst-case-wins color). Punches onto the
  // verdict banner first (brief, readable close-up), THEN settles on the
  // real final shot: the whole hierarchy AND the complete report row
  // (every repetition's own card plus this one) together in one frame --
  // user's explicit request, "la vista general... junto con... las
  // etiquetas de CPR... como resumen". An EXPLICIT revert (unlike most
  // feedTwinObservation call sites) because this is the very last beat:
  // there is no next beat to naturally pull the camera anywhere afterward.
  if (report && label) {
    const cmp = (report.comparisons || [])[0];
    const finalShot = [...everything, ...reportCardsByRep.values(), campaignCardLabel].filter(Boolean);
    feedTwinObservation({
      entityKey: `campaign:${beat.payload?.campaign_id || campaignBox.userData.id}`,
      entityName: "campaign", anchorBox: campaignBox,
      severity: report.all_delta_wcpr_acceptable ? "match" : "discrepancy",
      detail: cmp ? `ΔCPR ${cmp.delta_cpr} (${cmp.cpr_a} → ${cmp.cpr_b}) · Δwcpr ${cmp.delta_wcpr_acceptable ? "acceptable" : "NOT acceptable"}` : "",
      at: cmp?.generated_at,
      alertKind: "METRIC", alertTitle: report.verdict || "Campaign finished", alertHoldMs: 2600,
      alertCameraPunch: true, alertAnchorBox: label,
      alertRevertFocus: { groups: finalShot, opts: { paddingFactor: 1.7, duration: 2000 } },
    });
  }
}

const HANDLERS = {
  deployment: handleDeployment,
  tool_install: handleToolInstall,
  intervention: handleIntervention,
  attack: handleAttack,
  detection: handleDetection,
  case_created: handleCaseCreated,
  preservation_step: handleArtifact,
  analysis_phase: handleArtifact,
  reconstruction: handleReconstruction,
  seal: handleSeal,
  repetition_summary: handleRepetitionSummary,
  campaign_finale: handleCampaignFinale,
  campaign_failed: handleCampaignFailed,
};

function teardownRepetitionScoped() {
  const objs = [...repScopedObjects];
  repScopedObjects = [];
  reconObjects = reconObjects.filter((o) => !objs.includes(o));
  for (const obj of objs) fadeAndDispose(obj);
  caseBox = null;
  hostBoxes = new Map();
  hostToolBoxes = new Map();
  caseFocusedForRep = null;
}

let activeRepNum = null;

// The repetition row's own box otherwise only ever changes once, at
// repetition_summary (pending -> completed) -- this flips it to
// "in-progress" the moment its repetition's first beat fires, so the row
// actually shows the pending/in-progress/completed sequence the construction
// model describes, instead of jumping straight from pending to completed.
function markRepetitionInProgress(repNum) {
  if (repNum == null || repNum === activeRepNum) return;
  activeRepNum = repNum;
  const box = repBoxes.get(repNum);
  if (!box) return;
  recolorEntity(box, statusColor("running"));
  updateBadge(box.userData.card, "running", "in progress");
}

function applyBeat(index) {
  const beat = beats[index];
  if (!beat) return;
  // Reset BEFORE dispatching -- this beat's own handler is the only thing
  // allowed to set it (via triggerAlert), so a bulk instant replay (seekTo's
  // 0..target loop, isPlaying still false) can never let many earlier
  // beats' hold times stack into one huge stall once play actually resumes.
  extraHoldMs = 0;
  markRepetitionInProgress(beat.repetition_number);
  bumpProgress(beat);
  HANDLERS[beat.kind]?.(beat);
  maybeReturnToGlobalView(beat);
  onTick?.(beat, index, beats.length);
}

// ---------------------------------------------------------------------
// Transport: play / pause / reset / enter / exit
// ---------------------------------------------------------------------
function scheduleNext() {
  clearTimeout(timerId);
  if (!isPlaying) return;
  const beat = beats[currentIndex];
  // extraHoldMs (set by this same beat's own triggerAlert call, if any)
  // extends how long it stays on screen before advancing -- consumed once.
  const delay = compressedDurationMs(beat?.real_duration_seconds, beat?.kind) + extraHoldMs;
  extraHoldMs = 0;
  timerId = setTimeout(() => {
    if (currentIndex >= beats.length - 1) {
      isPlaying = false;
      return;
    }
    currentIndex += 1;
    applyBeat(currentIndex);
    scheduleNext();
  }, delay);
}

export function enter() {
  if (isActive) return;
  isActive = true;
  savedState = monitorBridge.getState();
  monitorBridge.stopLivePolling();
  monitorBridge.clearLiveScene();
  monitorBridge.setConnStatus("reconstruction mode · live polling paused", { reconstructing: true });
  createTwinWatcherIfNeeded();
}

export function play() {
  if (!beats.length) return;
  enter();
  if (isPlaying) return;
  isPlaying = true;
  if (!foundationBuilt) {
    buildFoundation();
    const handle = setTimeout(() => {
      applyBeat(0);
      scheduleNext();
    }, 900);
    pendingTimers.push(handle);
    return;
  }
  scheduleNext();
}

export function pause() {
  isPlaying = false;
  clearTimeout(timerId);
}

// Shared by reset() and seekTo(): tears down every 3D object and every
// piece of "what have we built so far" state, WITHOUT touching currentIndex
// or progressStats -- callers decide what those become next (0 for a real
// reset, an arbitrary target for a seek).
function _teardownScene() {
  clearTimeout(timerId);
  timerId = null;
  pendingTimers.forEach(clearTimeout);
  pendingTimers = [];
  const objs = [...reconObjects];
  reconObjects = [];
  persistentObjects = [];
  repScopedObjects = [];
  for (const obj of objs) disposeNow(obj);
  campaignBox = null;
  repBoxes = new Map();
  caseBox = null;
  hostBoxes = new Map();
  hostToolBoxes = new Map();
  lastHostBeatIds = new Set();
  caseFocusedForRep = null;
  builtRepetitions.clear();
  activeRepNum = null;
  resetTwinWatcherState();
  foundationBuilt = false;
  alertFeed = [];
  extraHoldMs = 0;
  repCaseMetrics = new Map();
  reportCardsByRep = new Map();
}

// Rewinds to the first beat but stays inside reconstruction mode (live
// polling stays paused) -- matches the explicit "Reset != exit" contract,
// and now does a REAL full teardown (every object, campaign/rep-row
// included) instead of just re-applying beat 0 on top of an already-built
// scene, per the user's explicit correction that the previous Reset "no
// elimina nada".
export function reset() {
  isPlaying = false;
  _teardownScene();
  currentIndex = 0;
  progressStats = freshProgressStats();
}

// VCR-style scrubbing (2026-10-12, user's own words: "pausar, y volver atrás
// si hace falta investigar un momento antes... como si estoy viendo un
// vídeo"). Every beat handler incrementally MUTATES scene state (deploy a
// host, install a tool, seal a case...) rather than rendering a pure
// function of "which beat am I on" -- so the only reliable way to reach an
// arbitrary beat, forward OR backward, is a full teardown + an instant
// (no animation-delay) replay of every beat from 0 up to the target. Beats
// still materialize with their own normal entrance animations (never
// rewritten to a second "instant" code path per handler -- too large and
// fragile a change for what this needed), so a big jump shows a brief,
// harmless flurry of catch-up animations rather than a silent snap; a
// real, accepted trade-off, not an oversight.
export function seekTo(targetIndex) {
  if (!beats.length) return;
  const wasPlaying = isPlaying;
  isPlaying = false;
  const clamped = Math.max(0, Math.min(targetIndex, beats.length - 1));
  _teardownScene();
  progressStats = freshProgressStats(); // re-accumulated by the replay loop below, never doubled
  buildFoundation();
  for (let i = 0; i <= clamped; i++) applyBeat(i);
  currentIndex = clamped;
  if (wasPlaying && clamped < beats.length - 1) {
    isPlaying = true;
    scheduleNext();
  }
}

export function stepBack() {
  seekTo(currentIndex - 1);
}

export function stepForward() {
  seekTo(currentIndex + 1);
}

export function canStepBack() {
  return currentIndex > 0;
}

export function canStepForward() {
  return currentIndex < beats.length - 1;
}

export function exitReconstruction() {
  reset();
  if (!isActive) return;
  isActive = false;
  destroyTwinWatcher();
  if (savedState) {
    monitorBridge.setState(savedState);
    monitorBridge.rebuildScene();
    monitorBridge.focusOnGroups(monitorBridge.allVisibleGroups());
  }
  monitorBridge.startLivePolling();
  savedState = null;
}
