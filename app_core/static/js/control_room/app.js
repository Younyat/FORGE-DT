import * as THREE from "three";

let lastHash = null;
let lastPayload = null;

const W = 1664, H = 930;
const stage = document.getElementById("stage");
const fit = () => {
  // Stretches (not "contain") to fill 100% of the available width and height
  // -- without this, empty bands remained whenever the container (index.html's
  // iframe, with its own aspect ratio) didn't exactly match 1664:930. The
  // slight non-uniform stretch is preferable to leaving unused space; no
  // module position is lost, it's just scaled.
  const sx = window.innerWidth / W;
  const sy = window.innerHeight / H;
  stage.style.transform = `translate(-50%,-50%) scale(${sx}, ${sy})`;
};
addEventListener("resize", fit);
fit();

// ---------------------------------------------------------------------------
// Mode switch: "Visual" (the mission-control panel above) vs "Tuberias"
// (every real field from the snapshot laid out as connected tables, for
// actually investigating a campaign/scenario/machine rather than glancing at
// it). Both modes poll the SAME /api/control-room/snapshot -- this only
// changes which DOM tree is visible. Choice remembered per-browser only
// (localStorage), never sent anywhere.
// ---------------------------------------------------------------------------
const pipelineView = document.getElementById("pipeline-view");
function setMode(mode) {
  const isPipeline = mode === "pipeline";
  stage.classList.toggle("hidden", isPipeline);
  pipelineView.classList.toggle("hidden", !isPipeline);
  document.querySelectorAll("#mode-switch button").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  try { localStorage.setItem("forgevi_control_room_mode", mode); } catch (e) { /* private mode / blocked storage */ }
  if (lastPayload) render(lastPayload);
}
document.querySelectorAll("#mode-switch button").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
// Always starts in "visual" -- restoring the last mode via localStorage made
// a tab that had been left in "All in One" during testing look, on reload,
// as if the original dashboard had disappeared.
setMode("visual");

const pad = (n) => String(n).padStart(2, "0");
function tickClock() {
  const d = new Date();
  document.getElementById("date").textContent = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  document.getElementById("clock").textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
tickClock();
setInterval(tickClock, 1000);

// ---------------------------------------------------------------------------
// Interconnection with the rest of the platform: this page normally lives
// inside index.html's iframe (data-view="control_room"). window.parent's
// global openView(key) is the same navigation function every sidebar card in
// index.html already calls -- reusing it means clicking a module here jumps
// to the real, full dashboard for that subsystem instead of duplicating it.
// ---------------------------------------------------------------------------
function openRealDashboard(viewKey) {
  if (!viewKey) return;
  try {
    if (window.parent && window.parent !== window && typeof window.parent.openView === "function") {
      window.parent.openView(viewKey);
      return;
    }
  } catch (e) { /* cross-origin or not embedded */ }
  window.location.href = `/${viewKey}.html`;
}

// ---------------------------------------------------------------------------
// Quick preview: clicking a module opens a fast, translucent overlay showing
// the REAL dashboard page for that subsystem in an iframe (not a static
// summary) -- the Control Room stays visible through the glassy backdrop.
// Opens/closes in ~120-150ms (Escape, the backdrop, or the close button all
// dismiss it instantly) so it never feels like leaving the control room.
// ---------------------------------------------------------------------------
const qpOverlay = document.getElementById("quick-preview");
const qpTitle = document.getElementById("qp-title");
const qpSummary = document.getElementById("qp-summary");
const qpFrame = document.getElementById("qp-frame");
let qpTarget = null;

function openQuickPreview(viewKey, title, summaryHtml) {
  qpTarget = viewKey || null;
  qpTitle.textContent = title || "FORGE-VI module";
  qpSummary.innerHTML = summaryHtml || "";
  document.getElementById("qp-fullscreen").hidden = !viewKey;
  if (viewKey) {
    qpFrame.src = `/${viewKey}.html`;
  } else {
    qpFrame.src = "about:blank";
  }
  qpOverlay.classList.remove("hidden");
}

function closeQuickPreview() {
  qpOverlay.classList.add("hidden");
  // Unload the iframe on close: the real embedded dashboard has its own
  // polling/JS -- if left loaded in the background it would keep consuming
  // cycles and requests even while not visible, exactly what "without
  // loading the system" asks to avoid.
  qpFrame.src = "about:blank";
}

document.getElementById("qp-close").addEventListener("click", closeQuickPreview);
document.getElementById("qp-backdrop").addEventListener("click", closeQuickPreview);
document.getElementById("qp-fullscreen").addEventListener("click", () => {
  if (qpTarget) openRealDashboard(qpTarget);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !qpOverlay.classList.contains("hidden")) closeQuickPreview();
});

document.querySelectorAll(".module,.core,.split-half[data-view]").forEach((card) => {
  card.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const title = card.dataset.title || card.querySelector("h2")?.textContent?.replace(/\s+/g, " ").trim() || "FORGE-VI module";
    const view = card.dataset.view;
    const summary = renderInspectorDetail(card.id || card.closest("[id]")?.id);
    openQuickPreview(view, title, summary);
  });
  card.addEventListener("pointermove", (e) => {
    const r = card.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
    card.style.transform = `perspective(700px) rotateX(${-y * 3}deg) rotateY(${x * 4}deg) translateZ(1px)`;
  });
  card.addEventListener("pointerleave", () => (card.style.transform = ""));
});

function renderInspectorDetail(moduleId) {
  const p = lastPayload;
  if (!p) return "<p>Cargando datos en vivo…</p>";
  const row = (k, v) => `<span class="qp-kv">${k}: <b>${v}</b></span>`;
  switch (moduleId) {
    case "openstack":
    case "node-health": {
      const sn = p.scenario_nodes || {};
      return row("Total nodes", fmt(sn.total)) + row("Active", fmt(sn.active)) + row("IT nodes", fmt(sn.it_count)) + row("OT nodes", fmt(sn.ot_count));
    }
    case "it-scenario":
      return row("IT instances", fmt((p.scenario_nodes || {}).it_count));
    case "ot-scenario": {
      const ot = p.ot_assets || {};
      return row("PLC", fmt(ot.plc_count)) + row("Registers", fmt(ot.register_count)) + row("HMI views", fmt(ot.hmi_view_count)) + row("Source", ot.source || "n/a");
    }
    case "tool-deployment":
      return row("Tools installed", fmt((p.tools || {}).tools_installed)) + row("Source", (p.tools || {}).source || "n/a");
    case "orchestration-core":
      return row("Worker PID", fmt((p.worker || {}).pid)) + row("Threads (this worker)", fmt((p.worker || {}).thread_count)) + `<p style="margin-top:8px">${(p.worker || {}).note || ""}</p>`;
    case "attack-lab": {
      const a = p.attack_lab || {};
      const la = a.last_attack;
      return row("Active now", fmt(a.active_now)) + row("Templates", fmt(a.templates_count)) + row("Recorded all-time", fmt(a.attacks_recorded_total)) +
        (la ? row("Last attack", fmt(la.attack_name)) + row("Last target", fmt(la.target_ip)) + row("Last started", fmt(la.started_at)) : "") +
        `<p style="margin-top:8px">${a.note || ""}</p>`;
    }
    case "detection-layer": {
      const al = p.alerts || {};
      const staleMap = nodeStalenessMap(p.scenario_nodes || {});
      const staleOnes = (al.items || []).filter((a) => staleMap[a.target] && staleMap[a.target].stale);
      return row("Alerts", fmt(al.count)) + row("Critical", fmt(al.critical)) + row("Warning", fmt(al.warning)) + row("Rules count", "n/a -- SSH on-demand per instance only") +
        (staleOnes.length ? `<p style="margin-top:8px;color:#ffca28">⚠ ${staleOnes.length} of these alerts are based on node metrics that are hours old (unrefreshed cache) -- do not assume they reflect the current state.</p>` : "");
    }
    case "forensic-acquisition": {
      const fa = p.forensic_acquisition || {};
      if (!fa.active) return `<p>${fa.source === "no_active_case" ? "No active case right now." : "No data."}</p>`;
      const st = fa.stages || {};
      return row("Case", fa.case_id) + row("Memory", st.memory) + row("Disk", st.disk) + row("Network", st.network) + row("Progress", fa.progress_pct != null ? fa.progress_pct + "%" : "n/a");
    }
    case "evidence-store": {
      const es = p.evidence_store || {};
      return row("Cases (top-level)", fmt(es.case_count)) + row("Artifacts (all-time)", fmt(es.artifact_count)) + row("Total size (all-time)", fmtBytes(es.total_size_bytes)) + `<p style="margin-top:8px">${es.note || ""}</p>`;
    }
    case "forensic-analysis": {
      const an = p.forensic_analysis || {};
      return row("Case", an.case_id || "n/a") + row("Phases done", `${fmt(an.phases_completed)} / ${fmt(an.phases_total)}`);
    }
    case "foc-reconstruction": {
      const foc = p.foc_reconstruction || {};
      return row("Case", foc.case_id || "n/a") + row("CPR", foc.cpr != null ? foc.cpr.toFixed(3) : "n/a") + row("Weighted CPR", foc.weighted_cpr != null ? foc.weighted_cpr.toFixed(3) : "n/a") + row("Graph nodes/edges", `${fmt(foc.node_count)} / ${fmt(foc.edge_count)}`);
    }
    case "campaign-repetitions": {
      const cs = p.campaigns_summary || {};
      const cc = p.campaign_comparisons || {};
      return row("Total runs", fmt(cs.total)) + row("Completed", fmt(cs.completed)) + row("Running", fmt(cs.running)) + row("Failed", fmt(cs.failed)) +
        row("Comparisons", fmt(cc.comparisons_count)) + row("Reproducibility", cc.reproducibility_index_pct != null ? cc.reproducibility_index_pct + "%" : "n/a");
    }
    case "remote-lab":
      return "<p>No real instrumentation available for this module in the current platform.</p>";
    default:
      return "<p>No additional detail.</p>";
  }
}

function fmt(v) { return v === null || v === undefined ? "n/a" : String(v); }
function fmtBytes(n) {
  if (n === null || n === undefined) return "n/a";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 10 || i === 0 ? 0 : 1) + " " + units[i];
}

// ---------------------------------------------------------------------------
// SVG fallback pipe flow animation (kept from the reference prototype) --
// works even if WebGL / Three.js is unavailable.
// ---------------------------------------------------------------------------
document.querySelectorAll("#pipe-fallback .pipe").forEach((base, idx) => {
  const flow = base.cloneNode(false);
  flow.removeAttribute("class");
  flow.dataset.flowFor = base.id;
  const state = base.classList.contains("red") ? "#ffe5e5" : base.classList.contains("yellow") ? "#fff7b0" : base.classList.contains("gray") ? "#e7f4fa" : "#d7ffe9";
  flow.setAttribute("stroke", state);
  flow.setAttribute("stroke-width", base.classList.contains("gray") ? "2.2" : "3.2");
  flow.setAttribute("fill", "none");
  flow.setAttribute("stroke-linecap", "round");
  flow.setAttribute("stroke-dasharray", "3 24");
  flow.style.opacity = base.classList.contains("gray") ? ".25" : ".86";
  flow.style.filter = `drop-shadow(0 0 5px ${state})`;
  flow.style.animation = `pipeFlow ${1.2 + (idx % 4) * 0.16}s linear infinite`;
  base.parentNode.appendChild(flow);
});

const FLOW_COLOR = { green: "#d7ffe9", yellow: "#fff7b0", red: "#ffd0d0", gray: "#e7f4fa" };

// Public API for external/manual control (mirrors the reference prototype).
window.FORGEVI_CONTROL = {
  setModuleState(id, state) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove("state-green", "state-yellow", "state-red", "state-gray");
    el.classList.add(`state-${state}`);
  },
  setPipeState(id, state) {
    const base = document.getElementById(id);
    if (base) {
      base.classList.remove("green", "yellow", "red", "gray");
      base.classList.add(state);
      const flow = document.querySelector(`[data-flow-for="${id}"]`);
      if (flow) {
        flow.setAttribute("stroke", FLOW_COLOR[state] || FLOW_COLOR.gray);
        flow.setAttribute("stroke-width", state === "gray" ? "2.2" : "3.2");
        flow.style.opacity = state === "gray" ? ".25" : ".86";
        flow.style.filter = `drop-shadow(0 0 5px ${FLOW_COLOR[state] || FLOW_COLOR.gray})`;
      }
    }
    if (window.__forgePipes && window.__forgePipes[id]) window.__forgePipes[id].setState(state);
  },
};

// ---------------------------------------------------------------------------
// Real Three.js metallic tube pipe layer (vendored ES module, no CDN). Falls
// back silently to the SVG pipes above if WebGL is unavailable.
// ---------------------------------------------------------------------------
(function initThreePipes() {
  const canvas = document.getElementById("three-layer");
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true, powerPreference: "high-performance" });
  } catch (e) {
    console.warn("Three.js/WebGL unavailable; keeping SVG pipe fallback.", e);
    return;
  }
  document.documentElement.classList.add("three-active");
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.setSize(W, H, false);
  renderer.setClearColor(0x000000, 0);
  const scene = new THREE.Scene();
  const camera = new THREE.OrthographicCamera(-W / 2, W / 2, H / 2, -H / 2, 1, 2500);
  camera.position.set(0, 0, 1000);
  scene.add(new THREE.AmbientLight(0x7dbbd9, 1.5));
  const key = new THREE.DirectionalLight(0xffffff, 2.2);
  key.position.set(-400, 650, 800);
  scene.add(key);
  const fillLight = new THREE.DirectionalLight(0x40bfff, 1.2);
  fillLight.position.set(650, -400, 550);
  scene.add(fillLight);

  const colors = { green: 0x20f17f, yellow: 0xffd21f, red: 0xff252f, gray: 0x94a5af };
  const emissive = { green: 0x0cb75a, yellow: 0xc09100, red: 0xb00009, gray: 0x293842 };
  const pipes = {};
  const p3 = (x, y, z = 0) => new THREE.Vector3(x - W / 2, H / 2 - y, z);

  const defs = [
    ["pipe-openstack-core", "gray", [[270, 246], [270, 290], [285, 307], [351, 307]]],
    ["pipe-it-core", "gray", [[535, 246], [535, 300]]],
    ["pipe-ot-core", "gray", [[670, 246], [670, 300]]],
    ["pipe-tools-core", "gray", [[1084, 246], [1084, 275], [1060, 298], [982, 298]]],
    ["pipe-core-attack-a", "gray", [[350, 352], [283, 352], [283, 418]]],
    ["pipe-core-attack-b", "gray", [[350, 352], [194, 352], [194, 418]]],
    ["pipe-core-detect", "gray", [[560, 405], [560, 418]]],
    ["pipe-core-health", "gray", [[850, 405], [850, 418]]],
    ["pipe-health-acq", "gray", [[987, 351], [1050, 351], [1050, 492], [1095, 492]]],
    ["pipe-health-remote", "gray", [[987, 370], [1160, 370], [1160, 595]]],
    ["pipe-warning-bus", "gray", [[382, 492], [785, 492], [785, 440]]],
    ["pipe-left-loop", "gray", [[43, 598], [43, 493], [98, 493]]],
    ["pipe-lower-warning", "gray", [[97, 568], [767, 568], [785, 548]]],
    ["pipe-acq-evidence", "gray", [[284, 686], [304, 686]]],
    ["pipe-evidence-analysis", "gray", [[486, 686], [499, 686]]],
    ["pipe-analysis-foc", "gray", [[673, 686], [692, 686]]],
    ["pipe-foc-campaign", "gray", [[878, 686], [905, 686]]],
    ["pipe-campaign-remote", "gray", [[1107, 686], [1120, 686]]],
    ["pipe-remote-return", "gray", [[1150, 595], [1150, 493], [1095, 493]]],
  ];

  const makeMat = (state, intensity = 1) => new THREE.MeshStandardMaterial({
    color: colors[state], metalness: 0.58, roughness: 0.26, emissive: emissive[state], emissiveIntensity: 1.15 * intensity,
    transparent: true, opacity: 0.96,
  });
  const darkMat = new THREE.MeshStandardMaterial({ color: 0x07131c, metalness: 0.9, roughness: 0.35, transparent: true, opacity: 0.92 });
  const ringMat = new THREE.MeshStandardMaterial({ color: 0xabc2d0, metalness: 0.85, roughness: 0.24 });

  defs.forEach(([id, state, pts]) => {
    const curve = new THREE.CatmullRomCurve3(pts.map((p, i) => p3(p[0], p[1], i % 2 ? 3 : 0)), false, "centripetal", 0.15);
    const group = new THREE.Group();
    const shell = new THREE.Mesh(new THREE.TubeGeometry(curve, Math.max(24, pts.length * 18), 11.2, 14, false), darkMat);
    group.add(shell);
    const body = new THREE.Mesh(new THREE.TubeGeometry(curve, Math.max(24, pts.length * 18), 8.4, 14, false), makeMat(state));
    group.add(body);
    const highlight = new THREE.Mesh(new THREE.TubeGeometry(curve, Math.max(24, pts.length * 18), 2.4, 9, false), new THREE.MeshBasicMaterial({ color: 0xd7fff2, transparent: true, opacity: state === "gray" ? 0.25 : 0.55 }));
    highlight.position.z = 5;
    group.add(highlight);
    pts.forEach((pt, idx) => {
      if (idx === 0 || idx === pts.length - 1) return;
      const joint = new THREE.Mesh(new THREE.SphereGeometry(12.2, 18, 10), ringMat);
      joint.position.copy(p3(pt[0], pt[1], 0));
      group.add(joint);
      const inner = new THREE.Mesh(new THREE.SphereGeometry(8.6, 16, 9), makeMat(state, 1.2));
      inner.position.copy(p3(pt[0], pt[1], 0));
      group.add(inner);
    });
    const particles = [];
    if (state !== "gray") {
      for (let i = 0; i < 4; i++) {
        const m = new THREE.Mesh(new THREE.SphereGeometry(4.1, 10, 7), new THREE.MeshBasicMaterial({ color: colors[state] }));
        scene.add(m);
        particles.push({ mesh: m, phase: i / 4, speed: 0.055 + i * 0.006 });
        const light = new THREE.PointLight(colors[state], 8, 75, 2);
        m.add(light);
      }
    }
    scene.add(group);
    pipes[id] = {
      group, body, particles, curve, state,
      setState(newState) {
        // rebuild particles when transitioning from/to "gray" (no-particle state)
        const hadParticles = this.state !== "gray";
        const willHaveParticles = newState !== "gray";
        this.state = newState;
        this.body.material = makeMat(newState);
        if (hadParticles && willHaveParticles) {
          this.particles.forEach((p) => {
            p.mesh.material.color.setHex(colors[newState]);
            p.mesh.children.forEach((c) => c.isPointLight && c.color.setHex(colors[newState]));
          });
        } else if (!hadParticles && willHaveParticles) {
          for (let i = 0; i < 4; i++) {
            const m = new THREE.Mesh(new THREE.SphereGeometry(4.1, 10, 7), new THREE.MeshBasicMaterial({ color: colors[newState] }));
            scene.add(m);
            this.particles.push({ mesh: m, phase: i / 4, speed: 0.055 + i * 0.006 });
            const light = new THREE.PointLight(colors[newState], 8, 75, 2);
            m.add(light);
          }
        } else if (hadParticles && !willHaveParticles) {
          this.particles.forEach((p) => scene.remove(p.mesh));
          this.particles.length = 0;
        }
      },
    };
  });
  window.__forgePipes = pipes;

  [[405, 344], [963, 344], [530, 485], [1125, 490]].forEach(([x, y]) => {
    const l = new THREE.PointLight(0x18cfff, 4, 120, 2);
    l.position.copy(p3(x, y, 40));
    scene.add(l);
  });

  const clock = new THREE.Clock();
  function animate() {
    requestAnimationFrame(animate);
    // Don't render while "Pipelines" mode is active (#stage hidden) --
    // continuing to draw a WebGL canvas nobody sees would be exactly the
    // unnecessary load the "without loading the system" principle asks to
    // avoid.
    if (stage.classList.contains("hidden")) return;
    const t = clock.getElapsedTime();
    Object.values(pipes).forEach((pipe) => pipe.particles.forEach((p, j) => {
      const u = (p.phase + t * p.speed) % 1;
      const pos = pipe.curve.getPointAt(u);
      p.mesh.position.copy(pos);
      p.mesh.position.z = 12 + Math.sin((u + j) * Math.PI * 2) * 2;
    }));
    renderer.render(scene, camera);
  }
  animate();
})();

// ---------------------------------------------------------------------------
// Real-data polling: /api/control-room/snapshot -> DOM text + module/pipe
// colors. Never invents a number -- every field either comes straight from
// the backend or is shown as "n/a" (not available).
// ---------------------------------------------------------------------------
const POLL_MS = 4000;

const PIPE_MODULES = {
  "pipe-openstack-core": ["openstack"],
  "pipe-it-core": ["it-scenario"],
  "pipe-ot-core": ["ot-scenario"],
  "pipe-tools-core": ["tool-deployment"],
  "pipe-core-attack-a": ["attack-lab"],
  "pipe-core-attack-b": ["attack-lab"],
  "pipe-core-detect": ["detection-layer"],
  "pipe-core-health": ["node-health"],
  "pipe-health-acq": ["node-health", "forensic-acquisition"],
  "pipe-health-remote": ["remote-lab"],
  "pipe-warning-bus": ["attack-lab", "detection-layer"],
  "pipe-left-loop": ["forensic-acquisition"],
  "pipe-lower-warning": ["attack-lab", "forensic-acquisition"],
  "pipe-acq-evidence": ["forensic-acquisition", "evidence-store"],
  "pipe-evidence-analysis": ["evidence-store", "forensic-analysis"],
  "pipe-analysis-foc": ["forensic-analysis", "foc-reconstruction"],
  "pipe-foc-campaign": ["foc-reconstruction", "campaign-repetitions"],
  "pipe-campaign-remote": ["campaign-repetitions", "remote-lab"],
  "pipe-remote-return": ["remote-lab"],
};
const STATE_RANK = { red: 3, yellow: 2, green: 1, gray: 0 };

function text(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

function applyModuleState(moduleId, state) {
  window.FORGEVI_CONTROL.setModuleState(moduleId, state === "amber" ? "yellow" : state);
}

function pillFor(state, labels) {
  const cls = { green: "green-pill", amber: "yellow-pill", red: "red-pill", gray: "gray-pill" }[state] || "gray-pill";
  const label = labels[state] || labels.gray || "–";
  return { cls, label };
}

function setPill(id, state, labels) {
  const el = document.getElementById(id);
  if (!el) return;
  const { cls, label } = pillFor(state, labels);
  el.className = "pill " + cls;
  el.textContent = label;
}

function render(p) {
  lastPayload = p;
  const host = p.host || {};
  const scenarioNodes = p.scenario_nodes || {};
  const otAssets = p.ot_assets || {};
  const tools = p.tools || {};
  const evidence = p.evidence_store || {};
  const alerts = p.alerts || {};
  const campaignsSummary = p.campaigns_summary || {};
  const currentProcess = p.current_process || null;
  const attackLab = p.attack_lab || {};
  const acq = p.forensic_acquisition || {};
  const analysis = p.forensic_analysis || {};
  const foc = p.foc_reconstruction || {};
  const comparisons = p.campaign_comparisons || {};

  const moduleState = {};

  // ---- header pills ----
  const online = !!host.hostname && host.hostname !== "not_available";
  text("m-status", online ? "OPERATIONAL" : "UNKNOWN");
  document.getElementById("m-status-dot").className = "dot " + (online ? "green" : "gray");
  text("m-nodes", `${fmt(scenarioNodes.active)} / ${fmt(scenarioNodes.total)}`);
  text("m-instances", fmt(scenarioNodes.total));
  text("m-running", fmt(campaignsSummary.running));
  text("m-alerts", alerts.count === null || alerts.count === undefined ? "n/a" : String(alerts.count));
  text("m-cases", fmt(evidence.case_count));

  // ---- OpenStack / Node Health (shared scenario_nodes source) ----
  const total = scenarioNodes.total || 0, active = scenarioNodes.active || 0;
  text("os-total", fmt(scenarioNodes.total));
  text("os-active", fmt(scenarioNodes.active));
  text("os-it", fmt(scenarioNodes.it_count));
  text("os-ot", fmt(scenarioNodes.ot_count));
  text("os-footer", `${fmt(active)} / ${fmt(total)}`);
  document.getElementById("os-bar").style.width = total ? `${Math.round((100 * active) / total)}%` : "0%";
  moduleState["openstack"] = total === 0 ? "gray" : active === total ? "green" : active > 0 ? "amber" : "red";

  text("nh-total", fmt(scenarioNodes.total));
  text("nh-active", fmt(scenarioNodes.active));
  text("nh-down", fmt(total ? total - active : 0));
  moduleState["node-health"] = moduleState["openstack"];

  // ---- IT scenario ----
  text("it-instances", fmt(scenarioNodes.it_count));
  moduleState["it-scenario"] = (scenarioNodes.it_count || 0) > 0 ? "green" : "gray";

  // ---- OT scenario ----
  text("ot-plc", fmt(otAssets.plc_count));
  text("ot-registers", fmt(otAssets.register_count));
  text("ot-hmi", fmt(otAssets.hmi_view_count));
  moduleState["ot-scenario"] = otAssets.source === "real_sensor" ? "green" : "gray";

  // ---- Tool deployment ----
  text("tools-count", tools.tools_installed === null || tools.tools_installed === undefined ? "n/a" : String(tools.tools_installed));
  const toolsState = tools.source === "real_sensor" ? (tools.tools_installed > 0 ? "green" : "gray") : "gray";
  setPill("tools-pill", toolsState, { green: "OK", gray: "N/D" });
  moduleState["tool-deployment"] = toolsState;

  // ---- Orchestration core ----
  text("core-threads", fmt((p.worker || {}).thread_count));

  // ---- Attack lab ----
  text("attack-active", fmt(attackLab.active_now));
  text("attack-templates", fmt(attackLab.templates_count));
  text("attack-total", fmt(attackLab.attacks_recorded_total));
  let attackState = "gray";
  if (attackLab.source === "real_sensor") attackState = (attackLab.active_now || 0) > 0 ? "red" : "green";
  setPill("attack-pill", attackState, { red: "ATTACKING", green: "IDLE", gray: "N/D" });
  moduleState["attack-lab"] = attackState;

  // ---- Detection layer ----
  text("det-alerts", alerts.count === null || alerts.count === undefined ? "n/a" : String(alerts.count));
  text("det-critical", fmt(alerts.critical));
  let detState = "gray";
  if (alerts.source === "real_sensor_cached") detState = alerts.critical > 0 ? "red" : alerts.warning > 0 ? "amber" : "green";
  setPill("det-pill", detState, { red: "CRITICAL", amber: "WARNING", green: "MONITORING", gray: "N/D" });
  moduleState["detection-layer"] = detState;

  // ---- Forensic acquisition ----
  const stepper = document.getElementById("acq-stepper");
  if (acq.active) {
    const st = acq.stages || {};
    text("acq-memory", st.memory || "pending");
    text("acq-disk", st.disk || "pending");
    text("acq-network", st.network || "pending");
    ["memory", "disk", "network"].forEach((k) => {
      const radio = document.getElementById(`acq-radio-${k}`);
      if (radio) radio.className = "radio" + (st[k] === "completed" || st[k] === "running" ? " active" : "");
    });
    const pct = acq.progress_pct;
    document.getElementById("acq-bar").style.width = (pct || 0) + "%";
    document.getElementById("acq-label").textContent = pct != null ? `Case ${acq.case_id} — ${pct}%` : `Case ${acq.case_id}`;
    stepper.querySelectorAll("b").forEach((b, i) => b.classList.toggle("step-off", pct == null || pct < (i + 1) * 33));
    moduleState["forensic-acquisition"] = pct === 100 ? "green" : "amber";
  } else {
    ["memory", "disk", "network"].forEach((k) => text(`acq-${k}`, "n/a"));
    document.getElementById("acq-bar").style.width = "0%";
    document.getElementById("acq-label").textContent = "Sin caso activo";
    stepper.querySelectorAll("b").forEach((b) => b.classList.add("step-off"));
    moduleState["forensic-acquisition"] = "gray";
  }

  // ---- Evidence store ----
  text("ev-artifacts", fmt(evidence.artifact_count));
  text("ev-size", fmtBytes(evidence.total_size_bytes));
  text("ev-cases", fmt(evidence.case_count));
  moduleState["evidence-store"] = evidence.source === "real_sensor" && (evidence.manifest_count || 0) > 0 ? "green" : "gray";

  // ---- Forensic analysis ----
  text("an-phases", fmt(analysis.phases_total));
  text("an-done", fmt(analysis.phases_completed));
  text("an-case", analysis.case_id || "n/a");
  if (analysis.source === "real_sensor") {
    moduleState["forensic-analysis"] = analysis.phases_completed === analysis.phases_total && analysis.phases_total > 0 ? "green" : "amber";
  } else {
    moduleState["forensic-analysis"] = "gray";
  }

  // ---- FOC reconstruction ----
  text("foc-cpr", foc.cpr != null ? foc.cpr.toFixed(3) : "n/a");
  text("foc-nodes", fmt(foc.node_count));
  text("foc-edges", fmt(foc.edge_count));
  let focState = "gray";
  if (foc.source === "real_sensor" && foc.cpr != null) focState = foc.cpr >= 0.85 ? "green" : foc.cpr >= 0.6 ? "amber" : "red";
  setPill("foc-pill", focState, { green: "RECOVERABLE", amber: "DEGRADED", red: "LOW CPR", gray: "N/D" });
  moduleState["foc-reconstruction"] = focState;

  // ---- Campaign repetitions + comparisons ----
  text("camp-total", fmt(campaignsSummary.total));
  text("camp-completed", fmt(campaignsSummary.completed));
  text("camp-running", fmt(campaignsSummary.running));
  text("camp-failed", fmt(campaignsSummary.failed));
  let campState = "gray";
  if (campaignsSummary.failed > 0) campState = "red";
  else if (campaignsSummary.running > 0) campState = "green";
  else if (campaignsSummary.total > 0) campState = "gray";
  moduleState["campaign-repetitions"] = campState;

  text("comp-count", fmt(comparisons.comparisons_count));
  text("comp-repro", comparisons.reproducibility_index_pct != null ? comparisons.reproducibility_index_pct + "%" : "n/a");
  const compState = comparisons.source === "real_sensor" ? "green" : "gray";
  document.getElementById("comp-status").textContent = comparisons.source === "real_sensor" ? (comparisons.verdict || "OK") : "N/D";
  document.getElementById("comp-status").className = compState === "green" ? "green-text" : "na-text";

  // ---- Remote lab (never invented — always gray/n.d.) ----
  moduleState["remote-lab"] = "gray";

  // ---- apply module colors ----
  Object.entries(moduleState).forEach(([id, state]) => applyModuleState(id, state));

  // ---- apply pipe colors (worst of connected modules) ----
  Object.entries(PIPE_MODULES).forEach(([pipeId, mods]) => {
    let worst = "gray";
    mods.forEach((m) => {
      const st = (moduleState[m] || "gray") === "amber" ? "yellow" : moduleState[m] || "gray";
      if ((STATE_RANK[st] || 0) > (STATE_RANK[worst] || 0)) worst = st;
    });
    window.FORGEVI_CONTROL.setPipeState(pipeId, worst);
  });

  // ---- current process (sidebar) ----
  // The backend never leaves this panel "empty" if there is ANY real
  // history: mode "running" = a campaign currently in progress;
  // "idle_last_campaign" = nothing running, shows the last real campaign +
  // its last real status + currently active attacks if there are any;
  // "attack_only" = no campaigns but standalone active attacks; "no_data" =
  // platform with no history yet.
  const cpTitle = document.getElementById("cp-title");
  const cpPill = document.getElementById("cp-pill");
  const cpKv = document.getElementById("cp-kv");
  const kvRow = (k, v) => `<p><span>${k}</span><b>${v}</b></p>`;
  const mode = currentProcess ? currentProcess.mode : "no_data";

  if (mode === "running") {
    cpTitle.textContent = currentProcess.execution_label || currentProcess.campaign_id || currentProcess.job_id;
    cpPill.textContent = "RUNNING";
    cpPill.className = "run-pill";
    cpKv.innerHTML =
      kvRow("Job ID", fmt(currentProcess.job_id)) +
      kvRow("Level", fmt(currentProcess.level)) +
      kvRow("Phase", fmt(currentProcess.current_phase_detail || currentProcess.current_phase)) +
      kvRow("Liveness", fmt(currentProcess.liveness)) +
      kvRow("Depth", fmt(currentProcess.depth));
  } else if (mode === "idle_last_campaign") {
    cpTitle.textContent = "Last campaign: " + (currentProcess.execution_label || currentProcess.campaign_id || currentProcess.job_id);
    const status = String(currentProcess.last_status || "").toLowerCase();
    const pillCls = status === "failed" ? "run-pill" : status.includes("degradation") || status === "partial" ? "run-pill" : status === "completed" ? "run-pill gray-run" : "run-pill gray-run";
    cpPill.textContent = (currentProcess.last_status || "UNKNOWN").toUpperCase();
    cpPill.className = pillCls;
    cpPill.style.background = status === "failed" ? "#7e1518" : status.includes("degradation") || status === "partial" ? "#665800" : "";
    cpPill.style.color = status === "failed" ? "#ffd6d7" : status.includes("degradation") || status === "partial" ? "#ffeb3c" : "";
    let rows = kvRow("Job ID", fmt(currentProcess.job_id)) + kvRow("Level", fmt(currentProcess.level)) + kvRow("Last status", fmt(currentProcess.last_status));
    if (currentProcess.active_attacks_now) rows += kvRow("Attacks active now", currentProcess.active_attacks_now);
    if (currentProcess.last_attack) {
      const la = currentProcess.last_attack;
      rows += kvRow("Last attack", fmt(la.attack_name)) + kvRow("Target", fmt(la.target_ip));
    }
    cpKv.innerHTML = rows;
  } else if (mode === "attack_only") {
    cpTitle.textContent = "No campaigns — active attacks";
    cpPill.textContent = "ATTACKING";
    cpPill.className = "run-pill";
    let rows = kvRow("Attacks active now", fmt(currentProcess.active_attacks_now));
    if (currentProcess.last_attack) {
      const la = currentProcess.last_attack;
      rows += kvRow("Last attack", fmt(la.attack_name)) + kvRow("Target", fmt(la.target_ip));
    }
    cpKv.innerHTML = rows;
  } else {
    cpTitle.textContent = "No history yet";
    cpPill.textContent = "NO DATA";
    cpPill.className = "run-pill gray-run";
    cpKv.innerHTML = "<p class='na-text' style='padding:6px 0'>No campaign or attack registered on the platform.</p>";
  }

  // ---- scenario nodes list (sidebar) -- CPU/RAM/Disk are cache-ONLY
  // (never trigger a new SSH probe); see scenario_nodes.metrics_note.
  const nodeRows = document.getElementById("node-rows");
  const nodes = scenarioNodes.nodes || [];
  const sevClass = (sev) => ({ ok: "sev-ok", warning: "sev-warning", critical: "sev-critical" }[sev] || "sev-unknown");
  const metricCell = (val, sev) => val === null || val === undefined
    ? `<span class="node-metric na">n/a</span>`
    : `<span class="node-metric ${sevClass(sev)}">${Math.round(val)}%</span>`;
  if (nodes.length) {
    nodeRows.innerHTML = nodes.map((n) => {
      const st = String(n.status || "").toUpperCase();
      const dotClass = st === "ACTIVE" ? "green" : st ? "yellow" : "gray";
      const staleCls = n.metrics_stale ? " stale" : "";
      const ageTitle = n.metrics_stale ? ` — reading from ${ageLabel(n.metrics_age_seconds)} ago, not live` : "";
      return `<div class="node-row${staleCls}" title="${escapeHtml(n.ip || "")} — ${escapeHtml(n.metrics_source || "")}${ageTitle}">` +
        `<i class="dot ${dotClass}"></i>` +
        `<span class="name">${escapeHtml(n.name || n.id || "?")}<small>${escapeHtml(n.role || "")}</small></span>` +
        metricCell(n.cpu_usage_pct, n.overall_severity) +
        metricCell(n.memory_usage_pct, n.overall_severity) +
        metricCell(n.disk_root_use_pct, n.overall_severity) +
        `</div>`;
    }).join("");
  } else {
    nodeRows.innerHTML = "<span class='na-text'>no nodes detected</span>";
  }
  text("node-metrics-note", scenarioNodes.metrics_note || "");

  renderTimeline(p);
  if (!pipelineView.classList.contains("hidden")) renderPipelineView(p);
}

// ---------------------------------------------------------------------------
// "All in One" mode: an element-by-element web reconstruction of the
// reference control-room photo (ceiling, branded back wall, upper bank of
// 9 wall modules, rear console, foreground console with 9 monitors, control
// strips) -- same structure/classes as the supplied reconstruction, but
// EVERY data-bearing element is rendered from the real snapshot instead of
// the reference's placeholder numbers. Purely decorative texture (the rear/
// front control-strip button grids, the rack-network glyph) is kept as
// physical-console ambience, exactly as the reference intends it -- never
// presented as a data readout. Operator figures were intentionally dropped
// per explicit request.
// ---------------------------------------------------------------------------

const STATE_COLOR = { on: "#1df06f", warn: "#ffca28", off: "#ff3d34", na: "#5a6b76" };
function lampStyle(state) {
  const c = STATE_COLOR[state] || STATE_COLOR.na;
  return `background:${c};box-shadow:0 0 5px ${c}`;
}
function stateFromBool(b) {
  return b === true ? "on" : b === false ? "off" : "na";
}
function stateFromSeverity(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical" || s === "failed" || s === "error") return "off";
  if (s === "warning" || s === "degraded" || s === "partial") return "warn";
  if (s === "ok" || s === "completed" || s === "active" || s === "running") return "on";
  return "na";
}

function buildCheckList(items) {
  return items.map((it) => `<div class="check"><i class="lamp" style="${lampStyle(it.state)}"></i><span>${it.label}</span><i class="side-ind" style="${lampStyle(it.state)}"></i></div>`).join("");
}

function buildStatusList(rows) {
  return rows.map((r) => {
    const label = r.state === "on" ? "UP" : r.state === "off" ? "DOWN" : "N/D";
    const color = r.state === "off" ? "#ff5d55" : "#39ff92";
    return `<div class="row"><i class="led" style="${lampStyle(r.state)}"></i><span>${escapeHtml(r.label)}</span><b>${r.value != null ? escapeHtml(String(r.value)) : ""}</b><em style="color:${color}">${label}</em></div>`;
  }).join("");
}

function buildSubtable(title, rows) {
  if (!rows.length) return `<div class="subtable"><b>${escapeHtml(title)}</b><span class="pv-empty" style="padding:4px 0">no data</span></div>`;
  return `<div class="subtable"><b>${escapeHtml(title)}</b>${rows.map(([l, r, color]) => `<span>${l}<em style="${color ? `color:${color}` : ""}">${r}</em></span>`).join("")}</div>`;
}

// Verified live (2026-09-28): node_health alerts are recomputed on EVERY
// poll (their generated_at is always "now"), but the cpu/ram/disk value that
// triggers them can come from an SSH probe hours old
// (metrics_stale/metrics_age_seconds per node) -- showing only the alert's
// timestamp makes something that is actually a re-evaluated stale reading
// look "critical right now". This function cross-references each "node"
// scope alert with that specific node's real staleness to show it honestly.
function nodeStalenessMap(scenarioNodes) {
  const map = {};
  (scenarioNodes.nodes || []).forEach((n) => {
    map[n.name] = { stale: !!n.metrics_stale, ageSeconds: n.metrics_age_seconds };
  });
  return map;
}
function ageLabel(seconds) {
  if (seconds == null) return null;
  if (seconds < 120) return Math.round(seconds) + "s";
  if (seconds < 7200) return Math.round(seconds / 60) + "min";
  return (seconds / 3600).toFixed(1) + "h";
}
function staleCaveat(alert, staleMap) {
  const info = staleMap[alert.target];
  if (alert.scope === "node" && info && info.stale) {
    return ` <em style="color:#ffca28">(reading from ${ageLabel(info.ageSeconds)} ago, not live)</em>`;
  }
  return "";
}

function buildAlertRows(items, staleMap) {
  if (!items.length) return `<div class="pv-empty" style="padding:6px 0">no active alerts</div>`;
  return items.map((a) => `<div class="alert-row"><i style="${lampStyle(stateFromSeverity(a.severity))}"></i><span>${escapeHtml(a.target || "-")}: ${escapeHtml(a.title || "-")}${staleCaveat(a, staleMap || {})}</span><b>${escapeHtml(a.severity || "-")}</b></div>`).join("");
}

// Procedural node topology (real node count/names/status) -- reuses the
// reference's exact `.links path` / `.nodes rect` / `.labels text` CSS
// classes, just laid out generically instead of hand-tuned fixed pixels, so
// it stays correct for however many real nodes actually exist.
function buildTopologySvg(nodes, { w = 300, h = 160 } = {}) {
  if (!nodes.length) return `<div class="pv-empty" style="padding:0;text-align:center;line-height:160px">no nodes</div>`;
  const boxW = 34, boxH = 24;
  const marginX = 44;
  const usableW = Math.max(1, w - marginX * 2);
  const step = nodes.length > 1 ? usableW / (nodes.length - 1) : 0;
  const y = h / 2 - boxH / 2;
  const pos = nodes.map((node, i) => ({ x: marginX + step * i - boxW / 2, y, node }));
  const links = pos.slice(1).map((p, i) => `<path d="M${pos[i].x + boxW / 2} ${pos[i].y + boxH / 2} L${p.x + boxW / 2} ${p.y + boxH / 2}" />`).join("");
  const rects = pos.map((p) => {
    const active = p.node.status === "ACTIVE";
    return `<rect x="${p.x}" y="${p.y}" width="${boxW}" height="${boxH}" style="stroke:${active ? "" : "#ff6b6b"};fill:${active ? "" : "#4a1414"}" />`;
  }).join("");
  const labels = pos.map((p) => `<text x="${p.x}" y="${p.y - 5}">${escapeHtml((p.node.name || p.node.id || "?").slice(0, 10))}</text>`).join("");
  return `<svg viewBox="0 0 ${w} ${h}"><g class="links">${links}</g><g class="nodes">${rects}</g><g class="labels">${labels}</g></svg>`;
}

function buildHealthGrid(cells) {
  return `<div class="health-grid">${cells.map((c) => `<div class="health-cell">${escapeHtml(c.label)}<i style="${lampStyle(c.state)}"></i><span>${escapeHtml(c.value)}</span></div>`).join("")}</div>`;
}

function buildRunList(rows) {
  const head = '<b style="display:block;margin-bottom:6px">Campaign Runs</b>';
  if (!rows.length) return head + `<div class="pv-empty">no campaigns registered</div>`;
  return head + rows.map((r) => {
    const tickChar = r.state === "on" ? "✓" : r.state === "warn" ? "●" : r.state === "off" ? "✗" : "–";
    const color = STATE_COLOR[r.state] || STATE_COLOR.na;
    return `<div class="run-row" title="${escapeHtml(r.title || "")}"><span>${escapeHtml(r.label)}</span><i class="tick" style="color:${color}">${tickChar}</i><span class="runbar" style="background:repeating-linear-gradient(90deg,${color} 0 8px,#13233b 8px 11px);border:1px solid ${color}"></span></div>`;
  }).join("");
}

function buildBarList(bars) {
  return bars.map(([label, pct]) => `<div class="bar-item"><span>${escapeHtml(label)}</span><span class="bar-track"><i style="width:${fmt2(pct)}%"></i></span><b>${pct != null ? Math.round(pct) + "%" : "n/a"}</b></div>`).join("");
}
function fmt2(v) { return v == null ? 0 : Math.max(0, Math.min(100, v)); }

function buildFileList(rows) {
  return rows.map(([l, v]) => `<div class="file-row"><span>${escapeHtml(l)}</span><b>${escapeHtml(String(v))}</b></div>`).join("");
}

// Decorative infra glyph (rack-network) and physical control-strip button
// grids -- kept purely as console texture, exactly as the reference intends
// (the reference itself fills these with a modulo pattern, not real
// per-cell telemetry). All REAL data lives in the labeled checklists,
// tables, topology diagrams and run lists elsewhere on the same wall.
function buildRackNetworkSvg() {
  const pts = [[18, 18], [70, 16], [126, 20], [165, 28], [24, 76], [64, 72], [107, 70], [145, 78], [178, 86], [29, 118], [65, 116], [102, 116], [140, 118], [176, 120]];
  const edges = [[0, 1], [1, 2], [2, 3], [0, 4], [1, 5], [2, 6], [3, 8], [4, 5], [5, 6], [6, 7], [7, 8], [4, 9], [5, 10], [6, 11], [7, 12], [8, 13], [9, 10], [10, 11], [11, 12], [12, 13]];
  const lines = edges.map(([a, b]) => {
    const [x1, y1] = pts[a], [x2, y2] = pts[b];
    const dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy), ang = (Math.atan2(dy, dx) * 180) / Math.PI;
    return `<span class="rn-line" style="left:${x1 + 13}px;top:${y1 + 11}px;width:${len}px;transform:rotate(${ang}deg)"></span>`;
  }).join("");
  const nodes = pts.map(([x, y]) => `<span class="rn-node" style="left:${x}px;top:${y}px"></span>`).join("");
  return lines + nodes;
}
function buildControlStrip(n) {
  let out = "";
  for (let i = 0; i < n; i++) out += `<span class="ctl ${i % 17 === 0 ? "r" : i % 11 === 0 ? "y" : i % 7 === 0 ? "g" : ""}"></span>`;
  return out;
}
function buildFrontControls(n) {
  let out = "";
  for (let i = 0; i < n; i++) {
    let cls = "fctl";
    if (i % 9 === 0) cls += " knob";
    else if (i % 23 === 0) cls += " r";
    else if (i % 17 === 0) cls += " y";
    else if (i % 7 === 0) cls += " g";
    out += `<span class="${cls}"></span>`;
  }
  return out;
}

function drawCompareChart(campaignRows) {
  const c = document.getElementById("compare-chart");
  if (!c) return;
  const rect = c.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const dpr = Math.min(devicePixelRatio || 1, 2);
  c.width = Math.max(1, rect.width * dpr);
  c.height = Math.max(1, rect.height * dpr);
  const ctx = c.getContext("2d");
  ctx.scale(dpr, dpr);
  const w = rect.width, h = rect.height;
  ctx.fillStyle = "#06131c";
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = "rgba(93,165,210,.18)";
  ctx.lineWidth = 1;
  for (let x = 10; x < w; x += 24) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
  for (let y = 10; y < h; y += 18) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
  if (!campaignRows.length) {
    ctx.fillStyle = "#5c7686"; ctx.font = "11px sans-serif"; ctx.fillText("no campaigns registered", 10, h / 2);
    return;
  }
  // Real per-run outcome (categorical status -> 0..1), not a fabricated continuous metric.
  const scoreOf = (s) => ({ completed: 1, running: 0.75, completed_with_degradation: 0.6, partial: 0.4, stopped: 0.2, failed: 0 }[String(s || "").toLowerCase()] ?? 0.3);
  const vals = campaignRows.slice(0, 12).reverse().map((c2) => scoreOf(c2.repetition_status));
  ctx.strokeStyle = "#2ce979"; ctx.lineWidth = 2; ctx.beginPath();
  vals.forEach((v, i) => {
    const x = 8 + (i * (w - 16)) / Math.max(1, vals.length - 1);
    const y = h - 12 - v * (h - 24);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    ctx.fillStyle = "#2ce979"; ctx.fillRect(x - 2, y - 2, 4, 4);
  });
  ctx.stroke();
}

function renderPipelineView(p) {
  const host = p.host || {};
  const worker = p.worker || {};
  const scenarioNodes = p.scenario_nodes || {};
  const otAssets = p.ot_assets || {};
  const tools = p.tools || {};
  const attackLab = p.attack_lab || {};
  const alerts = p.alerts || {};
  const acq = p.forensic_acquisition || {};
  const evidence = p.evidence_store || {};
  const analysis = p.forensic_analysis || {};
  const foc = p.foc_reconstruction || {};
  const campaigns = (p.active_campaigns || []).filter((c) => !c.error);
  const campaignsSummary = p.campaigns_summary || {};
  const comparisons = p.campaign_comparisons || {};
  const currentProcess = p.current_process || {};
  const itNodes = (scenarioNodes.nodes || []).filter((n) => ["victim", "attacker", "monitor"].includes(n.role));
  const otNodes = (scenarioNodes.nodes || []).filter((n) => ["plc", "scada"].includes(n.role));
  const staleMap = nodeStalenessMap(scenarioNodes);
  const maxStaleAge = Math.max(0, ...(scenarioNodes.nodes || []).map((n) => (n.metrics_stale ? n.metrics_age_seconds || 0 : 0)));

  // ==================== UPPER BANK: 9 wall modules ====================
  const upper = [];

  upper.push(`<article class="wall-module m-openstack">
    <header>OPENSTACK INFRASTRUCTURE</header>
    <div class="tabline"><span>Nodes</span><span>IT</span><span>OT</span><span>Worker</span></div>
    <div class="rack-network" id="rack-network">${buildRackNetworkSvg()}</div>
    <div class="status-list compact">${buildStatusList((scenarioNodes.nodes || []).slice(0, 6).map((n) => ({ label: n.name || n.id, value: n.role || "", state: stateFromBool(n.status === "ACTIVE") })))}</div>
    <div class="mini-metrics">
      <span>NODES <b>${fmt(scenarioNodes.active)}/${fmt(scenarioNodes.total)}</b></span>
      <span>LOADAVG <b>${escapeHtml(fmt(host.loadavg))}</b></span>
      <span>SWAP <b>${(host.memory || {}).swap_used_pct != null ? Math.round((host.memory || {}).swap_used_pct) + "%" : "n/a"}</b></span>
      <span>WORKER <b>${fmt(worker.pid)}</b></span>
    </div>
  </article>`);

  upper.push(`<article class="wall-module m-scenario">
    <header>SCENARIO DECLARATION<br>&amp; DEPLOYMENT</header>
    <div class="check-list">${buildCheckList([
      { label: "Nodes discovered", state: stateFromBool((scenarioNodes.total || 0) > 0) },
      { label: "IT topology", state: stateFromBool(itNodes.length > 0) },
      { label: "OT topology", state: stateFromBool(otNodes.length > 0) },
      { label: "Tools deployed", state: stateFromBool((tools.tools_installed || 0) > 0) },
      { label: "Campaign declared", state: stateFromBool(currentProcess.mode === "running" || currentProcess.mode === "idle_last_campaign") },
    ])}</div>
    ${buildSubtable("Recent Deployments", campaigns.slice(0, 4).map((c) => [escapeHtml((c.campaign_id || c.job_id || "").slice(0, 20)), escapeHtml(c.repetition_status || "-"), c.repetition_status === "running" ? "#3cff90" : ""]))}
  </article>`);

  upper.push(`<article class="wall-module m-tools">
    <header>TOOL PREPARATION</header>
    <div class="check-list small">${buildCheckList([
      { label: "Tools installed", state: stateFromBool((tools.tools_installed || 0) > 0) },
      { label: "Attack templates", state: stateFromBool((attackLab.templates_count || 0) > 0) },
      { label: "Tool source cached", state: stateFromBool(tools.source === "real_sensor") },
    ])}</div>
    ${buildSubtable("Tool Status", [
      ["Tools installed (current VMs)", fmt(tools.tools_installed)],
      ["Attack templates (catalog)", fmt(attackLab.templates_count)],
      ["Source", escapeHtml(tools.source || "n/a")],
    ])}
  </article>`);

  const runActive = currentProcess.mode === "running";
  upper.push(`<article class="wall-module m-incident">
    <header>CONTROLLED INCIDENT<br>EXECUTION</header>
    <div class="check-list alarm">${buildCheckList([
      { label: "Attack active", state: stateFromBool((attackLab.active_now || 0) > 0) },
      { label: "Campaign running", state: stateFromBool((campaignsSummary.running || 0) > 0) },
      { label: "Acquisition in progress", state: stateFromBool(!!acq.active) },
      { label: "Alerts critical", state: (alerts.critical || 0) > 0 ? "off" : "on" },
    ])}</div>
    <div class="run-box" style="${runActive ? "" : "border-color:#3a4a52;color:#7f97a3"}">
      <strong>${runActive ? "RUNNING SCENARIO" : "IDLE"}</strong>
      <b>${escapeHtml((currentProcess.job_id || "—").slice(-6))}</b>
      <span>${escapeHtml(fmt(currentProcess.execution_label || currentProcess.campaign_id || currentProcess.last_status || "no data")).slice(0, 26)}</span>
      <em>${escapeHtml(fmt(currentProcess.current_phase_detail || currentProcess.current_phase || currentProcess.last_status || "n/a"))}</em>
    </div>
  </article>`);

  const itRoleLabel = { victim: "Victim", attacker: "Attacker", monitor: "Monitor" };
  const otRoleLabel = { plc: "PLC", scada: "SCADA" };
  upper.push(`<article class="wall-module m-live">
    <header>SCENARIO NODES LIVE</header>
    <div class="dual-topology">
      <div class="topo it"><h3>IT ENVIRONMENT</h3>${buildTopologySvg(itNodes, { w: 300, h: 160 })}</div>
      <div class="topo ot"><h3>OT / INDUSTRIAL ENVIRONMENT</h3>${buildTopologySvg(otNodes, { w: 300, h: 160 })}</div>
    </div>
    <div class="node-health"><b>NODE HEALTH</b>${buildHealthGrid([
      { label: "IT Nodes", value: `${itNodes.filter((n) => n.status === "ACTIVE").length}/${itNodes.length}`, state: itNodes.length && itNodes.every((n) => n.status === "ACTIVE") ? "on" : itNodes.some((n) => n.status === "ACTIVE") ? "warn" : "na" },
      { label: "OT Nodes", value: `${otNodes.filter((n) => n.status === "ACTIVE").length}/${otNodes.length}`, state: otNodes.length && otNodes.every((n) => n.status === "ACTIVE") ? "on" : otNodes.some((n) => n.status === "ACTIVE") ? "warn" : "na" },
      { label: "Attack Lab", value: (attackLab.active_now || 0) > 0 ? "ACTIVE" : "idle", state: (attackLab.active_now || 0) > 0 ? "off" : "on" },
      { label: "Detection", value: fmt(alerts.count), state: stateFromSeverity((alerts.critical || 0) > 0 ? "critical" : (alerts.warning || 0) > 0 ? "warning" : "ok") },
      { label: "Forensic", value: acq.active ? "active" : "idle", state: acq.active ? "warn" : "na" },
      { label: "Storage", value: fmt(evidence.case_count), state: stateFromBool((evidence.case_count || 0) > 0) },
      { label: "Campaigns", value: `${fmt(campaignsSummary.running)}/${fmt(campaignsSummary.total)}`, state: (campaignsSummary.running || 0) > 0 ? "warn" : "na" },
    ])}</div>
  </article>`);

  upper.push(`<article class="wall-module m-detect">
    <header>DETECTION LAYER<br>&amp; ALERT HANDLING</header>
    ${maxStaleAge > 300 ? `<div style="background:#3a2a0c;color:#ffca28;font-size:9px;padding:4px 6px;border-bottom:1px solid #5a4415">⚠ node metrics up to ${ageLabel(maxStaleAge)} old — the alerts below may not reflect the current state</div>` : ""}
    <div class="alert-list">${buildAlertRows((alerts.items || []).slice(0, 4), staleMap)}</div>
    ${buildSubtable("Recent Alerts", (alerts.items || []).slice(0, 5).map((a) => [escapeHtml((a.generated_at || "").slice(11, 19)) + " " + escapeHtml(a.target || "") + staleCaveat(a, staleMap), escapeHtml(a.severity || "-"), a.severity === "critical" ? "#ff5d55" : "#ffc62f"]))}
  </article>`);

  upper.push(`<article class="wall-module m-acq">
    <header>FORENSIC ACQUISITION<br>&amp; EVIDENCE STORE</header>
    <div class="check-list small">${acq.active
      ? buildCheckList(["memory", "disk", "network"].map((k) => ({ label: k, state: stateFromBool((acq.stages || {})[k] === "completed" || (acq.stages || {})[k] === "running") })))
      : buildCheckList([{ label: "No active case", state: "na" }])}</div>
    ${buildSubtable("Acquisition Jobs", acq.active
      ? Object.entries(acq.stages || {}).filter(([k]) => k !== "live_response").map(([k, v]) => [escapeHtml(acq.case_id).slice(0, 10) + " " + k, escapeHtml(v || "pending"), v === "completed" ? "#2eff83" : v === "running" ? "#ffc62f" : ""])
      : [["Case", "none", ""], ["Cases (top-level)", fmt(evidence.case_count), ""]])}
  </article>`);

  upper.push(`<article class="wall-module m-analysis">
    <header>FORENSIC ANALYSIS<br>&amp; RECONSTRUCTION</header>
    <div class="check-list small">${buildCheckList([
      { label: "Analysis phases", state: stateFromBool(analysis.source === "real_sensor") },
      { label: "FOC reconstruction", state: stateFromBool(foc.source === "real_sensor") },
      { label: "Graph resolved", state: stateFromBool((foc.edge_count || 0) > 0) },
    ])}</div>
    <div class="pipeline"><b>Analysis Pipeline</b>${(analysis.phases_list || []).slice(0, 5).map((ph) => {
      const pct = ph.status === "completed" ? 100 : ph.status === "running" ? 50 : 0;
      return `<span>${escapeHtml(ph.label)}<i class="progress ${pct === 100 ? "g" : pct > 0 ? "y" : "r"}" style="--w:${pct}%"></i>${pct}%</span>`;
    }).join("") || `<span class="pv-empty">no analysis phases (no case resolved)</span>`}</div>
  </article>`);

  upper.push(`<article class="wall-module m-campaign">
    <header>CAMPAIGN REPETITIONS<br>&amp; COMPARISONS</header>
    <div class="check-list small">${buildCheckList([
      { label: "Run management", state: stateFromBool(campaigns.length > 0) },
      { label: "Result comparison", state: stateFromBool(comparisons.source === "real_sensor") },
      { label: "Remote lab exchange", state: "na" },
    ])}</div>
    <div class="run-list" id="run-list">${buildRunList(campaigns.slice(0, 7).map((c) => ({
      label: (c.campaign_id || c.job_id || "").slice(-10),
      state: stateFromSeverity(String(c.repetition_status || "").toLowerCase() === "running" ? "ok" : String(c.repetition_status || "").toLowerCase()),
      title: c.execution_label,
    })))}</div>
  </article>`);

  document.getElementById("upper-bank").innerHTML = upper.join("");
  document.getElementById("rear-controls").innerHTML = buildControlStrip(90);

  // ==================== FOREGROUND CONSOLE: 9 monitors ====================
  const bench = [];

  bench.push(`<article class="console-monitor cm-it"><header>IT SCENARIO</header>${buildTopologySvg(itNodes, { w: 230, h: 175 })}</article>`);
  bench.push(`<article class="console-monitor cm-ot"><header>OT SCENARIO</header>${buildTopologySvg(otNodes, { w: 230, h: 175 })}</article>`);
  bench.push(`<article class="console-monitor cm-attack"><header>ATTACK LAB</header><div class="terminal" id="attack-terminal">${escapeHtml(
    (attackLab.active_attacks || []).length
      ? attackLab.active_attacks.map((a) => `[${(a.started_at || "").slice(11, 19)}] ${a.attack_name} -> ${a.target_ip} ACTIVE`).join("\n")
      : attackLab.last_attack
      ? `[${(attackLab.last_attack.started_at || "").slice(11, 19)}] ${attackLab.last_attack.attack_name} -> ${attackLab.last_attack.target_ip} (${attackLab.last_attack.execution_status || "completed"})`
      : "no attack activity recorded"
  )}</div></article>`);
  bench.push(`<article class="console-monitor cm-detect"><header>DETECTION LAYER</header><div class="world-map"><div style="position:relative;z-index:3;padding:8px;font-size:9px;color:#bfe6ff;line-height:1.7">${
    (alerts.items || []).length ? alerts.items.slice(0, 6).map((a) => `${escapeHtml(a.severity)}: ${escapeHtml(a.target)}${staleCaveat(a, staleMap)}`).join("<br>") : "no active alerts"
  }</div></div></article>`);
  bench.push(`<article class="console-monitor cm-forensic"><header>FORENSIC ACQUISITION</header><div class="bar-list">${buildBarList([
    ["Memory", acq.active ? ((acq.stages || {}).memory === "completed" ? 100 : (acq.stages || {}).memory === "running" ? 50 : 0) : null],
    ["Disk", acq.active ? ((acq.stages || {}).disk === "completed" ? 100 : (acq.stages || {}).disk === "running" ? 50 : 0) : null],
    ["Network", acq.active ? ((acq.stages || {}).network === "completed" ? 100 : (acq.stages || {}).network === "running" ? 50 : 0) : null],
  ])}</div></article>`);
  bench.push(`<article class="console-monitor cm-store"><header>FORENSIC STORE</header><div class="file-list">${buildFileList([
    ["cases (top-level)", fmt(evidence.case_count)],
    ["artifacts (all-time)", fmt(evidence.artifact_count)],
    ["size (all-time)", fmtBytes(evidence.total_size_bytes)],
    ["manifests (dedup)", fmt(evidence.manifest_count)],
  ])}</div></article>`);
  bench.push(`<article class="console-monitor cm-foc" title="${escapeHtml((foc.graph_edges_preview || []).slice(0, 6).map((e) => `${e.source} -> ${e.target}`).join(" | "))}"><header>ANALYSIS &amp; FOC RECONSTRUCTION</header><svg viewBox="0 0 260 170"><g class="foc-links"><path d="M25 70H75M75 70H120M120 70H165M165 70H215M75 70V125M120 70V25M165 70V125"/></g><g class="foc-nodes" style="${foc.cpr != null ? `fill:${foc.cpr >= 0.85 ? "#173d61" : foc.cpr >= 0.6 ? "#413a17" : "#4a1717"}` : ""}"><rect x="15" y="58" width="20" height="20"/><rect x="65" y="58" width="20" height="20"/><rect x="110" y="58" width="20" height="20"/><rect x="155" y="58" width="20" height="20"/><rect x="205" y="58" width="20" height="20"/><rect x="65" y="115" width="20" height="20"/><rect x="110" y="15" width="20" height="20"/><rect x="155" y="115" width="20" height="20"/></g></svg></article>`);
  bench.push(`<article class="console-monitor cm-compare"><header>RUN COMPARISON</header><canvas id="compare-chart"></canvas><div class="legend-runs">${campaigns.length ? `CPR-based outcome trend · ${campaigns.length} runs` : "no campaigns registered"}</div></article>`);
  bench.push(`<article class="console-monitor cm-remote"><header>REMOTE LAB EXCHANGE</header><div class="world-map global"><div style="position:relative;z-index:3;padding:8px;font-size:9px;color:#8fb0c4">no real instrumentation available</div></div></article>`);

  document.getElementById("front-monitor-row").innerHTML = bench.join("");
  document.getElementById("front-controls").innerHTML = buildFrontControls(168);

  drawCompareChart(campaigns);
  renderOpsStrip(p, campaigns);
  resizeRoomStage();
}

// ---------------------------------------------------------------------------
// Ops strip: real host control actions + live host processes + cooperative
// job stop. Every action here calls the EXACT SAME endpoint (and repeats the
// SAME confirm() text) that Node Health already exposes and has audited --
// this never adds a new destructive capability, it only surfaces existing
// ones in this view too. Arbitrary OS-level "kill any process by PID" does
// NOT exist anywhere in the platform (confirmed by reading node_health_api.py
// end to end) -- only cooperative job-stop (the running job polls a
// stop-flag at safe checkpoints) exists, which is what the "Stop" buttons
// below call. Building true kill-by-PID would be a materially new,
// irreversible-class capability, so it is intentionally NOT added here
// without the user explicitly deciding to want it.
// ---------------------------------------------------------------------------
const opsState = {};

function opsButton(key, label, confirmText, action) {
  const st = opsState[key] || "idle";
  const badge = st === "busy" ? `<span class="ops-btn-state busy">running…</span>` : st === "ok" ? `<span class="ops-btn-state ok">done</span>` : st === "err" ? `<span class="ops-btn-state err">error</span>` : "";
  return `<button class="ops-btn" data-ops-key="${key}" data-ops-confirm="${escapeHtml(confirmText)}" ${st === "busy" ? "disabled" : ""}>${label}${badge}</button>`;
}

async function runOpsAction(key, confirmText, url, opts) {
  if (opsState[key] === "busy") return;
  if (confirmText && !window.confirm(confirmText)) return;
  opsState[key] = "busy";
  if (lastPayload) renderPipelineView(lastPayload);
  try {
    const r = await fetch(url, Object.assign({ method: "POST" }, opts || {}));
    opsState[key] = r.ok ? "ok" : "err";
  } catch (e) {
    opsState[key] = "err";
  }
  if (lastPayload) renderPipelineView(lastPayload);
  setTimeout(() => { opsState[key] = "idle"; if (lastPayload && !pipelineView.classList.contains("hidden")) renderPipelineView(lastPayload); }, 4000);
}

const OPS_ACTIONS = {
  "free-host-memory": {
    label: "Free Host Memory",
    confirm: "Free host memory now? Runs gc.collect() plus sync + drop_caches on the OpenStack controller host. Never touches scenario VMs, never deletes files.",
    url: "/api/node-health/host/free-memory",
  },
  "power-on-stopped": {
    label: "Power-On Stopped Nodes",
    confirm: "Power on every scenario VM currently in SHUTOFF state? Running instances are left untouched.",
    url: "/api/node-health/nodes/power-on-stopped",
  },
  "floating-ip-cleanup": {
    label: "Release Orphan Floating IPs",
    confirm: "Release all unattached (orphan) floating IPs until at least 65% of the quota is available? Floating IPs currently attached to running instances are never touched.",
    url: "/api/node-health/openstack/floating-ips/cleanup",
  },
  "restart-openstack": {
    label: "Restart OpenStack Services",
    confirm: "Restart OpenStack services (Horizon, Keystone, Nova, Neutron)? This can temporarily degrade the platform while containers restart.",
    url: "/api/node-health/openstack/restart/stream",
  },
};

let opsDelegated = false;
function ensureOpsDelegation() {
  if (opsDelegated) return;
  opsDelegated = true;
  document.getElementById("ops-strip").addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-ops-key]");
    if (btn) {
      const key = btn.dataset.opsKey;
      const action = OPS_ACTIONS[key];
      if (action) runOpsAction(key, action.confirm, action.url);
      return;
    }
    const stopBtn = ev.target.closest("[data-stop-job]");
    if (stopBtn) {
      const jobId = stopBtn.dataset.stopJob;
      const level = stopBtn.dataset.stopLevel;
      const url = level === "C" ? `/api/level-c/stop/${encodeURIComponent(jobId)}` : `/api/foc/experimentation/jobs/${encodeURIComponent(jobId)}/cancel`;
      runOpsAction(`stop-${jobId}`, `Request a cooperative stop of job ${jobId}? The job polls for this flag at its next safe checkpoint — it is not an immediate kill.`, url);
    }
  });
}

function renderOpsStrip(p, campaigns) {
  ensureOpsDelegation();
  const host = p.host || {};
  const procs = (host.processes || {}).top_cpu || [];
  const runningJobs = campaigns.filter((c) => String(c.repetition_status || "").toLowerCase() === "running");

  const hostControlCard = `<div class="ops-card">
    <h2>Host Control (real actions)</h2>
    ${opsButton("free-host-memory", "Free Host Memory", OPS_ACTIONS["free-host-memory"].confirm)}
    ${opsButton("power-on-stopped", "Power-On Stopped Nodes", OPS_ACTIONS["power-on-stopped"].confirm)}
    ${opsButton("floating-ip-cleanup", "Release Orphan Floating IPs", OPS_ACTIONS["floating-ip-cleanup"].confirm)}
    ${opsButton("restart-openstack", "Restart OpenStack Services", OPS_ACTIONS["restart-openstack"].confirm)}
    <div class="ops-note">Same endpoints already audited in Node Health, with the same confirm() — no new destructive action has been added.</div>
  </div>`;

  const procCard = `<div class="ops-card">
    <h2>Live Host Processes (top CPU)</h2>
    ${procs.length ? `<table class="ops-table"><thead><tr><th>PID</th><th>Command</th><th>CPU%</th><th>MEM%</th><th>Uptime</th></tr></thead><tbody>${procs.slice(0, 8).map((pr) => `<tr><td>${pr.pid}</td><td>${escapeHtml(pr.command)}</td><td>${pr.cpu_pct}</td><td>${pr.mem_pct}</td><td>${Math.round(pr.elapsed_seconds / 60)}m</td></tr>`).join("")}</tbody></table>` : `<div class="pv-empty">no process data</div>`}
    <div class="ops-note">HOST processes (not a VM's) — read-only, via local ps. Killing an arbitrary process by PID doesn't exist on the platform today; only cooperative job stop (right column).</div>
  </div>`;

  const jobCard = `<div class="ops-card">
    <h2>Job Control (cooperative stop)</h2>
    ${runningJobs.length ? runningJobs.map((c) => `<div class="ops-jobrow"><span>${escapeHtml((c.campaign_id || c.job_id || "").slice(0, 22))} <em class="na-text">(Level ${escapeHtml(c.level || "?")})</em></span><button data-stop-job="${escapeHtml(c.job_id)}" data-stop-level="${escapeHtml(c.level || "")}">Stop</button></div>`).join("") : `<div class="pv-empty">no campaign running right now</div>`}
    <div class="ops-note">Real cooperative stop (the job checks a flag at its next safe checkpoint) — not an immediate kill -9.</div>
  </div>`;

  // Memory/PSI and watchdog: real information that this very session's own
  // incident (drop_caches hung for 15s during real swap pressure, 2026-09-27
  // 12:30) demonstrates is necessary to see in order to investigate -- it
  // was computed in the backend from the start but never shown anywhere.
  const mem = host.memory || {};
  const events = mem.recent_watchdog_events || [];
  const lastEvent = events[0];
  const memCard = `<div class="ops-card">
    <h2>Memory Pressure &amp; Watchdog</h2>
    <div class="ops-note" style="margin-top:0">PSI some/full (10s avg): <b style="color:${mem.psi_some_avg10 > 20 ? "#ff6b6b" : mem.psi_some_avg10 > 5 ? "#ffd925" : "#29f18b"}">${fmt(mem.psi_some_avg10)}</b> / <b>${fmt(mem.psi_full_avg10)}</b></div>
    <div class="ops-note">Swap used: <b style="color:${mem.swap_used_pct > 80 ? "#ff6b6b" : "#29f18b"}">${mem.swap_used_pct != null ? mem.swap_used_pct + "%" : "n/a"}</b>  ·  Mem available: <b>${mem.mem_available_pct != null ? mem.mem_available_pct + "%" : "n/a"}</b></div>
    <hr class="soc-hr">
    ${lastEvent ? `<div class="ops-note" style="color:${lastEvent.drop_caches_ok ? "#8fb0c4" : "#ff8080"}">Last watchdog event (${escapeHtml(lastEvent.ts_utc || "")}): trigger=${escapeHtml(lastEvent.trigger || "?")}, drop_caches_ok=${String(lastEvent.drop_caches_ok)}${lastEvent.drop_caches_error ? `<br>⚠ ${escapeHtml(lastEvent.drop_caches_error)}` : ""}</div>` : `<div class="pv-empty">no recent watchdog events</div>`}
    <div class="ops-note">${events.length} real event(s) in this worker's in-memory history (not persisted across restarts).</div>
  </div>`;

  document.getElementById("ops-strip").innerHTML = hostControlCard + procCard + jobCard + memCard;
}

function resizeRoomStage() {
  const stage2 = document.getElementById("room-stage");
  if (!stage2 || pipelineView.classList.contains("hidden")) return;
  // Stretches both axes to fill 100% of the available width and height --
  // same criterion already applied to the Visual panel (fit()): "contain"
  // left empty bands whenever the container didn't have the exact 1672:941
  // ratio.
  const vw = pipelineView.clientWidth || window.innerWidth;
  const vh = pipelineView.clientHeight || window.innerHeight;
  const sx = vw / 1672;
  const sy = vh / 941;
  stage2.style.transformOrigin = "top left";
  stage2.style.transform = `scale(${sx}, ${sy})`;
  const vp = stage2.closest(".room-viewport");
  if (vp) { vp.style.height = vh + "px"; vp.style.justifyContent = "flex-start"; vp.style.alignItems = "flex-start"; }
}
addEventListener("resize", () => { if (lastPayload) resizeRoomStage(); });


function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderTimeline(p) {
  const el = document.getElementById("events");
  const items = [];
  (p.active_campaigns || []).forEach((c) => {
    if (c.error) return;
    const status = String(c.repetition_status || "").toLowerCase();
    items.push({
      sev: status === "failed" ? "red" : status === "running" ? "cyan" : status.includes("degradation") ? "yellow" : "green",
      text: `${c.execution_label || c.campaign_id || c.job_id} — ${c.repetition_status || "?"}`,
    });
  });
  if (p.alerts && p.alerts.count) {
    items.push({ sev: p.alerts.critical > 0 ? "red" : p.alerts.warning > 0 ? "yellow" : "green", text: `${p.alerts.count} active alerts (${p.alerts.critical || 0} critical)` });
  }
  if (!items.length) {
    el.innerHTML = "<span class='na-text' style='padding:14px'>no recent events</span>";
    return;
  }
  const timeLabel = new Date(p.generated_at || Date.now()).toLocaleTimeString();
  el.innerHTML = items.slice(0, 7).map((it) => `<div class="event ${it.sev}-event"><i></i><time>${timeLabel}</time><p>${escapeHtml(it.text)}</p></div>`).join("");
}

function fetchSnapshot() {
  if (document.hidden) return;
  const url = "/api/control-room/snapshot" + (lastHash ? `?since_hash=${encodeURIComponent(lastHash)}` : "");
  fetch(url, { cache: "no-store" })
    .then((r) => r.json())
    .then((data) => {
      if (data && data.unchanged) return;
      lastHash = data.hash || null;
      render(data);
    })
    .catch(() => {});
}

document.getElementById("btn-refresh").addEventListener("click", () => { lastHash = null; fetchSnapshot(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden) fetchSnapshot(); });

fetchSnapshot();
setInterval(fetchSnapshot, POLL_MS);
