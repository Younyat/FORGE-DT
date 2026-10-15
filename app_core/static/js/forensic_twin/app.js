// FORGE-VI Forensic Twin dashboard. Calls the read-only forensic_twin API
// (app_core/infrastructure/forensic_twin/api.py), built on top of signals
// already computed elsewhere (tool inventory, a live clock reading, PLC
// control-law state, Level C reproducibility). This page never computes
// anything itself -- it only renders what the backend already aggregated,
// and triggers the two explicit "check" actions on demand.

function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function fmt(v) { return v === null || v === undefined ? "n/a" : String(v); }
function lampHtml(color) { return `<span class="lamp lamp-${color}"></span>`; }

let selectedNodes = [];

async function loadNodes() {
  const sel = document.getElementById("node-select");
  try {
    const res = await fetch("/api/control-room/snapshot", { cache: "no-store" });
    const data = await res.json();
    selectedNodes = (data.scenario_nodes || {}).nodes || [];
    sel.innerHTML = selectedNodes.length
      ? selectedNodes.map((n) => `<option value="${esc(n.id)}">${esc(n.name)} (${esc(n.role)})</option>`).join("")
      : `<option value="">no nodes</option>`;
  } catch (e) {
    sel.innerHTML = `<option value="">error loading nodes</option>`;
  }
}

// Reuses the real, already-existing /api/level-c/jobs endpoint
// (level_c_orchestrator/api.py) -- never a free-text job id to type by hand.
// Most recent first, same label pattern as the real FOC Paper Evidence
// campaign picker ("{job_id} -- {detail}").
async function loadLevelCJobs() {
  const sel = document.getElementById("job-id-select");
  try {
    const res = await fetch("/api/level-c/jobs", { cache: "no-store" });
    const data = await res.json();
    const jobs = (data.jobs || []).slice().sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    sel.innerHTML = jobs.length
      ? jobs.map((j) => `<option value="${esc(j.job_id)}">${esc(j.job_id)} -- ${esc(j.status)} (${fmt(j.current_repetition)}/${fmt(j.level_c_repetitions)} reps)</option>`).join("")
      : `<option value="">no Level C jobs found</option>`;
  } catch (e) {
    sel.innerHTML = `<option value="">error loading Level C jobs</option>`;
  }
}

function renderNodeState(state) {
  const el = document.getElementById("node-state-body");
  const tools = state.tools || {};
  const clock = state.clock || {};
  const services = state.services || {};
  const plc = state.plc;

  let html = `<div class="ft-kv"><span class="k">Node</span><span>${esc(state.node_name)} (${esc(state.role)})</span></div>`;
  html += `<div class="fi-monitor-grid">`;
  html += `<div>
    <h3>Tools</h3>
    <div class="fi-note">Expected (per role): ${tools.expected_tools.map(esc).join(", ") || "none"}</div>
    <div class="fi-note">Installed: ${tools.installed_tools.map(esc).join(", ") || "none"}</div>
    <div class="fi-note" style="color:${tools.missing_tools.length ? "var(--red)" : "var(--green)"}">Missing: ${tools.missing_tools.length ? tools.missing_tools.map(esc).join(", ") : "none"}</div>
  </div>`;
  html += `<div>
    <h3>Clock</h3>
    <div class="fi-note">${lampHtml(clock.degraded ? "red" : "green")} Offset: ${fmt(clock.offset_ms)}ms &middot; ${esc(clock.temporal_sync_status)}</div>
  </div>`;
  html += `</div>`;

  if ((services.checked || []).length) {
    html += `<h3 style="margin-top:14px">Services</h3>`;
    html += `<div class="fi-note">${lampHtml(services.down.length ? "red" : "green")} Checked: ${services.checked.map((s) => `${esc(s.unit)}: ${esc(s.status)}`).join(", ")}${services.down.length ? ` &middot; <span style="color:var(--red)">down: ${services.down.map(esc).join(", ")}</span>` : ""}</div>`;
  }

  const snap = state.scenario_snapshot;
  html += `<div class="fi-note" style="margin-top:8px">Scenario snapshot reference: ${snap ? `${esc(snap.snapshot_id)} (captured ${esc(snap.captured_at_utc)})` : "none captured yet"}</div>`;

  if (plc) {
    html += `<h3 style="margin-top:14px">PLC Control Law &amp; Baseline</h3>`;
    if (plc.available) {
      const cl = plc.control_law || {};
      if (cl.applicable !== false) {
        html += `<div class="fi-note">Tank level (real): ${fmt(cl.level)} / max ${fmt(cl.level_max)} &middot; air valve: ${cl.air_valve_open ? "open" : "closed"}</div>`;
      }
      html += `<div class="fi-note">${lampHtml(cl.diverged ? "red" : "green")} Control law: branch=${esc(cl.branch || "n/a")}, applicable=${fmt(cl.applicable)}, diverged=${fmt(cl.diverged)}</div>`;
      if (plc.baseline_present) {
        const cmp = plc.comparison || {};
        html += `<div class="fi-note">${lampHtml(cmp.diverged ? "red" : "green")} Baseline comparison: diverged=${fmt(cmp.diverged)}</div>`;
        html += `<div class="fi-note">State hash (real): ${esc((cmp.observed_state_hash || "n/a").slice(0, 16))}... &middot; baseline: ${esc((cmp.expected_state_hash || "n/a").slice(0, 16))}...</div>`;
      } else {
        html += `<div class="fi-note">No baseline captured yet for this PLC -- <code>POST /api/ot-state-twin/baseline</code> to capture one.</div>`;
      }
    } else {
      html += `<div class="fi-note">${esc(plc.reason || "PLC state not available")}</div>`;
    }
  }

  if ((state.new_events || []).length) {
    html += `<h3 style="margin-top:14px;color:var(--red)">New Events From This Check</h3>`;
    html += state.new_events.map((e) => `<div class="fi-note" style="color:var(--red)">${esc(e.event_type)}: ${esc(e.evidence || "")}</div>`).join("");
  }

  el.innerHTML = html;
}

document.getElementById("btn-check-node").addEventListener("click", async () => {
  const nodeId = document.getElementById("node-select").value;
  if (!nodeId) { alert("Select a node first."); return; }
  const node = selectedNodes.find((n) => n.id === nodeId);
  if (!window.confirm(`Run a real check against "${node ? node.name : nodeId}"? This performs a live SSH clock reading (a few seconds).`)) return;
  const statusEl = document.getElementById("check-status");
  const btn = document.getElementById("btn-check-node");
  statusEl.textContent = "Checking...";
  btn.disabled = true;
  try {
    const res = await fetch(`/api/forensic-twin/check/${encodeURIComponent(nodeId)}`, { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      renderNodeState(data.state);
      statusEl.textContent = `Checked at ${data.state.checked_at}`;
    } else {
      statusEl.textContent = `Error: ${data.error || "unknown"}`;
    }
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
  btn.disabled = false;
  refreshEvents();
  refreshScopes();
});

document.getElementById("btn-check-campaign").addEventListener("click", async () => {
  const jobId = document.getElementById("job-id-select").value;
  if (!jobId) { alert("Select a Level C job first."); return; }
  if (!window.confirm(`Check reproducibility for campaign job "${jobId}"?`)) return;
  const statusEl = document.getElementById("campaign-status");
  statusEl.textContent = "Checking...";
  try {
    const res = await fetch(`/api/forensic-twin/check-campaign/${encodeURIComponent(jobId)}`, { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      const r = data.report;
      statusEl.textContent = `reproducibility_index=${r.reproducibility_index}, max_delta_wcpr=${r.max_delta_wcpr}, verdict=${r.verdict}`;
    } else {
      statusEl.textContent = `Error: ${data.error || "unknown"}`;
    }
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
  refreshEvents();
  refreshScopes();
});

function renderConfigState(state) {
  const el = document.getElementById("config-state-body");
  let html = `<div class="ft-kv">
    <span class="k">Node</span><span>${esc(state.node_name)}</span>
    <span class="k">Baseline captured</span><span>${esc(state.baseline_captured_at_utc)}</span>
    <span class="k">Files tracked</span><span>${fmt(state.files_tracked)}</span>
    <span class="k">Diverged</span><span>${lampHtml(state.diverged ? "red" : "green")} ${fmt(state.diverged)}</span>
  </div>`;
  if ((state.differences || []).length) {
    html += `<h3 style="margin-top:14px;color:var(--red)">Changed Files</h3>`;
    html += state.differences.map((d) => `<div class="fi-note" style="color:var(--red)">${esc(d.path)}: ${esc(d.reason)} (baseline ${esc(d.baseline_hash)}... &rarr; now ${esc(d.current_hash || "unreadable")}${d.current_hash ? "..." : ""})</div>`).join("");
  }
  if ((state.new_events || []).length) {
    html += `<h3 style="margin-top:14px;color:var(--red)">New Events From This Check</h3>`;
    html += state.new_events.map((e) => `<div class="fi-note" style="color:var(--red)">${esc(e.event_type)}: ${esc(e.evidence || "")}</div>`).join("");
  }
  el.innerHTML = html;
}

document.getElementById("btn-capture-config-baseline").addEventListener("click", async () => {
  const nodeId = document.getElementById("node-select").value;
  if (!nodeId) { alert("Select a node first (in section 1)."); return; }
  const node = selectedNodes.find((n) => n.id === nodeId);
  if (!window.confirm(`Capture a config-integrity baseline for "${node ? node.name : nodeId}"? This reads Suricata/Wazuh file contents over SSH (reuses the tooling probe, up to ~2 minutes).`)) return;
  const statusEl = document.getElementById("config-status");
  statusEl.textContent = "Capturing baseline...";
  try {
    const res = await fetch(`/api/forensic-twin/config-baseline/${encodeURIComponent(nodeId)}`, { method: "POST" });
    const data = await res.json();
    statusEl.textContent = data.ok
      ? `Baseline captured: ${Object.keys(data.baseline.files || {}).length} file(s) at ${data.baseline.captured_at_utc}`
      : `Error: ${data.error || "unknown"}`;
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
});

document.getElementById("btn-check-config").addEventListener("click", async () => {
  const nodeId = document.getElementById("node-select").value;
  if (!nodeId) { alert("Select a node first (in section 1)."); return; }
  const node = selectedNodes.find((n) => n.id === nodeId);
  if (!window.confirm(`Check config integrity for "${node ? node.name : nodeId}" against its captured baseline? This reads Suricata/Wazuh file contents over SSH (up to ~2 minutes).`)) return;
  const statusEl = document.getElementById("config-status");
  const btn = document.getElementById("btn-check-config");
  statusEl.textContent = "Checking...";
  btn.disabled = true;
  try {
    const res = await fetch(`/api/forensic-twin/check-config/${encodeURIComponent(nodeId)}`, { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      renderConfigState(data.state);
      statusEl.textContent = `Checked at ${data.state.checked_at}`;
    } else {
      statusEl.textContent = `Error: ${data.error || "unknown"}`;
    }
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
  btn.disabled = false;
  refreshEvents();
  refreshScopes();
});

function renderNetworkState(state) {
  const el = document.getElementById("network-state-body");
  let html = `<div class="ft-kv">
    <span class="k">Node</span><span>${esc(state.node_name)}</span>
    <span class="k">Baseline captured</span><span>${esc(state.baseline_captured_at_utc)}</span>
    <span class="k">Diverged</span><span>${lampHtml(state.diverged ? "red" : "green")} ${fmt(state.diverged)}</span>
  </div>`;
  html += `<h3 style="margin-top:14px">Listening Ports (real, right now)</h3>`;
  html += `<div class="fi-note">${(state.listening_ports || []).map(esc).join(", ") || "none"}</div>`;
  if ((state.new_listening_ports || []).length) {
    html += `<h3 style="margin-top:14px;color:var(--red)">New Since Baseline</h3>`;
    html += `<div class="fi-note" style="color:var(--red)">${state.new_listening_ports.map(esc).join(", ")}</div>`;
  }
  html += `<h3 style="margin-top:14px">Login Sessions (real, right now -- informational, never auto-flagged)</h3>`;
  html += (state.login_sessions || []).length
    ? state.login_sessions.map((s) => `<div class="fi-note">${esc(s)}</div>`).join("")
    : `<div class="fi-note">No interactive login sessions right now.</div>`;
  if ((state.new_events || []).length) {
    html += `<h3 style="margin-top:14px;color:var(--red)">New Events From This Check</h3>`;
    html += state.new_events.map((e) => `<div class="fi-note" style="color:var(--red)">${esc(e.event_type)}: ${esc(e.evidence || "")}</div>`).join("");
  }
  el.innerHTML = html;
}

document.getElementById("btn-capture-network-baseline").addEventListener("click", async () => {
  const nodeId = document.getElementById("node-select").value;
  if (!nodeId) { alert("Select a node first (in section 1)."); return; }
  const node = selectedNodes.find((n) => n.id === nodeId);
  if (!window.confirm(`Capture a network-exposure baseline for "${node ? node.name : nodeId}"? This reads listening ports over SSH.`)) return;
  const statusEl = document.getElementById("network-status");
  statusEl.textContent = "Capturing baseline...";
  try {
    const res = await fetch(`/api/forensic-twin/network-baseline/${encodeURIComponent(nodeId)}`, { method: "POST" });
    const data = await res.json();
    statusEl.textContent = data.ok
      ? `Baseline captured: ${(data.baseline.listening_ports || []).length} listening port(s) at ${data.baseline.captured_at_utc}`
      : `Error: ${data.error || "unknown"}`;
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
});

document.getElementById("btn-check-network").addEventListener("click", async () => {
  const nodeId = document.getElementById("node-select").value;
  if (!nodeId) { alert("Select a node first (in section 1)."); return; }
  const node = selectedNodes.find((n) => n.id === nodeId);
  if (!window.confirm(`Check network exposure for "${node ? node.name : nodeId}" against its captured baseline?`)) return;
  const statusEl = document.getElementById("network-status");
  const btn = document.getElementById("btn-check-network");
  statusEl.textContent = "Checking...";
  btn.disabled = true;
  try {
    const res = await fetch(`/api/forensic-twin/check-network/${encodeURIComponent(nodeId)}`, { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      renderNetworkState(data.state);
      statusEl.textContent = `Checked at ${data.state.checked_at}`;
    } else {
      statusEl.textContent = `Error: ${data.error || "unknown"}`;
    }
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
  btn.disabled = false;
  refreshEvents();
  refreshScopes();
});

function renderScenarioState(state) {
  const el = document.getElementById("scenario-state-body");
  let html = `<div class="ft-kv">
    <span class="k">Latest snapshot</span><span>${esc(state.latest_snapshot_id)} (captured ${esc(state.latest_captured_at)})</span>
    <span class="k">Total snapshots</span><span>${fmt(state.total_snapshots)}</span>
    <span class="k">Hash changed vs previous</span><span>${fmt(state.hash_changed_vs_previous)}</span>
    <span class="k">Overall reproduction ready</span><span>${lampHtml(state.overall_reproduction_ready === false ? "red" : "green")} ${fmt(state.overall_reproduction_ready)}</span>
  </div>`;
  if (state.diff_vs_previous) {
    html += `<h3 style="margin-top:14px">Diff vs Previous Snapshot</h3><pre style="white-space:pre-wrap;font-size:11px;color:var(--dim)">${esc(JSON.stringify(state.diff_vs_previous.diff || state.diff_vs_previous, null, 2))}</pre>`;
  }
  if ((state.new_events || []).length) {
    html += `<h3 style="margin-top:14px;color:var(--red)">New Events From This Check</h3>`;
    html += state.new_events.map((e) => `<div class="fi-note" style="color:var(--red)">${esc(e.event_type)}: ${esc(e.evidence || "")}</div>`).join("");
  }
  el.innerHTML = html;
}

document.getElementById("btn-check-scenario").addEventListener("click", async () => {
  if (!window.confirm("Check scenario-wide snapshot reproducibility now? This only reads already-captured snapshots -- no new capture is triggered.")) return;
  const statusEl = document.getElementById("scenario-status");
  const btn = document.getElementById("btn-check-scenario");
  statusEl.textContent = "Checking...";
  btn.disabled = true;
  try {
    const res = await fetch("/api/forensic-twin/scenario/check", { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      renderScenarioState(data.state);
      statusEl.textContent = `Checked at ${data.state.checked_at}`;
    } else {
      statusEl.textContent = `Error: ${data.error || "unknown"}`;
    }
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
  btn.disabled = false;
  refreshEvents();
  refreshScopes();
});

async function refreshEvents() {
  try {
    const res = await fetch("/api/forensic-twin/events?limit=30", { cache: "no-store" });
    const data = await res.json();
    const events = data.events || [];
    document.getElementById("stat-events").textContent = events.length;
    const body = document.getElementById("events-table-body");
    body.innerHTML = events.length
      ? events.map((e) => {
          // MITRE ATT&CK for ICS mapping (forensic_twin.service, 2026-10-09):
          // each real divergence already carries which adversary technique
          // it looks like -- shown here as a plain-language label next to
          // the raw event_type, not just an internal name only a specialist
          // would recognize. `null` for the two meta-signal event types
          // (reproducibility/scenario_validation) is shown honestly, never
          // forced into a technique that doesn't fit.
          const m = e.mitre_attck_ics;
          const mitreLabel = m
            ? `<span title="${esc(m.tactic || "")}${m.note ? " -- " + esc(m.note) : ""}" style="margin-left:6px;font-size:10px;color:var(--cyan);border:1px solid var(--cyan);border-radius:999px;padding:1px 6px;">${esc(m.technique_id)} &middot; ${esc(m.technique_name)}</span>`
            : `<span style="margin-left:6px;font-size:10px;color:var(--dim);border:1px dashed var(--dim);border-radius:999px;padding:1px 6px;">no ATT&amp;CK mapping</span>`;
          return `<tr>
          <td>${esc((e.generated_at_utc || "").slice(0, 19))}</td>
          <td>${esc(e.scope_id)}</td>
          <td><span class="pill failed">${esc(e.event_type)}</span>${mitreLabel}</td>
          <td style="max-width:400px;white-space:normal">${esc(e.evidence || "-")}</td>
        </tr>`;
        }).join("")
      : `<tr><td colspan="4" class="fi-note">no divergence events recorded</td></tr>`;
  } catch (e) { /* transient */ }
}

async function refreshScopes() {
  try {
    const res = await fetch("/api/forensic-twin/scopes", { cache: "no-store" });
    const data = await res.json();
    const scopes = data.scopes || {};
    const keys = Object.keys(scopes);
    document.getElementById("stat-scopes").textContent = keys.length;
    const el = document.getElementById("scopes-body");
    el.innerHTML = keys.length
      ? keys.map((k) => `<div class="campaign-row"><div class="cr-title">${esc(scopes[k].label)} <span class="fault-tag">${esc(scopes[k].kind)}</span></div><div class="cr-meta">${esc(k)} &middot; last seen ${esc((scopes[k].last_seen || "").slice(0, 19))}</div></div>`).join("")
      : `<div class="fi-note">no scopes checked yet</div>`;
  } catch (e) { /* transient */ }
}

function startPolling() {
  refreshEvents();
  refreshScopes();
  setInterval(refreshEvents, 8000);
  setInterval(refreshScopes, 8000);
}

// Real measured cost of this watcher's own checks (forge_dt_metrics,
// 2026-10-10) -- answers the guide's own objective 4 ("spend as little of
// the host's resources as possible") with a real number instead of just an
// unverified claim. Changes slowly (once per M3 window), so loaded once at
// page load rather than in the 8s event/scope poll loop.
async function loadMonitoringOverhead() {
  try {
    const res = await fetch("/api/forge-dt-metrics/report", { cache: "no-store" });
    const data = await res.json();
    const mo = data.monitoring_overhead || {};
    const el = document.getElementById("stat-overhead");
    if (!el) return;
    if (mo.mean_seconds_per_tick == null) {
      el.textContent = "no data yet";
      return;
    }
    el.textContent = `${mo.mean_seconds_per_tick.toFixed(2)}s/tick`;
    el.title = `${mo.total_ticks} real sensor tick(s) measured across ${mo.n_windows} monitoring window(s) -- this is how long this watcher's own checks take, not the gap between them.`;
  } catch (e) { /* transient */ }
}

loadNodes();
loadLevelCJobs();
loadMonitoringOverhead();
startPolling();
