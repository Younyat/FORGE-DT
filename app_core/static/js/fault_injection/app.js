// FORGE-VI Fault Injection dashboard. Launches Level A/B/C campaigns by
// calling the EXACT same real endpoints as FOC Paper Evidence
// (app_core/static/js/foc_paper_evidence.js), just attaching
// `injected_faults` to the campaign-creation payload (already supported by
// campaign_service.py). Fault catalog / apply / revert / effectiveness are
// served by the new /api/fault-injection/* blueprint. Node list and campaign
// progress are read from /api/control-room/snapshot -- already computed,
// never recalculated here.

const LEVEL_EXPLAIN = {
  A: "Level A: reproduces an existing forensic case in dry-run mode (no real attack, no new infrastructure deployed) -- generates N repetitions of analysis/causal reconstruction over the same case, to measure reconstruction reproducibility.",
  B: "Level B: launches a real attack (Modbus T0831 by default) against the already-deployed infrastructure, waits for a real alert, creates a forensic case, and runs acquisition+analysis+sealing. Each repetition is a full attack->forensics cycle.",
  C: "Level C: the full cycle -- destroys and redeploys the scenario from scratch, installs tools, and launches N nested Level B repetitions, comparing CPR/WCPR across repetitions to measure end-to-end reproducibility.",
};

let currentLevel = "A";
let faultCatalog = [];
let onDemandState = {}; // fault_id -> {node_id, injection_id, status}
let selectedNodes = [];

function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function fmt(v) { return v === null || v === undefined ? "n/a" : String(v); }

// ---------------------------------------------------------------------------
// Level tabs + level-specific launch fields
// ---------------------------------------------------------------------------
document.querySelectorAll(".fi-level-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".fi-level-tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    currentLevel = tab.dataset.level;
    renderLevelExplain();
    renderLevelFields();
    document.getElementById("campaign-picker-block").hidden = currentLevel === "A";
    if (currentLevel !== "A") { loadExistingCampaigns(); loadAttackCatalog(); }
    renderFaultCatalog();
    // Alternating treatments design only makes sense at Level C -- its own
    // repetition loop is the only one with a real per-repetition
    // apply/revert hook (level_c_orchestrator._apply_fault_schedule_for_rep).
    document.getElementById("alternating-design-block").hidden = currentLevel !== "C";
    renderAlternatingFaultCheckboxes();
  });
});

function renderLevelExplain() {
  document.getElementById("level-explain").textContent = LEVEL_EXPLAIN[currentLevel];
}

function renderLevelFields() {
  const el = document.getElementById("level-fields");
  if (currentLevel === "A") {
    el.innerHTML = `
      <div class="fi-field"><label>Case ID (base case to reproduce)</label><select id="f-case-id"><option value="">loading real cases...</option></select></div>
      <div class="fi-field"><label>Repetitions</label><input type="number" id="f-n-reps" value="10" min="1" /></div>`;
    loadSourceCases();
  } else if (currentLevel === "B") {
    el.innerHTML = `
      <div class="fi-field"><label>Attack ID</label><select id="f-attack-id"><option value="">loading real attacks...</option></select></div>
      <div class="fi-field"><label>Level B repetitions</label><input type="number" id="f-b-reps" value="3" min="1" /></div>
      <div class="fi-field"><label>Nested Level A repetitions</label><input type="number" id="f-a-reps" value="10" min="1" /></div>`;
  } else {
    el.innerHTML = `
      <div class="fi-field"><label>Attack ID</label><select id="f-attack-id"><option value="">loading real attacks...</option></select></div>
      <div class="fi-field"><label>Level C repetitions</label><input type="number" id="f-c-reps" value="2" min="1" /></div>
      <div class="fi-field"><label>Level B repetitions per round</label><input type="number" id="f-b-reps" value="3" min="1" /></div>
      <div class="fi-field"><label>Nested Level A repetitions</label><input type="number" id="f-a-reps" value="10" min="1" /></div>`;
  }
}

// Same real endpoint and same preference logic that foc_paper_evidence.js
// uses to pick the default attack (T0831 by attack_id, then by mitre_id,
// then the first available) -- here it is also left explicitly selectable
// instead of being silently fixed.
async function loadAttackCatalog() {
  const sel = document.getElementById("f-attack-id");
  if (!sel) return;
  try {
    const res = await fetch("/api/foc/experimentation/attack-catalog?target_role=plc", { cache: "no-store" });
    const data = await res.json();
    const attacks = data.attacks || [];
    if (!attacks.length) { sel.innerHTML = `<option value="">no attacks available for PLC</option>`; return; }
    sel.innerHTML = attacks.map((a) => `<option value="${esc(a.attack_id)}">${esc(a.attack_id)} - ${esc(a.display_name || a.attack_id)}</option>`).join("");
    const preferred = attacks.find((a) => String(a.attack_id || "").toUpperCase() === "T0831_MANIPULATION_OF_CONTROL_MODBUS")
      || attacks.find((a) => String(a.mitre_id || "").toUpperCase() === "T0831")
      || attacks[0];
    if (preferred) sel.value = preferred.attack_id;
  } catch (e) {
    sel.innerHTML = `<option value="">error loading attack catalog</option>`;
  }
}

// Same real endpoint that FOC Paper Evidence uses for its case selector
// (foc_paper_evidence.js::loadCases -> GET /api/foc/experimentation/source-cases)
// -- a case_id is never typed by hand.
async function loadSourceCases() {
  const sel = document.getElementById("f-case-id");
  if (!sel) return;
  try {
    const res = await fetch("/api/foc/experimentation/source-cases", { cache: "no-store" });
    const data = await res.json();
    const cases = data.cases || [];
    sel.innerHTML = cases.length
      ? cases.map((c) => `<option value="${esc(c.case_id)}">${esc(c.case_id)} &middot; ${esc(c.source_case_name || c.case_id)}</option>`).join("")
      : `<option value="">no cases available</option>`;
  } catch (e) {
    sel.innerHTML = `<option value="">error loading cases</option>`;
  }
}

// Exactly replicates populateCampaignPicker() from foc_paper_evidence.js:
// ALWAYS Level B campaigns (Level C also launches on top of a base Level B
// campaign -- confirmed by reading lc-campaign-select in the real
// dashboard), most recent first, same "campaign_id - name" label.
async function loadExistingCampaigns() {
  const sel = document.getElementById("existing-campaign-select");
  sel.innerHTML = `<option value="">Loading...</option>`;
  try {
    const res = await fetch("/api/foc/experimentation/campaigns", { cache: "no-store" });
    const data = await res.json();
    const prev = sel.value;
    const levelB = (data.campaigns || []).filter((c) => String(c.level || "").toUpperCase() === "B").slice().reverse();
    if (!levelB.length) { sel.innerHTML = `<option value="">No Level B campaigns found</option>`; return; }
    sel.innerHTML = levelB.map((c) => `<option value="${esc(c.campaign_id)}" ${c.campaign_id === prev ? "selected" : ""}>${esc(c.campaign_id)} - ${esc(c.name || c.attack_id || "")}</option>`).join("");
    if (!sel.value) sel.value = levelB[0].campaign_id;
  } catch (e) {
    sel.innerHTML = `<option value="">Error loading campaigns</option>`;
  }
}

// Real "Create New Level B Campaign" button (id lc-create-campaign-btn /
// paper-create-level-b-campaign-btn in foc_paper_evidence.html) -- same real
// flow: proposal -> create (with the attack_id already chosen in the
// dropdown and the repetitions/injected_faults already configured), then
// refreshes and selects the newly created campaign.
document.getElementById("existing-campaign-select").addEventListener("change", () => {
  if (document.getElementById("lamp-modbus_payload_precision")) refreshModbusLamp();
});

document.getElementById("btn-create-campaign").addEventListener("click", async () => {
  const statusEl = document.getElementById("create-campaign-status");
  const btn = document.getElementById("btn-create-campaign");
  btn.disabled = true;
  statusEl.textContent = "Creating Level B campaign...";
  try {
    const proposalRes = await fetch("/api/foc/experimentation/campaigns/proposal", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ level: "B" }) });
    const proposal = await proposalRes.json();
    const name = proposal.campaign_name || `Level B Repetition - ${proposal.scenario_id || "active_scenario"}`;
    const attackId = document.getElementById("f-attack-id")?.value || "T0831_MANIPULATION_OF_CONTROL_MODBUS";
    const bReps = Number(document.getElementById(currentLevel === "C" ? "f-b-reps" : "f-b-reps")?.value || 3);
    const aReps = Number(document.getElementById("f-a-reps")?.value || 10);
    const injectedFaults = collectInjectedFaults();
    const createRes = await fetch("/api/foc/experimentation/campaigns/create", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        level: "B", name, description: "Created from the Fault Injection dashboard.",
        scenario_id: proposal.scenario_id, repetitions: bReps, attack_id: attackId, nested_level_a_repetitions: aReps,
        analysis_profile_id: proposal.analysis_profile_id, foc_profile_id: proposal.foc_profile_id,
        detection_policy_id: proposal.detection_policy_id, trigger_policy_id: proposal.trigger_policy_id,
        acquisition_profile_id: proposal.acquisition_profile_id,
        notes: "fault-injection-dashboard", injected_faults: injectedFaults,
      }),
    });
    const created = await createRes.json();
    const campaignId = created.campaign_id || (created.campaign && created.campaign.campaign_id);
    if (!campaignId) { statusEl.textContent = `Error: ${JSON.stringify(created)}`; btn.disabled = false; return; }
    await loadExistingCampaigns();
    document.getElementById("existing-campaign-select").value = campaignId;
    if (document.getElementById("lamp-modbus_payload_precision")) refreshModbusLamp();
    statusEl.textContent = `Created: ${name} (${campaignId})`;
  } catch (e) {
    statusEl.textContent = `Error creating campaign: ${e.message}`;
  }
  btn.disabled = false;
});

// ---------------------------------------------------------------------------
// Fault catalog panel
// ---------------------------------------------------------------------------
async function loadFaultCatalog() {
  const res = await fetch("/api/fault-injection/catalog", { cache: "no-store" });
  const data = await res.json();
  faultCatalog = data.faults || [];
  renderFaultCatalog();
  renderAlternatingFaultCheckboxes();
}

function paramField(faultId, key, schema) {
  const id = `param-${faultId}-${key}`;
  if (schema.type === "enum") {
    return `<label>${key}<select id="${id}">${schema.values.map((v) => `<option value="${v}" ${v === schema.default ? "selected" : ""}>${v}</option>`).join("")}</select></label>`;
  }
  return `<label>${key}<input type="number" id="${id}" value="${schema.default ?? ""}" min="${schema.min ?? ""}" max="${schema.max ?? ""}" /></label>`;
}

function collectParams(faultId, schema) {
  const params = {};
  Object.keys(schema || {}).forEach((key) => {
    const el = document.getElementById(`param-${faultId}-${key}`);
    if (!el) return;
    params[key] = el.tagName === "SELECT" ? el.value : Number(el.value);
  });
  return params;
}

// Lamp helper: green = normal/measured, red = fault currently
// applied/detected. Explicit user request -- the state must be visible
// BEFORE and AFTER pressing Apply/Revert, not just as text.
function lampHtml(id, color) {
  return `<span class="lamp lamp-${color || "off"}" id="${id}" title="${color === "red" ? "fault active/detected" : color === "green" ? "normal" : "not measured yet"}"></span>`;
}
function setLamp(id, color) {
  const el = document.getElementById(id);
  if (el) { el.className = `lamp lamp-${color}`; }
}

function renderFaultCatalog() {
  const el = document.getElementById("fault-catalog-list");
  // Pre-attack faults genuinely depend on which Level you're about to
  // launch (they attach to THAT campaign's config), so they still filter
  // by currentLevel. On-demand faults do NOT depend on a campaign at all
  // (see the banner above this list) -- shown ALWAYS, every level, so
  // nothing available is ever hidden; one whose applicable_levels doesn't
  // include the currently-selected tab is marked (not removed) so it's
  // still visible and explained, just visually dimmed with the real reason.
  const preAttack = faultCatalog.filter((f) => f.applicable_phase !== "on_demand" && f.applicable_levels.includes(currentLevel));
  const onDemand = faultCatalog.filter((f) => f.applicable_phase === "on_demand");

  const groupHtml = (title, purpose, items, builder) => items.length
    ? `<div class="fault-group-head">${esc(title)}</div><div class="fault-group-purpose">${esc(purpose)}</div>${items.map(builder).join("")}`
    : "";

  el.innerHTML =
    groupHtml(
      "Attached to a campaign at launch (optional)",
      `Configure these BEFORE pressing "Launch campaign" in section 1, so the fault is already active from the first repetition of the next Level ${currentLevel} campaign -- or skip this entirely and use the live controls on each one below instead, any time, campaign or not.`,
      preAttack, buildPreAttackItem
    ) +
    groupHtml(
      "Applied directly, right now -- no campaign required",
      "Every one of these needs only a live, already-deployed node. A campaign running or not makes zero difference -- click Apply any time.",
      onDemand, buildOnDemandItem
    );

  if (!preAttack.length && !onDemand.length) {
    el.innerHTML = `<div class="fi-note">No injection type applies to Level ${currentLevel}.</div>`;
  }

  loadNodesIntoSelects();
  wireOnDemandButtons();
  wirePreAttackLiveControls();
}

// ---------------------------------------------------------------------------
// Alternating Treatments Design (Barlow & Hayes, 1979) -- Level C only.
// Reuses the real fault catalog for the checkbox list (same data as section
// 2's "Before launch" items), but this is a SEPARATE mechanism: those
// checkboxes configure a fault applied to EVERY repetition at campaign
// creation; this one alternates a fault on/off per Level C repetition,
// applied/reverted by level_c_orchestrator itself mid-run.
// ---------------------------------------------------------------------------
function renderAlternatingFaultCheckboxes() {
  const el = document.getElementById("alternating-fault-checkboxes");
  if (!el) return;
  if (!faultCatalog.length) { el.textContent = "loading catalog..."; return; }
  el.innerHTML = faultCatalog.map((f) => `
    <label style="display:block;font-weight:400">
      <input type="checkbox" class="alt-fault-enable" data-fault-id="${esc(f.fault_id)}" /> ${esc(f.label)}
      <span class="info-icon" tabindex="0" title="${esc(f.reference)}">&#9432;</span>
    </label>`).join("") || `<span class="fi-note">no fault types in catalog</span>`;
}

document.getElementById("f-use-alternating").addEventListener("change", (ev) => {
  document.getElementById("alternating-design-fields").hidden = !ev.target.checked;
});

// Returns null when the operator didn't opt in -- launchLevelC() then omits
// fault_schedule entirely from the payload, so an unchecked box changes
// NOTHING about the existing launch behavior.
function collectFaultSchedule() {
  const useAlternating = document.getElementById("f-use-alternating")?.checked;
  if (!useAlternating) return null;
  const faultIds = Array.from(document.querySelectorAll(".alt-fault-enable:checked")).map((cb) => cb.dataset.faultId);
  if (!faultIds.length) return null;
  return {
    fault_ids: faultIds,
    target_role: document.getElementById("f-alt-target-role")?.value || "plc",
    start_with: document.getElementById("f-alt-start-with")?.value || "control",
  };
}

function buildPreAttackItem(f) {
  const paramsHtml = Object.entries(f.params_schema || {}).map(([k, s]) => paramField(f.fault_id, k, s)).join("");
  const checkboxBlock = `<div class="fault-item-head"><label><input type="checkbox" class="fault-enable" data-fault-id="${f.fault_id}" /> <b>${esc(f.label)}</b></label><span class="fault-tag">pre-attack</span><span class="campaign-badge optional">campaign: optional</span></div>
    <div class="fault-purpose"><b>Why:</b> ${esc(f.purpose || "")}</div>
    <div class="fault-ref">${esc(f.reference)}</div>
    <div class="fault-desc">${esc(f.description)}</div>
    <div class="fault-controls">${paramsHtml}</div>`;

  let liveBlock = "";
  if (f.fault_id === "clock_skew") {
    liveBlock = `<div class="fault-controls" style="border-top:1px dashed var(--border);margin-top:8px;padding-top:8px">
      ${lampHtml("lamp-clock_skew", "off")}
      <label>Node <select class="node-select" data-fault-id="clock_skew"><option value="">loading...</option></select></label>
      <button class="fi-mini-btn" data-apply-fault="clock_skew">Produce offset</button>
      <button class="fi-mini-btn danger" data-revert-fault="clock_skew" disabled>Counteract (synchronize)</button>
      <span class="fi-note" id="status-clock_skew" style="margin:0"></span>
    </div>`;
  } else if (f.fault_id === "modbus_payload_precision") {
    liveBlock = `<div class="fault-controls" style="border-top:1px dashed var(--border);margin-top:8px;padding-top:8px">
      ${lampHtml("lamp-modbus_payload_precision", "off")}
      <span class="fi-note" style="margin:0">on the campaign selected above</span>
      <button class="fi-mini-btn danger" id="btn-apply-modbus">Activate fault (degrade)</button>
      <button class="fi-mini-btn" id="btn-revert-modbus">Revert (real value)</button>
      <span class="fi-note" id="status-modbus_payload_precision" style="margin:0"></span>
    </div>`;
  }
  return `<div class="fault-item">${checkboxBlock}${liveBlock}</div>`;
}

function buildOnDemandItem(f) {
  const paramsHtml = Object.entries(f.params_schema || {}).map(([k, s]) => paramField(f.fault_id, k, s)).join("");
  // Never hidden, per the user's explicit "show me everything available"
  // request -- a fault whose applicable_levels doesn't include the
  // currently-selected campaign Level tab is just dimmed + explained,
  // never removed. The backend itself has no notion of "Level" at all
  // (apply_fault only needs a live node_id) -- this is purely a
  // conceptual-fit note, never a hard block, so the button stays enabled.
  const levelMismatch = !f.applicable_levels.includes(currentLevel);
  const levelNote = levelMismatch
    ? `<div class="fault-level-note">Not typically meaningful at Level ${esc(currentLevel)} -- designed for Level ${f.applicable_levels.map(esc).join("/")}. Still applies for real if you click it anyway.</div>`
    : "";
  return `<div class="fault-item${levelMismatch ? " level-mismatch" : ""}">
    <div class="fault-item-head"><b>${esc(f.label)}</b><span class="fault-tag on-demand">on-demand</span><span class="campaign-badge not-required">no campaign needed</span></div>
    <div class="fault-purpose"><b>Why:</b> ${esc(f.purpose || "")}</div>
    <div class="fault-ref">${esc(f.reference)}</div>
    <div class="fault-desc">${esc(f.description)}</div>
    ${levelNote}
    <div class="fault-controls">
      <label>Node <select class="node-select" data-fault-id="${f.fault_id}"><option value="">loading...</option></select></label>
      ${paramsHtml}
      <button class="fi-mini-btn" data-apply-fault="${f.fault_id}">Apply</button>
      <button class="fi-mini-btn danger" data-revert-fault="${f.fault_id}" disabled>Revert</button>
      <span class="fi-note" id="status-${f.fault_id}" style="margin:0"></span>
    </div>
  </div>`;
}

// Refreshes the clock_skew lamp for the selected node -- called on node
// change and after every apply/revert.
async function refreshClockLamp(nodeId) {
  if (!nodeId) { setLamp("lamp-clock_skew", "off"); return; }
  try {
    const res = await fetch(`/api/fault-injection/clock-status/${encodeURIComponent(nodeId)}`, { cache: "no-store" });
    const data = await res.json();
    setLamp("lamp-clock_skew", data.ok ? data.lamp : "off");
  } catch (e) { setLamp("lamp-clock_skew", "off"); }
}

// Refreshes the modbus_payload_precision lamp for the currently selected
// campaign -- called on campaign change and after every activate/revert.
async function refreshModbusLamp() {
  const campaignId = document.getElementById("existing-campaign-select")?.value;
  if (!campaignId) { setLamp("lamp-modbus_payload_precision", "off"); return; }
  try {
    const res = await fetch(`/api/fault-injection/modbus-status/${encodeURIComponent(campaignId)}`, { cache: "no-store" });
    const data = await res.json();
    setLamp("lamp-modbus_payload_precision", data.ok ? data.lamp : "off");
  } catch (e) { setLamp("lamp-modbus_payload_precision", "off"); }
}

function wirePreAttackLiveControls() {
  const clockNodeSelect = document.querySelector('.node-select[data-fault-id="clock_skew"]');
  if (clockNodeSelect) clockNodeSelect.addEventListener("change", () => refreshClockLamp(clockNodeSelect.value));

  const applyModbusBtn = document.getElementById("btn-apply-modbus");
  const revertModbusBtn = document.getElementById("btn-revert-modbus");
  if (applyModbusBtn) {
    applyModbusBtn.onclick = async () => {
      const campaignId = document.getElementById("existing-campaign-select")?.value;
      if (!campaignId) { alert("Select or create a Level B campaign first."); return; }
      const confirmed = window.confirm("Activate the Modbus payload precision fault (degraded) on this campaign? It will apply starting from the next repetition.");
      if (!confirmed) return;
      const res = await fetch("/api/fault-injection/modbus-toggle", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ campaign_id: campaignId, mode: "degraded" }) });
      const data = await res.json();
      document.getElementById("status-modbus_payload_precision").textContent = data.ok ? "activated (degraded)" : `error: ${data.error || "?"}`;
      refreshModbusLamp();
    };
  }
  if (revertModbusBtn) {
    revertModbusBtn.onclick = async () => {
      const campaignId = document.getElementById("existing-campaign-select")?.value;
      if (!campaignId) { alert("Select or create a Level B campaign first."); return; }
      const confirmed = window.confirm("Revert to a real, explicit value (control condition) on this campaign? It will apply starting from the next repetition.");
      if (!confirmed) return;
      const value = Number(document.getElementById(`param-modbus_payload_precision-value`)?.value || 30);
      const res = await fetch("/api/fault-injection/modbus-toggle", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ campaign_id: campaignId, mode: "fixed", value }) });
      const data = await res.json();
      document.getElementById("status-modbus_payload_precision").textContent = data.ok ? "reverted (real value)" : `error: ${data.error || "?"}`;
      refreshModbusLamp();
    };
  }
  refreshModbusLamp();
}

async function loadNodesIntoSelects() {
  try {
    const res = await fetch("/api/control-room/snapshot", { cache: "no-store" });
    const data = await res.json();
    selectedNodes = (data.scenario_nodes || {}).nodes || [];
    document.querySelectorAll(".node-select").forEach((sel) => {
      sel.innerHTML = selectedNodes.map((n) => `<option value="${esc(n.id)}">${esc(n.name)} (${esc(n.role)})</option>`).join("") || `<option value="">no nodes</option>`;
    });
  } catch (e) { /* control room might be unavailable; leave selects empty */ }
}

function wireOnDemandButtons() {
  document.querySelectorAll("[data-apply-fault]").forEach((btn) => {
    btn.onclick = async () => {
      const faultId = btn.dataset.applyFault;
      const nodeSelect = document.querySelector(`.node-select[data-fault-id="${faultId}"]`);
      const nodeId = nodeSelect ? nodeSelect.value : "";
      if (!nodeId) { alert("Select a node first."); return; }
      const fault = faultCatalog.find((f) => f.fault_id === faultId);
      const confirmed = window.confirm(`Apply "${fault.label}" (real, reversible) against the selected node?`);
      if (!confirmed) return;
      const statusEl = document.getElementById(`status-${faultId}`);
      statusEl.textContent = "applying...";
      btn.disabled = true;
      try {
        const res = await fetch("/api/fault-injection/apply", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ fault_id: faultId, node_id: nodeId, params: collectParams(faultId, fault.params_schema) }),
        });
        const data = await res.json();
        if (data.ok) {
          onDemandState[faultId] = { injection_id: data.record.injection_id, status: "active", node_id: nodeId };
          statusEl.textContent = `active (${data.record.injection_id})`;
          document.querySelector(`[data-revert-fault="${faultId}"]`).disabled = false;
        } else {
          statusEl.textContent = `error: ${(data.record && data.record.errors && data.record.errors[0]) || data.error || "failed"}`;
        }
      } catch (e) {
        statusEl.textContent = `network error: ${e.message}`;
      }
      btn.disabled = false;
      if (faultId === "clock_skew") refreshClockLamp(nodeId);
      refreshInjectionsTable();
    };
  });
  document.querySelectorAll("[data-revert-fault]").forEach((btn) => {
    btn.onclick = async () => {
      const faultId = btn.dataset.revertFault;
      const state = onDemandState[faultId];
      if (!state) return;
      const fault = faultCatalog.find((f) => f.fault_id === faultId);
      // Explicit safety measure requested by the user: ALWAYS confirm, both
      // on apply and on revert, in case the click was not intentional --
      // same requirement for all 5 types, without exception.
      const confirmed = window.confirm(`Revert "${fault ? fault.label : faultId}" (injection_id=${state.injection_id})?`);
      if (!confirmed) return;
      const statusEl = document.getElementById(`status-${faultId}`);
      statusEl.textContent = "reverting...";
      btn.disabled = true;
      try {
        const res = await fetch("/api/fault-injection/revert", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ injection_id: state.injection_id }),
        });
        const data = await res.json();
        statusEl.textContent = data.ok ? "reverted" : `revert_failed: ${(data.record && data.record.errors && data.record.errors[0]) || "see record"}`;
        // Measure effectiveness once we have before/after data.
        fetch(`/api/fault-injection/effectiveness/${state.injection_id}`).then((r) => r.json()).then(() => refreshInjectionsTable());
      } catch (e) {
        statusEl.textContent = `network error: ${e.message}`;
      }
      if (faultId === "clock_skew" && state.node_id) refreshClockLamp(state.node_id);
      refreshInjectionsTable();
    };
  });
}

// ---------------------------------------------------------------------------
// Launch: replicate FOC Paper Evidence's exact real recipe, per level.
// ---------------------------------------------------------------------------
function collectInjectedFaults() {
  const faults = [];
  document.querySelectorAll(".fault-enable:checked").forEach((cb) => {
    const faultId = cb.dataset.faultId;
    const fault = faultCatalog.find((f) => f.fault_id === faultId);
    if (!fault) return;
    faults.push({ type: faultId, attack_id: currentLevel !== "A" ? (document.getElementById("f-attack-id")?.value || null) : null, phase: fault.applicable_phase, params: collectParams(faultId, fault.params_schema) });
  });
  return faults;
}

async function launchLevelA() {
  const caseId = document.getElementById("f-case-id").value.trim();
  const nReps = Number(document.getElementById("f-n-reps").value || 10);
  if (!caseId) return setLaunchStatus("Enter a real case_id.");
  setLaunchStatus("Launching Level A...");
  const res = await fetch("/api/foc/paper-evidence/level-a/run", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: caseId, level: "A", n_repetitions: nReps, generate_latex: false, generate_zip: false, dry_run: true }),
  });
  const data = await res.json();
  setLaunchStatus(res.ok ? `Launched: ${JSON.stringify(data)}` : `Error: ${JSON.stringify(data)}`);
}

function requireSelectedCampaign() {
  const campaignId = document.getElementById("existing-campaign-select").value;
  if (!campaignId) setLaunchStatus('Click "Create New Level B Campaign" or select an existing campaign before launching.');
  return campaignId;
}

async function launchLevelB() {
  const bReps = Number(document.getElementById("f-b-reps").value || 3);
  const aReps = Number(document.getElementById("f-a-reps").value || 10);
  const campaignId = requireSelectedCampaign();
  if (!campaignId) return;
  setLaunchStatus(`Launching real Level B on campaign ${campaignId}...`);
  const res = await fetch("/api/foc/paper-evidence/level-b/run", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ campaign_id: campaignId, level: "B", n_repetitions: bReps, requested_repetitions: bReps, nested_level_a_repetitions: aReps, cleanup_old_cases: false, generate_latex: false, generate_zip: false, dfir_mode_after: "on" }),
  });
  const data = await res.json();
  setLaunchStatus(res.ok ? `Launched (campaign_id=${campaignId}): ${JSON.stringify(data)}` : `Error: ${JSON.stringify(data)}`);
}

async function launchLevelC() {
  const cReps = Number(document.getElementById("f-c-reps").value || 2);
  const bReps = Number(document.getElementById("f-b-reps").value || 3);
  const aReps = Number(document.getElementById("f-a-reps").value || 10);
  const campaignId = requireSelectedCampaign();
  if (!campaignId) return;
  const faultSchedule = collectFaultSchedule();
  setLaunchStatus(`Launching Level C on base campaign ${campaignId}${faultSchedule ? " (alternating treatments design)" : ""}...`);
  const payload = { campaign_id: campaignId, level_c_repetitions: cReps, level_b_repetitions: bReps, level_a_repetitions: aReps, confirmation: "LAUNCH_LEVEL_C" };
  if (faultSchedule) payload.fault_schedule = faultSchedule;
  const res = await fetch("/api/level-c/launch", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  setLaunchStatus(res.ok ? `Launched: job_id=${data.job_id || "?"}` : `Error: ${JSON.stringify(data)}`);
}

function setLaunchStatus(text) { document.getElementById("launch-status").textContent = text; }

document.getElementById("btn-launch").addEventListener("click", async () => {
  const btn = document.getElementById("btn-launch");
  btn.disabled = true;
  try {
    if (currentLevel === "A") await launchLevelA();
    else if (currentLevel === "B") await launchLevelB();
    else await launchLevelC();
  } catch (e) {
    setLaunchStatus(`Unexpected error: ${e.message}`);
  }
  btn.disabled = false;
});

// ---------------------------------------------------------------------------
// Live monitoring: campaign progress (Control Room snapshot, reused) +
// injections effectiveness table (our own, cheap poll).
// ---------------------------------------------------------------------------
async function refreshCampaignProgress() {
  try {
    const res = await fetch("/api/control-room/snapshot", { cache: "no-store" });
    const data = await res.json();
    const rows = (data.active_campaigns || []).filter((c) => !c.error).slice(0, 8);
    const el = document.getElementById("campaign-progress-list");
    el.innerHTML = rows.length ? rows.map((c) => `<div class="campaign-row"><div class="cr-title">${esc(c.campaign_id || c.job_id)}</div><div class="cr-meta">Level ${esc(c.level)} &middot; ${esc(c.repetition_status)} &middot; ${esc(c.execution_label || "")}</div></div>`).join("") : `<div class="fi-note">no campaigns registered</div>`;
  } catch (e) { /* control room may be reloading; skip this tick */ }
}

async function refreshInjectionsTable() {
  try {
    const res = await fetch("/api/fault-injection/injections", { cache: "no-store" });
    const data = await res.json();
    const rows = data.injections || [];
    document.getElementById("stat-total").textContent = rows.length;
    document.getElementById("stat-active").textContent = rows.filter((r) => r.status === "active").length;
    document.getElementById("stat-effective").textContent = rows.filter((r) => r.effective === true).length;
    const body = document.getElementById("injections-table-body");
    body.innerHTML = rows.slice(0, 30).map((r) => {
      const effClass = r.effective === true ? "yes" : r.effective === false ? "no" : "na";
      const effLabel = r.effective === true ? "yes" : r.effective === false ? "no" : "n/a";
      return `<tr>
        <td>${esc((r.started_at || "").slice(0, 16).replace("T", " "))}</td>
        <td>${esc(r.label)}</td>
        <td>${esc(r.node_name)}</td>
        <td><span class="pill ${esc(r.status)}">${esc(r.status)}</span></td>
        <td><span class="pill ${effClass}">${effLabel}</span></td>
        <td style="max-width:260px;white-space:normal">${esc(r.effectiveness_evidence || "-")}</td>
        <td>${r.status === "active" ? `<button class="fi-mini-btn danger" data-table-revert="${esc(r.injection_id)}">Revert</button>` : ""}</td>
      </tr>`;
    }).join("") || `<tr><td colspan="7" class="fi-note">no injections registered yet</td></tr>`;
    body.querySelectorAll("[data-table-revert]").forEach((btn) => {
      btn.onclick = async () => {
        if (!window.confirm(`Revert injection ${btn.dataset.tableRevert}?`)) return;
        await fetch("/api/fault-injection/revert", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ injection_id: btn.dataset.tableRevert }) });
        refreshInjectionsTable();
      };
    });
  } catch (e) { /* transient */ }
}

function startPolling() {
  refreshCampaignProgress();
  refreshInjectionsTable();
  setInterval(refreshCampaignProgress, 5000);
  setInterval(refreshInjectionsTable, 4000);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
renderLevelExplain();
renderLevelFields();
loadFaultCatalog();
startPolling();
