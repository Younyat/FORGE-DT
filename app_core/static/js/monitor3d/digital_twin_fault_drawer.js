// Quick fault-injection drawer for Digital Twin View -- a collapsible panel
// docked to the right edge of the 3D viewport (toggled by its own tab
// handle) that lets a REAL fault be applied/reverted against any node
// without leaving this screen, so its effect (lamp color / event flash,
// both built in digital_twin_view.js) is watched live in the same scene.
// Reuses the exact same real endpoints the Fault Injection dashboard uses
// (/api/fault-injection/catalog|apply|revert) -- no new backend action, this
// is a second, faster-access real UI for an action that already exists.

let mounted = false;
let drawerOpen = false;
let catalog = [];
let nodes = []; // [{instance_id, name}]
let activeInjectionId = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function paramFieldHtml(faultId, key, schema) {
  const id = `dtf-param-${faultId}-${key}`;
  if (schema.type === "enum") {
    return `<label class="dtf-field">${esc(key)}<select id="${id}">${schema.values.map((v) => `<option value="${esc(v)}" ${v === schema.default ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>`;
  }
  return `<label class="dtf-field">${esc(key)}<input type="number" id="${id}" value="${schema.default ?? ""}" min="${schema.min ?? ""}" max="${schema.max ?? ""}" /></label>`;
}

function collectParams(faultId, schema) {
  const params = {};
  Object.keys(schema || {}).forEach((key) => {
    const el = document.getElementById(`dtf-param-${faultId}-${key}`);
    if (!el) return;
    params[key] = el.tagName === "SELECT" ? el.value : Number(el.value);
  });
  return params;
}

function selectedFault() {
  const sel = document.getElementById("dtf-fault");
  return catalog.find((f) => f.fault_id === sel?.value) || null;
}

function renderParams() {
  const el = document.getElementById("dtf-params");
  const ref = document.getElementById("dtf-ref");
  const fault = selectedFault();
  if (!fault) { el.innerHTML = ""; ref.textContent = ""; return; }
  ref.textContent = fault.reference;
  el.innerHTML = Object.entries(fault.params_schema || {}).map(([k, s]) => paramFieldHtml(fault.fault_id, k, s)).join("");
}

function renderFaultOptions() {
  const sel = document.getElementById("dtf-fault");
  sel.innerHTML = catalog.map((f) => `<option value="${esc(f.fault_id)}">${esc(f.label)}</option>`).join("");
  renderParams();
}

function renderNodeOptions() {
  const sel = document.getElementById("dtf-node");
  const current = sel.value;
  sel.innerHTML = nodes.map((n) => `<option value="${esc(n.instance_id)}">${esc(n.name)}</option>`).join("");
  if (current && nodes.some((n) => n.instance_id === current)) sel.value = current;
}

function setStatus(text) {
  const el = document.getElementById("dtf-status");
  if (el) el.textContent = text;
}

function setApplying(isApplying) {
  document.getElementById("dtf-apply").disabled = isApplying || !!activeInjectionId;
  document.getElementById("dtf-node").disabled = isApplying || !!activeInjectionId;
  document.getElementById("dtf-fault").disabled = isApplying || !!activeInjectionId;
}

async function doApply() {
  const nodeId = document.getElementById("dtf-node").value;
  const fault = selectedFault();
  if (!nodeId || !fault) { setStatus("select a node and a fault type first"); return; }
  setStatus("applying...");
  setApplying(true);
  try {
    const res = await fetch("/api/fault-injection/apply", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fault_id: fault.fault_id, node_id: nodeId, params: collectParams(fault.fault_id, fault.params_schema), campaign_id: null }),
    });
    const data = await res.json();
    if (data.ok) {
      activeInjectionId = data.record?.injection_id || null;
      setStatus(`active (injection_id=${activeInjectionId || "?"}) -- watch this node's lamp/feed now`);
      document.getElementById("dtf-revert").disabled = false;
    } else {
      setStatus(`apply_failed: ${(data.record?.errors && data.record.errors[0]) || data.error || "see record"}`);
    }
  } catch (e) {
    setStatus(`network error: ${e.message}`);
  }
  setApplying(false);
  const { refreshNow } = await import("./digital_twin_view.js");
  refreshNow();
}

async function doRevert() {
  if (!activeInjectionId) return;
  setStatus("reverting...");
  document.getElementById("dtf-revert").disabled = true;
  try {
    const res = await fetch("/api/fault-injection/revert", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ injection_id: activeInjectionId }),
    });
    const data = await res.json();
    if (data.ok) {
      setStatus("reverted");
      activeInjectionId = null;
    } else {
      // Revert genuinely failed -- the fault is still physically active on
      // that node. Keep activeInjectionId so Revert can be retried, instead
      // of silently losing track of a still-applied fault.
      setStatus(`revert_failed: ${(data.record?.errors && data.record.errors[0]) || data.error || "see record"}`);
      document.getElementById("dtf-revert").disabled = false;
    }
  } catch (e) {
    setStatus(`network error: ${e.message}`);
    document.getElementById("dtf-revert").disabled = false;
  }
  setApplying(false);
  const { refreshNow } = await import("./digital_twin_view.js");
  refreshNow();
}

function mount() {
  if (mounted) return;
  mounted = true;
  document.getElementById("dt-fault-drawer-handle").addEventListener("click", () => {
    drawerOpen = !drawerOpen;
    // Toggling `hidden` (not a transform/class) -- when hidden the panel is
    // not rendered at all, so it can never visually overlap the pre-existing
    // right-side detail panel the way an earlier translateX-based version
    // did (see monitor3d.html's comment on #dt-fault-drawer).
    document.getElementById("dt-fault-drawer-panel").hidden = !drawerOpen;
    document.getElementById("dt-fault-drawer-handle").innerHTML = drawerOpen ? "&#9654;" : "&#9664;";
  });
  document.getElementById("dtf-fault").addEventListener("change", renderParams);
  document.getElementById("dtf-apply").addEventListener("click", doApply);
  document.getElementById("dtf-revert").addEventListener("click", doRevert);
}

async function loadCatalogOnce() {
  if (catalog.length) return;
  try {
    const res = await fetch("/api/fault-injection/catalog", { cache: "no-store" });
    const data = await res.json();
    catalog = data.faults || [];
  } catch (e) { catalog = []; }
}

// Called by digital_twin_view.js's enter(), with the real live node list
// already fetched there (no second /api/monitor3d/snapshot call here).
export async function show(liveNodes) {
  mount();
  nodes = liveNodes || [];
  activeInjectionId = null;
  setStatus("");
  document.getElementById("dtf-revert").disabled = true;
  await loadCatalogOnce();
  renderNodeOptions();
  renderFaultOptions();
  setApplying(false);
  const drawer = document.getElementById("dt-fault-drawer");
  if (drawer) drawer.hidden = false;
}

// Called by digital_twin_view.js's exit() -- leaves any already-applied
// fault running (reverting it here would be a surprising side effect of
// just switching views); the dashboard's own injections table is still the
// authoritative way to revert something left active after leaving this view.
export function hide() {
  const drawer = document.getElementById("dt-fault-drawer");
  if (drawer) drawer.hidden = true;
  const panel = document.getElementById("dt-fault-drawer-panel");
  if (panel) panel.hidden = true;
  const handle = document.getElementById("dt-fault-drawer-handle");
  if (handle) handle.innerHTML = "&#9664;";
  drawerOpen = false;
}

// Called by digital_twin_view.js's handleSelect() so clicking a node in the
// 3D scene also preselects it here, for a fast apply-and-watch workflow.
export function setSelectedNode(nodeId) {
  const sel = document.getElementById("dtf-node");
  if (sel && nodes.some((n) => n.instance_id === nodeId)) sel.value = nodeId;
}
