// Reusable "phase timeline" widget -- renders one real intervention's
// lifecycle (Requested -> Applied -> Effect verified -> Seen by twin ->
// Evidence linked -> Reverted) as a horizontal HUD strip, from the
// read-only /api/intervention-ledger/phase-timeline(-for-node) endpoints
// (M1 Ledger + M4 linker + M5 Evidence Bridge joined server-side, see
// intervention_ledger/timeline.py). Every timestamp/detail text is real
// data from those modules -- this file only draws it. Built to be mounted
// both in Digital Twin View's node detail panel and, unchanged, as a new
// beat renderer in the Reconstruction View's historical timeline.

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmtTime(iso) {
  if (!iso) return null;
  try {
    return iso.replace("T", " ").replace(/\.\d+\+00:00$/, "").replace("+00:00", "") + " UTC";
  } catch {
    return iso;
  }
}

const PHASE_META = {
  requested: { icon: "1" },
  applied: { icon: "2" },
  effect_verified: { icon: "3" },
  twin_observed: { icon: "4" },
  evidence_linked: { icon: "5" },
  reverted: { icon: "6" },
};

// Index of the first "pending" phase right after the last "done" one --
// that connector segment is drawn as "live" (animated) only when the
// intervention itself is still active (applied, not yet reverted),
// signalling "this could still complete at any moment" rather than a
// permanently-stalled step.
function activeEdgeIndex(phases, isActive) {
  if (!isActive) return -1;
  for (let i = 0; i < phases.length; i++) {
    if (phases[i].status === "pending") return i - 1;
  }
  return -1;
}

export function renderPhaseTimelineHtml(data) {
  if (!data || data.ok === false) {
    return `<div class="pt-empty">${esc((data && data.error) || "No real intervention recorded yet for this node.")}</div>`;
  }
  const phases = data.phases || [];
  const activeEdge = activeEdgeIndex(phases, data.is_active);

  let html = `<div class="pt-header">`;
  html += `<span class="pt-type">${esc(data.type || "intervention")}</span>`;
  if (data.is_active) html += `<span class="pt-live-badge">LIVE -- still active</span>`;
  html += `</div>`;
  html += `<div class="pt-sub">intervention_id: ${esc(data.intervention_id)} -- target: ${esc(data.target_node_name || data.target_node_id || "n/a")}</div>`;

  html += `<div class="pt-timeline">`;
  phases.forEach((p, i) => {
    const statusClass = `pt-dot--${p.status}`;
    const connectorClass =
      i === activeEdge ? "pt-connector--active" : phases[i + 1] && phases[i + 1].status !== "pending" ? "pt-connector--done" : "pt-connector--pending";
    html += `<div class="pt-item">`;
    html += `<div class="pt-node-col">`;
    html += `<div class="pt-dot ${statusClass}"><span>${PHASE_META[p.phase]?.icon || ""}</span></div>`;
    if (i < phases.length - 1) html += `<div class="pt-connector ${connectorClass}"></div>`;
    html += `</div>`;
    html += `<div class="pt-body">`;
    html += `<div class="pt-label">${esc(p.label)}</div>`;
    html += `<div class="pt-time">${esc(fmtTime(p.at) || (p.status === "failed" ? "did not realize" : "not reached yet"))}</div>`;
    if (p.detail) html += `<div class="pt-detail">${esc(p.detail)}</div>`;
    html += `</div>`;
    html += `</div>`;
  });
  html += `</div>`;

  if ((data.older_interventions || []).length) {
    html += `<div class="pt-older">Earlier on this node: `;
    html += data.older_interventions
      .map((o) => `${esc(o.type)} (${esc(fmtTime(o.recorded_at_utc))})`)
      .join(" | ");
    html += `</div>`;
  }
  return html;
}

export async function fetchNodeTimeline(nodeId) {
  try {
    const res = await fetch(`/api/intervention-ledger/node-timeline/${encodeURIComponent(nodeId)}`, { cache: "no-store" });
    return await res.json();
  } catch (exc) {
    return { ok: false, error: String(exc) };
  }
}

export async function renderNodeTimelineInto(container, nodeId) {
  if (!container) return;
  container.innerHTML = `<div class="pt-empty">Loading real intervention history...</div>`;
  const data = await fetchNodeTimeline(nodeId);
  container.innerHTML = renderPhaseTimelineHtml(data);
}
