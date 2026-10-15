// FORGE-DT Scientific Validation (Gap-Experiment-Evidence matrix). Purely
// additive to the Fault Injection dashboard -- reads/writes only
// /api/gap-validation/*, never touches anything app.js already owns (its
// stats, catalog, campaign launcher, injections table are all untouched).
// See app_core/infrastructure/gap_validation/README.md for what every
// endpoint here reuses and what it does not yet implement.

function gvEsc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

let gvGaps = [];
let gvExperiments = [];
let gvLastCampaignStatuses = {};

// Matches report.py's own 4-state verdict exactly -- never a 5th
// "closed"/"proven" label invented on the frontend.
const VERDICT_LABEL = {
  not_evaluated: "not evaluated",
  not_supported: "not supported",
  partially_supported: "partially supported",
  supported_under_tested_conditions: "supported (tested conditions)",
};

// ---------------------------------------------------------------------------
// Gap Registry -- always shows a plain-language reading next to the verdict
// pill, never just a raw number/label (platform-wide rule: every dashboard
// metric carries a non-technical interpretation, visible by default).
// ---------------------------------------------------------------------------
async function gvLoadGaps() {
  const el = document.getElementById("gap-registry-list");
  try {
    const res = await fetch("/api/gap-validation/gaps", { cache: "no-store" });
    const data = await res.json();
    gvGaps = data.gaps || [];
  } catch (e) {
    el.innerHTML = `<div class="fi-note">error loading gap registry: ${gvEsc(e.message)}</div>`;
    return;
  }
  gvRenderGapSkeleton();
  gvRefreshVerdicts();
}

function gvRenderGapSkeleton() {
  const el = document.getElementById("gap-registry-list");
  if (!gvGaps.length) { el.innerHTML = `<div class="fi-note">no gaps registered</div>`; return; }
  el.innerHTML = gvGaps.map((g) => `
    <div class="gv-gap-row" id="gv-gap-${gvEsc(g.gap_id)}">
      <div class="gv-gap-title"><span>${gvEsc(g.title)}</span><span class="pill not_evaluated" id="gv-verdict-${gvEsc(g.gap_id)}">loading...</span></div>
      <div class="gv-gap-meta">${gvEsc(g.mechanism)} &middot; ${gvEsc(g.source_doc)}</div>
      <div class="gv-plain" id="gv-plain-${gvEsc(g.gap_id)}"></div>
    </div>`).join("");
}

// Fetches every gap's own real report (a static-only answer for a gap with
// no linked experiment, a real aggregated verdict otherwise) -- a single
// source of truth in report.py, nothing duplicated here.
async function gvRefreshVerdicts() {
  await Promise.all(gvGaps.map(async (g) => {
    try {
      const res = await fetch(`/api/gap-validation/gaps/${encodeURIComponent(g.gap_id)}/report`, { cache: "no-store" });
      const report = await res.json();
      const pill = document.getElementById(`gv-verdict-${g.gap_id}`);
      const plainEl = document.getElementById(`gv-plain-${g.gap_id}`);
      if (!report.ok) {
        if (pill) { pill.textContent = "error"; }
        return;
      }
      if (pill) {
        pill.className = `pill ${report.verdict}`;
        pill.textContent = VERDICT_LABEL[report.verdict] || report.verdict;
      }
      if (plainEl) plainEl.textContent = report.plain_language || "";
    } catch (e) { /* transient -- leave last known state on screen */ }
  }));
}

// ---------------------------------------------------------------------------
// Experiment catalog + launcher
// ---------------------------------------------------------------------------
async function gvLoadExperiments() {
  const sel = document.getElementById("gv-experiment-select");
  try {
    const res = await fetch("/api/gap-validation/experiments", { cache: "no-store" });
    const data = await res.json();
    gvExperiments = data.experiments || [];
    sel.innerHTML = gvExperiments.length
      ? gvExperiments.map((e) => `<option value="${gvEsc(e.experiment_id)}" ${e.implementation_status !== "ready" ? "disabled" : ""}>${gvEsc(e.experiment_id)}${e.implementation_status !== "ready" ? " (not implemented yet)" : ""}</option>`).join("")
      : `<option value="">no experiments in catalog</option>`;
  } catch (e) {
    sel.innerHTML = `<option value="">error loading catalog</option>`;
  }
  gvRenderExperimentDetail();
}

function gvRenderExperimentDetail() {
  const sel = document.getElementById("gv-experiment-select");
  const exp = gvExperiments.find((e) => e.experiment_id === sel.value);
  const el = document.getElementById("gv-experiment-detail");
  if (!exp) { el.innerHTML = ""; return; }
  el.innerHTML = `
    <div class="fault-purpose" style="margin-bottom:6px"><b>Why:</b> ${gvEsc(exp.purpose || "")}</div>
    <div class="fi-note" style="margin-bottom:0">
    Gaps tested: ${exp.gap_ids.map(gvEsc).join(", ")}<br/>
    Fault: ${exp.fault_id ? gvEsc(exp.fault_id) : "none (control-arm baseline)"} &middot; status: ${gvEsc(exp.implementation_status)}<br/>
    Expected signal: ${gvEsc(exp.expected_signal)}
  </div>`;
}

document.getElementById("gv-experiment-select").addEventListener("change", gvRenderExperimentDetail);

document.getElementById("gv-launch-btn").addEventListener("click", async () => {
  const btn = document.getElementById("gv-launch-btn");
  const statusEl = document.getElementById("gv-launch-status");
  const experimentId = document.getElementById("gv-experiment-select").value;
  const repetitions = Number(document.getElementById("gv-repetitions").value || 4);
  if (!experimentId) { statusEl.textContent = "Select an experiment first."; return; }
  const exp = gvExperiments.find((e) => e.experiment_id === experimentId);
  if (exp && exp.implementation_status !== "ready") {
    statusEl.textContent = `"${experimentId}" is not runnable yet (implementation_status=${exp.implementation_status}) -- it references a fault type not added to the catalog yet.`;
    return;
  }
  // Explicit safety confirmation -- same standing requirement as every
  // apply/revert button elsewhere on this page: this is a REAL, reversible
  // fault against a REAL live node, never a simulation.
  const confirmed = window.confirm(`Launch a real validation campaign for "${experimentId}" (${repetitions} repetitions, alternating control/treatment)? This applies and reverts a real, reversible fault against a live node.`);
  if (!confirmed) return;
  btn.disabled = true;
  statusEl.textContent = "Launching...";
  try {
    const res = await fetch("/api/gap-validation/campaigns", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ experiment_id: experimentId, repetitions }),
    });
    const data = await res.json();
    statusEl.textContent = data.ok ? `Launched: job_id=${data.job_id}` : `Error: ${data.error || "?"}`;
  } catch (e) {
    statusEl.textContent = `Network error: ${e.message}`;
  }
  btn.disabled = false;
  gvRefreshCampaigns();
});

// ---------------------------------------------------------------------------
// Running / recent validation campaigns
// ---------------------------------------------------------------------------
async function gvRefreshCampaigns() {
  try {
    const res = await fetch("/api/gap-validation/campaigns?limit=20", { cache: "no-store" });
    const data = await res.json();
    const rows = data.campaigns || [];
    const el = document.getElementById("gv-campaigns-list");
    el.innerHTML = rows.length
      ? rows.map((c) => {
          const statusPill = c.status === "completed" ? "active" : c.status === "failed" ? "failed" : "applying";
          return `<div class="campaign-row">
            <div class="cr-title">${gvEsc(c.job_id)} <span class="pill ${statusPill}">${gvEsc(c.status)}</span></div>
            <div class="cr-meta">${gvEsc(c.experiment_id)} &middot; rep ${gvEsc(c.current_repetition)}/${gvEsc(c.repetitions)} &middot; gaps: ${(c.gap_ids || []).map(gvEsc).join(", ")}
              ${c.status === "completed" ? ` &middot; <a href="#" data-gv-report="${gvEsc(c.job_id)}" style="color:var(--cyan)">view scoring</a>` : ""}
            </div>
            <div class="gv-plain" id="gv-report-${gvEsc(c.job_id)}" hidden></div>
          </div>`;
        }).join("")
      : `<div class="fi-note">no validation campaigns yet</div>`;

    el.querySelectorAll("[data-gv-report]").forEach((link) => {
      link.onclick = async (ev) => {
        ev.preventDefault();
        const jobId = link.dataset.gvReport;
        const box = document.getElementById(`gv-report-${jobId}`);
        box.hidden = !box.hidden;
        if (!box.hidden && !box.dataset.loaded) {
          try {
            const r = await fetch(`/api/gap-validation/campaigns/${encodeURIComponent(jobId)}/report`, { cache: "no-store" }).then((x) => x.json());
            box.textContent = r.ok
              ? `detection coverage: ${r.detection_coverage_rate ?? "n/a (control-only)"} · false-positive rate: ${r.false_positive_rate ?? "n/a"}`
              : `error: ${r.error || "?"}`;
            box.dataset.loaded = "1";
          } catch (e) { box.textContent = `network error: ${e.message}`; }
        }
      };
    });

    // A campaign reaching completed/failed can change a gap's verdict --
    // refresh the registry once when that happens, not on every poll tick.
    let anyNewlyTerminal = false;
    rows.forEach((c) => {
      const prev = gvLastCampaignStatuses[c.job_id];
      if (prev !== c.status && (c.status === "completed" || c.status === "failed")) anyNewlyTerminal = true;
      gvLastCampaignStatuses[c.job_id] = c.status;
    });
    if (anyNewlyTerminal) gvRefreshVerdicts();
  } catch (e) { /* transient */ }
}

function gvStartPolling() {
  gvRefreshCampaigns();
  setInterval(gvRefreshCampaigns, 5000);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
gvLoadGaps();
gvLoadExperiments();
gvStartPolling();
