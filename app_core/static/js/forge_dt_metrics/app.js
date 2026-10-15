// FORGE-DT Metrics dashboard -- reads only, from the real
// /api/forge-dt-metrics/*, /api/intervention-ledger/* endpoints already
// built this session. Every explanation on this page is printed directly
// next to its number (never a hover-only tooltip, never collapsed) --
// that's a deliberate design choice the user asked for explicitly.

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmtPct(value) {
  return value === null || value === undefined ? null : `${Math.round(value * 100)}%`;
}

// Per-metric, VALUE-AWARE verdicts -- not just "what IRR means" (that's
// `explain`, always the same text regardless of the number), but "what
// THIS result means in practice, good or bad, in plain words". Added at
// the user's explicit, generalized request: "no quiero solo resultados,
// quiero interpretaciones que todo el mundo entienda" -- every number on
// every dashboard needs a reading a non-specialist can act on, not just a
// percentage. Each returns {tone: "good"|"mixed"|"bad", text} or null when
// there's no value to interpret yet (the existing `note` already explains
// why).
const METRIC_META = [
  {
    key: "irr", label: "IRR", fullName: "Intervention Realization Rate",
    explain: "Of the faults/attacks we tried and actually measured, how many really worked.",
    getValue: (d) => d.irr.irr,
    getRaw: (d) => `${d.irr.n_realized}/${d.irr.n_measured} measured attempt(s) realized (${d.irr.n_attempts} total attempts)`,
    getNote: (d) => d.irr.note,
    getVerdict: (d, v) => {
      if (v == null) return null;
      if (v >= 0.9) return { tone: "good", text: "Almost everything we tried to apply really worked -- no silent failures." };
      if (v >= 0.5) return { tone: "mixed", text: "More than half worked, but a real share of attempts didn't actually take effect -- worth checking why." };
      return { tone: "bad", text: "Less than half of what we tried actually worked -- most attempts are failing silently and need investigating." };
    },
  },
  {
    key: "tor", label: "TOR", fullName: "Twin Observability Rate",
    explain: "Of the ones that really worked, how many the digital twin noticed on its own (never told in advance).",
    getValue: (d) => d.tor.tor,
    getRaw: (d) => `${d.tor.n_observed}/${d.tor.n_realized} realized intervention(s) observed`,
    getNote: (d) => d.tor.note,
    getVerdict: (d, v) => {
      if (v == null) return null;
      if (v >= 0.9) return { tone: "good", text: "The digital twin is catching real interventions almost every time, completely on its own -- it's doing its job." };
      if (v > 0) return { tone: "mixed", text: "The twin is missing some real interventions -- it's blind part of the time, not all of it." };
      return { tone: "bad", text: "The digital twin isn't noticing ANY of what's really happening in this scope -- a real detection gap right now." };
    },
  },
  {
    key: "latency", label: "L_obs", fullName: "Median Observation Latency",
    explain: "How long, on average, the digital twin took to notice after the real effect happened.",
    getValue: (d) => d.tor.median_latency_seconds,
    isSeconds: true,
    getRaw: (d) => `${(d.tor.observation_latencies_seconds || []).length} real latency sample(s)`,
    getNote: (d) => (d.tor.observation_latencies_seconds || []).length ? null : "no observed intervention has a usable latency sample yet",
    getVerdict: (d, v) => {
      if (v == null) return null;
      if (v <= 30) return { tone: "good", text: "Very fast -- the twin noticed almost immediately after the real effect happened." };
      if (v <= 300) return { tone: "mixed", text: "Reasonably fast -- the twin noticed within a few minutes, not instantly." };
      return { tone: "bad", text: "Slow -- the twin took more than 5 minutes to notice. Worth investigating why detection lagged." };
    },
  },
  {
    key: "ier", label: "IER", fullName: "Intervention Evidence Recall",
    explain: "Of the ones the twin noticed, how many also have real preserved evidence linked to them (Evidence Bridge).",
    getValue: (d) => d.ier.ier,
    getRaw: (d) => `${d.ier.n_with_evidence}/${d.ier.n_realized} observed intervention(s) have linked evidence`,
    getNote: (d) => d.ier.note,
    getVerdict: (d, v) => {
      if (v == null) return null;
      if (v >= 0.9) return { tone: "good", text: "Nearly everything the twin flagged is backed by real, checkable proof -- strong enough to stand up forensically." };
      if (v > 0) return { tone: "mixed", text: "Only some of the twin's alerts have real proof linked yet -- the rest would be hard to defend forensically today." };
      return { tone: "bad", text: "None of what the twin noticed has real evidence linked to it yet -- these alerts can't be proven right now." };
    },
  },
  {
    key: "esr", label: "ESR", fullName: "Evidence Support Ratio",
    explain: "Of ALL evidence links recorded on this platform, how many genuinely support what they're linked to (vs. contradicting it or being unclear).",
    getValue: (d) => d.esr.esr,
    getRaw: (d) => `${d.esr.n_supported}/${d.esr.n_links} link(s) are "supported"`,
    getNote: (d) => d.esr.note,
    getVerdict: (d, v) => {
      if (v == null) return null;
      if (v >= 0.9) return { tone: "good", text: "The evidence collected is reliable -- it genuinely backs up what it's linked to." };
      if (v > 0) return { tone: "mixed", text: "Some evidence contradicts or is unclear about what it's linked to -- worth reviewing before trusting every alert." };
      return { tone: "bad", text: "None of the recorded evidence actually supports what it's linked to -- these links need review." };
    },
  },
];

// Full name + what the metric WOULD measure (not just why it's missing) --
// so a metric with no real data yet is still fully understandable, not just
// an acronym with an apology next to it.
const UNAVAILABLE_META = {
  TMR: { fullName: "Transient Miss Rate", what: "Of short-lived faults (ones that might self-correct quickly), what fraction the twin missed because it wasn't checking often enough." },
  CAA: { fullName: "Causal Attribution Accuracy", what: "Whether the twin's explanation of WHY something happened points to the real cause, not just that something changed." },
  FRG: { fullName: "Forensic Reconstruction Gain", what: "How much better the forensic reconstruction score (CPR) gets once the Evidence Bridge is included, compared to without it." },
  WFRG: { fullName: "Weighted Forensic Reconstruction Gain", what: "The same idea as FRG, using the weighted score (WCPR) instead." },
  "Ambiguity Reduction": { fullName: "Ambiguity Reduction", what: "How many 'we're not sure' relationships in the causal graph get resolved once the Evidence Bridge is included." },
  "False Divergence Rate": { fullName: "False Divergence Rate", what: "Of all alerts the twin raised with NO real fault/attack happening, how many were false alarms." },
  "Cross-run stability": { fullName: "Cross-run stability", what: "Whether these same numbers stay consistent if the exact same intervention is repeated on a freshly redeployed scenario." },
  "Monitoring overhead": { fullName: "Monitoring overhead", what: "How much extra CPU/memory/network cost the digital twin's own checks add to the host." },
};

function renderMetricsGrid(data) {
  const grid = document.getElementById("metrics-grid");
  grid.innerHTML = METRIC_META.map((m) => {
    const value = m.getValue(data);
    const note = m.getNote(data);
    const hasValue = value !== null && value !== undefined;
    const displayValue = !hasValue ? "n/a" : (m.isSeconds ? `${value.toFixed(2)}s` : fmtPct(value));
    const verdict = m.getVerdict ? m.getVerdict(data, hasValue ? value : null) : null;
    return `
      <div class="dtm-metric-card">
        <div class="dtm-metric-value${hasValue ? "" : " unknown"}">${esc(displayValue)}</div>
        <div class="dtm-metric-name">${esc(m.label)}</div>
        <div class="dtm-metric-full-name">${esc(m.fullName)}</div>
        <div class="dtm-metric-explain">${esc(m.explain)}</div>
        ${verdict ? `<div class="dtm-metric-verdict ${esc(verdict.tone)}">${esc(verdict.text)}</div>` : ""}
        <div class="dtm-metric-raw">${note ? esc(note) : esc(m.getRaw(data))}</div>
      </div>`;
  }).join("");
}

function renderMonitoringOverhead(mo) {
  const el = document.getElementById("monitoring-overhead-box");
  if (!el) return;
  if (!mo || !mo.n_windows) {
    el.innerHTML = `<p class="fi-note">Monitoring overhead: no M3 experimental window has completed yet -- this measures the real time cost of the blind observation windows used to verify Attack Lab/fault interventions. It will show real numbers the next time one runs.</p>`;
    return;
  }
  const perSensor = Object.entries(mo.per_sensor_total_seconds || {}).map(([k, v]) => `${esc(k)}: ${v.toFixed(2)}s total`).join(", ");
  el.innerHTML = `
    <p class="fi-note"><b>Monitoring overhead</b> -- how much real time the twin's blind observation windows (M3) have actually cost, across ${mo.n_windows} real window(s) run so far: ${mo.total_ticks} sensor check(s), averaging ${mo.mean_seconds_per_tick != null ? mo.mean_seconds_per_tick.toFixed(3) : "n/a"}s per check (${perSensor || "no per-sensor breakdown yet"}).</p>`;
}

function renderUnavailable(unavailableMetrics) {
  const el = document.getElementById("unavailable-list");
  const entries = Object.entries(unavailableMetrics || {});
  if (!entries.length) { el.innerHTML = `<p class="fi-note">Everything the study defines is already computed from real data.</p>`; return; }
  el.innerHTML = entries.map(([name, note]) => {
    const meta = UNAVAILABLE_META[name] || {};
    return `
    <div class="dtm-unavailable-row" style="flex-direction:column;align-items:stretch">
      <b>${esc(name)}${meta.fullName ? ` <span style="font-weight:400">(${esc(meta.fullName)})</span>` : ""}</b>
      ${meta.what ? `<span style="color:var(--text)">What it would measure: ${esc(meta.what)}</span>` : ""}
      <span>Why it's not computed yet: ${esc(note)}</span>
    </div>`;
  }).join("");
}

// Fills the Campaign/Case dropdowns with the platform's own REAL, complete
// lists (the same ones the Fault Injection dashboard already uses) -- not
// just whatever happens to already be tagged in the Ledger, which today is
// a much smaller, incomplete list (see the campaign_id gap documented in
// investigaciones_y_implementacion/00_estado_implementacion.md). This way
// the user can pick ANY real campaign/case, even one the Ledger hasn't
// recorded anything against yet -- the metrics below will honestly show
// "0 entries" for those, which is itself real information.
async function loadScopeOptions() {
  try {
    const res = await fetch("/api/foc/experimentation/campaigns", { cache: "no-store" });
    const data = await res.json();
    const campaigns = (data.campaigns || []).slice().reverse();
    fillDropdown(
      "scope-campaign",
      campaigns.map((c) => ({ value: c.campaign_id, text: `${c.campaign_id} - ${c.name || c.attack_id || ""}` })),
      "All campaigns",
    );
  } catch (e) { /* transient -- dropdown just stays at "All campaigns" */ }

  try {
    const res = await fetch("/api/foc/experimentation/source-cases", { cache: "no-store" });
    const data = await res.json();
    const cases = data.cases || [];
    fillDropdown(
      "scope-case",
      cases.map((c) => ({ value: c.case_id, text: `${c.case_id}${c.source_case_name ? " - " + c.source_case_name : ""}` })),
      "All cases",
    );
  } catch (e) { /* transient -- dropdown just stays at "All cases" */ }
}

// Same fix, same reason, for the Level C campaign-run picker below: filled
// in automatically from the platform's own real job list
// (/api/level-c/jobs), newest first -- never a blank box asking the user
// to already know/type a job_id.
async function loadLevelCJobOptions() {
  const el = document.getElementById("cpr-job-id");
  const current = el.value;
  try {
    const res = await fetch("/api/level-c/jobs", { cache: "no-store" });
    const data = await res.json();
    const jobs = (data.jobs || []).slice().sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    if (!jobs.length) { el.innerHTML = `<option value="">No Level C campaigns run yet</option>`; return; }
    el.innerHTML = jobs.map((j) => {
      const when = (j.created_at || "").replace("T", " ").slice(0, 16);
      const status = j.error ? "failed" : (j.completed_at ? "completed" : "running");
      return `<option value="${esc(j.job_id)}">${esc(j.job_id)} -- ${esc(when)} UTC (${esc(status)}, ${esc(j.current_repetition ?? 0)}/${esc(j.level_c_repetitions ?? "?")} rep)</option>`;
    }).join("");
    if (jobs.some((j) => j.job_id === current)) el.value = current;
  } catch (e) {
    el.innerHTML = `<option value="">Error loading real campaigns</option>`;
  }
}

function fillDropdown(elId, options, allLabel) {
  const el = document.getElementById(elId);
  const current = el.value;
  el.innerHTML = `<option value="">${esc(allLabel)}</option>` + options.map((o) => `<option value="${esc(o.value)}">${esc(o.text)}</option>`).join("");
  if (options.some((o) => o.value === current)) el.value = current;
}

// A specific campaign/case picked above can honestly have ZERO ledger
// entries -- not a bug, just real data: today most real interventions still
// aren't tagged with a campaign_id/case_id yet (a known gap, see
// investigaciones_y_implementacion/00_estado_implementacion.md). Without
// this banner, every metric card just silently goes blank, indistinguishable
// from the page being broken.
function renderScopeEmptyBanner(scope, nLedgerEntries) {
  const banner = document.getElementById("scope-empty-banner");
  const scoped = !!(scope.source || scope.campaign_id || scope.case_id);
  if (scoped && nLedgerEntries === 0) {
    banner.style.display = "block";
    banner.innerHTML = `<b>No interventions found for this specific filter.</b> This does NOT mean the twin isn't working -- it means no fault/attack recorded in the Ledger is tagged with this exact campaign/case/source yet (most real interventions today aren't tagged to a campaign yet). Clear the filters above (pick "Both" / "All campaigns" / "All cases") to see everything that's really been recorded.`;
  } else {
    banner.style.display = "none";
  }
}

function currentScope() {
  return {
    source: document.getElementById("scope-source").value.trim() || null,
    campaign_id: document.getElementById("scope-campaign").value.trim() || null,
    case_id: document.getElementById("scope-case").value.trim() || null,
  };
}

async function loadMetrics() {
  const status = document.getElementById("refresh-status");
  status.textContent = "Loading real data...";
  try {
    const scope = currentScope();
    const params = new URLSearchParams();
    if (scope.source) params.set("source", scope.source);
    if (scope.campaign_id) params.set("campaign_id", scope.campaign_id);
    if (scope.case_id) params.set("case_id", scope.case_id);
    const res = await fetch(`/api/forge-dt-metrics/report?${params.toString()}`, { cache: "no-store" });
    const data = await res.json();
    if (!data.ok) { status.textContent = `Error: ${data.error || "unknown"}`; return; }
    renderMetricsGrid(data);
    renderMonitoringOverhead(data.monitoring_overhead);
    renderUnavailable(data.unavailable_metrics);
    renderScopeEmptyBanner(scope, data.n_ledger_entries);
    document.getElementById("stat-ledger-count").textContent = data.n_ledger_entries ?? 0;
    status.textContent = `Last refreshed ${new Date().toLocaleTimeString()} -- ${data.n_ledger_entries} ledger entr${data.n_ledger_entries === 1 ? "y" : "ies"} in scope`;
  } catch (e) {
    status.textContent = `Network error: ${e.message}`;
  }
}

async function loadLedgerIntegrity() {
  try {
    const res = await fetch("/api/intervention-ledger/verify", { cache: "no-store" });
    const data = await res.json();
    const el = document.getElementById("stat-chain-ok");
    const cp = data.checkpoints || {};
    // Hash-chaining alone (data.ok) cannot detect someone deleting the
    // whole ledger file or truncating-then-forging a replacement chain --
    // verified live in isolation, 2026-10-10 (see
    // intervention_ledger/README.md). The external checkpoint file
    // (write_checkpoint/verify_chain_against_checkpoints) catches exactly
    // that, so "OK" here means BOTH checks passed, not just the weaker one.
    const chainOk = data.ok;
    const checkpointsOk = cp.ok !== false; // no checkpoints yet (cp.ok===true, checkpoints_checked:0) is honestly still "ok so far"
    const allOk = chainOk && checkpointsOk;
    el.textContent = allOk ? "OK" : "BROKEN";
    el.style.color = allOk ? "var(--green)" : "var(--red)";
    el.title = cp.checkpoints_checked != null
      ? `Hash chain: ${chainOk ? "ok" : "broken"} -- ${cp.checkpoints_checked} external checkpoint(s) cross-checked, ${checkpointsOk ? "all match" : `${(cp.mismatches || []).length} mismatch(es) -- possible truncate-and-forge`}`
      : "";
  } catch (e) { /* transient */ }
}

async function loadEvidenceCount() {
  try {
    const res = await fetch("/api/evidence-bridge/links", { cache: "no-store" });
    const data = await res.json();
    document.getElementById("stat-evidence-count").textContent = (data.links || []).length;
  } catch (e) { /* transient */ }
}

async function loadLedgerTable() {
  const tbody = document.getElementById("ledger-rows");
  try {
    const scope = currentScope();
    const params = new URLSearchParams({ limit: "30" });
    if (scope.source) params.set("source", scope.source);
    if (scope.campaign_id) params.set("campaign_id", scope.campaign_id);
    if (scope.case_id) params.set("case_id", scope.case_id);
    const res = await fetch(`/api/intervention-ledger/entries?${params.toString()}`, { cache: "no-store" });
    const data = await res.json();
    const entries = (data.entries || []).slice().reverse();
    if (!entries.length) { tbody.innerHTML = `<tr><td colspan="6" class="fi-note">No interventions recorded yet in this scope.</td></tr>`; return; }
    tbody.innerHTML = entries.map((e) => {
      const eff = (e.effect_verification || {}).effective;
      const effLabel = eff === true ? `<span class="pill yes">Yes</span>` : eff === false ? `<span class="pill no">No</span>` : `<span class="pill na">Not measured</span>`;
      const target = e.target_node_name || e.target_node_id || e.target_ip || "--";
      return `<tr>
        <td>${esc((e.recorded_at_utc || "").replace("T", " ").slice(0, 19))}</td>
        <td>${esc(e.type)}</td>
        <td>${esc(e.class)}</td>
        <td><span class="pill ${e.phase === "reverted" ? "reverted" : "active"}">${esc(e.phase)}</span></td>
        <td>${esc(target)}</td>
        <td>${effLabel}</td>
      </tr>`;
    }).join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="fi-note">Network error: ${esc(e.message)}</td></tr>`;
  }
}

// Plain-language reading of the reproducibility numbers -- same "don't just
// show the number" rule as METRIC_META's getVerdict above, applied to the
// CPR/WCPR comparison grid too.
function interpretReproducibility(repIndex, maxDelta, acceptable) {
  if (repIndex == null && maxDelta == null) return null;
  if (acceptable) {
    return { tone: "good", text: "Every repetition of this campaign reached essentially the same forensic conclusion -- the result is reproducible, not a fluke of one run." };
  }
  return { tone: "bad", text: "At least two repetitions of this campaign reached meaningfully different forensic conclusions -- something about the environment or the attack isn't behaving the same way every time." };
}

async function loadCprReport() {
  const jobId = document.getElementById("cpr-job-id").value.trim();
  const el = document.getElementById("cpr-result");
  if (!jobId) { el.innerHTML = `<p class="fi-note">Enter a real Level C job_id first.</p>`; return; }
  el.innerHTML = `<p class="fi-note">Loading...</p>`;
  try {
    const res = await fetch(`/api/forge-dt-metrics/cpr/${encodeURIComponent(jobId)}`, { cache: "no-store" });
    const data = await res.json();
    if (!data.ok) { el.innerHTML = `<p class="fi-note">Error: ${esc(data.error || "not found")}</p>`; return; }
    const comparisons = data.c0_comparisons || [];
    const repVerdict = interpretReproducibility(data.c0_reproducibility_index, data.c0_max_delta_wcpr, data.c0_all_delta_wcpr_acceptable);
    const hasC3 = data.c3_cpr != null;
    let c3Html = "";
    if (hasC3) {
      const perCase = (data.c3_detail && data.c3_detail.per_case) || [];
      c3Html = `
        <div class="dtm-cpr-grid" style="margin-top:14px">
          <div class="dtm-cpr-cell"><b>${esc(data.c3_cpr)}</b><label>C3 CPR (mean, real cases)</label></div>
          <div class="dtm-cpr-cell"><b>${perCase.filter((c) => c.independently_confirmed).length} / ${perCase.length}</b><label>Cases independently confirmed by the twin</label></div>
        </div>
        <div class="dtm-metric-verdict good" style="margin-top:10px">C3 adds independent confirmation from the digital twin (Intervention Ledger + post-hoc Linker + Evidence Bridge) on top of the traditional forensic chain -- when a real intervention's effect was verified AND the twin observed it on its own, that counts as real proof even for cases where the forensic attestation chain alone fell short.</div>
        ${perCase.map((c) => `<div class="fi-note">Case ${esc(c.case_id)}: C0 CPR ${c.c0_cpr} → C3 CPR ${c.c3_cpr}${c.independently_confirmed ? ` (upgraded by real intervention ${esc(c.confirming_intervention_id)})` : " (no independent confirmation found for this case)"}</div>`).join("")}
      `;
    } else {
      c3Html = `<p class="fi-note" style="margin-top:10px;color:var(--yellow)">${esc(data.c3_note || "")}</p>`;
    }
    el.innerHTML = `
      <p class="fi-note" style="margin-top:10px">${esc(data.c0_verdict || "")}</p>
      <div class="dtm-cpr-grid">
        <div class="dtm-cpr-cell"><b>${esc(data.c0_reproducibility_index ?? "n/a")}</b><label>Reproducibility index</label></div>
        <div class="dtm-cpr-cell"><b>${esc(data.c0_max_delta_wcpr ?? "n/a")}</b><label>Max ΔWCPR</label></div>
        <div class="dtm-cpr-cell"><b>${data.c0_all_delta_wcpr_acceptable ? "Yes" : "No"}</b><label>Acceptable?</label></div>
      </div>
      ${repVerdict ? `<div class="dtm-metric-verdict ${esc(repVerdict.tone)}" style="margin-top:10px">${esc(repVerdict.text)}</div>` : ""}
      <p class="fi-note" style="margin-top:10px">${comparisons.length} real pairwise repetition comparison(s):</p>
      ${comparisons.map((c) => `<div class="fi-note">Rep ${c.rep_a} vs Rep ${c.rep_b}: CPR ${c.cpr_a} → ${c.cpr_b} (Δ${c.delta_cpr}), WCPR ${c.wcpr_a} → ${c.wcpr_b} (Δ${c.delta_wcpr})</div>`).join("")}
      ${c3Html}
    `;
  } catch (e) {
    el.innerHTML = `<p class="fi-note">Network error: ${esc(e.message)}</p>`;
  }
}

async function loadAblationReport() {
  const jobId = document.getElementById("cpr-job-id").value.trim();
  const el = document.getElementById("ablation-result");
  if (!jobId) { el.innerHTML = `<p class="fi-note">Enter a real Level C job_id above first.</p>`; return; }
  el.innerHTML = `<p class="fi-note">Loading...</p>`;
  try {
    const res = await fetch(`/api/forge-dt-metrics/ablation/${encodeURIComponent(jobId)}`, { cache: "no-store" });
    const data = await res.json();
    if (!data.ok) { el.innerHTML = `<p class="fi-note">Error: ${esc(data.error || "not found")}</p>`; return; }
    el.innerHTML = `
      <div class="dtm-ablation-layer"><b>${esc(data.c0.label)}</b><p>${esc(data.c0.plain_explanation || "")}</p><p>Reproducibility index: ${esc(data.c0.c0_reproducibility_index ?? "n/a")}, max ΔWCPR: ${esc(data.c0.c0_max_delta_wcpr ?? "n/a")}</p></div>
      <div class="dtm-ablation-layer"><b>${esc(data.c1.label)}</b><p>${esc(data.c1.plain_explanation || "")}</p><p>${data.c1.n_divergence_events} real divergence event(s) seen, types: ${esc((data.c1.event_types || []).join(", ") || "none")}</p></div>
      <div class="dtm-ablation-layer"><b>${esc(data.c2.label)}</b><p>${esc(data.c2.plain_explanation || "")}</p><p>IRR=${esc(fmtPct(data.c2.irr.irr) ?? "n/a")}, TOR=${esc(fmtPct(data.c2.tor.tor) ?? "n/a")}</p></div>
      <div class="dtm-ablation-layer"><b>${esc(data.c3.label)}</b><p>${esc(data.c3.plain_explanation || "")}</p><p>IER=${esc(fmtPct(data.c3.ier.ier) ?? "n/a")}, ESR=${esc(fmtPct(data.c3.esr.esr) ?? "n/a")}</p></div>
    `;
  } catch (e) {
    el.innerHTML = `<p class="fi-note">Network error: ${esc(e.message)}</p>`;
  }
}

function refreshAll() {
  loadScopeOptions();
  loadMetrics();
  loadLedgerIntegrity();
  loadEvidenceCount();
  loadLedgerTable();
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-refresh").addEventListener("click", refreshAll);
  document.getElementById("btn-load-cpr").addEventListener("click", loadCprReport);
  document.getElementById("btn-load-ablation").addEventListener("click", loadAblationReport);
  loadLevelCJobOptions();
  refreshAll();
  setInterval(refreshAll, 20000);
});
