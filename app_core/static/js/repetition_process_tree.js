/* Repetition process-tree library — 2026-07-23.
   Pure, self-contained tree-building/rendering helpers reused by the
   EXISTING repBell -> #repDetailOverlay flow already in index.html (no
   separate page, no new icon — this file only supplies functions that
   repDetailOpen()/repDetailRenderHtml() call into). Reuses the same
   /api/campaign-repetitions/* endpoints that overlay already fetches from.
   Every exported name is prefixed repTree* to avoid colliding with
   index.html's own (very large) inline script. */

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

function repTreeEsc(v) {
  return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function repTreeUnk(v, fallback = "unknown") {
  return (v === null || v === undefined || v === "") ? fallback : v;
}

function repTreeFmtAbs(iso) {
  if (!iso) return "unknown";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "unknown";
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  } catch (e) {
    return "unknown";
  }
}

function repTreeFmtElapsed(seconds) {
  if (seconds === null || seconds === undefined || isNaN(seconds)) return null;
  seconds = Math.max(0, Math.round(seconds));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function repTreeStatusColor(status) {
  const s = String(status || "").toLowerCase();
  if (["completed", "recovered", "installed", "ok", "completed_with_degradation"].includes(s)) return "#22c55e";
  if (["running", "waiting", "started"].includes(s)) return "#38bdf8";
  if (["partial", "ambiguous", "wait", "warning"].includes(s)) return "#eab308";
  if (["failed", "stopped", "cancelled", "completed_with_failures", "failed_or_skipped", "error"].includes(s)) return "#ef4444";
  if (["pending", "unknown"].includes(s)) return "#64748b";
  return "#64748b";
}

async function repTreeGetJson(url) {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Generic tree node shape: { label, status, started_at, finished_at,
// elapsed_seconds, target, detail, error_detail, children: [] }
// ---------------------------------------------------------------------------

function repTreeNode(label, status, opts = {}) {
  return {
    label,
    status: status || "unknown",
    started_at: opts.started_at ?? null,
    finished_at: opts.finished_at ?? null,
    elapsed_seconds: opts.elapsed_seconds ?? null,
    target: opts.target ?? null,
    detail: opts.detail ?? null,
    error_detail: opts.error_detail ?? null,
    children: opts.children ?? [],
  };
}

function repTreeStageToNode(stage, extraChildren = []) {
  // 2026-07-26: a stage can show "completed" while real WARN-level problems
  // happened inside it (e.g. Level C's "Deploying OT infrastructure" -- a
  // PLC/FUXA deploy failure is a warning, not a hard stage failure, so the
  // orchestrator proceeds anyway; it's very often the actual root cause a
  // repetition failed downstream, and used to be completely invisible here).
  // User explicitly asked for this after exactly that happened. Each real
  // warning becomes its own small leaf node under the stage, same as any
  // other sub-event -- nothing invented, only what the backend already
  // scoped to this stage's own time window (see campaign_repetitions
  // service.py::get_level_c_repetition_detail()).
  const warningNodes = (stage.warnings || []).map((w) => repTreeNode(w, "warning", {}));
  return repTreeNode(stage.label || stage.stage_key || "stage", stage.status, {
    started_at: stage.started_at,
    finished_at: stage.finished_at,
    elapsed_seconds: stage.elapsed_seconds,
    detail: stage.detail,
    error_detail: stage.error_detail,
    children: [...warningNodes, ...extraChildren],
  });
}

// ---------------------------------------------------------------------------
// Level A tree
// ---------------------------------------------------------------------------

function repTreeBuildLevelATree(detail) {
  const root = repTreeNode(
    `Level A — ${repTreeUnk(detail.execution_label)}`,
    detail.repetition_status,
    {
      started_at: detail.started_at,
      finished_at: detail.finished_at,
      elapsed_seconds: detail.total_elapsed_seconds,
      children: [],
    }
  );

  for (const stage of detail.stages || []) {
    root.children.push(repTreeStageToNode(stage));
  }

  // 2026-10-09: was reading `per_dry_run_reconstruction`, which the backend
  // itself only ever populates for ALREADY-COMPLETED dry-runs (see
  // campaign_repetitions/service.py::_la_dry_run_history's own docstring) --
  // so this node showed nothing at all for the one dry-run actually in
  // progress, the exact thing a reader watching a live campaign most wants
  // to see. `dry_run_history` is the full chronological list (completed AND
  // in-progress) the dedicated Level A report page already renders
  // correctly; switched to the same source here so the SAME embedded tree
  // the Level C report uses shows it too, not a second, poorer copy.
  const dr = detail.dry_run_repetitions || {};
  const history = detail.dry_run_history || [];
  const dryRunNode = repTreeNode(
    `Dry-run repetitions (${repTreeUnk(dr.completed, "0")}/${repTreeUnk(dr.requested, "?")} completed)`,
    dr.completed >= dr.requested && dr.requested ? "completed" : "running",
    { children: [] }
  );
  for (const run of history) {
    const cprText = run.cpr != null ? `CPR ${(run.cpr * 100).toFixed(1)}%` : null;
    const wcprText = run.weighted_cpr != null ? `Weighted CPR ${(run.weighted_cpr * 100).toFixed(1)}%` : null;
    const label = `Dry-run ${repTreeUnk(run.dry_run_index)}` + (cprText ? ` — ${cprText}` : "");
    const detailParts = [wcprText, run.status === "running" ? run.current_phase_detail || run.current_phase_label : null].filter(Boolean);
    dryRunNode.children.push(repTreeNode(
      label,
      run.status,
      {
        started_at: run.started_at,
        finished_at: run.finished_at,
        elapsed_seconds: run.elapsed_seconds,
        detail: detailParts.length ? detailParts.join(" — ") : null,
      }
    ));
  }
  if (dryRunNode.children.length) root.children.push(dryRunNode);

  if (detail.conclusions) {
    const c = detail.conclusions;
    root.children.push(repTreeNode("Conclusions", "completed", {
      detail: `CPR mean ${repTreeUnk(c.cpr_mean)}, WCPR mean ${repTreeUnk(c.weighted_cpr_mean)}, Δ CPR ${repTreeUnk(c.delta_cpr)}, Δ WCPR ${repTreeUnk(c.delta_weighted_cpr)}`,
    }));
  }

  if (detail.parent_level_b && detail.parent_level_b.job_id) {
    root.children.push(repTreeNode(
      `↑ Parent Level B repetition ${repTreeUnk(detail.parent_level_b.repetition_number)} (${repTreeUnk(detail.parent_level_b.campaign_id)})`,
      "completed",
      { detail: "This Level A run was launched from that Level B repetition." }
    ));
  }

  return root;
}

// ---------------------------------------------------------------------------
// Level B tree
// ---------------------------------------------------------------------------

async function repTreeBuildLevelBTree(detail) {
  const root = repTreeNode(
    `Level B repetition ${repTreeUnk(detail.repetition_number)} — ${repTreeUnk(detail.execution_label)}`,
    detail.repetition_status,
    {
      started_at: detail.stages?.[0]?.started_at,
      elapsed_seconds: detail.total_elapsed_seconds,
      children: [],
    }
  );

  const attack = detail.attack;
  const detection = detail.detection;
  const acquisition = detail.acquisition;
  const caseInfo = detail.case;

  for (const stage of detail.stages || []) {
    let extra = [];
    if (stage.stage_key === "lb.rep.attack" && attack) {
      extra.push(repTreeNode(
        `Attack: ${repTreeUnk(attack.attack_name)} (${repTreeUnk(attack.attack_profile_id)})`,
        attack.completed_at ? "completed" : "unknown",
        {
          started_at: attack.started_at, finished_at: attack.completed_at,
          target: repTreeUnk(attack.target_node),
          detail: `protocol=${repTreeUnk(attack.protocol)} fc=${repTreeUnk(attack.function_code)} register=${repTreeUnk(attack.register)} value=${repTreeUnk(attack.value)}`,
        }
      ));
    }
    if (stage.stage_key === "lb.rep.alert" && detection) {
      extra.push(repTreeNode(
        `Detection outcome: ${repTreeUnk(detection.outcome)}`,
        detection.trigger_alert_detected ? "completed" : "failed",
        {
          started_at: detection.trigger_alert_timestamp,
          target: detection.trigger_alert_rule ? `rule ${detection.trigger_alert_rule}` : null,
          detail: `severity=${repTreeUnk(detection.trigger_alert_severity)} attempts=${repTreeUnk(detection.trigger_attempts_total)}`,
        }
      ));
      for (const attempt of detection.trigger_attempt_trace || []) {
        extra.push(repTreeNode(
          `Trigger attempt ${repTreeUnk(attempt.attempt_number, "?")}`,
          attempt.trigger_alert_detected ? "completed" : "failed",
          {
            started_at: attempt.attack_started_at,
            finished_at: attempt.attack_completed_at,
            detail: attempt.eligibility_reason || null,
          }
        ));
      }
    }
    if (stage.stage_key === "lb.rep.trigger" && caseInfo && caseInfo.case_id) {
      extra.push(repTreeNode(
        `Case: ${repTreeUnk(caseInfo.case_real_name)}`,
        "completed",
        {
          started_at: caseInfo.case_created_utc,
          // Real folder name AND the short internal alias (sha1-based, see
          // level_b_orchestrator.py::_case_id_for_case_dir) shown together --
          // 2026-07-24: user was confused seeing only the alias and asked for
          // both, since the system genuinely uses both for different things.
          detail: [
            `internal alias: ${repTreeUnk(caseInfo.case_id)}`,
            caseInfo.case_path ? `path: ${caseInfo.case_path}` : null,
          ].filter(Boolean).join(" — "),
        }
      ));
    }
    if (stage.stage_key === "lb.rep.acquisition" && acquisition) {
      if (detail.stage_timeline && detail.stage_timeline.length) {
        for (const st of detail.stage_timeline) {
          const sizeDetail = st.size_bytes ? `${(st.size_bytes / (1024 ** 3)).toFixed(2)} GiB preserved` : null;
          // "usual" = real historical median for this exact stage
          // (stage_timing_service._historical_median_seconds(), computed from
          // OTHER still-on-disk cases -- never invented, "no history yet" if
          // there simply isn't enough data). "delayed" flags when a still-
          // running stage has already clearly exceeded that median.
          // 2026-07-24: user explicitly asked for this baseline to appear in
          // the tree, not just size/progress.
          const usualDetail = st.expected_seconds != null ? `~${repTreeFmtElapsed(st.expected_seconds)} usual` : "no history yet";
          extra.push(repTreeNode(
            repTreeUnk(st.label),
            st.status,
            {
              started_at: st.started_at, finished_at: st.finished_at, elapsed_seconds: st.elapsed_seconds,
              target: st.target ? `${st.target}${st.target_ip ? " (" + st.target_ip + ")" : ""}` : null,
              detail: [usualDetail, sizeDetail, st.progress_detail].filter(Boolean).join(" — ") || null,
              error_detail: st.delayed ? "Running notably longer than usual for this stage." : (st.error_detail || null),
            }
          ));
        }
      } else {
        extra.push(repTreeNode("Memory acquisition", acquisition.memory_status, {
          detail: acquisition.memory_size_bytes ? `${(acquisition.memory_size_bytes / (1024 ** 3)).toFixed(2)} GiB` : null,
        }));
        extra.push(repTreeNode("Disk acquisition", acquisition.disk_status, {
          detail: acquisition.disk_size_bytes ? `${(acquisition.disk_size_bytes / (1024 ** 3)).toFixed(2)} GiB` : null,
        }));
        extra.push(repTreeNode("Network/OT acquisition", acquisition.network_status, {
          detail: acquisition.network_size_gib ? `${acquisition.network_size_gib} GiB, ${repTreeUnk(acquisition.pcap_segments_imported)} segments` : null,
        }));
      }
    }
    if (stage.stage_key === "lb.rep.analysis" && detail.analysis_layers) {
      for (const layer of detail.analysis_layers) {
        extra.push(repTreeNode(`Analysis layer: ${repTreeUnk(layer.layer)}`, layer.status, { detail: layer.detail || null, error_detail: layer.error || null }));
      }
    }
    root.children.push(repTreeStageToNode(stage, extra));
  }

  if (detail.nested_level_a && detail.nested_level_a.job_id) {
    const laDetail = await repTreeGetJson(`/api/campaign-repetitions/level-a/${encodeURIComponent(detail.nested_level_a.job_id)}`);
    if (laDetail) {
      root.children.push(repTreeBuildLevelATree(laDetail));
    } else {
      root.children.push(repTreeNode(
        `Level A (nested) — ${repTreeUnk(detail.nested_level_a.execution_label)}`,
        detail.nested_level_a.status || "unknown",
        { started_at: detail.nested_level_a.started_at, finished_at: detail.nested_level_a.finished_at, detail: "Detail could not be resolved for this job." }
      ));
    }
  }

  return root;
}

// ---------------------------------------------------------------------------
// Level C tree
// ---------------------------------------------------------------------------

async function repTreeBuildLevelCTree(detail) {
  const root = repTreeNode(
    `Level C repetition ${repTreeUnk(detail.repetition_number)}/${repTreeUnk(detail.total_repetitions)} — ${repTreeUnk(detail.execution_label)}`,
    detail.repetition_status,
    {
      started_at: detail.stages?.[0]?.started_at,
      elapsed_seconds: detail.total_elapsed_seconds,
      children: [],
    }
  );

  const toolsByInstance = {};
  for (const t of detail.tool_installs || []) {
    toolsByInstance[t.instance] = toolsByInstance[t.instance] || [];
    toolsByInstance[t.instance].push(t);
  }

  for (const stage of detail.stages || []) {
    let extra = [];
    if (stage.stage_key === "lc.installing_tools" && detail.tool_installs?.length) {
      for (const [instance, tools] of Object.entries(toolsByInstance)) {
        const instNode = repTreeNode(instance, "completed", { children: [] });
        for (const t of tools) {
          instNode.children.push(repTreeNode(t.tool, t.status === "installed" ? "installed" : "failed_or_skipped", { started_at: t.ts, detail: t.reason || null }));
        }
        extra.push(instNode);
      }
    }
    if (stage.stage_key === "lc.verifying_monitoring" && detail.monitoring_verification?.length) {
      const seen = new Map();
      for (const m of detail.monitoring_verification) seen.set(m.detail, m);
      for (const m of seen.values()) {
        extra.push(repTreeNode(m.detail.trim(), m.level === "WARN" ? "waiting" : "completed", { started_at: m.ts }));
      }
    }
    if (stage.stage_key === "lc.waiting_level_b" && detail.level_b_job_id) {
      // 2026-10-09: was only ever fetching the single "live" repetition
      // number, so a Level C repetition configured with level_b_repetitions
      // > 1 silently hid every earlier Level B repetition's own tree (attack/
      // detection/case/nested Level A) the moment the job moved on to the
      // next one. User explicitly asked for "todas las repeticiones de nivel
      // B" here -- loop over every repetition this Level B job was actually
      // asked to run, not just whichever one happens to be live right now.
      const liveRepNum = detail.level_b_live?.repetition_number || 1;
      const totalLbReps = detail.level_b_requested_repetitions || liveRepNum;
      for (let repNum = 1; repNum <= totalLbReps; repNum++) {
        const lbDetail = await repTreeGetJson(`/api/campaign-repetitions/level-b/${encodeURIComponent(detail.level_b_job_id)}/${repNum}`);
        if (lbDetail) {
          extra.push(await repTreeBuildLevelBTree(lbDetail));
        } else {
          extra.push(repTreeNode(`Level B repetition ${repNum} (job ${detail.level_b_job_id})`, "unknown", { detail: "Detail could not be resolved for this repetition yet." }));
        }
      }
    }
    root.children.push(repTreeStageToNode(stage, extra));
  }

  if (detail.snapshot_infrastructure) {
    const infra = detail.snapshot_infrastructure;
    const infraNode = repTreeNode(`Snapshot infrastructure (captured ${repTreeFmtAbs(infra.captured_at)})`, "completed", { children: [] });
    for (const inst of infra.instances || []) {
      const ip = inst.ip_floating || inst.ip_private;
      const instNode = repTreeNode(
        `${repTreeUnk(inst.name)} (${repTreeUnk(ip)})`,
        inst.status || "unknown",
        { started_at: inst.created_at, detail: `flavor=${repTreeUnk(inst.flavor_id)}`, children: [] }
      );
      for (const t of inst.tools || []) {
        instNode.children.push(repTreeNode(repTreeUnk(t.tool_name), t.status, { started_at: t.installed_at }));
      }
      infraNode.children.push(instNode);
    }
    if (infraNode.children.length) root.children.push(infraNode);
  }

  if (detail.floating_ip_cleanups?.length) {
    const fipNode = repTreeNode("Floating IP cleanups during this repetition", "completed", { children: [] });
    for (const c of detail.floating_ip_cleanups) {
      fipNode.children.push(repTreeNode(
        `Released ${repTreeUnk(c.released_count)} IP(s) (${repTreeUnk(c.triggered_by)})`,
        c.status,
        { started_at: c.started_at, finished_at: c.finished_at, detail: `quota available: ${repTreeUnk(c.before_available_pct)}% → ${repTreeUnk(c.after_available_pct)}%` }
      ));
    }
    root.children.push(fipNode);
  }

  if (detail.time_sync_checks?.length) {
    const tsNode = repTreeNode("Time sync checks during this repetition", "completed", { children: [] });
    for (const c of detail.time_sync_checks) {
      tsNode.children.push(repTreeNode(
        repTreeUnk(c.node_name || c.instance_id),
        repTreeUnk(c.temporal_sync_status, "unknown"),
        { finished_at: c.finished_at, detail: `max clock offset: ${repTreeUnk(c.max_clock_offset_ms)} ms, correction applied: ${repTreeUnk(c.correction_applied)}` }
      ));
    }
    root.children.push(tsNode);
  }

  return root;
}

// ---------------------------------------------------------------------------
// Whole-campaign tree (every Level C repetition reached so far, each with its
// own full nested Level B / Level A sub-tree) -- 2026-07-24: user explicitly
// asked for full transparency across ALL repetitions of a campaign, not just
// the one repetition they happened to click on the repBell list. Purely
// additive: reuses repTreeBuildLevelCTree() per repetition number, nothing
// about the single-repetition view changes.
// ---------------------------------------------------------------------------

async function repTreeBuildLevelCCampaignTree(jobId, firstRepDetail) {
  const total = firstRepDetail.total_repetitions || 1;
  const root = repTreeNode(
    `Level C campaign — ${repTreeUnk(jobId)} (${repTreeUnk(firstRepDetail.execution_label)})`,
    "running",
    { children: [] }
  );
  for (let rep = 1; rep <= total; rep++) {
    // BUG FIXED 2026-07-24: this used to be `rep === 1 ? firstRepDetail : ...`,
    // silently assuming the repetition the user happened to have open was
    // repetition #1. If they opened the campaign view from, say, repetition
    // 7, repetition 1 was never fetched at all and repetition 7's own detail
    // got inserted in its place (wrong content AND wrong position) -- caught
    // live by the user, who noticed repetition 7 appearing first and
    // repetition 1 missing entirely. Now only reuses the already-fetched
    // detail when it actually matches this loop iteration's repetition
    // number; every other repetition is always freshly fetched.
    const detail = firstRepDetail.repetition_number === rep
      ? firstRepDetail
      : await repTreeGetJson(`/api/campaign-repetitions/level-c/${encodeURIComponent(jobId)}/${rep}`);
    if (!detail) {
      root.children.push(repTreeNode(`Repetition ${rep}/${total}`, "unknown", { detail: "Detail could not be resolved for this repetition." }));
      continue;
    }
    root.children.push(await repTreeBuildLevelCTree(detail));
  }
  // Real, not synthetic: "completed" only once every repetition actually
  // reached a terminal status; "running" while any of them are still pending
  // or in progress -- same pending/never-omitted rule as everywhere else in
  // this module.
  root.status = root.children.every((c) => !["pending", "running"].includes(c.status)) ? "completed" : "running";
  return root;
}

// ---------------------------------------------------------------------------
// Whole-campaign SUMMARY TABLE (one row per repetition, every level's key
// facts side by side) -- 2026-07-24: user asked for a second, scannable view
// next to the full-campaign tree: same underlying data, but laid out so every
// repetition's case/errors/status can be compared at a glance instead of
// having to expand a deep nested tree for each one. Purely additive, reuses
// the exact same endpoints/fields as the tree builders above -- nothing here
// is computed differently, just rendered differently.
// ---------------------------------------------------------------------------

function repTreeSummaryPill(status) {
  const c = repTreeStatusColor(status);
  return `<span style="font-size:10px;font-weight:900;text-transform:uppercase;color:${c};border:1px solid ${c}55;background:${c}15;border-radius:999px;padding:1px 7px;white-space:nowrap;">${repTreeEsc(status || "unknown")}</span>`;
}

async function repTreeBuildCampaignSummaryHtml(jobId, firstRepDetail) {
  const total = firstRepDetail.total_repetitions || 1;
  const rows = [];
  for (let rep = 1; rep <= total; rep++) {
    // Same fix as repTreeBuildLevelCCampaignTree() -- only reuse the
    // already-fetched detail when it actually matches this repetition number.
    const lc = firstRepDetail.repetition_number === rep
      ? firstRepDetail
      : await repTreeGetJson(`/api/campaign-repetitions/level-c/${encodeURIComponent(jobId)}/${rep}`);
    if (!lc) {
      rows.push({ rep, lcStatus: "unknown", cell: "<td colspan=\"7\" style=\"color:#f87171;\">Could not be resolved.</td>" });
      continue;
    }
    const failedTools = (lc.tool_installs || []).filter((t) => t.status !== "installed");
    let lb = null;
    if (lc.level_b_job_id) {
      const repNum = lc.level_b_live?.repetition_number || 1;
      lb = await repTreeGetJson(`/api/campaign-repetitions/level-b/${encodeURIComponent(lc.level_b_job_id)}/${repNum}`);
    }
    const caseInfo = lb?.case;
    const detection = lb?.detection;
    const blockers = lb?.blockers || [];
    const na = lb?.nested_level_a;
    let laCell = "—";
    if (na && na.job_id) {
      const dr = na.dry_run_repetitions || {};
      laCell = `${repTreeUnk(dr.completed, "0")}/${repTreeUnk(dr.requested, "?")} dry-runs ${repTreeSummaryPill(na.status || "unknown")}`;
    }
    rows.push({
      rep,
      lcStatus: lc.repetition_status,
      cell: `
        <td style="white-space:nowrap;font-weight:800;">Rep ${rep}/${total}</td>
        <td>${repTreeSummaryPill(lc.repetition_status)}<div style="color:rgba(148,163,184,0.6);font-size:10px;margin-top:2px;">${lc.total_elapsed_seconds != null ? repTreeFmtElapsed(lc.total_elapsed_seconds) : "—"}</div></td>
        <td>${(() => {
          // BUG FIXED 2026-07-24: a repetition that hasn't reached the
          // install-tools stage yet (pending, or still earlier in DESTROYING/
          // DEPLOYING) also has an empty tool_installs list -- same as a
          // repetition where every tool genuinely succeeded. Caught live by
          // the user: pending repetitions 8/9/10 were showing "all OK" before
          // a single tool had even been attempted. Distinguish "nothing
          // attempted yet" from "attempted and all succeeded" explicitly.
          if (failedTools.length) {
            return `<span style="color:#f87171;font-weight:800;">${failedTools.length} failed</span><div style="color:rgba(148,163,184,0.6);font-size:10px;">${failedTools.map((t) => repTreeEsc(`${t.instance}←${t.tool}`)).join(", ")}</div>`;
          }
          if (!lc.tool_installs || !lc.tool_installs.length) {
            return `<span style="color:rgba(148,163,184,0.6);">not started yet</span>`;
          }
          return `<span style="color:#22c55e;">all OK</span>`;
        })()}</td>
        <td>${caseInfo?.case_id ? `${repTreeEsc(caseInfo.case_real_name || "unknown")}<div style="color:rgba(148,163,184,0.55);font-size:10px;">${repTreeEsc(caseInfo.case_id)}</div>` : `<span style="color:rgba(148,163,184,0.6);">none created</span>`}</td>
        <td>${lb ? repTreeSummaryPill(lb.repetition_status) : "—"}</td>
        <td>${detection ? repTreeEsc(detection.outcome) : "—"}</td>
        <td>${blockers.length ? `<span style="color:#f87171;">${blockers.map((b) => repTreeEsc(b)).join("; ")}</span>` : "—"}</td>
        <td>${laCell}</td>
      `,
    });
  }
  const bodyRows = rows.map((r) => `<tr style="border-top:1px solid rgba(148,163,184,0.1);">${r.cell}</tr>`).join("");
  return `
    <div style="overflow-x:auto;">
      <table style="border-collapse:collapse;width:100%;font-size:11.5px;">
        <thead>
          <tr style="text-align:left;color:rgba(148,163,184,0.7);font-size:10px;text-transform:uppercase;letter-spacing:.05em;">
            <th style="padding:4px 8px 4px 0;">Repetition</th>
            <th style="padding:4px 8px;">Level C</th>
            <th style="padding:4px 8px;">Tool installs</th>
            <th style="padding:4px 8px;">Case</th>
            <th style="padding:4px 8px;">Level B</th>
            <th style="padding:4px 8px;">Detection</th>
            <th style="padding:4px 8px;">Error / blocker</th>
            <th style="padding:4px 8px;">Level A</th>
          </tr>
        </thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>
  `;
}

async function repTreeBuildTree(level, detail) {
  if (level === "C") return repTreeBuildLevelCTree(detail);
  if (level === "B") return repTreeBuildLevelBTree(detail);
  return repTreeBuildLevelATree(detail);
}

// ---------------------------------------------------------------------------
// Tree rendering (terminal-style connectors)
// ---------------------------------------------------------------------------

function repTreeNodeLineHtml(n) {
  const color = repTreeStatusColor(n.status);
  const elapsed = repTreeFmtElapsed(n.elapsed_seconds);
  const timeParts = [];
  if (n.started_at) timeParts.push(repTreeFmtAbs(n.started_at));
  if (n.finished_at) timeParts.push("→ " + repTreeFmtAbs(n.finished_at));
  else if (n.started_at) timeParts.push("→ …");
  if (elapsed) timeParts.push(`(${elapsed})`);
  let html = `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:${color};"></span>`;
  html += `<span style="font-weight:800;color:rgba(241,245,249,0.94);">${repTreeEsc(n.label)}</span> `;
  html += `<span style="font-size:10px;font-weight:900;text-transform:uppercase;color:${color};border:1px solid ${color}55;background:${color}18;border-radius:999px;padding:1px 7px;">${repTreeEsc(n.status || "unknown")}</span>`;
  if (timeParts.length) html += ` <span style="color:rgba(148,163,184,0.7);font-size:10.5px;">${repTreeEsc(timeParts.join(" "))}</span>`;
  return html;
}

// Builds the tree-connector prefix purely from recursion depth, carrying an
// explicit array of "is this ancestor the last sibling at its level" -- the
// standard approach for rendering an arbitrary-depth tree with box-drawing
// connectors (├──/└──/│) without string-hacking a prefix in place.
function repTreeRenderLines(rootNodes) {
  const out = [];
  function walk(n, ancestorsLast) {
    let prefix = "";
    for (let i = 0; i < ancestorsLast.length - 1; i++) {
      prefix += ancestorsLast[i] ? "&nbsp;&nbsp;&nbsp;&nbsp;" : "│&nbsp;&nbsp;&nbsp;";
    }
    if (ancestorsLast.length > 0) {
      prefix += ancestorsLast[ancestorsLast.length - 1] ? "└── " : "├── ";
    }
    out.push(`<div style="white-space:pre;font-size:11.5px;line-height:1.85;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;">${prefix}${repTreeNodeLineHtml(n)}</div>`);
    const subPrefix = (() => {
      let p = "";
      for (let i = 0; i < ancestorsLast.length; i++) {
        p += ancestorsLast[i] ? "&nbsp;&nbsp;&nbsp;&nbsp;" : "│&nbsp;&nbsp;&nbsp;";
      }
      return p + "&nbsp;&nbsp;&nbsp;&nbsp;";
    })();
    if (n.target) out.push(`<div style="white-space:pre;font-size:11px;line-height:1.7;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:#a78bfa;">${subPrefix}target: ${repTreeEsc(n.target)}</div>`);
    if (n.detail) out.push(`<div style="white-space:pre;font-size:11px;line-height:1.7;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:rgba(148,163,184,0.75);font-style:italic;">${subPrefix}${repTreeEsc(n.detail)}</div>`);
    if (n.error_detail) out.push(`<div style="white-space:pre;font-size:11px;line-height:1.7;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:#f87171;">${subPrefix}⚠ ${repTreeEsc(n.error_detail)}</div>`);
    const children = n.children || [];
    children.forEach((child, i) => walk(child, [...ancestorsLast, i === children.length - 1]));
  }
  rootNodes.forEach((r, i) => walk(r, [i === rootNodes.length - 1]));
  return out.join("");
}
