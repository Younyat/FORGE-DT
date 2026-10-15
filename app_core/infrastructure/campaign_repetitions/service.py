"""
Campaign repetitions detail center
===================================
Read-only aggregators that turn already-durable Level C / Level B / Level A
data into one consistent "what happened in THIS repetition" view, stage by
stage, using each level's own real vocabulary.

Hard rules (do not violate when extending this module):
  - Never invent a stage that doesn't exist at that level. Each level's stage
    list comes directly from the orchestration code that runs it
    (level_c_orchestrator.service, level_b_repetition_runner, or
    level_a_scientific_report_service.PHASES) — not from guessing.
  - A stage not yet reached is "pending", never omitted and never guessed.
  - Never blend levels: Level C, B and A each keep their own real terminal
    status vocabulary (see LC/LB/LA status sets below). The only synthetic,
    cross-level value allowed anywhere in this module is "pending".
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..foc_reconstruction.foc_config import PROJECT_ROOT
from ..level_c_orchestrator import service as level_c_service
from ..foc_experimentation import job_runner
from ..foc_experimentation import campaign_service as experimentation_campaign_service
from ..foc_experimentation import execution_service
from ..foc_experimentation import level_a_scientific_report_service
from ..foc_experimentation.config import CAMPAIGNS_ROOT, EVIDENCE_STORE_ROOT

# Real per-level terminal status vocabularies — used by callers (frontend and
# this module) to know which values are legitimate for which level. "pending"
# is the one synthetic value added on top, for stages/repetitions not yet
# reached by real execution.
LEVEL_C_STATUSES = {"running", "completed", "failed", "stopped", "pending"}
LEVEL_B_REPETITION_STATUSES = {"completed", "partial", "failed", "pending", "running"}
LEVEL_A_STATUSES = {
    "running", "completed", "completed_with_degradation", "failed",
    "cancelled", "stopped", "pending",
}


def _json_load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _parse_ts(raw) -> float | None:
    return level_c_service._parse_ts(raw)


def _seconds_between(start_iso: str | None, end_iso: str | None) -> float | None:
    a = _parse_ts(start_iso)
    b = _parse_ts(end_iso)
    if a is None or b is None:
        return None
    return round(b - a, 3)


def _fmt_dt(iso: str | None) -> str:
    """Human-readable 'launched at' string for execution labels — never the
    bare campaign_id, which can be weeks old and reused across many runs
    (see the 2026-07-19 incident writeup in this module's README: showing
    only campaign_id made a same-day repetition look "very old")."""
    ts = _parse_ts(iso)
    if ts is None:
        return "unknown time"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _annotate_relative_offsets(stages: list[dict]) -> None:
    """Adds 'elapsed_since_start_seconds' to each stage in place — how many
    seconds after this repetition's own first real stage each one began, so
    the frontend can render "at minute X" / "T+00:00" style narrative offsets
    instead of only a bare per-stage duration. Anchored on the first stage
    with a real started_at (pending stages get None)."""
    anchor = None
    for s in stages:
        if s.get("started_at"):
            anchor = _parse_ts(s["started_at"])
            break
    for s in stages:
        ts = _parse_ts(s.get("started_at")) if anchor is not None else None
        s["elapsed_since_start_seconds"] = round(ts - anchor, 1) if ts is not None else None


_DRY_RUN_PROGRESS_RE = re.compile(r"Run Dry-Run Execution (\d+)/(\d+)")


def _parse_current_dry_run(phase_detail: str | None) -> dict | None:
    """Which dry-run repetition a Level A job is currently on, parsed out of
    its own current_phase_detail prose (the only place this number exists —
    _run_level_a_report_job's generation loop only ever puts it in a
    human-readable detail string, never a structured field)."""
    if not phase_detail:
        return None
    m = _DRY_RUN_PROGRESS_RE.search(str(phase_detail))
    if not m:
        return None
    return {"index": int(m.group(1)), "total": int(m.group(2))}


def _total_elapsed_seconds(stages: list[dict], live_anchor_iso: str | None) -> float | None:
    """How long THIS repetition has taken overall: first real stage's start
    to either its last stage's finish (if the repetition is done) or a live
    anchor (if still in progress) — that anchor is the parent job's own
    `updated_at` (heartbeat), so a genuinely running repetition grows live
    and a dead one freezes at its last known moment, same reasoning as the
    per-stage running-elapsed fix above. 2026-07-19: user explicitly asked
    for "el tiempo total de las repeticiones", missing from both this
    module's detail view and the Live Campaign Status panel.
    """
    started_ats = [s["started_at"] for s in stages if s.get("started_at")]
    if not started_ats:
        return None
    start = min(_parse_ts(s) for s in started_ats)
    if start is None:
        return None
    still_running = any(s.get("status") == "running" for s in stages)
    if still_running:
        end = _parse_ts(live_anchor_iso)
    else:
        finished_ats = [s["finished_at"] for s in stages if s.get("finished_at")]
        end = max((_parse_ts(f) for f in finished_ats), default=None) if finished_ats else None
    if end is None:
        return None
    return round(end - start, 3)


def _stage(
    stage_key: str,
    label: str,
    status: str,
    *,
    started_at: str | None = None,
    finished_at: str | None = None,
    elapsed_seconds: float | None = None,
    target: str | None = None,
    detail: str | None = None,
    error_detail: str | None = None,
    warnings: list[str] | None = None,
) -> dict:
    return {
        "stage_key": stage_key,
        "label": label,
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_seconds": elapsed_seconds,
        "target": target,
        "detail": detail,
        "error_detail": error_detail,
        # 2026-07-26: a stage can genuinely finish "completed" while real
        # WARN-level problems happened inside it (e.g. Level C's
        # DEPLOYING_OT: a PLC/FUXA deploy failure is a WARN, not a hard stage
        # failure, so the orchestrator proceeds anyway -- the stage still
        # shows "completed" even though it's the actual reason the
        # repetition failed downstream). User explicitly asked for more
        # transparency after exactly this happened and the tree showed
        # "Deploying OT infrastructure: completed" with no hint anything had
        # gone wrong. Never invented -- only real WARN log lines already
        # written by the orchestrator, scoped to this stage's own time
        # window, excluding whatever a more specific parser (tool installs,
        # monitoring verification) already surfaces elsewhere.
        "warnings": warnings or [],
    }


# ---------------------------------------------------------------------------
# Level C
# ---------------------------------------------------------------------------

# Real per-repetition Level C phases, in the exact order _run_level_c_job
# executes them (level_c_orchestrator/service.py _run_level_c_job). Job-level
# phases (VALIDATING, COMPARING, COMPLETED/FAILED/STOPPED) are NOT repetition
# stages and are reported separately.
LC_REPETITION_PHASES: list[tuple[str, str]] = [
    ("DESTROYING", "Destroying scenario"),
    ("CLEANING", "Cleaning residual state"),
    ("DEPLOYING_IT", "Deploying IT infrastructure"),
    ("DEPLOYING_OT", "Deploying OT infrastructure"),
    ("WAITING_NODES", "Waiting for nodes to become reachable"),
    ("SYNCING_CLOCKS", "Synchronizing node clocks"),
    ("INSTALLING_TOOLS", "Installing tools"),
    ("VERIFYING_MONITORING", "Verifying monitoring stack"),
    ("RUNNING_LEVEL_B", "Launching Level B"),
    ("WAITING_LEVEL_B", "Waiting for Level B to finish"),
    ("CAPTURING_SNAPSHOT", "Capturing scenario snapshot"),
]
_LC_PHASE_LABELS = dict(LC_REPETITION_PHASES)

_LC_PHASE_LINE_RE = re.compile(r"^→ ([A-Z_]+)(?:\s+\(rep (\d+)/(\d+)\))?$")
_LC_TOOL_INSTALL_RE = re.compile(r"^\s*(\S+)\s+←\s+(\S+):\s+(installed|failed/skipped)\s*$")
_LC_TOOL_FAILURE_BANNER_RE = re.compile(r"(?im)^\s*((?:fallo|error)[^\n]{0,160})\s*$")
# How stale tools-installer/logs/<instance>_<tool>.log's mtime is allowed to be,
# relative to the job log's own failure timestamp, before it's rejected as
# belonging to a LATER repetition's re-run of the same tool/instance rather than
# the one being looked at. Every repetition takes at least many minutes end to
# end, so a multi-minute tolerance can't accidentally accept a stale file while
# still forgiving normal clock/logging skew between "script wrote its log" and
# "orchestrator logged the OK/WARN status line".
_LC_TOOL_LOG_STALENESS_TOLERANCE_SECONDS = 180


def _lc_tool_install_reason(instance: str, tool: str, failure_ts: str | None) -> str | None:
    """Real reason for a failed/skipped tool install, read from that install
    script's own dedicated log file (tools-installer/logs/<instance>_<tool>.log --
    written fresh by _install_tool_on_instance() every single run, see
    level_c_orchestrator/service.py). Deliberately does NOT parse the job's own
    combined log for this: that log interleaves/batches STDOUT from several tools
    together out of order relative to their OK/WARN status lines (confirmed live,
    2026-07-24 -- a naive nearby-lines scan mis-attributed one tool's failure
    banner to a completely different tool). The per-tool log file has no such
    ambiguity, but IS overwritten by the next repetition that installs the same
    tool on the same instance role -- so this only trusts the file if its mtime
    is close to the failure being looked at (see staleness tolerance above);
    otherwise the evidence for THIS specific historical failure is genuinely gone,
    and this returns None rather than risk showing a later run's unrelated reason.
    """
    if not failure_ts:
        return None
    try:
        failure_epoch = datetime.fromisoformat(str(failure_ts).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", instance.lower())
    log_path = PROJECT_ROOT / "tools-installer" / "logs" / f"{safe}_{tool}.log"
    try:
        if abs(log_path.stat().st_mtime - failure_epoch) > _LC_TOOL_LOG_STALENESS_TOLERANCE_SECONDS:
            return None
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    m = _LC_TOOL_FAILURE_BANNER_RE.search(text)
    return m.group(1).strip() if m else None


def _lc_tool_failure_seen_before(instance: str, tool: str, exclude_job_id: str) -> bool:
    """Whether this exact instance/tool combination has ever failed to install in
    ANY other preserved Level C job log -- used only to phrase an honest "first time
    seen" vs "recurring, still uncaptured" fallback when no banner text was found
    (see _lc_tool_install_reason). Scans real job_state.json logs on disk, nothing
    cached or invented; bounded to whatever jobs are actually still on disk.
    """
    needle = f"{tool}: failed/skipped"
    try:
        for job_dir in level_c_service.JOBS_DIR.iterdir():
            if job_dir.name == exclude_job_id or not job_dir.is_dir():
                continue
            state = _json_load(job_dir / "job_state.json")
            if not isinstance(state, dict):
                continue
            for entry in state.get("log") or []:
                msg = str(entry.get("msg") or "")
                if instance in msg and needle in msg:
                    return True
    except Exception:
        pass
    return False


def _lc_load_state(job_id: str) -> dict | None:
    path = level_c_service.JOBS_DIR / job_id / "job_state.json"
    return _json_load(path)


def _lc_execution_label(state: dict) -> str:
    config = state.get("config") or {}
    launched = _fmt_dt(state.get("created_at"))
    c = config.get("level_c_repetitions") or 1
    b = config.get("level_b_repetitions") or "?"
    a = config.get("level_a_repetitions") or "?"
    return (
        f"Level C execution launched {launched} · {c} Level C repetition(s) · "
        f"up to {b} Level B repetition(s) per C-rep · {a} Level A repetition(s) per B-rep"
    )


def _lc_snapshot_infrastructure(snapshot_id: str | None) -> dict | None:
    """Real per-instance machines/IPs/tools for one Level C repetition, read from the
    scenario snapshot captured at the end of that repetition. 2026-07-21: user asked for
    this exact detail per Level C rep ("las maquinas tools instalados ips de sts maquina")
    -- found it already exists in full inside every snapshot (infrastructure.instances,
    tools.by_node, network_config.floating_ips), just never surfaced here; this only reads
    it, nothing new is collected. Each Level C rep destroys/redeploys the scenario, so this
    is the ONLY place this specific rep's instance IDs/IPs still exist once the next rep's
    DESTROYING phase tears them down.
    """
    if not snapshot_id:
        return None
    try:
        from ..scenario_snapshot.service import get_snapshot
        snap = get_snapshot(snapshot_id)
    except Exception:
        return None
    if not isinstance(snap, dict):
        return None

    infra = snap.get("infrastructure") or {}
    instances_raw = infra.get("instances") or []
    tools_by_node = (snap.get("tools") or {}).get("by_node") or {}

    instances = []
    for inst in instances_raw:
        instance_id = inst.get("instance_id")
        node_tools = (tools_by_node.get(instance_id) or {}).get("tools") or []
        instances.append({
            "instance_id": instance_id,
            "name": inst.get("name"),
            "status": inst.get("status"),
            "ip_private": inst.get("ip_private"),
            "ip_floating": inst.get("ip_floating"),
            "flavor_id": inst.get("flavor_id"),
            "created_at": inst.get("created_at"),
            "tools": [
                {"tool_name": t.get("tool_name"), "status": t.get("status"), "installed_at": t.get("installed_at")}
                for t in node_tools
            ],
        })

    network = snap.get("network_config") or {}
    fip_summary = (network.get("summary") or {}).get("floating_ip_count")

    return {
        "snapshot_id": snapshot_id,
        "captured_at": snap.get("captured_at_utc"),
        "instances": instances,
        "floating_ip_count_at_capture": fip_summary,
    }


def _lc_rep_infra_events(rep_start_iso: str | None, rep_end_iso: str | None) -> dict:
    """Floating-IP cleanup runs and node time-sync measurements that happened during this
    Level C repetition's own time window. 2026-07-21: these are both global, timestamp-only
    logs with no existing concept of "which Level C repetition" -- correlated here purely by
    time window overlap, nothing is invented or guessed beyond that overlap check. Returns
    empty lists (never null) when nothing falls in the window, or when the window itself
    isn't known yet (rep still running / not started) -- honest "no events", not "unknown".
    """
    result: dict[str, list] = {"floating_ip_cleanups": [], "time_sync_checks": []}
    if not rep_start_iso:
        return result
    start_ts = _parse_ts(rep_start_iso)
    end_ts = _parse_ts(rep_end_iso) if rep_end_iso else None
    if start_ts is None:
        return result

    def _in_window(iso: str | None) -> bool:
        ts = _parse_ts(iso)
        if ts is None:
            return False
        if ts < start_ts:
            return False
        if end_ts is not None and ts > end_ts:
            return False
        return True

    try:
        from ..node_health.node_health_api import floating_ip_cleanup_status
        history = floating_ip_cleanup_status().get("history") or []
        for entry in history:
            if _in_window(entry.get("started_at")):
                result["floating_ip_cleanups"].append({
                    "triggered_by": entry.get("triggered_by"),
                    "status": entry.get("status"),
                    "started_at": entry.get("started_at"),
                    "finished_at": entry.get("finished_at"),
                    "duration_seconds": entry.get("duration_seconds"),
                    "released_count": entry.get("released_count"),
                    "before_available_pct": (entry.get("before") or {}).get("available_pct"),
                    "after_available_pct": (entry.get("after") or {}).get("available_pct"),
                })
    except Exception:
        pass

    try:
        from ..node_health.node_health_api import NODE_HEALTH_TIME_SYNC_DIR
        if NODE_HEALTH_TIME_SYNC_DIR.is_dir():
            for node_dir in NODE_HEALTH_TIME_SYNC_DIR.iterdir():
                status_path = node_dir / "job_status.json"
                payload = _json_load(status_path)
                if not isinstance(payload, dict):
                    continue
                if not _in_window(payload.get("finished_at") or payload.get("updated_at")):
                    continue
                node = payload.get("node") or {}
                result_hint = payload.get("result_hint") or {}
                result["time_sync_checks"].append({
                    "instance_id": node_dir.name,
                    "node_name": node.get("name"),
                    "fix_time": payload.get("fix_time"),
                    "temporal_sync_status": result_hint.get("temporal_sync_status"),
                    "max_clock_offset_ms": result_hint.get("max_clock_offset_ms"),
                    "correction_applied": result_hint.get("correction_applied"),
                    "finished_at": payload.get("finished_at"),
                })
    except Exception:
        pass

    return result


def _lc_pending_shell(job_id: str, rep_num: int, total_reps: int, state: dict) -> dict:
    stages = [_stage(f"lc.{p.lower()}", lbl, "pending") for p, lbl in LC_REPETITION_PHASES]
    _annotate_relative_offsets(stages)
    return {
        "job_id": job_id,
        "execution_label": _lc_execution_label(state),
        "repetition_number": rep_num,
        "total_repetitions": total_reps,
        "repetition_status": "pending",
        "total_elapsed_seconds": None,
        "stages": stages,
        "level_b_job_id": None,
        "snapshot_id": None,
        "snapshot_infrastructure": None,
        "tool_installs": [],
        "monitoring_verification": [],
        "floating_ip_cleanups": [],
        "time_sync_checks": [],
    }


def get_level_c_repetition_detail(job_id: str, rep_num: int) -> dict | None:
    state = _lc_load_state(job_id)
    if not isinstance(state, dict):
        return None

    total_reps = int((state.get("config") or {}).get("level_c_repetitions") or 1)
    if rep_num < 1 or rep_num > total_reps:
        return None

    log = state.get("log") or []
    phase_events: list[dict] = []
    for idx, entry in enumerate(log):
        if entry.get("level") != "PHASE":
            continue
        m = _LC_PHASE_LINE_RE.match(str(entry.get("msg") or ""))
        if not m:
            continue
        phase_events.append({
            "idx": idx,
            "phase": m.group(1),
            "rep": int(m.group(2)) if m.group(2) else None,
            "ts": entry.get("ts"),
        })

    rep_events = [e for e in phase_events if e["rep"] == rep_num]
    if not rep_events:
        return _lc_pending_shell(job_id, rep_num, total_reps, state)

    next_rep_events = [e for e in phase_events if e["rep"] == rep_num + 1]
    window_start_idx = rep_events[0]["idx"]
    window_end_idx = next_rep_events[0]["idx"] if next_rep_events else len(log)
    window_log = log[window_start_idx:window_end_idx]

    events_by_phase: dict[str, list[dict]] = {}
    for ev in rep_events:
        events_by_phase.setdefault(ev["phase"], []).append(ev)

    job_status = str(state.get("status") or "").lower()
    current_repetition = state.get("current_repetition")

    stages = []
    for phase_name, label in LC_REPETITION_PHASES:
        stage_key = f"lc.{phase_name.lower()}"
        matches = events_by_phase.get(phase_name)
        if not matches:
            stages.append(_stage(stage_key, label, "pending"))
            continue
        started_at = matches[0]["ts"]
        this_idx = matches[0]["idx"]
        later = [e for e in phase_events if e["idx"] > this_idx]
        finished_at = later[0]["ts"] if later else None
        if finished_at:
            status = "completed"
        elif job_status == "running" and rep_num == current_repetition:
            status = "running"
        elif job_status in ("failed", "stopped"):
            status = job_status
        else:
            status = "completed" if job_status == "completed" else "running"
        elapsed = _seconds_between(started_at, finished_at) if finished_at else (
            _seconds_between(started_at, state.get("updated_at")) if status == "running" else None
        )
        error_detail = None
        if status in ("failed", "stopped"):
            err_lines = [str(e.get("msg")) for e in log[this_idx:window_end_idx] if e.get("level") == "ERROR"]
            error_detail = err_lines[-1] if err_lines else state.get("error")
        # Real WARN-level lines from inside this stage's own time window that
        # aren't already surfaced by a more specific parser below (tool
        # installs, monitoring verification) -- see _stage()'s docstring
        # comment for why this exists. Scoped to [this stage's start, next
        # stage's start) exactly like error_detail above, just without
        # requiring the stage itself to have failed.
        stage_end_idx = later[0]["idx"] if later else window_end_idx
        stage_warnings = [
            str(e.get("msg")).strip()
            for e in log[this_idx:stage_end_idx]
            if e.get("level") == "WARN"
            and not _LC_TOOL_INSTALL_RE.match(str(e.get("msg") or ""))
            and "wazuh-manager=" not in str(e.get("msg") or "")
            and "wazuh-agent=" not in str(e.get("msg") or "")
        ]
        stages.append(_stage(
            stage_key, label, status,
            started_at=started_at, finished_at=finished_at,
            elapsed_seconds=elapsed, error_detail=error_detail,
            warnings=stage_warnings,
        ))

    level_b_job_id = None
    for e in window_log:
        if e.get("level") == "INFO":
            m = re.match(r"^Level B job started: (.+)$", str(e.get("msg") or ""))
            if m:
                level_b_job_id = m.group(1).strip()

    snapshot_ids = state.get("level_c_snapshot_ids") or []
    snapshot_id = snapshot_ids[rep_num - 1] if len(snapshot_ids) >= rep_num else None

    tool_installs = []
    for idx, e in enumerate(window_log):
        if e.get("level") not in ("OK", "WARN"):
            continue
        m = _LC_TOOL_INSTALL_RE.match(str(e.get("msg") or ""))
        if not m:
            continue
        install_status = "installed" if m.group(3) == "installed" else "failed_or_skipped"
        reason = None
        # 2026-07-24: user explicitly asked that any failure always come with SOME
        # explanation -- never a bare status with nothing else. Real reason first
        # (that tool's own dedicated log file, if it's still fresh enough to
        # trust); if genuinely not captured/recoverable, an honest, explicit
        # fallback instead of silence -- distinguishing "never seen before" from
        # "seen before but still uncaptured", both true statements, never a
        # guessed root cause.
        if install_status == "failed_or_skipped":
            reason = _lc_tool_install_reason(m.group(1), m.group(2), e.get("ts"))
            if not reason:
                if _lc_tool_failure_seen_before(m.group(1), m.group(2), job_id):
                    reason = "Unknown reason — this failure has occurred before for this tool, but no specific error text was captured in the log."
                else:
                    reason = "Unknown reason — first time this type of failure has been observed for this tool in this lab."
        tool_installs.append({
            "instance": m.group(1),
            "tool": m.group(2),
            "status": install_status,
            "ts": e.get("ts"),
            "reason": reason,
        })

    monitoring_verification = []
    for e in window_log:
        msg = str(e.get("msg") or "")
        if e.get("level") in ("INFO", "WARN") and ("wazuh-manager=" in msg or "wazuh-agent=" in msg):
            monitoring_verification.append({"ts": e.get("ts"), "level": e.get("level"), "detail": msg.strip()})

    if next_rep_events:
        repetition_status = "completed"
    elif rep_num == current_repetition:
        repetition_status = job_status if job_status in ("running", "failed", "stopped", "completed") else "running"
    elif current_repetition and rep_num < current_repetition:
        repetition_status = "completed"
    else:
        repetition_status = job_status if job_status == "completed" else "pending"

    _annotate_relative_offsets(stages)

    # Embed the SAME live, per-host, per-artifact detail (stage_timeline with
    # real byte sizes, analysis layers) the Level B repetition view shows,
    # right here in the Level C view too -- the user explicitly asked for
    # this in both places at once, not just the Level B detail page.
    # RUNNING_LEVEL_B/WAITING_LEVEL_B is exactly when this is most needed
    # (that's when the reader is staring at an opaque "waiting" stage).
    level_b_live = None
    level_b_requested_repetitions = None
    if level_b_job_id:
        try:
            lb_job = job_runner.get_job(level_b_job_id)
            if lb_job:
                # Exposed so the process-tree UI can show EVERY Level B
                # repetition this job will run/has run, not only the one
                # currently "live" -- user explicitly asked for this
                # (2026-10-09) after noticing the embedded tree only ever
                # showed the live repetition, hiding any earlier ones within
                # the same Level C repetition when level_b_repetitions > 1.
                level_b_requested_repetitions = int((lb_job.get("meta") or {}).get("requested_repetitions") or 0) or None
                lb_rep_num = None
                m = _LB_CURRENT_PHASE_REP_RE.match(str(lb_job.get("current_phase") or ""))
                if m:
                    lb_rep_num = int(m.group(1))
                if lb_rep_num:
                    lb_detail = get_level_b_repetition_detail(level_b_job_id, lb_rep_num)
                    if lb_detail:
                        level_b_live = {
                            "job_id": level_b_job_id,
                            "repetition_number": lb_rep_num,
                            "repetition_status": lb_detail.get("repetition_status"),
                            "case": lb_detail.get("case"),
                            "stage_timeline": lb_detail.get("stage_timeline"),
                            "analysis_layers": lb_detail.get("analysis_layers"),
                        }
        except Exception:
            pass

    rep_start_iso = stages[0].get("started_at") if stages else None
    rep_end_iso = stages[-1].get("finished_at") if stages else None
    infra_events = _lc_rep_infra_events(rep_start_iso, rep_end_iso)

    return {
        "job_id": job_id,
        "execution_label": _lc_execution_label(state),
        "campaign_id": (state.get("config") or {}).get("campaign_id"),
        "repetition_number": rep_num,
        "total_repetitions": total_reps,
        "repetition_status": repetition_status,
        "total_elapsed_seconds": _total_elapsed_seconds(stages, state.get("updated_at")),
        "stages": stages,
        "level_b_job_id": level_b_job_id,
        "level_b_live": level_b_live,
        "level_b_requested_repetitions": level_b_requested_repetitions,
        "snapshot_id": snapshot_id,
        "snapshot_infrastructure": _lc_snapshot_infrastructure(snapshot_id),
        "tool_installs": tool_installs,
        "monitoring_verification": monitoring_verification,
        "floating_ip_cleanups": infra_events["floating_ip_cleanups"],
        "time_sync_checks": infra_events["time_sync_checks"],
    }


def list_level_c_repetition_statuses(job: dict) -> list[dict]:
    """Lightweight per-repetition status for EVERY repetition of a Level C
    job, derived only from the job's own summary fields (status,
    current_repetition, level_c_repetitions) -- no log parsing. Unlike
    get_level_c_repetition_detail (which re-scans the whole job log and is
    meant to be called for ONE repetition at a time), this is safe to call
    for all N repetitions on every poll of a live dashboard. Same real
    classification rules as _lc_list_recent's per-repetition rows, just
    listing every repetition instead of only ones already reached.
    """
    total_reps = int(job.get("level_c_repetitions") or 1)
    current_rep = int(job.get("current_repetition") or 0)
    status = str(job.get("status") or "unknown")
    rows = []
    for rep in range(1, total_reps + 1):
        if rep < current_rep:
            rep_status = "completed"
        elif rep == current_rep:
            rep_status = status if status in ("running", "failed", "stopped", "completed") else "running"
        else:
            rep_status = "completed" if status == "completed" else "pending"
        rows.append({
            "repetition_number": rep,
            "total_repetitions": total_reps,
            "status": rep_status,
            "is_focus": rep == current_rep,
        })
    return rows


def _lc_list_recent(limit: int) -> list[dict]:
    rows = []
    for job in level_c_service.list_jobs():
        job_id = job.get("job_id")
        total_reps = int(job.get("level_c_repetitions") or 1)
        current_rep = int(job.get("current_repetition") or 0)
        status = str(job.get("status") or "unknown")
        execution_label = (
            f"Level C execution launched {_fmt_dt(job.get('created_at'))} · "
            f"{total_reps} Level C repetition(s)"
        )
        # Only list repetitions that have genuinely started (idx <= current_rep,
        # or all of them if the job already reached a terminal state) — never
        # fabricate a row for a repetition that hasn't started.
        upper = total_reps if status in ("completed", "failed", "stopped") else max(current_rep, 0)
        # Descending (most recent repetition first) -- 2026-07-20: user opened the bell,
        # saw rep 1 (the oldest, already "completed") listed/shown before the genuinely
        # still-running rep 2, and read that as the whole campaign being done early. Since
        # every repetition of the same job shares one created_at, the cross-level sort in
        # list_recent_repetitions() can't separate them -- only this iteration order does.
        for rep in range(upper, 0, -1):
            if rep < current_rep:
                rep_status = "completed"
            elif rep == current_rep:
                rep_status = status if status in ("running", "failed", "stopped", "completed") else "running"
            else:
                rep_status = "completed" if status == "completed" else "pending"
            rows.append({
                "level": "C",
                "job_id": job_id,
                "execution_label": execution_label,
                "repetition_number": rep,
                "total_repetitions": total_reps,
                "repetition_status": rep_status,
                "created_at": job.get("created_at"),
                "completed_at": job.get("completed_at"),
            })
            if len(rows) >= limit:
                return rows
    return rows


# ---------------------------------------------------------------------------
# Level B
# ---------------------------------------------------------------------------

# Real per-repetition Level B phase-key suffixes, in the order
# level_b_repetition_runner._run_single_repetition emits them via _emit_phase.
LB_STAGE_ORDER = ["start", "attack", "alert", "trigger", "acquisition", "seal", "analysis", "reconstruction", "cleanup", "store"]
LB_STAGE_LABELS = {
    "start": "Start repetition",
    "attack": "Execute OT register-modification attack",
    "alert": "Wait for high-severity alert",
    "trigger": "Verify forensic intervention trigger",
    "acquisition": "Run automatic acquisition",
    "seal": "Seal and register case",
    "analysis": "Run multilayer analysis",
    "reconstruction": "Run reconstruction/dependency analysis",
    "cleanup": "Clean heavy generated case",
    "store": "Store repetition result",
}


def _lb_stage_entries_for_repetition(job: dict, repetition_number: int) -> list[dict]:
    prefix = f"repetition_{repetition_number}_"
    grouped: dict[str, list[dict]] = {}
    for e in job.get("phase_statuses") or []:
        key = str(e.get("phase_key") or "")
        if not key.startswith(prefix):
            continue
        suffix = key[len(prefix):]
        grouped.setdefault(suffix, []).append(e)

    stages = []
    for suffix in LB_STAGE_ORDER:
        label = LB_STAGE_LABELS[suffix]
        stage_key = f"lb.rep.{suffix}"
        occ = grouped.get(suffix)
        if not occ:
            stages.append(_stage(stage_key, label, "pending"))
            continue
        started_at = occ[0].get("updated_at")
        last = occ[-1]
        status = str(last.get("status") or "running")
        finished_at = last.get("updated_at") if status != "running" else None
        elapsed = _seconds_between(started_at, finished_at) if finished_at else (
            _seconds_between(started_at, job.get("updated_at")) if status == "running" else None
        )
        error_detail = last.get("detail") if status == "failed" else None
        stages.append(_stage(
            stage_key, label, status,
            started_at=started_at, finished_at=finished_at, elapsed_seconds=elapsed,
            detail=last.get("detail"), error_detail=error_detail,
        ))
    return stages


def _lb_execution_label(job: dict) -> str:
    meta = job.get("meta") or {}
    launched = _fmt_dt(job.get("started_at") or job.get("requested_at"))
    requested = meta.get("requested_repetitions") or "?"
    nested_a = meta.get("nested_level_a_repetitions") or "?"
    return (
        f"Level B batch launched {launched} · {requested} Level B repetition(s) requested · "
        f"{nested_a} nested Level A repetition(s) per B-rep"
    )


def _lb_detection_outcome(result: dict) -> str:
    if result.get("trigger_alert_detected"):
        return "detected"
    blockers = [str(b) for b in (result.get("blockers") or [])]
    if any("detection_stream_silent" in b for b in blockers):
        return "never_detected_stream_silent"
    if blockers:
        return "never_detected_exhausted_attempts"
    return "never_detected"


def get_level_b_repetition_detail(job_id: str, repetition_number: int) -> dict | None:
    job = job_runner.get_job(job_id)
    if not job:
        return None

    per_rep = job.get("per_repetition_results") or []
    result = next(
        (r for r in per_rep if isinstance(r, dict) and r.get("repetition_number") == repetition_number),
        None,
    )
    stages = _lb_stage_entries_for_repetition(job, repetition_number)
    _annotate_relative_offsets(stages)
    total_elapsed = _total_elapsed_seconds(stages, job.get("updated_at"))
    requested = int((job.get("meta") or {}).get("requested_repetitions") or 0)
    execution_label = _lb_execution_label(job)

    if result is None:
        job_status = str(job.get("status") or "").lower()
        any_progress = any(s["status"] != "pending" for s in stages)
        if any_progress and job_status == "running":
            status = "running"
        elif any_progress and job_status in ("failed", "stopped", "cancelled"):
            # This repetition was genuinely reached and made real progress
            # (see stages) but never got its own per_repetition_results
            # entry — it was cut off, not "not yet started". Report the
            # parent job's own real terminal status instead of "pending",
            # which would wrongly imply this repetition never ran.
            status = job_status
        else:
            status = "pending"
        # A repetition mid-flight has no per_repetition_results entry yet
        # (only written once it finishes), but its case IS already being
        # acquired right now -- the job's own current_case_id is set the
        # instant the case is created (same field get_live_campaign_summary()
        # already reads). Wiring it in here gives the same real, per-host,
        # per-artifact stage timeline (with real byte sizes -- see
        # stage_timing_service.py's 2026-07-19 change) WHILE the repetition
        # is still running, not only after it finishes. 2026-07-19: user
        # explicitly asked "no veo qué artefactos se están preservando en el
        # instante ni lo que pesan ni cuánto se tarda en cada paso" -- this
        # data already existed for the live panel, it just wasn't wired into
        # this still-running branch of the per-repetition detail view.
        live_case_id = job.get("current_case_id")
        live_analysis_layers = None
        live_stage_timeline = None
        if live_case_id:
            try:
                from ..forensics import stage_timing_service
                live_analysis_layers = stage_timing_service.summarize_case_analysis_layers_by_case_id(live_case_id)
                live_stage_timeline = stage_timing_service.get_case_stage_timeline_by_case_id(live_case_id)
            except Exception:
                pass
        # The nested Level A launch is real and running the instant this
        # repetition reaches "store" -- current_child_job_id is set then,
        # well before this repetition finishes and gets its own
        # per_repetition_results entry (which is what the block below this
        # branch relies on). Without this, "which dry-run am I on" stayed
        # invisible for the entire, often 20-60+ minute, live window.
        # 2026-07-19: user explicitly asked to always see the current
        # repetition/dry-run numbers, not just after the fact.
        live_nested_level_a = None
        nested_job_id_live = job.get("current_child_job_id")
        if nested_job_id_live:
            try:
                nested_job_live = job_runner.get_job(nested_job_id_live)
                if nested_job_live:
                    live_nested_level_a = {
                        "job_id": nested_job_id_live,
                        "status": nested_job_live.get("status"),
                        "execution_label": _la_execution_label(nested_job_live),
                        "started_at": nested_job_live.get("started_at"),
                        "finished_at": nested_job_live.get("finished_at"),
                        "elapsed_seconds": _seconds_between(nested_job_live.get("started_at"), nested_job_live.get("finished_at") or job.get("updated_at")),
                        "current_dry_run": _parse_current_dry_run(nested_job_live.get("current_phase_detail")),
                        "current_phase_label": nested_job_live.get("current_phase_label"),
                        "current_phase_detail": nested_job_live.get("current_phase_detail"),
                        "dry_run_history": _la_dry_run_history((nested_job_live.get("meta") or {}).get("campaign_id")),
                    }
            except Exception:
                pass
        # 2026-07-24: the case's real, human-readable folder name
        # (CASE-YYYYMMDD-HHMMSS) was never exposed while a repetition is
        # still running -- only the short internal alias (case_id, a sha1
        # hash of that folder name -- see level_b_orchestrator.py's
        # _case_id_for_case_dir()) was shown, which the user correctly found
        # confusing ("dos nombres, y el sistema usa dos??"). Resolves the
        # real name via the SAME canonical alias resolver the rest of the FOC
        # reconstruction module already uses (get_case_entry()) -- no new
        # alias logic invented here, and this only reads, it doesn't touch
        # the live pipeline's job state at all.
        live_case_real_name = None
        if live_case_id:
            try:
                from ..foc_reconstruction.foc_case_analysis import get_case_entry
                live_entry = get_case_entry(live_case_id)
                if live_entry:
                    live_case_real_name = live_entry.get("source_case_name")
            except Exception:
                pass
        return {
            "job_id": job_id,
            "execution_label": execution_label,
            "repetition_number": repetition_number,
            "requested_repetitions": requested,
            "repetition_status": status,
            "total_elapsed_seconds": total_elapsed,
            "stages": stages,
            "attack": None, "detection": None,
            "case": {"case_id": live_case_id, "case_real_name": live_case_real_name, "case_path": None, "case_created_utc": None} if live_case_id else None,
            "acquisition": None,
            "between_lb_and_la": None, "nested_level_a": live_nested_level_a,
            "analysis_layers": live_analysis_layers, "stage_timeline": live_stage_timeline, "reconstruction": None,
            "warnings": [], "blockers": [],
        }

    timing = result.get("timing_metrics") or {}

    case_created_utc = None
    acquisition_profile_rel = (result.get("artifacts") or {}).get("acquisition_profile")
    if acquisition_profile_rel:
        prof = _json_load(PROJECT_ROOT / acquisition_profile_rel)
        if isinstance(prof, dict):
            case_created_utc = prof.get("case_created_utc")

    analysis_layers = None
    stage_timeline = None
    case_id = result.get("case_id")
    if case_id:
        try:
            from ..forensics import stage_timing_service
            analysis_layers = stage_timing_service.summarize_case_analysis_layers_by_case_id(case_id)
            stage_timeline = stage_timing_service.get_case_stage_timeline_by_case_id(case_id)
        except Exception:
            pass

    # Enrich the nested Level A reference with ITS OWN real duration and
    # per-dry-run breakdown, resolved fresh from that exact job_id — each
    # Level B repetition launches its own separate nested Level A job, so
    # this is never shared/overwritten between repetitions even though they
    # can look identical at a glance without this detail (2026-07-19: user
    # explicitly asked to distinguish "2 Level A reps for B-rep 1" from
    # "however many for B-rep 2" instead of one ambiguous nested_level_a blob).
    nested_level_a = dict(result.get("nested_level_a") or {})
    nested_job_id = nested_level_a.get("job_id")
    if nested_job_id:
        try:
            nested_job = job_runner.get_job(nested_job_id)
            if nested_job:
                nested_level_a["execution_label"] = _la_execution_label(nested_job)
                nested_level_a["started_at"] = nested_job.get("started_at")
                nested_level_a["finished_at"] = nested_job.get("finished_at")
                nested_level_a["elapsed_seconds"] = _seconds_between(
                    nested_job.get("started_at"), nested_job.get("finished_at")
                )
                nested_detail = get_level_a_repetition_detail(nested_job_id)
                if nested_detail:
                    nested_level_a["dry_run_repetitions"] = nested_detail.get("dry_run_repetitions")
                    nested_level_a["per_dry_run_reconstruction"] = nested_detail.get("per_dry_run_reconstruction")
                    nested_level_a["conclusions"] = nested_detail.get("conclusions")
                    nested_level_a["current_dry_run"] = nested_detail.get("current_dry_run")
                    nested_level_a["dry_run_history"] = nested_detail.get("dry_run_history")
        except Exception:
            pass

    return {
        "job_id": job_id,
        "execution_label": execution_label,
        "repetition_number": repetition_number,
        "requested_repetitions": requested,
        "repetition_status": result.get("execution_status"),
        "total_elapsed_seconds": total_elapsed,
        "stages": stages,
        "attack": {
            "attack_profile_id": result.get("attack_profile_id"),
            "attack_name": result.get("attack_name"),
            "target_node": result.get("target_node"),
            "protocol": result.get("protocol"),
            "function_code": result.get("function_code"),
            "register": result.get("register"),
            "value": result.get("value"),
            "started_at": result.get("attack_started_at"),
            "completed_at": result.get("attack_completed_at"),
        },
        "detection": {
            "outcome": _lb_detection_outcome(result),
            "trigger_alert_detected": result.get("trigger_alert_detected"),
            "trigger_alert_id": result.get("trigger_alert_id"),
            "trigger_alert_rule": result.get("trigger_alert_rule"),
            "trigger_alert_severity": result.get("trigger_alert_severity"),
            "trigger_alert_timestamp": result.get("trigger_alert_timestamp"),
            "trigger_alert_mitre": result.get("trigger_alert_mitre") or [],
            "trigger_attempts_total": result.get("trigger_attempts_total"),
            "trigger_attempt_trace": result.get("trigger_attempt_trace") or [],
        },
        "case": {
            "case_id": case_id,
            "case_real_name": Path(result.get("case_path")).name if result.get("case_path") else None,
            "case_path": result.get("case_path"),
            "case_created_utc": case_created_utc,
        },
        "acquisition": {
            "memory_status": result.get("memory_acquisition_status"),
            "memory_hash": result.get("memory_hash"),
            "memory_size_bytes": timing.get("memory_dump_size_bytes"),
            "disk_status": result.get("disk_acquisition_status"),
            "disk_size_bytes": timing.get("disk_snapshot_size_bytes"),
            "network_status": result.get("network_context_status"),
            "pcap_segments_imported": result.get("pcap_segments_imported"),
            "network_size_gib": timing.get("pcap_periodic_context_size_gib"),
            "ot_status": result.get("ot_export_status"),
        },
        "between_lb_and_la": {
            "case_sealed_to_analysis_completed_seconds": timing.get("case_sealed_to_analysis_completed_seconds"),
            "t_case_sealed_seconds": timing.get("t_case_sealed_seconds"),
        },
        "nested_level_a": nested_level_a,
        "analysis_layers": analysis_layers,
        "stage_timeline": stage_timeline,
        "reconstruction": result.get("reconstruction_metrics") or {},
        "warnings": result.get("warnings") or [],
        "blockers": result.get("blockers") or [],
    }


_LB_CURRENT_PHASE_REP_RE = re.compile(r"^repetition_(\d+)_")


def _lb_list_recent(limit: int) -> list[dict]:
    rows = []
    jobs = []
    for job_path in CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
        payload = _json_load(job_path)
        if isinstance(payload, dict) and payload.get("job_type") == "level_b_repetitions":
            jobs.append(payload)
    jobs.sort(key=lambda j: j.get("started_at") or j.get("requested_at") or "", reverse=True)

    for job in jobs:
        job_id = job.get("job_id")
        campaign_id = (job.get("meta") or {}).get("campaign_id")
        requested = int((job.get("meta") or {}).get("requested_repetitions") or 0)
        execution_label = _lb_execution_label(job)
        per_rep = {r.get("repetition_number"): r for r in (job.get("per_repetition_results") or []) if isinstance(r, dict)}
        job_status = str(job.get("status") or "").lower()
        current_rep = None
        m = _LB_CURRENT_PHASE_REP_RE.match(str(job.get("current_phase") or ""))
        if m:
            current_rep = int(m.group(1))
        seen = set(per_rep.keys())
        if current_rep and job_status == "running" and current_rep not in seen:
            seen.add(current_rep)
        # Descending (most recent repetition first) -- same reasoning as _lc_list_recent()
        # above: an older, already-finished repetition of the same job was surfacing
        # before the genuinely still-running one, reading as "it's done" when it wasn't.
        for rep_num in sorted(seen, reverse=True):
            result = per_rep.get(rep_num)
            status = result.get("execution_status") if result else ("running" if job_status == "running" else "pending")
            rows.append({
                "level": "B",
                "job_id": job_id,
                "execution_label": execution_label,
                "campaign_id": campaign_id,
                "repetition_number": rep_num,
                "requested_repetitions": requested,
                "repetition_status": status,
                "case_id": (result or {}).get("case_id"),
                "started_at": job.get("started_at"),
            })
            if len(rows) >= limit:
                return rows
    return rows


# ---------------------------------------------------------------------------
# Level A
# ---------------------------------------------------------------------------

def _la_stage_entries(job: dict) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for e in job.get("phase_statuses") or []:
        key = str(e.get("phase_key") or "")
        grouped.setdefault(key, []).append(e)

    stages = []
    for phase_key, label in level_a_scientific_report_service.PHASES:
        stage_key = f"la.{phase_key}"
        occ = grouped.get(phase_key)
        if not occ:
            stages.append(_stage(stage_key, label, "pending"))
            continue
        started_at = occ[0].get("updated_at")
        last = occ[-1]
        status = str(last.get("status") or "running")
        finished_at = last.get("updated_at") if status != "running" else None
        elapsed = _seconds_between(started_at, finished_at) if finished_at else (
            _seconds_between(started_at, job.get("updated_at")) if status == "running" else None
        )
        error_detail = last.get("detail") if status == "failed" else None
        stages.append(_stage(
            stage_key, label, status,
            started_at=started_at, finished_at=finished_at, elapsed_seconds=elapsed,
            detail=last.get("detail"), error_detail=error_detail,
        ))
    return stages


def _la_locate_dry_run_job_timing(campaign_id: str, execution_id: str) -> dict | None:
    """Find the exact campaign_dry_run_execution child job that produced a
    given generated_execution_id, for real per-dry-run start/finish timing.
    execution_manifest.json's own created_at/updated_at are both stamped at
    write time (effectively the finish moment, not a true start), so this is
    the only place a real per-dry-run duration exists. Each dry-run job's
    own meta.execution_id is set once it finishes (dry_run_orchestrator.py's
    final update_job call merges create_execution_from_campaign()'s result,
    which includes execution_id, into meta).
    """
    if not campaign_id or not execution_id:
        return None
    for job_path in (CAMPAIGNS_ROOT / campaign_id / "jobs").glob("*.json"):
        payload = _json_load(job_path)
        if not isinstance(payload, dict) or payload.get("job_type") != "campaign_dry_run_execution":
            continue
        if (payload.get("meta") or {}).get("execution_id") == execution_id:
            return {
                "started_at": payload.get("started_at"),
                "finished_at": payload.get("finished_at"),
                "elapsed_seconds": _seconds_between(payload.get("started_at"), payload.get("finished_at")),
            }
    return None


def _la_dry_run_history(campaign_id: str) -> list[dict]:
    """Every dry-run execution this Level A job has launched, in chronological
    order, whether already finished or still running right now — a full
    narrative timeline: exactly when each one started, how long it took (or
    has taken so far), and which inner phase (Bootstrap FOC, Regenerate
    Reconstruction, Run Causal Reconstruction, Run Full Evidence Lifecycle,
    Finalize — see dry_run_orchestrator.py's own `_phase()` calls) it's
    currently on. `per_dry_run_reconstruction` only ever had COMPLETED
    dry-runs (keyed off `generated_execution_ids`, only populated once an
    execution is actually registered) — the one currently in progress was
    invisible here even though it's real, running, and the exact thing a
    reader watching live wants to see. 2026-07-19: explicitly requested by
    the user as "una historia" after manually piecing this together by hand
    from raw job files.
    """
    if not campaign_id:
        return []
    jobs_dir = CAMPAIGNS_ROOT / campaign_id / "jobs"
    if not jobs_dir.is_dir():
        return []
    candidates = []
    for job_path in jobs_dir.glob("*.json"):
        payload = _json_load(job_path)
        if isinstance(payload, dict) and payload.get("job_type") == "campaign_dry_run_execution":
            candidates.append(payload)
    candidates.sort(key=lambda d: d.get("started_at") or "")

    history = []
    for idx, d in enumerate(candidates, start=1):
        status = d.get("status")
        started_at = d.get("started_at")
        finished_at = d.get("finished_at")
        elapsed = _seconds_between(started_at, finished_at) if finished_at else (
            _seconds_between(started_at, d.get("updated_at")) if status == "running" else None
        )
        execution_id = (d.get("meta") or {}).get("execution_id")
        cpr = None
        weighted_cpr = None
        if execution_id:
            try:
                execution_payload = execution_service.load_execution(execution_id, campaign_id)
                if execution_payload:
                    result_card_rel = (execution_payload.get("artifacts") or {}).get("forensic_result_card")
                    if result_card_rel:
                        card = _json_load(Path(result_card_rel))
                        if isinstance(card, dict):
                            cpr = card.get("CPR")
                            weighted_cpr = card.get("Weighted_CPR")
            except Exception:
                pass
        history.append({
            "dry_run_index": idx,
            "job_id": d.get("job_id"),
            "status": status,
            "started_at": started_at,
            "finished_at": finished_at,
            "elapsed_seconds": elapsed,
            "current_phase_label": d.get("current_phase_label"),
            "current_phase_detail": d.get("current_phase_detail"),
            "execution_id": execution_id,
            "cpr": cpr,
            "weighted_cpr": weighted_cpr,
        })
    return history


def _la_requested_repetitions(job: dict) -> int | None:
    """The requested dry-run repetition count, resolved as early and as
    reliably as possible. `level_a_report.requested_repetitions` is only
    written once the job reaches the dry-run-generation phase — a job that
    dies before then (e.g. interrupted early, see the 2026-07-19 incidents in
    this README) never gets it, and used to show "?" in execution_label even
    though the real number was known from the very first instant: it's part
    of the campaign's own config (`repetitions`, set at `create_campaign()`
    time), never derived or guessed.
    """
    report = job.get("level_a_report") or {}
    requested = report.get("requested_repetitions")
    if requested is not None:
        return int(requested)
    campaign_id = (job.get("meta") or {}).get("campaign_id")
    if not campaign_id:
        return None
    try:
        info = experimentation_campaign_service.get_campaign(campaign_id) or {}
        config_requested = (info.get("config") or {}).get("repetitions")
        return int(config_requested) if config_requested is not None else None
    except Exception:
        return None


def _la_execution_label(job: dict) -> str:
    launched = _fmt_dt(job.get("started_at") or job.get("requested_at"))
    requested = _la_requested_repetitions(job)
    requested_str = str(requested) if requested is not None else "?"
    return f"Level A report launched {launched} · {requested_str} dry-run repetition(s) requested"


def _lb_locate_repetition_by_execution_id(campaign_id: str, execution_id: str) -> tuple[str, int] | None:
    """Find which level_b_repetitions job (and repetition number within it)
    produced a given execution_id, so a nested Level A report can link back
    to the exact Level B repetition detail view, not just the campaign.
    """
    if not campaign_id or not execution_id:
        return None
    for job_path in (CAMPAIGNS_ROOT / campaign_id / "jobs").glob("*.json"):
        payload = _json_load(job_path)
        if not isinstance(payload, dict) or payload.get("job_type") != "level_b_repetitions":
            continue
        for result in payload.get("per_repetition_results") or []:
            if isinstance(result, dict) and result.get("execution_id") == execution_id:
                return str(payload.get("job_id") or ""), int(result.get("repetition_number") or 0)
    return None


def get_level_a_repetition_detail(job_id: str) -> dict | None:
    job = job_runner.get_job(job_id)
    if not job or job.get("job_type") != "level_a_scientific_report":
        return None

    stages = _la_stage_entries(job)
    campaign_id = (job.get("meta") or {}).get("campaign_id")

    parent_level_b = None
    if campaign_id:
        try:
            info = experimentation_campaign_service.get_campaign(campaign_id) or {}
            config = info.get("config") or {}
            if config.get("parent_campaign_id"):
                parent_campaign_id = config.get("parent_campaign_id")
                parent_execution_id = config.get("parent_execution_id")
                located = _lb_locate_repetition_by_execution_id(parent_campaign_id, parent_execution_id)
                parent_level_b = {
                    "campaign_id": parent_campaign_id,
                    "execution_id": parent_execution_id,
                    "parent_level": config.get("parent_level"),
                    "job_id": located[0] if located else None,
                    "repetition_number": located[1] if located else None,
                }
        except Exception:
            pass

    report = job.get("level_a_report") or {}
    generated_execution_ids = list(report.get("generated_execution_ids") or [])
    requested_repetitions = _la_requested_repetitions(job)
    completed_repetitions = report.get("completed_repetitions") or len(generated_execution_ids)

    per_dry_run = []
    cprs: list[float] = []
    wcprs: list[float] = []
    for execution_id in generated_execution_ids:
        entry = {
            "execution_id": execution_id, "cpr": None, "weighted_cpr": None, "status": None,
            "started_at": None, "finished_at": None, "elapsed_seconds": None,
        }
        try:
            execution_payload = execution_service.load_execution(execution_id, campaign_id)
            if execution_payload:
                entry["status"] = execution_payload.get("status")
                result_card_rel = (execution_payload.get("artifacts") or {}).get("forensic_result_card")
                if result_card_rel:
                    card = _json_load(Path(result_card_rel))
                    if isinstance(card, dict):
                        entry["cpr"] = card.get("CPR")
                        entry["weighted_cpr"] = card.get("Weighted_CPR")
        except Exception:
            pass
        timing = _la_locate_dry_run_job_timing(campaign_id, execution_id)
        if timing:
            entry.update(timing)
        if isinstance(entry["cpr"], (int, float)):
            cprs.append(entry["cpr"])
        if isinstance(entry["weighted_cpr"], (int, float)):
            wcprs.append(entry["weighted_cpr"])
        per_dry_run.append(entry)

    conclusions = None
    if cprs or wcprs:
        conclusions = {
            "cpr_mean": round(sum(cprs) / len(cprs), 4) if cprs else None,
            "weighted_cpr_mean": round(sum(wcprs) / len(wcprs), 4) if wcprs else None,
            "delta_cpr": round(max(cprs) - min(cprs), 4) if len(cprs) >= 2 else None,
            "delta_weighted_cpr": round(max(wcprs) - min(wcprs), 4) if len(wcprs) >= 2 else None,
        }

    analysis_layers = None
    anchor_case_id = job.get("current_case_id")
    if anchor_case_id:
        try:
            from ..forensics import stage_timing_service
            analysis_layers = stage_timing_service.summarize_case_analysis_layers_by_case_id(anchor_case_id)
        except Exception:
            pass

    _annotate_relative_offsets(stages)

    return {
        "job_id": job_id,
        "execution_label": _la_execution_label(job),
        "campaign_id": campaign_id,
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        # Was _seconds_between(started_at, finished_at) -- always None while
        # running (finished_at doesn't exist yet), the exact same "black
        # hole" bug already fixed for individual stages, just at the
        # top-level total instead. Uses the same live-anchor-on-updated_at
        # pattern (grows while alive, freezes if dead) via
        # _total_elapsed_seconds(). 2026-07-19: user explicitly asked for
        # this total to be visible, in both this center and the Live
        # Campaign Status panel.
        "total_elapsed_seconds": _total_elapsed_seconds(stages, job.get("updated_at")),
        "repetition_status": job.get("status"),
        # "estoy en dry-run 1 o 2?" -- current_phase_detail only ever said
        # this inside a prose sentence ("Run Dry-Run Execution 2/2: ...").
        # 2026-07-19: parsed out into a clean field, same fix applied to the
        # Live Campaign Status panel's standalone_level_a/nested-Level-A-via-B
        # cases (level_c_orchestrator.py).
        "current_dry_run": _parse_current_dry_run(job.get("current_phase_detail")),
        "stages": stages,
        "parent_level_b": parent_level_b,
        "dry_run_repetitions": {
            "requested": requested_repetitions,
            "completed": completed_repetitions,
            "generated_execution_ids": generated_execution_ids,
        },
        "analysis_layers": analysis_layers,
        "per_dry_run_reconstruction": per_dry_run,
        # Full chronological story of every dry-run this job has launched,
        # including the one currently in progress (per_dry_run_reconstruction
        # above only ever has completed ones) -- see _la_dry_run_history()'s
        # own docstring. 2026-07-19, explicitly requested as "una historia".
        "dry_run_history": _la_dry_run_history(campaign_id),
        "conclusions": conclusions,
        "warnings": job.get("warnings") or [],
        "errors": job.get("errors") or [],
    }


def _la_list_recent(limit: int) -> list[dict]:
    rows = []
    jobs = []
    for job_path in CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
        payload = _json_load(job_path)
        if isinstance(payload, dict) and payload.get("job_type") == "level_a_scientific_report":
            jobs.append(payload)
    jobs.sort(key=lambda j: j.get("started_at") or j.get("requested_at") or "", reverse=True)
    for job in jobs[:limit]:
        rows.append({
            "level": "A",
            "job_id": job.get("job_id"),
            "execution_label": _la_execution_label(job),
            "campaign_id": (job.get("meta") or {}).get("campaign_id"),
            "repetition_status": job.get("status"),
            "started_at": job.get("started_at"),
            "finished_at": job.get("finished_at"),
        })
    return rows


# ---------------------------------------------------------------------------
# Cross-level listing (feeds the repetitions bell)
# ---------------------------------------------------------------------------

def list_recent_repetitions(level: str | None = None, limit: int = 20) -> list[dict]:
    level = (level or "").strip().upper() or None
    limit = max(1, min(200, int(limit or 20)))

    rows: list[dict] = []
    if level in (None, "C"):
        rows.extend(_lc_list_recent(limit))
    if level in (None, "B"):
        rows.extend(_lb_list_recent(limit))
    if level in (None, "A"):
        rows.extend(_la_list_recent(limit))

    if level is None:
        rows.sort(key=lambda r: r.get("created_at") or r.get("started_at") or "", reverse=True)
    return rows[:limit]
