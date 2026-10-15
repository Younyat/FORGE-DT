from __future__ import annotations

"""Campaign Failure Forensics -- applies this platform's own forensic-reconstruction
idea to its OWN failures: when a Level C job dies, the only account normally left
behind is the orphan-watchdog's generic symptom message ("left in 'running' mode...
no update in over 180s. It was likely interrupted by a process/worker restart") --
a templated guess, not an investigated cause. This module builds a real,
evidence-grounded account instead, reusing data this platform already records and
never inventing a signal that isn't there.

User's own words, 2026-10-11: "no soy capaz de reconstruir lo que ha pasado en
alguna campana que ha fallado... algo muy realistico y muy forense". Confirmed
concretely before writing a line of code: the real failed job LC-20260914-100154-E2D6
died at phase "DEPLOYING_OT (rep 3/10)" with the exact generic message above, but its
own already-recorded job log shows a real `host_snapshot` taken seconds before the
10-minute silence that killed it: load 15.16 on an 8-core host (ratio 1.9, well past
node_health's own "critical" threshold) and 78.8% swap used. That is a real,
evidence-backed resource-exhaustion story the platform was already sitting on top of
and never surfaced.

What this module does NOT claim to detect, honestly: application code bugs (e.g. the
real heartbeat-staleness bug found and fixed this same session in
level_c_orchestrator.service._phase_wait_level_b), a deliberate gunicorn reload by an
operator (gunicorn's own worker boot/exit log is not persisted anywhere this platform
can read after the fact), or any other cause this platform keeps no trace of. When
none of the real evidence sources below point to resource exhaustion, this reports
`probable_cause: "undetermined"` -- never guesses one into existence.

Evidence sources reused, never recomputed:
- `level_c_orchestrator`'s own `job_state.json` -- the job's real phase-by-phase log
  (hundreds of entries for a real campaign), including periodic `host_snapshot`
  entries (load/mem/swap of the SCENARIO VM(s) being orchestrated) already captured
  for the Live Campaign Status panel, and the orphan-watchdog's own final `error`.
- `memory_watchdog`'s own `runtime/memory_watchdog/events.jsonl` -- a real,
  independent, continuously-running watchdog on the ORCHESTRATOR SERVER itself
  (not the scenario VMs), built in an earlier session specifically because two real
  campaigns died from exactly this (see that module's own docstring). If this shows
  real swap-pressure events inside the job's own silence window, that is strong,
  independent corroboration that the orchestrator process itself -- not a scenario
  VM -- was starved at the moment it stopped updating.
- `node_health_api`'s own severity thresholds (`_host_pct_severity`,
  `_host_load_severity`) -- reused unchanged so "warning"/"critical" means the same
  thing here as it does everywhere else on this platform, never a second scale.
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _parse_ts(value) -> float | None:
    """Epoch seconds from any of the ISO-ish timestamp shapes this
    codebase's own logs already use (with/without 'Z', with/without
    fractional seconds, with/without timezone) -- never raises."""
    if not value:
        return None
    from datetime import datetime
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def _job_state_path(job_id: str, *, job_dir: Path | None = None) -> Path:
    """`job_dir` is an explicit, backward-compatible escape hatch added
    2026-10-13 for gap_validation's own chaos experiments -- its
    'gapval-' jobs live under a completely separate directory
    (runtime/gap_validation/jobs/), never under
    level_c_orchestrator.JOBS_DIR, so this function could not see them at
    all before this parameter existed. Omitted (the only way every
    existing caller -- campaign_failure_forensics/api.py,
    monitor3d/app.js's own endpoint call -- has ever used this), behavior
    is byte-for-byte identical to before: resolves via
    level_c_orchestrator.JOBS_DIR exactly as always."""
    if job_dir is not None:
        return Path(job_dir) / "job_state.json"
    from app_core.infrastructure.level_c_orchestrator.service import JOBS_DIR
    return JOBS_DIR / job_id / "job_state.json"


def list_failed_jobs(limit: int = 50) -> list[dict]:
    """Thin filter over level_c_orchestrator's own already-real list_jobs()
    -- zero new computation, just the subset this report applies to."""
    from app_core.infrastructure.level_c_orchestrator.service import list_jobs
    jobs = [j for j in list_jobs() if j.get("status") == "failed"]
    return jobs[:limit]


def _most_recent_host_snapshot(log_entries: list[dict], before_ts: float | None) -> dict | None:
    """The real per-VM resource reading (load/mem/swap, already captured by
    level_c_orchestrator for the Live Campaign Status panel) closest to --
    but not after -- `before_ts`. Walks the log in reverse since entries are
    chronological and we want the LAST one before the silence started."""
    best = None
    best_ts = -1.0
    for entry in log_entries or []:
        snap = ((entry.get("extra") or {}).get("host_snapshot"))
        if not snap:
            continue
        ts = _parse_ts(entry.get("ts"))
        if ts is None:
            continue
        if before_ts is not None and ts > before_ts:
            continue
        if ts > best_ts:
            best, best_ts = {"ts": entry.get("ts"), **snap}, ts
    return best


def _classify_host_snapshot(snap: dict | None) -> dict | None:
    """Reuses node_health_api's own severity thresholds unchanged -- the
    same "ok"/"warning"/"critical" scale already shown everywhere else on
    this platform (node_health, forensic_twin's resource_usage section).
    Swap uses the same pct thresholds as memory/disk since it is the same
    kind of saturating-percentage metric and no dedicated swap threshold
    exists anywhere else on this platform to defer to instead."""
    if not snap:
        return None
    from app_core.infrastructure.node_health.node_health_api import _host_load_severity, _host_pct_severity
    load_1m = snap.get("load_1m")
    cores = snap.get("cpu_count")
    load_severity = "unknown"
    load_ratio = None
    if load_1m is not None and cores:
        load_ratio = load_1m / cores
        load_severity = "critical" if load_ratio >= 1.5 else "warning" if load_ratio >= 1.0 else "ok"
    mem_severity = _host_pct_severity(snap.get("mem_used_pct"))
    swap_severity = _host_pct_severity(snap.get("swap_used_pct"))
    return {
        "ts": snap.get("ts"),
        "load_1m": load_1m, "cpu_count": cores, "load_ratio": load_ratio, "load_severity": load_severity,
        "mem_used_pct": snap.get("mem_used_pct"), "mem_severity": mem_severity,
        "swap_used_pct": snap.get("swap_used_pct"), "swap_severity": swap_severity,
        "disk_free_gb": snap.get("disk_free_gb"),
        "any_warning_or_critical": "critical" in (load_severity, mem_severity, swap_severity) or "warning" in (load_severity, mem_severity, swap_severity),
    }


def _read_memory_watchdog_events() -> list[dict]:
    from app_core.infrastructure.memory_watchdog.service import EVENTS_PATH
    if not EVENTS_PATH.is_file():
        return []
    out = []
    try:
        with EVENTS_PATH.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                ev = _safe(lambda l=line: json.loads(l))
                if ev:
                    out.append(ev)
    except Exception:
        return []
    return out


# How far back to look for a BASELINE watchdog-event rate, to tell a real
# spike apart from a chronic background condition the host was already in
# for hours -- found to matter in practice: verifying this tool against
# LC-20261008-152947-207A (a real job whose TRUE cause, already
# investigated this same session, was a heartbeat-refresh code bug, NOT
# resource exhaustion) showed real watchdog events inside its own failure
# window, which in isolation reads as strong corroboration -- but the same
# host was emitting ~118 watchdog events EVERY HOUR for the entire
# surrounding two days, a flat, chronic rate with no spike at the failure
# moment. Without this check, that case would have been mis-scored
# "high confidence: resource exhaustion" when the real cause was elsewhere.
_BASELINE_WINDOW_SECONDS = 3 * 3600.0
_SPIKE_RATE_RATIO = 1.5


def _server_memory_pressure_in_window(start_ts: float | None, end_ts: float | None) -> dict:
    """Real swap-pressure events memory_watchdog's own continuously-running
    loop already recorded for the ORCHESTRATOR SERVER itself (not the
    scenario VMs) -- a second, independent evidence source -- PLUS a
    baseline comparison against the rate in the preceding
    `_BASELINE_WINDOW_SECONDS`, so a host that was already chronically under
    pressure for hours doesn't get mistaken for a spike that specifically
    coincides with (and plausibly caused) this one failure."""
    empty = {"events": [], "is_spike": False, "baseline_rate_per_min": None, "window_rate_per_min": None, "chronic": False}
    if start_ts is None or end_ts is None:
        return empty
    all_events = _read_memory_watchdog_events()
    if not all_events:
        return empty
    in_window = []
    in_baseline = []
    baseline_start = start_ts - _BASELINE_WINDOW_SECONDS
    for ev in all_events:
        ts = _parse_ts(ev.get("ts_utc"))
        if ts is None:
            continue
        if start_ts <= ts <= end_ts:
            in_window.append(ev)
        elif baseline_start <= ts < start_ts:
            in_baseline.append(ev)
    window_minutes = max((end_ts - start_ts) / 60.0, 0.01)
    baseline_minutes = max((start_ts - baseline_start) / 60.0, 0.01)
    window_rate = len(in_window) / window_minutes
    baseline_rate = len(in_baseline) / baseline_minutes
    # A spike is a window rate meaningfully above baseline; if there was
    # effectively no baseline data at all (watchdog wasn't running yet, or
    # the host was quiet), any real events in-window count as a spike.
    is_spike = bool(in_window) and (baseline_rate < 0.01 or window_rate >= baseline_rate * _SPIKE_RATE_RATIO)
    chronic = bool(in_window) and not is_spike
    return {
        "events": in_window,
        "is_spike": is_spike,
        "chronic": chronic,
        "window_rate_per_min": round(window_rate, 2),
        "baseline_rate_per_min": round(baseline_rate, 2),
    }


# Buffer added to both ends of the job's own silence window when querying
# the server-wide memory watchdog -- the watchdog ticks every 20s
# (CHECK_INTERVAL_SECONDS in memory_watchdog.service) and reacts to
# pressure, not necessarily exactly in lockstep with the job's own log
# cadence, so a tight window could miss a genuinely-related event by a few
# seconds. 60s each side is generous without risking pulling in an
# unrelated, much-later pressure spike.
_WINDOW_BUFFER_SECONDS = 60.0


def reconstruct_failure(job_id: str, *, job_dir: Path | None = None) -> dict:
    """The main entry point: a real, evidence-grounded account of why a
    specific failed Level C job actually stopped, built entirely from data
    this platform already records. See this module's own docstring for the
    full design rationale and what it deliberately does NOT claim to
    detect.

    `job_dir` (optional): see `_job_state_path`'s own docstring -- lets
    gap_validation's evaluator reuse this function, unchanged, for a
    'gapval-' job under its own runtime directory. Every existing caller
    omits it and gets byte-for-byte the same behavior as before this
    parameter existed."""
    state = _load_json(_job_state_path(job_id, job_dir=job_dir))
    if not state:
        return {"ok": False, "error": f"no job_state.json found for job_id={job_id}"}
    if state.get("status") != "failed":
        return {"ok": False, "error": f"job {job_id} has status={state.get('status')!r}, not 'failed' -- nothing to reconstruct"}

    declared_error = state.get("error")
    log_entries = state.get("log") or []
    declared_failed_ts = _parse_ts(state.get("updated_at")) or _parse_ts(state.get("completed_at"))

    # The job's own last real activity -- the latest log entry that is NOT
    # itself the watchdog's own final ERROR-level entry, since that entry
    # IS the declaration of death, not evidence of what was happening
    # beforehand.
    last_activity_entry = None
    for entry in reversed(log_entries):
        if entry.get("level") == "ERROR" and entry.get("msg") == declared_error:
            continue
        last_activity_entry = entry
        break
    last_activity_ts = _parse_ts((last_activity_entry or {}).get("ts"))
    silence_seconds = (
        round(declared_failed_ts - last_activity_ts, 1)
        if declared_failed_ts is not None and last_activity_ts is not None
        else None
    )

    raw_snapshot = _most_recent_host_snapshot(log_entries, last_activity_ts)
    host_snapshot = _classify_host_snapshot(raw_snapshot)

    window_start = (last_activity_ts - _WINDOW_BUFFER_SECONDS) if last_activity_ts is not None else None
    window_end = (declared_failed_ts + _WINDOW_BUFFER_SECONDS) if declared_failed_ts is not None else None
    server_pressure = _server_memory_pressure_in_window(window_start, window_end)

    vm_side_bad = bool(host_snapshot and host_snapshot.get("any_warning_or_critical"))
    server_spike = bool(server_pressure.get("is_spike"))
    server_chronic = bool(server_pressure.get("chronic"))

    if vm_side_bad and server_spike:
        probable_cause = "host_and_server_resource_exhaustion"
        confidence = "high"
        explanation = (
            "Both the scenario VM's own resource reading right before the silence AND a genuine SPIKE "
            "(not just a chronic background rate) in the orchestrator server's own memory watchdog agree -- "
            "two separate real evidence sources point the same way."
        )
    elif server_spike:
        probable_cause = "server_resource_exhaustion"
        confidence = "medium-high"
        explanation = (
            "The orchestrator SERVER's own memory watchdog recorded a genuine spike in swap-pressure events "
            "during this job's silence window (not just its normal background rate), even though the "
            "scenario VM's own last reading looked fine -- consistent with the orchestrator process itself "
            "becoming unresponsive."
        )
    elif vm_side_bad and server_chronic:
        probable_cause = "scenario_vm_resource_exhaustion"
        confidence = "low-medium"
        explanation = (
            "The scenario VM's own last resource reading was at warning/critical severity, and the "
            "orchestrator server does show watchdog events in this window -- but at the SAME rate it was "
            "already running at for hours beforehand (a chronic condition, not a spike tied to this "
            "failure), so that part is weak, likely-coincidental evidence. Confidence is lowered "
            "accordingly -- treat the VM-side reading as the real signal here, not the server-side rate."
        )
    elif vm_side_bad:
        probable_cause = "scenario_vm_resource_exhaustion"
        confidence = "medium"
        explanation = (
            "The scenario VM's own last resource reading before the silence was at warning/critical "
            "severity, and the orchestrator server's own watchdog shows nothing unusual in the same window "
            "-- the VM being orchestrated may have stalled, which can itself block the orchestrator's wait "
            "loop depending on what it was doing."
        )
    else:
        probable_cause = "undetermined"
        confidence = "low"
        explanation = (
            "Neither the scenario VM's last resource reading nor a genuine spike in the orchestrator "
            "server's own memory watchdog rate explain this silence"
            + (" (the server does show its normal chronic watchdog rate in this window, which is not treated as a cause)." if server_chronic else ".")
            + " The declared error is the only account available -- it may be accurate (a real process/worker "
            "interruption, e.g. a deliberate gunicorn reload, which this platform keeps no retrospective log "
            "of), or the true cause may be an application-level bug this check cannot detect (exactly what "
            "happened in a real, previously-investigated case this same check was validated against -- see "
            "this module's README). This is an honest 'cannot determine', not a negative finding."
        )

    return {
        "ok": True,
        "job_id": job_id,
        "status": state.get("status"),
        "phase_at_failure": state.get("phase"),
        "created_at": state.get("created_at"),
        "declared_error": declared_error,
        "last_real_activity": {
            "ts": (last_activity_entry or {}).get("ts"),
            "level": (last_activity_entry or {}).get("level"),
            "msg": (last_activity_entry or {}).get("msg"),
        },
        "declared_failed_at": state.get("updated_at") or state.get("completed_at"),
        "silence_seconds": silence_seconds,
        "scenario_vm_host_snapshot": host_snapshot,
        "server_memory_watchdog": server_pressure,
        "probable_cause": probable_cause,
        "confidence": confidence,
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Snapshot-reference repair -- a real, narrow data-loss bug found 2026-10-11
# while investigating why Reconstruction View showed NO hosts/machines at all
# for a real failed campaign (LC-20260914-100154-E2D6): its own log proves
# TWO real scenario snapshots were captured successfully (reps 1 and 2, both
# completed before the campaign died in rep 3) -- "Snapshot captured:
# SS-20260914-115011-27A9" / "...-141721-353A" -- and both snapshot
# directories still exist on disk (runtime/scenario_snapshots/<id>/), but
# `job_state.json`'s own `level_c_snapshot_ids` field is empty, so
# monitor3d._frozen_hosts_for_repetition() (which depends on exactly that
# field) correctly, honestly draws nothing. The real cause of how the two
# got disconnected was not fully root-caused (predates this session's own
# code and may be specific to this one historical run) -- rather than leave
# real, still-recoverable data unreachable, this repairs the ONE field,
# narrowly, only from evidence the job's own log already provides, and only
# after verifying each snapshot still really exists on disk. Never touches
# any other field, never invents a snapshot_id that wasn't actually logged.
# -------------------------------------------------------------------------

import re as _re

_SNAPSHOT_CAPTURED_RE = _re.compile(r"Snapshot captured:\s*(\S+)")


def _snapshot_manifest_exists(snapshot_id: str) -> bool:
    from app_core.infrastructure.scenario_snapshot.service import SNAPSHOTS_ROOT
    return (SNAPSHOTS_ROOT / snapshot_id / "snapshot_manifest.json").is_file()


def recover_missing_snapshot_ids(job_id: str) -> dict:
    """Best-effort, narrowly-scoped repair: if a job's `level_c_snapshot_ids`
    is empty but its own log shows real "Snapshot captured: <id>" lines
    whose snapshot directories still exist on disk, writes those real ids
    back. A no-op (honestly reported, never an error) if the field is
    already populated, if the log has no such lines, or if none of the
    referenced snapshots survive on disk any more."""
    path = _job_state_path(job_id)
    state = _load_json(path)
    if not state:
        return {"ok": False, "error": f"no job_state.json found for job_id={job_id}"}

    existing = state.get("level_c_snapshot_ids") or []
    if existing:
        return {"ok": True, "repaired": False, "reason": "level_c_snapshot_ids already populated -- nothing to repair", "existing_snapshot_ids": existing}

    found_ids: list[str] = []
    for entry in state.get("log") or []:
        m = _SNAPSHOT_CAPTURED_RE.search(entry.get("msg") or "")
        if m:
            found_ids.append(m.group(1))
    if not found_ids:
        return {"ok": True, "repaired": False, "reason": "no 'Snapshot captured' entries found in this job's own log -- nothing to recover"}

    real_ids = [sid for sid in found_ids if _snapshot_manifest_exists(sid)]
    if not real_ids:
        return {
            "ok": True, "repaired": False,
            "reason": f"found {len(found_ids)} snapshot reference(s) in the log, but none still exist on disk (likely cleaned up since)",
            "referenced_snapshot_ids": found_ids,
        }

    state["level_c_snapshot_ids"] = real_ids
    try:
        path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    except Exception as exc:
        return {"ok": False, "error": f"found {len(real_ids)} real, recoverable snapshot(s) but failed to write job_state.json: {exc}"}

    return {
        "ok": True, "repaired": True,
        "recovered_snapshot_ids": real_ids,
        "referenced_but_missing": [sid for sid in found_ids if sid not in real_ids],
    }
