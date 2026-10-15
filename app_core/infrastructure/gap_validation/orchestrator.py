from __future__ import annotations

"""Experiment orchestrator -- runs a real gap-validation campaign for one
EXPERIMENT_CATALOG entry whose `implementation_status` is "ready" (its
`fault_id`, if any, already exists unchanged in
fault_injection.catalog.FAULT_CATALOG). Reuses, never reimplements:

- `level_c_orchestrator._fault_schedule_condition` -- the exact same
  Barlow & Hayes (1979) strict-alternation rule Level C campaigns already
  use, so "control" vs "treatment" means the same thing here as it does
  there.
- `fault_injection.apply_fault`/`revert_fault` -- the exact same call the
  Fault Injection dashboard's own on-demand buttons make. These ALREADY
  notify both `forensic_twin` (a real lifecycle event) and the
  Intervention Ledger (a real `record_intervention` entry) on every call
  (fault_injection/service.py:495-496, 556-557) -- this module adds no
  separate Ledger-recording code of its own.
- `forensic_twin.check_node_state` -- the same real tools+clock(+PLC) check
  the Digital Twin View uses, called once per repetition to capture
  whatever divergence (or absence of one) actually happened.

Runs as a background thread, exactly like level_c_orchestrator's own job
model, but in its OWN job-id space and its OWN runtime directory --
`runtime/gap_validation/jobs/<job_id>/job_state.json` -- a `gapval-`
prefixed job_id can never collide with, and this module never reads or
writes, `runtime/level_c_jobs/`. No past campaign's result is read or
altered by anything in this file.
"""

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .catalog import get_experiment

PROJECT_ROOT = Path(__file__).resolve().parents[3]
JOBS_DIR = PROJECT_ROOT / "runtime" / "gap_validation" / "jobs"

# Which node role each existing fault_id is meaningfully applied against --
# matches the role each fault's own effectiveness_signal already assumes
# in fault_injection/catalog.py (plc_io_manipulation/clock_skew target the
# PLC's own state; detection_outage targets the monitor's detection
# service). The no-fault baseline experiment has no fault_id, so it simply
# falls back to "plc" -- any live node works equally well for a pure
# check_node_state baseline.
_DEFAULT_ROLE_FOR_FAULT = {
    "plc_io_manipulation": "plc",
    "clock_skew": "plc",
    "detection_outage": "monitor",
}

# Hold time between applying a treatment fault and checking for its effect
# -- bounded by, never exceeding, the experiment's own declared
# safety.max_duration_seconds (gap_validation/catalog.py), with a floor so
# a real effect has time to actually appear before the check.
_MIN_HOLD_SECONDS = 15.0
_MAX_HOLD_SECONDS = 60.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_job_id() -> str:
    return f"gapval-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"


def _job_dir(job_id: str) -> Path:
    return JOBS_DIR / job_id


def _save_state(job_dir: Path, state: dict) -> None:
    job_dir.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = _utc_now()
    (job_dir / "job_state.json").write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")


def _load_state(job_id: str) -> dict | None:
    path = _job_dir(job_id) / "job_state.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _log(state: dict, level: str, msg: str) -> None:
    state.setdefault("log", []).append({"ts": _utc_now(), "level": level, "msg": msg})


def _safe(fn, default=None):
    try:
        return fn()
    except Exception as exc:
        return default if default is not None else {"ok": False, "error": str(exc)}


def _resolve_node_by_role(role: str) -> dict | None:
    from app_core.infrastructure.node_health.node_health_api import _list_nodes
    nodes = _list_nodes()
    return next((n for n in nodes if str(n.get("role") or "").lower() == str(role or "").lower()), None)


def _default_params_for(fault_id: str | None) -> dict:
    if not fault_id:
        return {}
    from app_core.infrastructure.fault_injection.catalog import get_fault
    fault = get_fault(fault_id)
    if not fault:
        return {}
    return {k: spec.get("default") for k, spec in (fault.get("params_schema") or {}).items()}


# Substring unique to scenario_snapshot's own forced-failure message
# (force_capture_snapshot_failure_once's docstring) -- matched rather than
# an exact-equality check so a future wording tweak over there doesn't
# silently break this check.
_FORCED_FAILURE_MARKER = "gap_validation acquisition_failure experiment"

# Single-shot, opt-in test hook for the orchestrator_failure experiment --
# makes THIS module's own _run_campaign loop raise a deliberate exception
# during its next repetition step, consumed and cleared immediately. Armed
# only via fault_injection.apply_fault("orchestrator_failure", ...) (same
# pattern as scenario_snapshot's own force_capture_snapshot_failure_once).
# Structurally safe: this flag is only ever CHECKED inside _run_campaign
# below, which only ever runs for a 'gapval-' job_id (_new_job_id's own
# format) -- there is no code path by which a real Level C campaign could
# ever be affected by it, not merely a runtime allowlist check.
_FORCE_ORCHESTRATOR_FAILURE_FLAG = PROJECT_ROOT / "runtime" / "gap_validation" / "sandbox" / "force_orchestrator_failure_once.flag"


def force_orchestrator_failure_once() -> None:
    _FORCE_ORCHESTRATOR_FAILURE_FLAG.parent.mkdir(parents=True, exist_ok=True)
    _FORCE_ORCHESTRATOR_FAILURE_FLAG.write_text("1", encoding="utf-8")


def is_orchestrator_failure_armed() -> bool:
    return _FORCE_ORCHESTRATOR_FAILURE_FLAG.is_file()


def disarm_orchestrator_failure_once() -> None:
    _FORCE_ORCHESTRATOR_FAILURE_FLAG.unlink(missing_ok=True)


def _run_verification_check(experiment: dict, node: dict) -> dict:
    """Runs whichever real check this experiment's own `verification`
    field (catalog.py) declares, and normalizes the result into the same
    {"ok": bool, "new_events": [...]} shape regardless of which one ran --
    so the per-repetition loop above, and evaluator.py downstream, never
    need to know which verification mechanism produced it."""
    verification = experiment.get("verification") or "forensic_twin_check_node_state"
    if verification == "capture_snapshot_once":
        from app_core.infrastructure.scenario_snapshot.service import capture_snapshot
        result = _safe(lambda: capture_snapshot(), default={"status": "ERROR", "error": "capture_snapshot() raised an exception"})
        forced = isinstance(result, dict) and result.get("status") == "ERROR" and _FORCED_FAILURE_MARKER in (result.get("error") or "")
        new_events = [{"event_type": "capture_snapshot_forced_failure", "evidence": (result or {}).get("error")}] if forced else []
        return {"ok": isinstance(result, dict), "new_events": new_events}
    from app_core.infrastructure.forensic_twin.service import check_node_state
    twin_result = _safe(lambda: check_node_state(node["id"], source="gap_validation"))
    return {
        "ok": bool((twin_result or {}).get("ok")),
        "new_events": ((twin_result or {}).get("state") or {}).get("new_events") or [],
    }


def _run_recovery_check(experiment: dict, node: dict) -> dict:
    """After a treatment fault is reverted, runs ONE more real
    forensic_twin.check_node_state call and measures whether the
    originally-expected divergence event_type is now gone -- a real,
    measured recovery_capability signal, not merely 'revert_fault returned
    ok=True' (which only confirms the revert CALL succeeded, not that the
    twin's own state has actually settled back to baseline). Only
    meaningful for the "forensic_twin_check_node_state" verification mode
    -- the other two (capture_snapshot_once's single-shot flag,
    orchestrator_crash_confound_check's deliberate crash) have no
    comparable notion of a node settling back down, so this returns
    {"applicable": False} for those (and for the control-only baseline,
    which has no expected_event_types to check recovery against)."""
    expected_types = set(experiment.get("expected_event_types") or [])
    if not expected_types or experiment.get("verification") not in (None, "forensic_twin_check_node_state"):
        return {"applicable": False}
    from app_core.infrastructure.forensic_twin.service import check_node_state
    start = time.monotonic()
    twin_result = _safe(lambda: check_node_state(node["id"], source="gap_validation_recovery"))
    elapsed = round(time.monotonic() - start, 2)
    observed_types = {ev.get("event_type") for ev in ((twin_result or {}).get("state") or {}).get("new_events") or []}
    recovered = not (observed_types & expected_types)
    return {
        "applicable": True, "recovered": recovered, "check_seconds": elapsed,
        "observed_event_types": sorted(observed_types),
    }


def _hold_seconds_for(experiment: dict) -> float:
    # NOT `... or _MIN_HOLD_SECONDS` -- an explicit 0 (state_divergence_baseline,
    # acquisition_failure) is falsy in Python, so that would have silently
    # replaced a deliberate "no hold needed" with the 15s default instead of
    # honoring it. Found and fixed 2026-10-13 while wiring acquisition_failure.
    safety = experiment.get("safety") or {}
    max_dur = safety.get("max_duration_seconds")
    if max_dur is None:
        max_dur = _MIN_HOLD_SECONDS
    if max_dur <= 0:
        return 0.0
    return max(_MIN_HOLD_SECONDS, min(float(max_dur), _MAX_HOLD_SECONDS))


def launch_validation_campaign(experiment_id: str, *, repetitions: int = 4, target_node_role: str | None = None) -> dict:
    """Starts a real gap-validation campaign in the background, returns
    immediately. `repetitions` must be >= 2 so a real control/treatment
    alternation is possible (a single repetition can't be compared against
    anything)."""
    experiment = get_experiment(experiment_id)
    if not experiment:
        return {"ok": False, "error": f"unknown experiment_id={experiment_id!r}"}
    if experiment.get("implementation_status") != "ready":
        return {"ok": False, "error": (
            f"experiment {experiment_id!r} is not runnable yet "
            f"(implementation_status={experiment.get('implementation_status')!r}) -- "
            "it references a fault_id not yet added to fault_injection's catalog"
        )}
    try:
        repetitions = int(repetitions)
    except (TypeError, ValueError):
        return {"ok": False, "error": "repetitions must be an integer"}
    # orchestrator_failure is a single deliberate crash, not a repeatable
    # alternating-treatments measurement -- it has no control arm by design
    # (see its own catalog entry), so repetitions=1 is valid for it alone.
    min_repetitions = 1 if experiment.get("verification") == "orchestrator_crash_confound_check" else 2
    if repetitions < min_repetitions:
        return {"ok": False, "error": f"repetitions must be >= {min_repetitions} for this experiment"}

    fault_id = experiment.get("fault_id")
    role = target_node_role or _DEFAULT_ROLE_FOR_FAULT.get(fault_id, "plc")

    job_id = _new_job_id()
    job_dir = _job_dir(job_id)
    state = {
        "job_id": job_id,
        "experiment_id": experiment_id,
        "gap_ids": experiment["gap_ids"],
        "fault_id": fault_id,
        "target_node_role": role,
        "repetitions": repetitions,
        "status": "running",
        "current_repetition": 0,
        "created_at": _utc_now(),
        "repetition_results": [],
        "log": [],
    }
    _log(state, "INFO", (
        f"Launching gap-validation campaign {job_id} for experiment={experiment_id!r} "
        f"({repetitions} repetitions, fault_id={fault_id!r}, target_role={role!r}, "
        f"gap_ids={experiment['gap_ids']})."
    ))
    _save_state(job_dir, state)

    thread = threading.Thread(target=_run_campaign, args=(job_id,), daemon=True)
    thread.start()
    return {"ok": True, "job_id": job_id, "status": "running"}


def _run_campaign(job_id: str) -> None:
    state = _load_state(job_id)
    if not state:
        return
    job_dir = _job_dir(job_id)
    experiment = get_experiment(state["experiment_id"])
    fault_id = state.get("fault_id")
    role = state.get("target_node_role")
    repetitions = state.get("repetitions", 4)
    hold_seconds = _hold_seconds_for(experiment or {})

    try:
        from app_core.infrastructure.level_c_orchestrator.service import _fault_schedule_condition
        from app_core.infrastructure.fault_injection.service import apply_fault, revert_fault

        node = _resolve_node_by_role(role)
        if not node:
            state["status"] = "failed"
            state["error"] = f"no live node found for role={role!r}"
            _log(state, "ERROR", state["error"])
            _save_state(job_dir, state)
            return

        fault_schedule = {"fault_ids": [fault_id], "start_with": "control", "target_role": role} if fault_id else None
        # orchestrator_failure has no control arm (single deliberate crash,
        # see launch_validation_campaign's own comment) -- its one
        # repetition is always "treatment".
        force_treatment = experiment.get("verification") == "orchestrator_crash_confound_check"

        for rep in range(1, repetitions + 1):
            state["current_repetition"] = rep
            condition = "treatment" if force_treatment else (_fault_schedule_condition(fault_schedule, rep) if fault_id else "control")
            _log(state, "INFO", f"[Rep {rep}/{repetitions}] condition={condition}")
            _save_state(job_dir, state)

            injection_id = None
            apply_error = None
            if condition == "treatment" and fault_id:
                params = _default_params_for(fault_id)
                result = apply_fault(fault_id, node["id"], params, campaign_id=job_id)
                if result.get("ok"):
                    injection_id = (result.get("record") or {}).get("injection_id")
                    _log(state, "INFO", f"[Rep {rep}] applied fault_id={fault_id!r} injection_id={injection_id!r}")
                else:
                    apply_error = result.get("error") or (result.get("record") or {}).get("errors")
                    _log(state, "WARN", f"[Rep {rep}] apply_fault failed: {apply_error}")

            # orchestrator_failure's whole point: the fault just armed above
            # doesn't act on any external system -- consuming it HERE, by
            # deliberately raising, IS the fault's real effect. Propagates to
            # the outer except below, exactly like a genuine orchestrator bug
            # would -- reusing that existing failure-handling path unchanged.
            if fault_id == "orchestrator_failure" and injection_id and is_orchestrator_failure_armed():
                disarm_orchestrator_failure_once()
                raise RuntimeError(
                    f"gap_validation orchestrator_failure experiment: deliberate forced failure "
                    f"(single-shot, injection_id={injection_id!r})"
                )

            if hold_seconds > 0:
                time.sleep(hold_seconds)

            check_result = _run_verification_check(experiment, node)

            revert_ok = None
            if injection_id:
                revert_result = revert_fault(injection_id)
                revert_ok = revert_result.get("ok")
                _log(state, "INFO", f"[Rep {rep}] reverted injection_id={injection_id!r} -> ok={revert_ok}")

            recovery_check = {"applicable": False}
            if injection_id and revert_ok:
                recovery_check = _run_recovery_check(experiment, node)
                if recovery_check.get("applicable"):
                    _log(state, "INFO", (
                        f"[Rep {rep}] post-revert recovery check: recovered={recovery_check.get('recovered')} "
                        f"(check took {recovery_check.get('check_seconds')}s)"
                    ))

            state.setdefault("repetition_results", []).append({
                "repetition": rep,
                "condition": condition,
                "injection_id": injection_id,
                "apply_error": apply_error,
                "revert_ok": revert_ok,
                "twin_check_ok": check_result["ok"],
                "new_events": check_result["new_events"],
                "recovery_check": recovery_check,
                "checked_at": _utc_now(),
            })
            _save_state(job_dir, state)

        state["status"] = "completed"
        state["completed_at"] = _utc_now()
        _log(state, "INFO", f"Campaign {job_id} completed.")
        _save_state(job_dir, state)
    except Exception as exc:
        state["status"] = "failed"
        state["error"] = str(exc)
        _log(state, "ERROR", f"Campaign {job_id} failed with an unhandled exception: {exc}")
        _save_state(job_dir, state)


def get_validation_campaign_status(job_id: str) -> dict:
    state = _load_state(job_id)
    if not state:
        return {"ok": False, "error": f"no gap-validation job found for job_id={job_id!r}"}
    return {"ok": True, "state": state}


def list_validation_campaigns(limit: int = 50) -> list[dict]:
    """Lightweight listing -- same shape level_c_orchestrator.list_jobs()
    uses, scoped to this module's own job directory only."""
    if not JOBS_DIR.is_dir():
        return []
    jobs = []
    for job_dir in JOBS_DIR.iterdir():
        if not job_dir.is_dir():
            continue
        state = _load_state(job_dir.name)
        if not state:
            continue
        jobs.append({
            "job_id": state.get("job_id"),
            "experiment_id": state.get("experiment_id"),
            "gap_ids": state.get("gap_ids"),
            "status": state.get("status"),
            "current_repetition": state.get("current_repetition"),
            "repetitions": state.get("repetitions"),
            "created_at": state.get("created_at"),
            "updated_at": state.get("updated_at"),
        })
    jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
    return jobs[:limit]
