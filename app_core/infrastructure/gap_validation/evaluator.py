from __future__ import annotations

"""Automated evaluator -- scores a completed gap-validation campaign
(orchestrator.py) against its experiment's own declared
`expected_event_types` (catalog.py), repetition by repetition. Never
re-derives a divergence signal: every repetition's `new_events` was
already produced by the real `forensic_twin.check_node_state` call the
orchestrator made and persisted verbatim in `job_state.json` -- this
module only reads that back and compares it against what the catalog
says should have appeared.

Confound detection: if the gap-validation CAMPAIGN JOB itself ended with
status="failed" (its own background thread hit an unhandled exception --
not merely a fault that failed to apply, which is recorded per-repetition
and handled normally), this calls
`campaign_failure_forensics.reconstruct_failure(job_id, job_dir=...)`
unchanged, via the backward-compatible `job_dir` parameter added
2026-10-13 (campaign_failure_forensics/service.py's own `_job_state_path`
docstring) specifically so it can see a 'gapval-' job under this module's
own `runtime/gap_validation/jobs/`, which it could not before that
parameter existed. This is the real, evidence-grounded account of WHETHER
a campaign's failure was a platform/resource problem (a confound -- not
informative about the gap being tested) versus something else -- attached
as `confound_analysis`, never silently discarded.
"""

from .catalog import get_experiment
from .orchestrator import _job_dir, get_validation_campaign_status

# campaign_failure_forensics.reconstruct_failure's own resource-exhaustion
# probable_cause values (service.py) -- used by
# _evaluate_orchestrator_failure_run to confirm it does NOT falsely claim
# one of these for a failure that was actually a deliberate code-level
# crash with zero real resource pressure behind it.
_RESOURCE_EXHAUSTION_CAUSES = (
    "host_and_server_resource_exhaustion", "server_resource_exhaustion", "scenario_vm_resource_exhaustion",
)


def _safe(fn):
    try:
        return fn()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _evaluate_orchestrator_failure_run(job_id: str, state: dict, experiment: dict) -> dict:
    """orchestrator_failure succeeds, by design, when the campaign job
    itself ends status='failed' AND campaign_failure_forensics.
    reconstruct_failure (reused via its job_dir parameter) correctly
    avoids a false resource-exhaustion attribution for what is actually a
    deliberately injected code-level crash -- it has no category for that
    real cause, so the honest, calibrated answer is probable_cause=
    'undetermined'. No control arm (see this experiment's own catalog
    entry) -- `detection_coverage_rate`/`false_positive_rate` keys are
    still populated (coverage=1.0 if correctly calibrated, else 0.0; no
    false-positive concept applies) purely so report.py's existing
    aggregation math works unchanged on this experiment's results too."""
    job_status = state.get("status")
    if job_status != "failed":
        return {
            "ok": True, "job_id": job_id, "experiment_id": state["experiment_id"], "gap_ids": experiment["gap_ids"],
            "job_status": job_status, "confound_analysis": None,
            "detection_coverage_rate": 0.0, "false_positive_rate": None,
            "repetitions": [{"repetition": 1, "condition": "treatment", "detected": False,
                              "matched_expected_event_types": [], "observed_event_types": [],
                              "twin_check_ok": None, "apply_error": None}],
            "is_control_only_experiment": False, "expected_event_types": [],
            "recovery_capability": {"applicable_repetitions": 0, "recovered_repetitions": 0, "recovery_success_rate": None, "mean_recovery_check_seconds": None},
            "note": "expected the campaign job to end status='failed' by design -- it did not",
        }
    from app_core.infrastructure.campaign_failure_forensics.service import reconstruct_failure
    confound_analysis = _safe(lambda: reconstruct_failure(job_id, job_dir=_job_dir(job_id)))
    probable_cause = (confound_analysis or {}).get("probable_cause")
    falsely_blamed_resources = probable_cause in _RESOURCE_EXHAUSTION_CAUSES
    detected = bool(confound_analysis and confound_analysis.get("ok")) and not falsely_blamed_resources
    return {
        "ok": True, "job_id": job_id, "experiment_id": state["experiment_id"], "gap_ids": experiment["gap_ids"],
        "job_status": job_status, "confound_analysis": confound_analysis, "probable_cause": probable_cause,
        "detection_coverage_rate": 1.0 if detected else 0.0, "false_positive_rate": None,
        "repetitions": [{"repetition": 1, "condition": "treatment", "detected": detected,
                          "matched_expected_event_types": ["orchestrator_failure_correctly_calibrated"] if detected else [],
                          "observed_event_types": [], "twin_check_ok": None, "apply_error": None}],
        "is_control_only_experiment": False, "expected_event_types": [],
        "recovery_capability": {"applicable_repetitions": 0, "recovered_repetitions": 0, "recovery_success_rate": None, "mean_recovery_check_seconds": None},
    }


def evaluate_experiment_run(job_id: str) -> dict:
    """Per-repetition detection scoring for one gap-validation campaign.
    Returns {ok, job_id, experiment_id, gap_ids, repetitions: [...],
    detection_coverage_rate, false_positive_rate} -- or {ok: False, error}
    if the job doesn't exist, hasn't finished, or its experiment has no
    machine-checkable signal defined yet."""
    status = get_validation_campaign_status(job_id)
    if not status.get("ok"):
        return status
    state = status["state"]
    if state.get("status") not in ("completed", "failed"):
        return {"ok": False, "error": f"job {job_id} is still running (status={state.get('status')!r}) -- nothing to evaluate yet"}

    experiment = get_experiment(state["experiment_id"])
    if not experiment:
        return {"ok": False, "error": f"job {job_id} references unknown experiment_id={state['experiment_id']!r}"}

    if experiment.get("verification") == "orchestrator_crash_confound_check":
        return _evaluate_orchestrator_failure_run(job_id, state, experiment)

    expected_types = set(experiment.get("expected_event_types") or [])
    is_control_only_experiment = experiment.get("fault_id") is None

    scored_reps = []
    for rep in state.get("repetition_results", []):
        observed_types = {ev.get("event_type") for ev in (rep.get("new_events") or [])}
        matched = sorted(observed_types & expected_types)
        scored_reps.append({
            "repetition": rep["repetition"],
            "condition": rep["condition"],
            "observed_event_types": sorted(observed_types),
            "matched_expected_event_types": matched,
            "detected": bool(matched),
            "twin_check_ok": rep.get("twin_check_ok"),
            "apply_error": rep.get("apply_error"),
            "recovery_check": rep.get("recovery_check"),
        })

    treatment_reps = [r for r in scored_reps if r["condition"] == "treatment"]
    control_reps = [r for r in scored_reps if r["condition"] == "control"]

    if not expected_types:
        # A pure control-arm baseline experiment (e.g. state_divergence_baseline):
        # there is nothing to "detect" by design -- what's measured is simply
        # whether the twin stayed quiet (its own real false-positive rate).
        detection_coverage_rate = None
        false_positive_rate = (
            round(sum(1 for r in control_reps if r["detected"]) / len(control_reps), 4)
            if control_reps else None
        )
    else:
        detection_coverage_rate = (
            round(sum(1 for r in treatment_reps if r["detected"]) / len(treatment_reps), 4)
            if treatment_reps else None
        )
        false_positive_rate = (
            round(sum(1 for r in control_reps if r["detected"]) / len(control_reps), 4)
            if control_reps else None
        )

    confound_analysis = None
    if state.get("status") == "failed":
        from app_core.infrastructure.campaign_failure_forensics.service import reconstruct_failure
        confound_analysis = _safe(lambda: reconstruct_failure(job_id, job_dir=_job_dir(job_id)))

    # recovery_capability: NOT "did revert_fault return ok=True" (that only
    # confirms the revert CALL succeeded) -- a real, measured post-revert
    # forensic_twin.check_node_state confirming the node's own divergence
    # actually cleared, and how long that confirmation took.
    applicable_checks = [r["recovery_check"] for r in scored_reps if (r.get("recovery_check") or {}).get("applicable")]
    recovered_checks = [rc for rc in applicable_checks if rc.get("recovered")]
    recovery_capability = {
        "applicable_repetitions": len(applicable_checks),
        "recovered_repetitions": len(recovered_checks),
        "recovery_success_rate": round(len(recovered_checks) / len(applicable_checks), 4) if applicable_checks else None,
        "mean_recovery_check_seconds": (
            round(sum(rc["check_seconds"] for rc in recovered_checks) / len(recovered_checks), 2)
            if recovered_checks else None
        ),
    }

    return {
        "ok": True,
        "job_id": job_id,
        "experiment_id": state["experiment_id"],
        "gap_ids": experiment["gap_ids"],
        "job_status": state.get("status"),
        "is_control_only_experiment": is_control_only_experiment,
        "expected_event_types": sorted(expected_types),
        "repetitions": scored_reps,
        "detection_coverage_rate": detection_coverage_rate,
        "false_positive_rate": false_positive_rate,
        "confound_analysis": confound_analysis,
        "recovery_capability": recovery_capability,
    }
