from __future__ import annotations

"""Per-gap validation report -- aggregates every completed gap-validation
campaign ever run for a gap's linked experiments (evaluator.py's own
scoring, never re-derived) into one formal verdict. Four states only,
deliberately never "closed"/"proven" -- a gap this platform's own
mechanism answers is still a claim about THIS platform's behavior under
THESE specific tested conditions, not a general scientific proof:

- not_evaluated       -- no completed campaign exists yet for this gap.
- not_supported       -- campaigns ran, but detection coverage stayed at
                          or near zero, or every run failed outright.
- partially_supported -- some real detection happened, but coverage is
                          below threshold, false positives are above
                          threshold, dispersion across repetitions is
                          high, or at least one run's own campaign status
                          was "failed" (an unresolved confound -- this
                          round does not yet distinguish an injected
                          failure from a platform bug, see evaluator.py's
                          own docstring, so a failed run is scored
                          conservatively rather than ignored).
- supported_under_tested_conditions -- coverage and false-positive rate
                          both clear their threshold, dispersion is low,
                          and no run failed -- stated with the sample
                          size that produced it, never silently implying
                          more confidence than the repetition count
                          supports.
"""

import statistics

from .registry import get_gap
from .catalog import experiments_for_gap, get_experiment
from .orchestrator import list_validation_campaigns
from .evaluator import evaluate_experiment_run

# Thresholds -- documented here, not hidden constants: a gap needs at
# least this much real detection coverage, at most this much false-positive
# rate, and at most this much dispersion (population stdev of the
# per-run coverage rates) across its own runs to be called "supported
# under tested conditions". Deliberately conservative defaults; revisit
# once more real campaigns exist to calibrate against.
_COVERAGE_THRESHOLD = 0.8
_FALSE_POSITIVE_THRESHOLD = 0.2
_DISPERSION_THRESHOLD = 0.25
_MIN_REPETITIONS_FOR_CONFIDENCE = 4


def _mean(values: list[float]) -> float | None:
    return round(statistics.mean(values), 4) if values else None


def _pstdev(values: list[float]) -> float:
    return round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0


def build_gap_validation_report(gap_id: str) -> dict:
    gap = get_gap(gap_id)
    if not gap:
        return {"ok": False, "error": f"unknown gap_id={gap_id!r}"}

    experiments = experiments_for_gap(gap_id)
    experiment_ids = {e["experiment_id"] for e in experiments}

    if not experiment_ids:
        return {
            "ok": True, "gap_id": gap_id, "title": gap["title"], "mechanism": gap["mechanism"],
            "verdict": "not_evaluated",
            "plain_language": (
                "This gap has no automated experiment linked to it yet -- it is either a human-factors "
                "study or a literature-mapping task this platform cannot run on its own, by design."
            ),
            "total_runs": 0, "total_repetitions": 0, "runs": [],
        }

    all_campaigns = [c for c in list_validation_campaigns(limit=1000) if c["experiment_id"] in experiment_ids]
    finished = [c for c in all_campaigns if c.get("status") in ("completed", "failed")]

    if not finished:
        return {
            "ok": True, "gap_id": gap_id, "title": gap["title"], "mechanism": gap["mechanism"],
            "verdict": "not_evaluated",
            "plain_language": (
                "An experiment is defined for this gap, but no validation campaign has finished running "
                "yet -- launch one from the Scientific Validation panel to produce a real verdict."
            ),
            "total_runs": 0, "total_repetitions": 0, "runs": [],
        }

    runs = []
    any_failed_job = False
    failed_job_confounds = []
    for campaign in finished:
        campaign_experiment = get_experiment(campaign["experiment_id"])
        # orchestrator_failure's campaign job is EXPECTED to end
        # status='failed' -- that is its success condition, not a
        # confound to flag (see evaluator.py's own
        # _evaluate_orchestrator_failure_run, which already scores it via
        # detection_coverage_rate instead).
        expected_failure_by_design = bool(campaign_experiment and campaign_experiment.get("verification") == "orchestrator_crash_confound_check")
        if campaign.get("status") == "failed" and not expected_failure_by_design:
            any_failed_job = True
        result = evaluate_experiment_run(campaign["job_id"])
        if result.get("ok"):
            runs.append(result)
            if result.get("job_status") == "failed" and result.get("confound_analysis") and not expected_failure_by_design:
                failed_job_confounds.append(result["confound_analysis"])

    coverages = [r["detection_coverage_rate"] for r in runs if r.get("detection_coverage_rate") is not None]
    false_positives = [r["false_positive_rate"] for r in runs if r.get("false_positive_rate") is not None]
    total_repetitions = sum(len(r.get("repetitions") or []) for r in runs)

    mean_coverage = _mean(coverages)
    mean_fp = _mean(false_positives)
    coverage_dispersion = _pstdev(coverages)

    # recovery_capability: a real, measured post-revert check (see
    # orchestrator.py::_run_recovery_check), never just "revert_fault
    # returned ok=True" -- simple mean-of-per-run-means, informative only,
    # does not drive the verdict (a slow-but-eventual recovery is a
    # real finding worth surfacing, not grounds to downgrade "supported").
    recovery_times = [
        r["recovery_capability"]["mean_recovery_check_seconds"] for r in runs
        if r.get("recovery_capability") and r["recovery_capability"].get("mean_recovery_check_seconds") is not None
    ]
    recovery_rates = [
        r["recovery_capability"]["recovery_success_rate"] for r in runs
        if r.get("recovery_capability") and r["recovery_capability"].get("recovery_success_rate") is not None
    ]
    mean_recovery_seconds = _mean(recovery_times)
    mean_recovery_success_rate = _mean(recovery_rates)

    if any_failed_job:
        verdict = "partially_supported"
        # Real, evidence-grounded account of WHY the campaign job itself
        # failed (campaign_failure_forensics.reconstruct_failure, reused
        # unchanged via its job_dir parameter) -- never silently discarded.
        # The verdict still stays conservative either way: a confound
        # explains the failure, it does not erase it.
        confound_causes = {c.get("probable_cause") for c in failed_job_confounds if c and c.get("ok")}
        if confound_causes:
            causes_text = ", ".join(sorted(c.replace("_", " ") for c in confound_causes if c))
            plain = (
                f"At least one validation campaign for this gap ended with status='failed'. Real evidence "
                f"(campaign_failure_forensics) attributes the failure to: {causes_text} -- review the "
                "campaign's own log and this analysis before trusting the verdict; a resource-related cause "
                "here would mean the gap itself was never really tested, not that it failed."
            )
        else:
            plain = (
                "At least one validation campaign for this gap ended with status='failed' rather than "
                "completing cleanly, and no real evidence could be gathered about why (see each campaign's "
                "own log) -- scored conservatively rather than ignored."
            )
    elif mean_coverage is None:
        # control-only experiments (no detection target by design) -- judged purely on false positives.
        if mean_fp is not None and mean_fp <= _FALSE_POSITIVE_THRESHOLD:
            verdict = "supported_under_tested_conditions"
            plain = (
                f"This gap's experiment(s) have no detection target by design (a control-arm baseline). "
                f"Across {total_repetitions} real repetition(s), the platform's own false-positive rate "
                f"stayed at {mean_fp:.0%}, at or below the {_FALSE_POSITIVE_THRESHOLD:.0%} threshold."
            )
        else:
            verdict = "not_evaluated"
            plain = "No false-positive-bearing control repetitions have completed yet for this gap's experiment(s)."
    elif mean_coverage <= 0.0:
        verdict = "not_supported"
        plain = (
            f"Across {total_repetitions} real repetition(s), the platform never produced the expected "
            "signal when the fault was actually applied -- the mechanism this gap relies on did not "
            "show up under the conditions tested."
        )
    elif (
        mean_coverage >= _COVERAGE_THRESHOLD
        and (mean_fp is None or mean_fp <= _FALSE_POSITIVE_THRESHOLD)
        and coverage_dispersion <= _DISPERSION_THRESHOLD
    ):
        verdict = "supported_under_tested_conditions"
        confidence_note = (
            "" if total_repetitions >= _MIN_REPETITIONS_FOR_CONFIDENCE else
            f" (only {total_repetitions} repetition(s) so far -- treat this as preliminary, not conclusive)"
        )
        recovery_note = (
            f" Confirmed real recovery (not just a successful revert call) in {mean_recovery_success_rate:.0%} "
            f"of applicable repetitions, averaging {mean_recovery_seconds}s to confirm."
            if mean_recovery_seconds is not None else ""
        )
        plain = (
            f"Across {total_repetitions} real repetition(s), detection coverage averaged {mean_coverage:.0%} "
            f"with a {mean_fp:.0%} false-positive rate" if mean_fp is not None else
            f"Across {total_repetitions} real repetition(s), detection coverage averaged {mean_coverage:.0%}"
        ) + f" -- the mechanism behind this gap worked reliably under the tested conditions{confidence_note}.{recovery_note}"
    else:
        verdict = "partially_supported"
        plain = (
            f"Across {total_repetitions} real repetition(s), detection coverage averaged {mean_coverage:.0%} "
            f"(threshold {_COVERAGE_THRESHOLD:.0%}), false-positive rate "
            f"{mean_fp:.0%} (threshold {_FALSE_POSITIVE_THRESHOLD:.0%}), dispersion {coverage_dispersion:.2f} "
            f"(threshold {_DISPERSION_THRESHOLD:.2f}) -- some real detection happened, but not reliably "
            "enough across repetitions to call this fully supported yet."
            if mean_fp is not None else
            f"Across {total_repetitions} real repetition(s), detection coverage averaged {mean_coverage:.0%} "
            f"but did not consistently clear the {_COVERAGE_THRESHOLD:.0%} threshold with low enough "
            "dispersion to call this fully supported yet."
        )

    return {
        "ok": True,
        "gap_id": gap_id,
        "title": gap["title"],
        "mechanism": gap["mechanism"],
        "verdict": verdict,
        "plain_language": plain,
        "total_runs": len(runs),
        "total_repetitions": total_repetitions,
        "mean_detection_coverage_rate": mean_coverage,
        "mean_false_positive_rate": mean_fp,
        "coverage_dispersion": coverage_dispersion,
        "mean_recovery_check_seconds": mean_recovery_seconds,
        "mean_recovery_success_rate": mean_recovery_success_rate,
        "any_failed_job": any_failed_job,
        "thresholds": {
            "coverage": _COVERAGE_THRESHOLD,
            "false_positive": _FALSE_POSITIVE_THRESHOLD,
            "dispersion": _DISPERSION_THRESHOLD,
            "min_repetitions_for_confidence": _MIN_REPETITIONS_FOR_CONFIDENCE,
        },
        "runs": [{"job_id": r["job_id"], "detection_coverage_rate": r.get("detection_coverage_rate"),
                   "false_positive_rate": r.get("false_positive_rate"), "job_status": r.get("job_status")}
                  for r in runs],
    }
