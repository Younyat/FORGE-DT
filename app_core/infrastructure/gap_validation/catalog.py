from __future__ import annotations

"""Experiment catalog -- data only, no logic. Every entry names exactly
which gap(s) (gap_validation/registry.py) it evaluates -- this is NOT a
generic attack/fault collection; an entry with no gap_ids would be a bug in
this file, not a valid experiment.

`implementation_status`:
  - "ready" -- `fault_id` (if any) already exists in
    fault_injection/catalog.py::FAULT_CATALOG, unchanged. These experiments
    can run today, reusing apply_fault/revert_fault exactly as the Fault
    Injection dashboard's own on-demand buttons do.
  - "planned" -- `fault_id` does not exist yet; it is a NEW fault type to be
    added to FAULT_CATALOG in a later implementation round, following the
    exact same schema (reversible, bounded params_schema,
    effectiveness_signal) and, for evidence_loss/record_corruption/
    orchestrator_failure, an explicit sandbox/allowlist guard checked in
    code -- see this module's README for the isolation rules. Listed here
    now so the Gap-Experiment-Evidence matrix is complete even for the
    experiments not yet runnable.

`fault_id=None` means no fault is injected at all -- the experiment is a
pure control-arm run (e.g. state_divergence_baseline), used to establish a
real false-positive baseline for a detector rather than to test its
response to an induced fault.

`expected_event_types` -- the machine-checkable half of `expected_signal`:
the exact `forensic_twin` divergence `event_type` string(s)
(`check_node_state`'s own `new_events`, see forensic_twin/service.py)
whose presence on a TREATMENT repetition counts as "the experiment's
expected signal was observed". Empty for an experiment with no
twin-divergence signal to check (the pure control-arm baseline) or for a
"planned" experiment not wired to the evaluator yet. This stays a
separate, additive field precisely so the free-text `expected_signal`
(which also references non-twin signals like CPR/WCPR deltas or
evidence_strength that the evaluator does not score yet) never has to be
parsed.

`verification` -- which real check orchestrator.py runs once per
repetition to produce `new_events`:
  - "forensic_twin_check_node_state" (default) -- calls
    `forensic_twin.check_node_state(node_id)` and uses its own real
    `new_events` verbatim.
  - "capture_snapshot_once" -- calls
    `scenario_snapshot.capture_snapshot()` directly (this experiment's
    target IS the acquisition pipeline, not a node) and synthesizes a
    single `{"event_type": "capture_snapshot_forced_failure"}` pseudo-event
    when that real call failed with the fault's own declared forced-failure
    message -- kept in the exact same `new_events` shape so evaluator.py
    needs zero changes to score it.
"""

EXPERIMENT_CATALOG: list[dict] = [
    {
        "experiment_id": "modbus_state_manipulation",
        "purpose": "Answers: if someone secretly tampers with a PLC register outside any known attack script, does the platform notice AND correctly label that evidence as causally confirmed, not just a coincidence?",
        "gap_ids": ["g15_01_edge_evidence_strength", "g15_04_divergence_mitre_mapping"],
        "fault_id": "plc_io_manipulation",
        "category": "modbus_plc_manipulation",
        "expected_signal": (
            "forensic_twin.check_node_state emits a plc_control_law_violation divergence event carrying a "
            "real MITRE ATT&CK for ICS technique id (service._mitre_attck_ics_for), AND "
            "foc_causal_reconstruction produces a CausalEdge for the affected node/time window with "
            "evidence_strength='causal' (not 'temporal' or 'co_occurrence')."
        ),
        "safety": {"max_duration_seconds": 120, "reversible": True, "isolation_level": "scenario_node_only"},
        "implementation_status": "ready",
        "expected_event_types": ["plc_control_law_violation", "plc_baseline_divergence"],
        "verification": "forensic_twin_check_node_state",
    },
    {
        "experiment_id": "temporal_inconsistency",
        "purpose": "Answers: if a node's clock silently drifts, does the platform notice, and does it recover cleanly once the clock is fixed?",
        "gap_ids": ["g15_05_contextual_reality_gap"],
        "fault_id": "clock_skew",
        "category": "temporal_inconsistency",
        "expected_signal": (
            "forensic_twin.check_node_state emits a clock_offset_degraded divergence event "
            "(|offset_ms| > 1000, same threshold as forensics/scripts/time_sync_preflight.sh), AND the "
            "Intervention Ledger's build_phase_timeline shows effect_verified falling outside the "
            "tolerance_seconds window relative to twin_observed for this intervention."
        ),
        "safety": {"max_duration_seconds": 600, "reversible": True, "isolation_level": "scenario_node_only"},
        "implementation_status": "ready",
        "expected_event_types": ["clock_offset_degraded"],
        "verification": "forensic_twin_check_node_state",
    },
    {
        "experiment_id": "service_interruption",
        "purpose": "Answers: if the detection service itself goes silent, does the platform's own resilience metrics (how fast it reports, how reliably) actually drop -- proving they measure something real?",
        "gap_ids": ["g17_industry5_resilience_metrics"],
        "fault_id": "detection_outage",
        "category": "service_interruption",
        "expected_signal": (
            "A measurable drop in forge_dt_metrics.compute_ier / compute_tor_and_latency during the outage "
            "window, recovering to baseline after revert_fault restarts the detection service."
        ),
        "safety": {"max_duration_seconds": 300, "reversible": True, "isolation_level": "scenario_node_only"},
        "implementation_status": "ready",
        "expected_event_types": ["service_down"],
        "verification": "forensic_twin_check_node_state",
    },
    {
        "experiment_id": "state_divergence_baseline",
        "purpose": "Answers: on a perfectly healthy node with nothing wrong, how often does the digital twin raise a false alarm? (the honest baseline every other experiment here is compared against)",
        "gap_ids": ["g02_02_causal_reconstruction_reproducibility", "g17_industry5_resilience_metrics"],
        "fault_id": None,
        "category": "state_divergence",
        "expected_signal": (
            "N real repetitions of forensic_twin.check_node_state / check_campaign_reproducibility with NO "
            "fault injected (a pure control arm) -- establishes a real false-positive baseline for the "
            "twin's own divergence detection, reused by the false_positive_rate metric for every other "
            "experiment in this catalog."
        ),
        "safety": {"max_duration_seconds": 0, "reversible": True, "isolation_level": "read_only"},
        "implementation_status": "ready",
        "expected_event_types": [],
        "verification": "forensic_twin_check_node_state",
    },
    {
        "experiment_id": "acquisition_failure",
        "purpose": "Answers: when the platform's OWN evidence-capture step fails for real, does it say so honestly, or silently pretend everything worked?",
        "gap_ids": ["g17_chaos_engineering_forensic_pipeline"],
        "fault_id": "acquisition_failure",
        "category": "acquisition_failure",
        "expected_signal": (
            "A single, deliberately forced failure of scenario_snapshot.capture_snapshot() (a single-shot "
            "flag, see fault_injection/service.py::_apply_acquisition_failure); the orchestrator calls "
            "capture_snapshot() directly once per repetition (this experiment's target IS the acquisition "
            "pipeline, not a node) and the evaluator checks the real returned status/error against what "
            "this fault declares -- confirming the pipeline's own failure handling (status='ERROR', a real "
            "declared message) behaves correctly when a real acquisition failure happens, versus staying "
            "silent or reporting a false 'COMPLETED'."
        ),
        "safety": {"max_duration_seconds": 0, "reversible": True, "isolation_level": "single_shot_flag_only"},
        "implementation_status": "ready",
        "expected_event_types": ["capture_snapshot_forced_failure"],
        "verification": "capture_snapshot_once",
    },
    {
        "experiment_id": "evidence_loss",
        "purpose": "Answers: if part of a sealed case's evidence is lost or damaged, does the platform's own completeness/integrity scoring actually notice and drop? (blocked today -- no real sealed case exists yet to test this against)",
        "gap_ids": ["g17_chaos_engineering_forensic_pipeline"],
        "fault_id": "evidence_loss",
        "category": "evidence_loss",
        "expected_signal": (
            "evidence_completeness_ratio / by_support_state (ESR, forge_dt_metrics.compute_esr) and the "
            "reconstruction metrics' own evidence_completeness_ratio correctly register the induced, "
            "bounded loss of a non-critical log window, and fully recover after the backup is restored."
        ),
        "safety": {"max_duration_seconds": 120, "reversible": True, "isolation_level": "gap_validation_sandbox_only"},
        "implementation_status": "planned",
        "expected_event_types": [],
    },
    {
        "experiment_id": "record_corruption",
        "purpose": "Answers: if a case record is corrupted after the fact, does the platform's integrity check catch it? (blocked today -- same reason as evidence_loss)",
        "gap_ids": ["g17_chaos_engineering_forensic_pipeline"],
        "fault_id": "record_corruption",
        "category": "record_corruption",
        "expected_signal": (
            "integrity_verification_ratio / integrity_status (foc_causal_reconstruction's own "
            "reconstruction_metrics.json fields) correctly flag the corrupted artifact COPY -- never "
            "touches a real case's evidence directory, operates only on a copy created inside "
            "runtime/gap_validation/sandbox/ by the experiment itself."
        ),
        "safety": {"max_duration_seconds": 60, "reversible": True, "isolation_level": "gap_validation_sandbox_only"},
        "implementation_status": "planned",
        "expected_event_types": [],
    },
    {
        "experiment_id": "orchestrator_failure",
        "purpose": "Answers: when this platform's OWN orchestrator crashes for an unrelated reason, does its failure-diagnosis tool give an honest 'I can't tell', instead of wrongly blaming it on resource exhaustion?",
        "gap_ids": ["g17_retrospective_failure_forensics", "g17_chaos_engineering_forensic_pipeline"],
        "fault_id": "orchestrator_failure",
        "category": "orchestrator_failure",
        "expected_signal": (
            "A single-shot flag makes gap_validation's OWN orchestrator raise a deliberate exception "
            "during its next repetition step, ending that one gap-validation job (job_id prefixed "
            "'gapval-' by construction -- never a real tracked Level C campaign, structurally impossible "
            "since this flag is only ever consumed inside gap_validation/orchestrator.py's own loop) with "
            "status='failed'. campaign_failure_forensics.reconstruct_failure (reused via its job_dir "
            "parameter) is then checked for the CORRECT, calibrated answer: it has no category for 'a "
            "deliberately injected code bug', so the honest, correct outcome is probable_cause="
            "'undetermined' -- what matters is that it does NOT falsely claim resource exhaustion for a "
            "failure that had nothing to do with resources. No control arm: this is a single deliberate "
            "crash, not a repeatable alternating-treatments measurement."
        ),
        "safety": {"max_duration_seconds": 0, "reversible": True, "isolation_level": "gapval_job_id_allowlist_only"},
        "implementation_status": "ready",
        "expected_event_types": [],
        "verification": "orchestrator_crash_confound_check",
    },
]


def get_experiment(experiment_id: str) -> dict | None:
    return next((e for e in EXPERIMENT_CATALOG if e["experiment_id"] == experiment_id), None)


def list_experiments() -> list[dict]:
    return list(EXPERIMENT_CATALOG)


def experiments_for_gap(gap_id: str) -> list[dict]:
    return [e for e in EXPERIMENT_CATALOG if gap_id in e.get("gap_ids", [])]
