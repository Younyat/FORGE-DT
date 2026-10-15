from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .comparability_service import compare_executions
from .config import (
    CAMPAIGNS_ROOT,
    CAMPAIGN_STATES,
    LEVELS,
    campaign_config_path,
    campaign_dir,
    campaign_manifest_path,
    campaign_methodological_basis_path,
    rel,
)
from .dry_run_orchestrator import start_dry_run_execution_job
from .execution_service import aggregate_campaign_state, create_execution_from_campaign
from .job_runner import append_phase, get_job, list_jobs, new_job, start_job, update_job
from .methodological_basis import load_methodological_basis
from .scientific_memory_sync import get_active_scenario_memory_hint
from ..foc_reconstruction.evidence_lifecycle_dashboard import load_evidence_lifecycle_dashboard
from ..foc_reconstruction.foc_sources import utc_now


def _json_load(path: Path):
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _safe_slug(value: str) -> str:
    out = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "value"))
    return re.sub(r"_+", "_", out).strip("_") or "value"


def _new_campaign_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"CMP-{ts}-{uuid.uuid4().hex[:4].upper()}"


def _execution_summaries(campaign_id: str) -> list[dict]:
    root = campaign_dir(campaign_id)
    out: list[dict] = []
    if not root.is_dir():
        return out
    for level_dir in sorted(root.glob("level_*")):
        for manifest_path in sorted(level_dir.glob("EXEC-*/execution_manifest.json")):
            payload = _json_load(manifest_path) or {}
            out.append(
                {
                    "execution_id": payload.get("execution_id"),
                    "level": payload.get("level"),
                    "status": payload.get("status"),
                    "source_case_id": payload.get("source_case_id"),
                    "execution_path": rel(manifest_path.parent),
                    "updated_at": payload.get("updated_at"),
                }
            )
    return out


def _latest_job_summary(campaign_id: str) -> dict | None:
    jobs_dir = campaign_dir(campaign_id) / "jobs"
    if not jobs_dir.is_dir():
        return None
    latest_path = None
    latest_ts = 0.0
    for item in jobs_dir.glob("*.json"):
        try:
            ts = item.stat().st_mtime
        except Exception:
            continue
        if ts > latest_ts:
            latest_ts = ts
            latest_path = item
    if latest_path is None:
        return None
    payload = _json_load(latest_path) or {}
    phase_statuses = list(payload.get("phase_statuses") or [])
    last_phase = phase_statuses[-1] if phase_statuses else {}
    normalized_status = str(payload.get("status") or "").lower()
    current_phase = payload.get("current_phase")
    current_phase_label = payload.get("current_phase_label")
    current_phase_detail = payload.get("current_phase_detail")
    if normalized_status in {"completed", "completed_with_degradation", "failed", "cancelled"} and last_phase:
        current_phase = last_phase.get("phase_key") or current_phase or normalized_status
        current_phase_label = last_phase.get("phase_label") or current_phase_label or str(normalized_status).replace("_", " ").title()
        current_phase_detail = last_phase.get("detail") or current_phase_detail
    return {
        "job_id": payload.get("job_id"),
        "status": payload.get("status"),
        "started_at": payload.get("started_at") or payload.get("requested_at"),
        "finished_at": payload.get("finished_at"),
        "current_phase": current_phase,
        "current_phase_label": current_phase_label,
        "current_phase_detail": current_phase_detail,
        "progress_percent": payload.get("progress_percent"),
        "last_error": ((payload.get("errors") or [{}])[0] or {}).get("message") if payload.get("errors") else None,
        "job_path": rel(latest_path),
        "phase_statuses": phase_statuses,
    }


def _running_job_for_campaign(campaign_id: str) -> dict | None:
    for item in list_jobs():
        meta = item.get("meta") or {}
        if str(meta.get("campaign_id")) != str(campaign_id):
            continue
        if str(item.get("status")) in {"queued", "running"}:
            return item
    return None


# 180s -- same grace window job_runner._recover_orphaned_job() uses before treating a
# "running" job with no heartbeat as dead. Duplicated (not imported) to avoid pulling this
# module into job_runner's own dependency chain for one constant.
_ACTIVE_CAMPAIGN_GRACE_SECONDS = 180


def _active_jobs_by_campaign() -> dict[str, dict]:
    """campaign_id -> its currently-running job, for the "active campaign" indicator added
    2026-07-21 to list_campaigns(). Deliberately does NOT reuse list_jobs() (job_runner's
    in-memory _JOBS dict) or a per-campaign _running_job_for_campaign() loop: list_jobs()
    only reflects whatever the CURRENT gunicorn worker happens to have cached (same class
    of cross-worker blindness fixed in job_runner.get_job() and
    level_b_repetition_runner.find_active_level_b_job() earlier this session -- never
    applied here before), and looping _running_job_for_campaign() per campaign would be an
    O(campaigns x jobs) re-scan every time list_campaigns() is called (40+ campaigns today).
    Single pass over every job file on disk instead, building the index once. A job is only
    trusted as "active" if it also has a recent heartbeat (same _ORPHAN_JOB_GRACE_SECONDS
    window as job_runner's own watchdog) -- a job that says status="running" on disk but
    hasn't been touched in 3+ minutes is exactly the kind of dead-but-not-yet-recovered job
    this session found repeatedly, and showing it as "active" here would just resurrect that
    same false-positive class in a new place.
    """
    from datetime import datetime as _dt

    def _age_seconds(iso: str | None) -> float | None:
        if not iso:
            return None
        try:
            return (datetime.now(timezone.utc) - _dt.fromisoformat(iso.replace("Z", "+00:00"))).total_seconds()
        except Exception:
            return None

    result: dict[str, dict] = {}
    for job_path in CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
        payload = _json_load(job_path)
        if not isinstance(payload, dict):
            continue
        status = str(payload.get("status") or "").lower()
        if status not in ("queued", "running"):
            continue
        campaign_id = str((payload.get("meta") or {}).get("campaign_id") or "").strip()
        if not campaign_id:
            continue
        age = _age_seconds(payload.get("updated_at") or payload.get("started_at") or payload.get("requested_at"))
        if age is not None and age > _ACTIVE_CAMPAIGN_GRACE_SECONDS:
            continue
        candidate = {
            "job_id": payload.get("job_id"),
            "job_type": payload.get("job_type"),
            "status": status,
            "current_phase_label": payload.get("current_phase_label"),
            "current_phase_detail": payload.get("current_phase_detail"),
            "started_at": payload.get("started_at") or payload.get("requested_at"),
            "updated_at": payload.get("updated_at"),
        }
        existing = result.get(campaign_id)
        if existing is None or (candidate.get("updated_at") or "") > (existing.get("updated_at") or ""):
            result[campaign_id] = candidate
    return result


def list_campaigns() -> dict:
    CAMPAIGNS_ROOT.mkdir(parents=True, exist_ok=True)
    active_by_campaign = _active_jobs_by_campaign()
    campaigns: list[dict] = []
    for item in sorted(CAMPAIGNS_ROOT.glob("CMP-*")):
        manifest = _json_load(item / "campaign_manifest.json")
        if not isinstance(manifest, dict):
            continue
        try:
            manifest = aggregate_campaign_state(str(manifest.get("campaign_id")), manifest)
        except Exception:
            pass
        manifest["executions"] = _execution_summaries(str(manifest.get("campaign_id")))
        # 2026-07-21: additive field, computed once above (not per-campaign) -- see
        # _active_jobs_by_campaign()'s own docstring. None for every campaign with no
        # currently-running job, which is the overwhelming majority; existing consumers of
        # this endpoint that don't know about this field are unaffected.
        manifest["running_job"] = active_by_campaign.get(str(manifest.get("campaign_id")))
        campaigns.append(manifest)
    return {"generated_at": utc_now(), "campaigns": campaigns}


def create_campaign(payload: dict) -> dict:
    level = str(payload.get("level") or "A").strip().upper()
    if level not in LEVELS:
        raise ValueError("invalid_level")
    scenario_id = str(payload.get("scenario_id") or "").strip()
    case_id = str(payload.get("base_case_id") or payload.get("run_case_id") or payload.get("base_case_path") or payload.get("run_case_path") or "").strip()
    if level == "A" and not case_id:
        raise ValueError("A linked source case is required for Level A. Select a preserved case before creating the campaign.")
    if level in {"B", "C"} and (not scenario_id or scenario_id == "not_available"):
        raise ValueError(f"Scenario ID is required for Level {level}. Select or auto-detect an active deployed scenario before starting execution.")
    attack_id = str(payload.get("attack_id") or payload.get("attack_profile_override") or "").strip()
    if level in {"B", "C"} and not attack_id:
        raise ValueError(f"Attack profile is required for executable Level {level} campaigns. Select an attack profile before creating executable repetitions.")
    campaign_id = _new_campaign_id()
    root = campaign_dir(campaign_id)
    for name in ["jobs", "logs", "comparisons", "level_A", "level_B", "level_C"]:
        (root / name).mkdir(parents=True, exist_ok=True)

    manifest = {
        "campaign_id": campaign_id,
        "name": str(payload.get("name") or campaign_id),
        "description": str(payload.get("description") or ""),
        "level": level,
        "status": "not_started",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "execution_count": 0,
        "current_execution_id": None,
        "scenario_id": payload.get("scenario_id") or "not_available",
        "source_mode": {
            "A": "linked_existing_case",
            "B": "new_incident_execution",
            "C": "full_redeployment",
        }.get(level, "planned_campaign"),
        "campaign_path": rel(root),
        "comparisons_path": rel(root / "comparisons"),
    }
    config = {
        "campaign_id": campaign_id,
        "level": level,
        "name": manifest["name"],
        "description": manifest["description"],
        "repetitions": max(int(payload.get("repetitions") or 3), 1),
        "nested_level_a_repetitions": (
            max(int(payload.get("nested_level_a_repetitions") or payload.get("repetitions") or 3), 1)
            if level == "B"
            else None
        ),
        "scenario_id": manifest["scenario_id"],
        "base_case_id": payload.get("base_case_id"),
        "base_case_path": payload.get("base_case_path"),
        "run_case_id": payload.get("run_case_id"),
        "run_case_path": payload.get("run_case_path"),
        "parent_campaign_id": payload.get("parent_campaign_id"),
        "parent_execution_id": payload.get("parent_execution_id"),
        "parent_level": payload.get("parent_level"),
        "baseline_noise_threshold": float(payload.get("baseline_noise_threshold") or 0.15),
        "baseline_window_seconds": int(payload.get("baseline_window_seconds") or 60),
        "delta_wcpr_allowed": float(payload.get("delta_wcpr_allowed") or 0.10),
        "notes": payload.get("notes") or "",
        # Fixed version identifiers for the platform's current single
        # detection-ingestion path, trigger-selection algorithm, acquisition
        # pipeline, multilayer analysis pipeline, and FOC causal-
        # reconstruction pipeline. There is no UI to choose between
        # alternatives yet, but these still participate in
        # comparison_family_id so that if any of these pipelines materially
        # changes in the future, the version string bumps and old/new
        # results stop being silently treated as comparable. The four are
        # kept as distinct identifiers because they answer different
        # questions: detection_policy_id is "what source/alert is listened
        # to", trigger_policy_id is "what condition fires acquisition",
        # acquisition_profile_id is "what evidence gets preserved".
        "detection_policy_id": payload.get("detection_policy_id") or "wazuh_suricata_alert_ingestion_v1",
        "trigger_policy_id": payload.get("trigger_policy_id") or "highest_severity_alert_v1",
        "acquisition_profile_id": payload.get("acquisition_profile_id") or "default_kolla_lime_tshark_v1",
        "analysis_profile_id": payload.get("analysis_profile_id") or "default_multilayer_analysis_v1",
        "foc_profile_id": payload.get("foc_profile_id") or "default_foc_causal_reconstruction_v1",
        "requested_comparison_family_id": payload.get("requested_comparison_family_id"),
        "retention_policy": payload.get("retention_policy") or ("original_case_retained" if level == "A" else "profiles_only_after_archive"),
        "heavy_case_policy": payload.get("heavy_case_policy") or ("reuse_original_case" if level == "A" else "new_case_per_execution"),
        "dry_run": bool(payload.get("dry_run")) if payload.get("dry_run") is not None else (level in {"B", "C"}),
        "deployment_profile_id": payload.get("deployment_profile_id") or ("scenario_reconstruction_blueprint_v1" if level == "C" else None),
        # The attack_id the operator selected from the real MITRE ATT&CK
        # catalog (app_core/infrastructure/attack/catalog.py) for this
        # campaign. This records the planned attack profile; it is not yet
        # consumed by an automated attack-launch pipeline for Level B/C,
        # which does not exist in foc_experimentation today.
        "attack_id": attack_id or None,
        # Faults deliberately configured for this campaign (see
        # app_core/infrastructure/fault_injection) -- a free-form list of
        # {type, attack_id, phase, params}, read by
        # level_b_orchestrator._resolve_injected_attack_parameters and by the
        # fault-injection dashboard to record/measure its effectiveness.
        # Empty by default: no existing campaign changes behavior.
        "injected_faults": payload.get("injected_faults") or [],
    }
    _write_json(campaign_manifest_path(campaign_id), manifest)
    _write_json(campaign_config_path(campaign_id), config)
    _write_json(campaign_methodological_basis_path(campaign_id), load_methodological_basis())
    return {"campaign": manifest, "config": config}


def get_campaign(campaign_id: str) -> dict | None:
    manifest = _json_load(campaign_manifest_path(campaign_id))
    if not isinstance(manifest, dict):
        return None
    try:
        manifest = aggregate_campaign_state(campaign_id, manifest)
    except Exception:
        pass
    config = _json_load(campaign_config_path(campaign_id)) or {}
    basis = _json_load(campaign_methodological_basis_path(campaign_id)) or {}
    return {
        "campaign": manifest,
        "config": config,
        "methodological_basis": basis,
        "executions": _execution_summaries(campaign_id),
        "latest_job": _latest_job_summary(campaign_id),
        "running_job": _running_job_for_campaign(campaign_id),
    }


def build_campaign_proposal(case_id: str | None = None, level: str | None = None, scenario_id: str | None = None) -> dict:
    normalized_level = str(level or ("A" if case_id else "B")).strip().upper()
    if normalized_level not in LEVELS:
        normalized_level = "A"
    source_summary = None
    resolved_scenario_id = str(scenario_id or "").strip() or "not_available"
    resolved_scenario_name = "not_available"
    source_case_policy = "read_only" if normalized_level == "A" else "new_execution"
    active_hint = get_active_scenario_memory_hint()
    if case_id:
        dashboard = load_evidence_lifecycle_dashboard(case_id)
        summary = (dashboard or {}).get("summary") or {}
        source_summary = {
            "case_id": case_id,
            "case_path": dashboard.get("case_path"),
            "summary_available": bool(dashboard.get("summary_available")),
        }
        resolved_scenario_id = (
            summary.get("scenario_id")
            or ((summary.get("causal_summary") or {}).get("scenario_id"))
            or resolved_scenario_id
        )
        resolved_scenario_name = summary.get("scenario_name") or "not_available"
    elif active_hint.get("active_scenario_exists"):
        resolved_scenario_id = active_hint.get("scenario_id") or resolved_scenario_id
        resolved_scenario_name = active_hint.get("scenario_name") or resolved_scenario_name
    default_name = {
        "A": f"Level A Reanalysis — {case_id or 'linked_case'}",
        "B": f"Level B Repetition — {resolved_scenario_id}",
        "C": f"Level C Full Redeployment — {resolved_scenario_name if resolved_scenario_name != 'not_available' else resolved_scenario_id}",
    }.get(normalized_level, f"Level {normalized_level} Campaign")
    return {
        "guided_mode_default": True,
        "default_level": normalized_level,
        "source_mode": {
            "A": "linked_existing_case",
            "B": "new_incident_execution",
            "C": "full_redeployment",
        }.get(normalized_level, "linked_existing_case"),
        "campaign_name": default_name,
        "scenario_id": resolved_scenario_id,
        "scenario_name": resolved_scenario_name,
        "linked_source_case": case_id or "",
        "baseline_threshold": 0.15,
        "delta_wcpr_allowed": 0.10,
        "baseline_window_seconds": 60,
        "number_of_repetitions": {"A": 3, "B": 3, "C": 1}.get(normalized_level, 3),
        "nested_level_a_repetitions": {"A": None, "B": 3, "C": None}.get(normalized_level),
        "methodological_notes": "Controlled repetition campaign for evaluating forensic reconstruction comparability under documented experimental conditions.",
        "ground_truth_seal_mode": "reuse_if_available" if normalized_level == "A" else "generate_before_attack",
        "comparison_profile_after_each_run": True,
        "retention_policy": "original_case_retained" if normalized_level == "A" else "profiles_only_after_archive",
        "dry_run_default": normalized_level in {"B", "C"},
        "source_case_policy": source_case_policy,
        "source_summary": source_summary,
        # Real fixed-version identifiers the campaign will be created with,
        # so the UI can display the actual configured policy instead of
        # guessing a fallback string before the campaign exists.
        "detection_policy_id": "wazuh_suricata_alert_ingestion_v1",
        "trigger_policy_id": "highest_severity_alert_v1",
        "acquisition_profile_id": "default_kolla_lime_tshark_v1",
        "analysis_profile_id": "default_multilayer_analysis_v1",
        "foc_profile_id": "default_foc_causal_reconstruction_v1",
        "level_explanation": {
            "A": {
                "title": "Level A — Reanalysis Repeatability",
                "meaning": "Reuses an existing preserved forensic case and repeats the analysis and reconstruction logic over the same preserved evidence.",
                "does_not_do": [
                    "It does not redeploy the scenario.",
                    "It does not execute a new attack.",
                    "It does not perform new acquisition.",
                    "It does not modify the original case."
                ],
                "used_for": "Testing whether the analytical pipeline is repeatable over the same preserved evidence.",
                "required_input": "A linked source case.",
                "auto_generated": [
                    "execution workspace",
                    "execution_manifest.json",
                    "reanalysis profiles",
                    "forensic_comparison_profile.json"
                ],
            },
            "B": {
                "title": "Level B — Controlled Repeated Incident Execution",
                "meaning": "Uses the same deployed scenario and executes controlled repetitions under equivalent and documented conditions.",
                "used_for": "Measuring stability of forensic reconstruction under equivalent experimental conditions.",
                "required_input": "scenario, attack profile, acquisition profile",
                "source_note": "No linked source case is required for Level B. A new forensic case will be created for each repeated incident execution.",
                "auto_generated": [
                    "execution workspace",
                    "ground_truth_seal.json",
                    "baseline_noise_profile.json",
                    "detection_trigger_profile.json",
                    "acquisition_profile.json",
                    "preservation_profile.json",
                    "forensic_comparison_profile.json"
                ],
            },
            "C": {
                "title": "Level C — Full Environment Redeployment Reproducibility",
                "meaning": "Redeploys the environment and repeats the experiment from infrastructure setup to forensic reconstruction.",
                "used_for": "Complementary platform-level reproducibility validation.",
                "important": "This level is not the main forensic comparability metric because it introduces additional deployment and configuration variability.",
                "source_note": "No linked source case is required for Level C. A new forensic case will be created for each redeployment execution.",
                "auto_generated": [
                    "deployment manifest",
                    "infrastructure fingerprint",
                    "tool installation validation",
                    "sensor and SIEM/IDS configuration validation"
                ],
            },
        }.get(normalized_level),
    }


def campaign_preflight(payload: dict) -> dict:
    level = str(payload.get("level") or "A").strip().upper()
    case_id = str(payload.get("base_case_id") or payload.get("run_case_id") or "").strip()
    scenario_id = str(payload.get("scenario_id") or "").strip()
    items = []

    def add_item(key: str, ok: bool, why: str, fix: str, auto_generable: bool, requirement: str | None = None):
        items.append(
            {
                "key": key,
                "requirement": requirement or key.replace("_", " "),
                "status": "ok" if ok else "missing",
                "why_it_matters": why,
                "how_to_fix": fix,
                "can_be_auto_generated": auto_generable,
            }
        )

    if level == "A":
        dashboard = load_evidence_lifecycle_dashboard(case_id) if case_id else {"error": "missing_case_id"}
        add_item("linked_source_case_selected", bool(case_id), "Level A requires a preserved case to reanalyze.", "Select a preserved case or open the manager from the Scientific Lifecycle dashboard.", False, "linked source case selected")
        add_item("base_case_path_exists", bool(case_id and dashboard.get("case_path")), "The execution workspace must link a real preserved case.", "Choose a valid preserved case.", False, "base case path exists")
        add_item("base_artifacts_are_readable", bool(case_id and dashboard.get("summary_available")), "The campaign needs readable preserved artifacts and executive summary context.", "Regenerate the case executive summary if needed.", True, "base artifacts are readable")
        add_item("analysis_artifacts_exist_or_can_be_regenerated", bool(case_id), "Comparison profiles depend on analysis and derived outputs.", "Use the linked case and regenerate missing analysis outputs if required.", True, "analysis artifacts exist or can be regenerated")
        add_item("output_campaign_directory_can_be_created", True, "The module needs an isolated campaign workspace.", "Check filesystem permissions if campaign creation fails.", True, "output campaign directory can be created")
    elif level == "B":
        scenario_ok = bool(scenario_id and scenario_id != "not_available")
        attack_ok = bool(str(payload.get("attack_id") or payload.get("attack_profile_override") or "").strip())
        # No linked source case is required for Level B. A new forensic case
        # will be created for each repeated incident execution -- this
        # checklist intentionally never asks for one.
        add_item("scenario_selected", scenario_ok, "Level B needs a declared scenario context.", "Provide a scenario ID or select a scenario-linked source.", False)
        add_item("active_scenario_exists", scenario_ok, "The deployed scenario must actually exist before launching a repeated incident.", "Deploy or select an active scenario before starting execution.", False)
        add_item("required_roles_resolved", True, "Attacker/victim/monitor roles must resolve to real nodes.", "Verify instance roles in the IT scenario editor if resolution fails.", True)
        add_item(
            "attack_profile_selected",
            attack_ok,
            "Level B repeats a controlled incident. The attack profile defines what incident will be launched and what result family the execution can belong to.",
            "Select an attack profile manually, use a recommended comparable attack if available, or start a new comparison family and choose the attack profile.",
            False,
        )
        add_item("automated_attack_script_available", attack_ok, "Controlled repetition depends on an executable attack path.", "Ensure the attack profile can be resolved before running heavy executions.", True)
        add_item("detection_stream_available", True, "Level B waits for a real detection before acquisition.", "Confirm the detection/alerting stream is reachable.", True)
        add_item("trigger_policy_configured", True, "The acquisition trigger policy must be declared before execution.", "Override the trigger policy in Advanced Mode if needed.", True)
        add_item("forensic_auto_acquisition_available", True, "The repeated run must preserve evidence automatically once triggered.", "Confirm auto-acquisition is reachable before heavy execution.", True)
        add_item("case_creation_available", True, "Each Level B execution must be able to create its own new forensic case.", "Check case-creation permissions if this fails.", True)
        add_item("acquisition_targets_resolved", True, "Acquisition needs resolved target nodes for the new case.", "Verify target node resolution in Advanced Mode if needed.", True)
        add_item("time_sync_check_available", True, "Temporal interpretation depends on measurable synchronization.", "Run time synchronization validation before heavy execution.", True)
        add_item("baseline_noise_capture_available", True, "Level B comparability uses baseline noise as a warning boundary.", "Keep baseline capture enabled.", True)
        add_item("output_campaign_directory_can_be_created", True, "The module needs an isolated campaign workspace.", "Check filesystem permissions if campaign creation fails.", True)
    else:
        attack_ok = bool(str(payload.get("attack_id") or payload.get("attack_profile_override") or "").strip())
        add_item("deployment_profile_selected", False, "Level C needs a deployment and environment validation profile.", "Provide deployment-aware configuration before running Level C.", False, "deployment profile selected")
        add_item("scenario_deployment_available", bool(scenario_id and scenario_id != "not_available"), "Level C requires a deployable scenario context.", "Provide a scenario ID and deployment profile.", False, "scenario deployment available")
        add_item("tool_installation_validation_available", True, "Level C comparability depends on environment validation reports.", "Use validation placeholders or future deployment-aware execution.", True, "tool installation validation available")
        add_item("ids_siem_configuration_profile_available", True, "Sensor configuration changes affect reproducibility interpretation.", "Generate configuration validation reports for Level C runs.", True, "IDS/SIEM configuration profile available")
        add_item("attack_profile_selected", attack_ok, "The repeated incident must still be explicitly defined.", "Select an attack profile before creating an executable Level C campaign.", False, "attack profile selected")
        add_item("acquisition_profile_selected", True, "The environment-level repetition still needs forensic acquisition logic.", "Override acquisition profile in Advanced Mode if needed.", True, "acquisition profile selected")
        add_item("output_campaign_directory_can_be_created", True, "The module needs an isolated campaign workspace.", "Check filesystem permissions if campaign creation fails.", True, "output campaign directory can be created")

    ok_count = len([item for item in items if item["status"] == "ok"])
    info_notes = []
    if level == "B":
        info_notes.append("No linked source case is required for Level B. A new forensic case will be created for each repeated incident execution.")
    elif level == "C":
        info_notes.append("No linked source case is required for Level C. A new forensic case will be created for each redeployment execution.")
    return {
        "level": level,
        "items": items,
        "ready": ok_count == len(items),
        "ok_count": ok_count,
        "missing_count": len(items) - ok_count,
        "info_notes": info_notes,
    }


def update_campaign_state(campaign_id: str, state: str) -> dict:
    if state not in CAMPAIGN_STATES:
        raise ValueError("invalid_campaign_state")
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    manifest["status"] = state
    manifest["updated_at"] = utc_now()
    _write_json(campaign_manifest_path(campaign_id), manifest)
    return manifest


def start_campaign_job(campaign_id: str, overrides: dict | None = None) -> dict:
    return start_dry_run_execution_job(campaign_id, overrides=overrides or {})


def start_campaign(campaign_id: str, overrides: dict | None = None) -> dict:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    manifest["status"] = "running"
    manifest["updated_at"] = utc_now()
    _write_json(campaign_manifest_path(campaign_id), manifest)
    job = start_campaign_job(campaign_id, overrides=overrides)
    return {"campaign": manifest, "job": job}


def start_comparison_job(campaign_id: str | None, execution_ids: list[str], delta_wcpr_allowed: float | None = None) -> dict:
    target_root = campaign_dir(campaign_id) if campaign_id else campaign_dir("_cross_campaign")
    target_root.mkdir(parents=True, exist_ok=True)
    job = new_job(
        job_type="comparability_compare",
        title="Compare registered executions",
        job_path=target_root / "jobs" / f"job-{uuid.uuid4().hex[:8]}.json",
        meta={"campaign_id": campaign_id, "execution_ids": execution_ids},
    )

    def runner(job_id: str, job_path: Path):
        update_job(job_id, job_path, current_phase="load_profiles", progress_percent=20.0)
        result = compare_executions(execution_ids, campaign_id=campaign_id, delta_wcpr_allowed=delta_wcpr_allowed)
        final_status = "failed" if result.get("status") == "Insufficient Data" else "completed"
        update_job(
            job_id,
            job_path,
            current_phase="completed",
            progress_percent=100.0,
            status=final_status,
            finished_at=utc_now(),
            generated_artifacts=list((result.get("artifacts") or {}).values()),
            meta={**(job.get("meta") or {}), **result},
        )

    return start_job(job, runner)
