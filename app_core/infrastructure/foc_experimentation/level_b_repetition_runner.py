from __future__ import annotations

import contextlib
import csv
import gc
import json
import logging
import math
import os
import shutil
import statistics
import subprocess
import threading
import time
import tracemalloc
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .campaign_service import create_campaign
from .comparability_service import compare_executions
from .config import CAMPAIGNS_ROOT, EVIDENCE_STORE_ROOT, campaign_config_path, campaign_dir, campaign_manifest_path, execution_dir, rel
from .execution_service import aggregate_campaign_state, attach_real_case_to_execution, comparable_execution_ids_for_campaign, create_execution_from_campaign, load_execution
from .job_runner import append_job_list, append_phase, get_job, job_cancel_requested, new_job, raise_if_cancelled, request_cancel, request_force_stop, start_job, update_job
from .level_a_scientific_report_service import start_level_a_scientific_report_job
from .retention_service import delete_generated_case_artifacts
from .level_b_orchestrator import (
    CONFIRMATION_TOKEN,
    DEFAULT_DETECTION_TIMEOUT_SECONDS,
    _build_alert_matcher,
    _case_id_for_case_dir,
    _launch_attack,
    _resolve_injected_attack_parameters,
    _resolve_real_targets,
    _sha256_path,
    _wait_for_lifecycle_job,
)
from ..attack.catalog import find_attack_by_id
from ..foc_reconstruction.evidence_lifecycle_dashboard import start_full_lifecycle_job
from ..foc_reconstruction.foc_attestation_builder import _parse_mbpoll_command
from ..foc_reconstruction.foc_case_analysis import _case_dir_from_entry, cases_with_analysis_state, get_case_entry, load_analysis_status
from ..foc_reconstruction.foc_paths import project_path, relative_path
from ..foc_reconstruction.foc_sources import utc_now
from ..forensics.forensics_api import (
    _add_artifact_fast,
    _active_preservation_guard,
    _append_case_event,
    _append_custody_entry,
    _case_preservation_in_progress,
    _clear_active_preservation_state,
    _dfir_create_case_internal,
    _resolve_dfir_targets_from_openstack,
    _dfir_ssh_user_for_role,
    acquire_disk,
    acquire_memory,
    disk_acquisition_preflight,
)
from ..forensics.network_context_importer import (
    import_continuous_network_context,
    initialize_volatile_first_acquisition,
    update_acquisition_profile,
)
from ..monitor.alerts_logger import run_monitor_session
from ..node_health.node_health_api import cleanup_node_free_space

# OT State Twin (gemelo digital forense, piloto) -- capa opcional y aditiva: importada de forma
# defensiva para que un fallo en ese modulo nuevo (PLC inalcanzable, mbpoll ausente, etc.) nunca
# impida importar este orquestador ni tumbe una repeticion Level B/C real. Ver
# investigacion_y_novedad/06_implementacion_forge_dt.md para el porque de este enganche.
try:
    from ..ot_state_twin.service import (
        capture_baseline_for_repetition,
        compute_corroboration_verdict,
        poll_burst_and_compare_for_repetition,
        repetition_scope_id,
    )
except Exception:
    def capture_baseline_for_repetition(campaign_id: str, execution_id: str) -> dict:
        return {"ok": False, "reason": "ot_state_twin_unavailable"}

    def poll_burst_and_compare_for_repetition(campaign_id: str, execution_id: str, **_kwargs) -> dict:
        return {"ok": False, "reason": "ot_state_twin_unavailable"}

    def repetition_scope_id(campaign_id: str, execution_id: str) -> str:
        return f"{campaign_id}__{execution_id}"

    def compute_corroboration_verdict(scope_id: str) -> dict:
        return {"scope_id": scope_id, "verdict": "ot_state_twin_unavailable"}

RUNTIME_ROOT = project_path("runtime", "level_b_repetitions")
VALIDATION_REPORTS_ROOT = EVIDENCE_STORE_ROOT / "validation_reports"
ACTIVE_CASE_PTR = EVIDENCE_STORE_ROOT / "_active_case.txt"
MAX_TRIGGER_ARMING_ATTEMPTS = 10
TRIGGER_ARMING_INTERVAL_SECONDS = 10
RECENT_BACKGROUND_CASE_MAX_AGE_SECONDS = 900
STALE_PLACEHOLDER_CASE_MIN_AGE_SECONDS = 30
CRITICAL_EVIDENCE_GATE_REL = "metadata/critical_evidence_gate.json"
TRIGGER_ALERT_BINDING_REL = "metadata/trigger_alert_binding.json"
FORENSIC_INTERVENTION_REL = "metadata/forensic_intervention.json"
NORMALIZED_TIMESTAMPS_REL = "metadata/normalized_causal_timestamps.json"
ALERT_MATCH_MAX_PRE_SECONDS = 30
ALERT_MATCH_MAX_POST_SECONDS = 300
LEVEL_B_FREE_SPACE_CLEANUP_ROLES = ("fuxa", "plc")

SETUP_PHASES: list[tuple[str, str]] = [
    ("prepare_level_b_job", "Prepare Level B job"),
    ("optional_cleanup", "Optional cleanup of old cases"),
    ("resolve_active_scenario", "Resolve active scenario"),
    ("verify_plc_target", "Verify PLC target"),
    ("enable_dfir_mode", "Enable DFIR mode"),
    ("verify_disk_acquisition", "Verify disk acquisition prerequisites"),
]

REPETITION_PHASES: list[tuple[str, str]] = [
    ("start_repetition", "Start repetition"),
    ("execute_attack", "Execute OT register-modification attack"),
    ("wait_alert", "Wait for high-severity alert"),
    ("verify_trigger", "Verify forensic intervention trigger"),
    ("run_acquisition", "Run automatic acquisition"),
    ("seal_case", "Seal and register case"),
    ("run_analysis", "Run multilayer analysis"),
    ("run_reconstruction", "Run reconstruction/dependency analysis"),
    ("cleanup_case", "Clean heavy generated case"),
    ("store_result", "Store repetition result"),
]

FINAL_PHASES: list[tuple[str, str]] = [
    ("generate_report", "Generate Level B report"),
    ("complete", "Complete"),
]


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def _write_case_json_artifact(
    case_dir: Path,
    rel_path: str,
    artifact_type: str,
    payload: dict,
    *,
    run_id: str,
    event_name: str | None = None,
    event_meta: dict | None = None,
) -> str:
    target = case_dir / rel_path
    _write_json(target, payload)
    try:
        size = target.stat().st_size
    except Exception:
        size = None
    sha256 = _sha256_path(target) if target.is_file() else None
    _add_artifact_fast(str(case_dir), rel_path, artifact_type, sha256=sha256, size=size)
    if event_name:
        _append_case_event(str(case_dir), event_name, run_id=run_id, meta=event_meta or {"artifact_rel": rel_path})
    return relative_path(target)


def _recent_case_age_seconds(case_dir: Path) -> float | None:
    profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") or {}
    anchor = (
        profile.get("acquisition_started_utc")
        or profile.get("case_created_utc")
        or profile.get("trigger_time_utc")
    )
    anchor_dt = _parse_dt(str(anchor or ""))
    if not anchor_dt:
        try:
            return max(0.0, time.time() - case_dir.stat().st_mtime)
        except Exception:
            return None
    return max(0.0, time.time() - anchor_dt.timestamp())


def _is_stale_placeholder_case_dir(case_dir: Path) -> bool:
    if not case_dir.exists() or not case_dir.is_dir():
        return False
    if (case_dir / "manifest.json").exists():
        return False
    if (case_dir / "chain_of_custody.log").exists():
        return False
    if (case_dir / "metadata" / "pipeline_events.jsonl").exists():
        return False
    try:
        age_seconds = max(0.0, time.time() - case_dir.stat().st_mtime)
    except Exception:
        return False
    return age_seconds >= STALE_PLACEHOLDER_CASE_MIN_AGE_SECONDS


def _prune_stale_placeholder_cases() -> list[str]:
    deleted: list[str] = []
    active_case_dir = _active_case_dir()
    for case_dir in sorted(EVIDENCE_STORE_ROOT.glob("CASE-*")):
        case_dir = case_dir.resolve()
        if not _is_stale_placeholder_case_dir(case_dir):
            continue
        try:
            if active_case_dir and active_case_dir == case_dir:
                try:
                    ACTIVE_CASE_PTR.write_text("", encoding="utf-8")
                except Exception:
                    pass
            try:
                _clear_active_preservation_state(
                    str(case_dir),
                    final_state="cleaned_as_incomplete_placeholder",
                    reason="stale_placeholder_case_pruned",
                )
            except Exception:
                pass
            shutil.rmtree(case_dir)
            deleted.append(relative_path(case_dir))
        except Exception:
            continue
    return deleted


def _is_background_case_candidate(case_dir: Path) -> bool:
    if not case_dir.exists() or not case_dir.is_dir():
        return False
    if not (case_dir / "manifest.json").is_file():
        return False
    if not (case_dir / "metadata" / "pipeline_events.jsonl").is_file():
        return False
    age_seconds = _recent_case_age_seconds(case_dir)
    if age_seconds is not None and age_seconds > RECENT_BACKGROUND_CASE_MAX_AGE_SECONDS:
        return False
    if _case_preservation_in_progress(str(case_dir)):
        return True
    profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") or {}
    if profile.get("acquisition_started_utc") or profile.get("memory_started_utc") or profile.get("disk_started_utc"):
        return True
    events = _read_jsonl(case_dir / "metadata" / "pipeline_events.jsonl")
    interesting = {
        "active_preservation_claimed",
        "memory_start",
        "network_context_import_started",
        "disk_start",
        "dfir_orchestration_done",
    }
    return any(str(item.get("event") or "") in interesting for item in events)


def _manifest_artifacts(case_dir: Path) -> list[dict]:
    payload = _json_load(case_dir / "manifest.json") or {}
    artifacts = list(payload.get("artifacts") or [])
    return [item for item in artifacts if isinstance(item, dict)]


def _artifact_matches(artifact: dict, *, rel_prefix: str = "", rel_suffixes: tuple[str, ...] = (), type_tokens: tuple[str, ...] = ()) -> bool:
    rel_path = str(artifact.get("rel_path") or "")
    artifact_type = str(artifact.get("type") or "")
    if rel_prefix and rel_path.startswith(rel_prefix):
        return True
    if rel_suffixes and any(rel_path.endswith(suffix) for suffix in rel_suffixes):
        return True
    if type_tokens and any(token in artifact_type for token in type_tokens):
        return True
    return False


def _persist_trigger_alert_binding(
    *,
    case_dir: Path,
    run_id: str,
    execution_id: str,
    case_id: str,
    attack: dict,
    matched_alert: dict | None,
) -> dict:
    primary = (matched_alert or {}).get("primary") or {}
    triage = (matched_alert or {}).get("triage") or {}
    raw = primary.get("raw") or {}
    payload = {
        "generated_at_utc": utc_now(),
        "execution_id": execution_id,
        "case_id": case_id,
        "attack_profile_id": attack.get("attack_id"),
        "trigger_alert_id": primary.get("event_id"),
        "rule_id": primary.get("rule_id"),
        "timestamp_utc": primary.get("ts_utc") or primary.get("timestamp"),
        "severity": triage.get("severity"),
        "recommend_forensics": triage.get("recommend_forensics"),
        "alert_type": primary.get("alert_type"),
        "signature": primary.get("signature"),
        "description": primary.get("description"),
        "original_sensor": primary.get("original_sensor"),
        "collector": primary.get("collector"),
        "protocol": primary.get("protocol"),
        "mitre_mapping": raw.get("mitre_mapping"),
        "source_agent": raw.get("agent") or raw.get("agent_name"),
        "full_log": raw.get("full_log"),
        "raw_json": raw,
        "derived_from_background_case": bool((matched_alert or {}).get("derived_from_background_case")),
        "background_case_id": (matched_alert or {}).get("background_case_id"),
    }
    _write_case_json_artifact(
        case_dir,
        TRIGGER_ALERT_BINDING_REL,
        "trigger_alert_binding",
        payload,
        run_id=run_id,
        event_name="trigger_alert_binding_preserved",
        event_meta={"artifact_rel": TRIGGER_ALERT_BINDING_REL, "trigger_alert_id": payload.get("trigger_alert_id")},
    )

    # 2026-07-22: also preserve this same alert as an individual per-case JSON
    # file under alerts/, in the shape foc_case_analysis._phase_alerts() reads
    # (rule_level/severity, source, protocol, rule_id, signature, raw). Before
    # this, the trigger alert's full content was only ever written to
    # TRIGGER_ALERT_BINDING_REL above -- _phase_alerts() globs
    # case_dir/alerts/*.json and found nothing there in 23/38 real cases,
    # skipping alert analysis and cross-layer alert-signature findings even
    # though the alert was fully captured and just never copied to where that
    # phase looks (confirmed: no writer for case_dir/alerts/ existed anywhere
    # in the pipeline). Purely additive -- does not change
    # trigger_alert_binding.json, chain_of_custody.log, or any other existing
    # behavior; only adds one more preserved artifact.
    if primary or triage:
        alert_id = str(primary.get("event_id") or f"{execution_id}-trigger")
        alert_rel = f"alerts/{alert_id}.json"
        alert_payload = {
            "alert_id": alert_id,
            "severity": triage.get("severity"),
            "source": primary.get("collector") or primary.get("original_sensor"),
            "protocol": primary.get("protocol"),
            "rule_id": primary.get("rule_id"),
            "signature": primary.get("signature"),
            "event_id": primary.get("event_id"),
            "ts_utc": primary.get("ts_utc") or primary.get("timestamp"),
            "raw": raw,
        }
        _write_case_json_artifact(
            case_dir,
            alert_rel,
            "alert_json",
            alert_payload,
            run_id=run_id,
            event_name="trigger_alert_case_copy_preserved",
            event_meta={"artifact_rel": alert_rel, "trigger_alert_id": alert_id},
        )
    return payload


def _persist_forensic_intervention_artifact(
    *,
    case_dir: Path,
    run_id: str,
    execution_id: str,
    case_id: str,
    acquisition_profile_id: str,
    trigger_binding: dict,
    memory_result: dict,
    network_result: dict,
    disk_result: dict,
    intervention_started_at: str | None,
    intervention_completed_at: str | None,
) -> dict:
    payload = {
        "generated_at_utc": utc_now(),
        "execution_id": execution_id,
        "case_id": case_id,
        "triggering_alert_id": trigger_binding.get("trigger_alert_id"),
        "triggering_alert_rule_id": trigger_binding.get("rule_id"),
        "intervention_started_at": intervention_started_at,
        "intervention_completed_at": intervention_completed_at,
        "acquisition_profile_id": acquisition_profile_id,
        "selected_actions": [
            "memory_acquisition",
            "network_context_import",
            "disk_acquisition",
        ],
        "preserved_evidence_categories": {
            "memory": bool(memory_result.get("ok")),
            "network_packet_context": int(network_result.get("preserved_segments") or 0) > 0,
            "network_context_manifest": not bool(network_result.get("error")),
            "disk": bool(disk_result.get("ok")),
        },
        "intervention_status": "completed" if intervention_completed_at else "partial",
    }
    _write_case_json_artifact(
        case_dir,
        FORENSIC_INTERVENTION_REL,
        "forensic_intervention",
        payload,
        run_id=run_id,
        event_name="forensic_intervention_preserved",
        event_meta={"artifact_rel": FORENSIC_INTERVENTION_REL, "case_id": case_id},
    )
    return payload


def _persist_normalized_causal_timestamps(
    *,
    case_dir: Path,
    run_id: str,
    execution_id: str,
    case_id: str,
    attack_started_at: str | None,
    attack_completed_at: str | None,
    matched_alert: dict | None,
) -> dict:
    profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") or {}
    events = _read_jsonl(case_dir / "metadata" / "pipeline_events.jsonl")
    _alert_ts = ((matched_alert or {}).get("primary") or {}).get("ts_utc") or ((matched_alert or {}).get("primary") or {}).get("timestamp")
    payload = {
        "generated_at_utc": utc_now(),
        "execution_id": execution_id,
        "case_id": case_id,
        "attack_started_at_utc": attack_started_at,
        "attack_completed_at_utc": attack_completed_at,
        "alert_observed_at_utc": _alert_ts,
        # detection_surface_hit_at_utc: the platform reads Suricata through the Wazuh SIEM pipeline.
        # The IDS engine-level timestamp is not exported independently from the SIEM alert timestamp.
        # This field is set to the Wazuh alert timestamp as the earliest available proxy for the
        # detection surface event. A separate suricata_event_at_utc requires direct eve.json export.
        "detection_surface_hit_at_utc": _alert_ts,
        "suricata_event_at_utc": None,
        "suricata_timestamp_exported": False,
        "forensic_intervention_started_at_utc": profile.get("acquisition_started_utc") or _find_event_time(events, "active_preservation_claimed"),
        "memory_acquisition_started_at_utc": profile.get("memory_started_utc") or _find_event_time(events, "memory_start"),
        "memory_preserved_at_utc": profile.get("memory_completed_utc") or _latest_event_time(events, "memory_preserved"),
        "network_context_import_started_at_utc": profile.get("network_context_import_started_utc") or _find_event_time(events, "network_context_import_started"),
        "network_context_import_completed_at_utc": profile.get("network_context_import_completed_utc") or _latest_event_time(events, "network_context_import_completed"),
        "ot_export_started_at_utc": _find_event_time(events, "ot_export_start"),
        "ot_export_preserved_at_utc": _latest_event_time(events, "ot_export_preserved"),
        "disk_snapshot_started_at_utc": profile.get("disk_started_utc") or _find_event_time(events, "disk_start"),
        "disk_snapshot_preserved_at_utc": profile.get("disk_completed_utc") or _latest_event_time(events, "disk_preserved"),
        "first_seal_at_utc": _latest_event_time(events, "case_digest_written") or _latest_event_time(events, "memory_preserved"),
        "case_sealed_at_utc": _latest_event_time(events, "dfir_orchestration_done") or _latest_event_time(events, "disk_preserved"),
    }
    _write_case_json_artifact(
        case_dir,
        NORMALIZED_TIMESTAMPS_REL,
        "normalized_causal_timestamps",
        payload,
        run_id=run_id,
        event_name="normalized_causal_timestamps_written",
        event_meta={"artifact_rel": NORMALIZED_TIMESTAMPS_REL, "case_id": case_id},
    )
    return payload


def _critical_evidence_gate(
    *,
    case_dir: Path,
    run_id: str,
    execution_id: str,
    case_id: str,
) -> dict:
    manifest_present = (case_dir / "manifest.json").is_file()
    custody_present = (case_dir / "chain_of_custody.log").is_file()
    artifacts = _manifest_artifacts(case_dir)
    profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") or {}
    network_manifest = _json_load(case_dir / "network" / "traffic_preserved" / "network_context_manifest.json") or {}
    trigger_binding_present = (case_dir / TRIGGER_ALERT_BINDING_REL).is_file()
    forensic_intervention_present = (case_dir / FORENSIC_INTERVENTION_REL).is_file()
    normalized_timestamps_present = (case_dir / NORMALIZED_TIMESTAMPS_REL).is_file()
    pcap_artifacts = [item for item in artifacts if _artifact_matches(item, rel_prefix="network/traffic_preserved/full_scenario_captures/", type_tokens=("network_pcap", "pcap"))]
    ot_artifacts = [item for item in artifacts if _artifact_matches(item, rel_prefix="industrial/", type_tokens=("industrial_ot_export", "ot_export"))]
    memory_artifacts = [item for item in artifacts if _artifact_matches(item, rel_prefix="memory/", type_tokens=("memory",))]
    disk_artifacts = [item for item in artifacts if _artifact_matches(item, rel_prefix="disk/", type_tokens=("disk",))]
    preserved_segments = int(((network_manifest.get("summary") or {}).get("preserved_segments")) or 0)
    timestamps = _json_load(case_dir / NORMALIZED_TIMESTAMPS_REL) or {}
    normalized_timestamp_fields = [
        "attack_started_at_utc",
        "attack_completed_at_utc",
        "alert_observed_at_utc",
        "forensic_intervention_started_at_utc",
        "memory_acquisition_started_at_utc",
        "disk_snapshot_preserved_at_utc",
        "case_sealed_at_utc",
    ]
    missing = []
    checks = {
        "pcap_packet_level_modbus_evidence_present": bool(pcap_artifacts) or preserved_segments > 0,
        "ot_export_present_in_manifest": bool(ot_artifacts),
        "raw_wazuh_trigger_binding_present": trigger_binding_present,
        "forensic_intervention_artifact_present": forensic_intervention_present,
        "memory_artifacts_present": bool(memory_artifacts),
        "disk_artifacts_present": bool(disk_artifacts),
        "manifest_present": manifest_present,
        "custody_present": custody_present,
        "normalized_timestamps_available": all(bool(timestamps.get(name)) for name in normalized_timestamp_fields),
    }
    for key, ok in checks.items():
        if not ok:
            missing.append(key)
    found_paths = {
        "pcap_packet_level_modbus_evidence_present": [str(item.get("rel_path") or "") for item in pcap_artifacts],
        "ot_export_present_in_manifest": [str(item.get("rel_path") or "") for item in ot_artifacts],
        "raw_wazuh_trigger_binding_present": [TRIGGER_ALERT_BINDING_REL] if trigger_binding_present else [],
        "forensic_intervention_artifact_present": [FORENSIC_INTERVENTION_REL] if forensic_intervention_present else [],
        "memory_artifacts_present": [str(item.get("rel_path") or "") for item in memory_artifacts],
        "disk_artifacts_present": [str(item.get("rel_path") or "") for item in disk_artifacts],
        "manifest_present": ["manifest.json"] if manifest_present else [],
        "custody_present": ["chain_of_custody.log"] if custody_present else [],
        "normalized_timestamps_available": [NORMALIZED_TIMESTAMPS_REL] if normalized_timestamps_present else [],
    }
    expected_paths = {
        "pcap_packet_level_modbus_evidence_present": ["network/traffic_preserved/full_scenario_captures/**/*.pcap*", "network/traffic_preserved/network_context_manifest.json:summary.preserved_segments>0"],
        "ot_export_present_in_manifest": ["industrial/ot_export_*.json"],
        "raw_wazuh_trigger_binding_present": [TRIGGER_ALERT_BINDING_REL],
        "forensic_intervention_artifact_present": [FORENSIC_INTERVENTION_REL],
        "memory_artifacts_present": ["memory/*.lime"],
        "disk_artifacts_present": ["disk/*.raw or disk/*.qcow2"],
        "manifest_present": ["manifest.json"],
        "custody_present": ["chain_of_custody.log"],
        "normalized_timestamps_available": [NORMALIZED_TIMESTAMPS_REL],
    }
    failure_details = [
        {
            "check": key,
            "expected_paths": expected_paths.get(key) or [],
            "found_paths": found_paths.get(key) or [],
            "supporting_condition": checks.get(key),
        }
        for key in missing
    ]
    gate_status = "scientifically_complete" if not missing else "diagnostic_failed"
    payload = {
        "generated_at_utc": utc_now(),
        "execution_id": execution_id,
        "case_id": case_id,
        "gate_status": gate_status,
        "scientifically_complete": not bool(missing),
        "missing_critical_evidence": missing,
        "checks": checks,
        "failure_details": failure_details,
        "supporting_metrics": {
            "pcap_artifact_count": len(pcap_artifacts),
            "preserved_segments": preserved_segments,
            "ot_export_artifact_count": len(ot_artifacts),
            "memory_artifact_count": len(memory_artifacts),
            "disk_artifact_count": len(disk_artifacts),
        },
        "message": (
            "Critical scientific evidence gate passed."
            if not missing
            else "Critical scientific evidence gate failed; this case is diagnostic/audit only and must not be treated as scientifically complete."
        ),
    }
    _write_case_json_artifact(
        case_dir,
        CRITICAL_EVIDENCE_GATE_REL,
        "critical_evidence_gate",
        payload,
        run_id=run_id,
        event_name="critical_evidence_gate_evaluated",
        event_meta={"artifact_rel": CRITICAL_EVIDENCE_GATE_REL, "gate_status": gate_status, "missing_critical_evidence": missing},
    )
    return payload


def _ensure_case_registered_in_cases_index(case_dir: Path, case_id: str) -> dict:
    cases_index_path = project_path("foc-reconstruction", "indexes", "cases_index.json")
    payload = _json_load(cases_index_path)
    if not isinstance(payload, dict):
        payload = {"generated_at": utc_now(), "cases": []}
    cases = [item for item in list(payload.get("cases") or []) if isinstance(item, dict)]
    manifest = _json_load(case_dir / "manifest.json") or {}
    trigger_summary = _json_load(case_dir / "derived" / "executive" / "evidence_lifecycle_summary.json") or {}
    trigger_info = (trigger_summary.get("trigger_summary") or {}) if isinstance(trigger_summary, dict) else {}
    entry = {
        "case_id": case_id,
        "source_case_name": case_dir.name,
        "path": relative_path(case_dir),
        "artifacts_count": len(list(manifest.get("artifacts") or [])) if isinstance(manifest, dict) else 0,
        "manifest_path": relative_path(case_dir / "manifest.json"),
        "pipeline_path": relative_path(case_dir / "metadata" / "pipeline_events.jsonl"),
        "custody_path": relative_path(case_dir / "chain_of_custody.log"),
        "target_node_ids": list((next((item for item in cases if item.get("case_id") == case_id), {}) or {}).get("target_node_ids") or []),
        "target_instance_ids": list((next((item for item in cases if item.get("case_id") == case_id), {}) or {}).get("target_instance_ids") or []),
    }
    if trigger_info:
        if trigger_info.get("selected_trigger_id"):
            entry["trigger_alert_id"] = trigger_info.get("selected_trigger_id")
        if trigger_info.get("selected_trigger_source"):
            entry["trigger_type"] = trigger_info.get("selected_trigger_source")
        if trigger_info.get("selection_score") is not None:
            entry["trigger_selection_score"] = trigger_info.get("selection_score")
        if trigger_info.get("selection_reason"):
            entry["trigger_selection_reason"] = trigger_info.get("selection_reason")
    cases = [
        item
        for item in cases
        if str(item.get("case_id") or "") != case_id and str(item.get("path") or "") != entry["path"]
    ]
    cases.append(entry)
    cases.sort(key=lambda item: str(item.get("source_case_name") or ""))
    payload["generated_at"] = utc_now()
    payload["cases"] = cases
    _write_json(cases_index_path, payload)
    return entry


def _link_real_case_into_execution_scaffold(campaign_id: str, execution_id: str, case_id: str, case_dir: Path) -> None:
    exec_dir = execution_dir(campaign_id, "B", execution_id)
    manifest_path = exec_dir / "execution_manifest.json"
    manifest = _json_load(manifest_path) or {}
    warnings = [
        str(item)
        for item in list(manifest.get("warnings") or [])
        if "dry-run planning scaffold" not in str(item).lower()
        and "no source case was linked" not in str(item).lower()
        and "no linked source case was provided" not in str(item).lower()
    ]
    manifest.update(
        {
            "updated_at": utc_now(),
            "status": "partial",
            "dry_run": False,
            "run_case_id": case_id,
            "run_case_path": relative_path(case_dir),
            "planned_case_id": None,
            "warnings": warnings,
        }
    )
    _write_json(manifest_path, manifest)


def _read_jsonl(path: Path | None) -> list[dict]:
    if path is None or not path.is_file():
        return []
    rows: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except Exception:
                    continue
                if isinstance(payload, dict):
                    rows.append(payload)
    except Exception:
        return []
    return rows


def _safe_float(value) -> float | None:
    try:
        if value in {None, "", "not_available"}:
            return None
        return float(value)
    except Exception:
        return None


def _parse_dt(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def _seconds_between(start: str | None, end: str | None) -> float | None:
    start_dt = _parse_dt(start)
    end_dt = _parse_dt(end)
    if not start_dt or not end_dt:
        return None
    return round((end_dt - start_dt).total_seconds(), 3)


def _human_bytes(size: int | None) -> str:
    if size is None:
        return "not_available"
    value = float(size)
    units = ["B", "KB", "MB", "GB", "TB"]
    unit = 0
    while value >= 1024.0 and unit < len(units) - 1:
        value /= 1024.0
        unit += 1
    return f"{value:.2f} {units[unit]}"


def _dir_size_bytes(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except Exception:
                continue
    return total


def _sample_std(values: list[float]) -> float:
    if len(values) <= 1:
        return 0.0
    try:
        return round(statistics.stdev(values), 6)
    except Exception:
        return 0.0


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    try:
        return round(statistics.mean(values), 6)
    except Exception:
        return 0.0


def _alert_haystack(alert_payload: dict) -> str:
    primary = (alert_payload or {}).get("primary") or {}
    raw = primary.get("raw") or {}
    raw_data = raw.get("data") or {}
    raw_alert = raw_data.get("alert") or {}
    parts = [
        primary.get("signature"),
        primary.get("alert_type"),
        primary.get("description"),
        primary.get("rule_id"),
        raw_alert.get("signature"),
        raw_alert.get("signature_id"),
        json.dumps(raw_alert.get("metadata") or {}, ensure_ascii=False),
    ]
    return " ".join(str(item or "") for item in parts).lower()


def _mitre_matches_attack(alert_payload: dict, attack: dict) -> bool:
    attack_mitre = str(attack.get("mitre_id") or "").strip().upper()
    if not attack_mitre:
        return False
    primary = (alert_payload or {}).get("primary") or {}
    raw = primary.get("raw") or {}
    raw_mitre = raw.get("mitre_mapping")
    if isinstance(raw_mitre, str) and attack_mitre in raw_mitre.upper():
        return True
    if isinstance(raw_mitre, list):
        for item in raw_mitre:
            if attack_mitre in str(item or "").upper():
                return True
    return False


def _alert_candidate_datetimes(alert_payload: dict) -> list[datetime]:
    primary = (alert_payload or {}).get("primary") or {}
    triage = (alert_payload or {}).get("triage") or {}
    raw = primary.get("raw") or {}
    raw_data = raw.get("data") or {}
    candidates: list[datetime] = []
    seen: set[str] = set()
    for raw_value in (
        primary.get("ts_utc"),
        primary.get("timestamp"),
        raw_data.get("timestamp"),
        raw.get("timestamp"),
        triage.get("ts_utc"),
    ):
        dt = _parse_dt(raw_value)
        if not dt:
            continue
        key = dt.isoformat()
        if key in seen:
            continue
        seen.add(key)
        candidates.append(dt)
    return candidates


def _best_alert_dt_for_attack_window(
    alert_payload: dict,
    *,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
    max_pre_seconds: int = ALERT_MATCH_MAX_PRE_SECONDS,
    max_post_seconds: int = ALERT_MATCH_MAX_POST_SECONDS,
) -> datetime | None:
    candidates = _alert_candidate_datetimes(alert_payload)
    if not candidates:
        return None
    attack_started_dt = _parse_dt(attack_started_at)
    attack_completed_dt = _parse_dt(attack_completed_at) or attack_started_dt
    if not attack_started_dt or not attack_completed_dt:
        return candidates[0]
    earliest = attack_started_dt - timedelta(seconds=int(max_pre_seconds))
    latest = attack_completed_dt + timedelta(seconds=int(max_post_seconds))
    in_window = [dt for dt in candidates if earliest <= dt <= latest]
    if in_window:
        return min(in_window, key=lambda dt: abs((dt - attack_completed_dt).total_seconds()))
    return min(candidates, key=lambda dt: abs((dt - attack_completed_dt).total_seconds()))


def _alert_within_attack_window(
    alert_payload: dict,
    *,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
    max_pre_seconds: int = ALERT_MATCH_MAX_PRE_SECONDS,
    max_post_seconds: int = ALERT_MATCH_MAX_POST_SECONDS,
) -> bool:
    if not attack_started_at and not attack_completed_at:
        return True
    attack_started_dt = _parse_dt(attack_started_at)
    attack_completed_dt = _parse_dt(attack_completed_at) or attack_started_dt
    alert_dt = _best_alert_dt_for_attack_window(
        alert_payload,
        attack_started_at=attack_started_at,
        attack_completed_at=attack_completed_at,
        max_pre_seconds=max_pre_seconds,
        max_post_seconds=max_post_seconds,
    )
    if not alert_dt or not attack_started_dt or not attack_completed_dt:
        return False
    earliest = attack_started_dt - timedelta(seconds=int(max_pre_seconds))
    latest = attack_completed_dt + timedelta(seconds=int(max_post_seconds))
    return earliest <= alert_dt <= latest


def _score_alert_for_attack(
    alert_payload: dict,
    attack: dict,
    *,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
) -> tuple[int, list[str]]:
    triage = (alert_payload or {}).get("triage") or {}
    primary = (alert_payload or {}).get("primary") or {}
    severity = str(triage.get("severity") or "").upper()
    recommend = bool(triage.get("recommend_forensics"))
    if severity not in {"HIGH", "CRITICAL"} or not recommend:
        return 0, ["alert is not HIGH/CRITICAL with forensic recommendation"]
    if not _alert_within_attack_window(
        alert_payload,
        attack_started_at=attack_started_at,
        attack_completed_at=attack_completed_at,
    ):
        return 0, ["alert timestamp falls outside the allowed attack-correlation window"]

    score = 2
    reasons = ["high-severity alert eligible for forensic intervention"]
    haystack = _alert_haystack(alert_payload)
    expected_alert_tokens = {
        str(item).strip().lower().replace("_", " ")
        for item in (attack.get("expected_alerts") or [])
        if str(item).strip()
    }
    if expected_alert_tokens:
        matched_tokens = [token for token in expected_alert_tokens if token and token in haystack]
        if matched_tokens:
            score += 4
            reasons.append(f"expected alert token match: {', '.join(matched_tokens[:4])}")
    if _mitre_matches_attack(alert_payload, attack):
        score += 4
        reasons.append("MITRE technique mapping matches the selected attack profile")
    raw_rule = str(primary.get("rule_id") or "")
    if raw_rule in {"910836101", "910836102", "910836103", "910836104"}:
        score += 3
        reasons.append("matched known OT Modbus write detection rule")
    if "modbus" in haystack:
        score += 2
        reasons.append("alert text contains Modbus indicators")
    if "write" in haystack or "register" in haystack or "control" in haystack:
        score += 1
        reasons.append("alert text contains write/register/control indicators")
    alert_dt = _best_alert_dt_for_attack_window(
        alert_payload,
        attack_started_at=attack_started_at,
        attack_completed_at=attack_completed_at,
    )
    if alert_dt and attack_completed_at:
        attack_completed_dt = _parse_dt(attack_completed_at)
        if attack_completed_dt:
            proximity_seconds = abs((alert_dt - attack_completed_dt).total_seconds())
            if proximity_seconds <= 30:
                score += 3
                reasons.append("alert timestamp is within 30s of attack completion")
            elif proximity_seconds <= 120:
                score += 2
                reasons.append("alert timestamp is within 120s of attack completion")
            elif proximity_seconds <= ALERT_MATCH_MAX_POST_SECONDS:
                score += 1
                reasons.append("alert timestamp is within the extended post-attack correlation window")
    return score, reasons


def _best_observed_alert_for_attack(
    observed_alerts: list[dict],
    attack: dict,
    *,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
) -> tuple[dict | None, list[str]]:
    best_alert = None
    best_score = -1
    best_reasons: list[str] = []
    for alert_payload in observed_alerts or []:
        score, reasons = _score_alert_for_attack(
            alert_payload,
            attack,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
        )
        if score > best_score:
            best_score = score
            best_alert = alert_payload
            best_reasons = reasons
    if best_alert and best_score >= 4:
        return best_alert, best_reasons
    return None, best_reasons


def _trigger_eligibility(alert_payload: dict | None) -> tuple[bool, str]:
    triage = ((alert_payload or {}).get("triage") or {})
    severity = str(triage.get("severity") or "").upper()
    recommend = bool(triage.get("recommend_forensics"))
    if severity not in {"HIGH", "CRITICAL"}:
        return False, f"observed alert severity is {severity or 'unknown'}, not HIGH/CRITICAL"
    if not recommend:
        return False, "observed alert is not marked as eligible for forensic intervention"
    return True, "observed alert is HIGH/CRITICAL and eligible for forensic intervention"


def _diagnose_trigger_failure(attempt_trace: list[dict], dfir_mode_after: str) -> tuple[str, list[str]]:
    mode = str(dfir_mode_after or "unknown").strip().lower() or "unknown"
    if mode != "on":
        return (
            "Forensic preservation was never armed because DFIR mode remained OFF during the repeated attack attempts. "
            "Alerts may have been observed, but the platform was not in forensic intervention mode.",
            ["dfir_mode_off_during_trigger_arming"],
        )

    if any(bool(item.get("trigger_alert_detected")) for item in attempt_trace):
        return (
            "Alerts were observed during the repeated attack attempts, but none of them reached a trigger state eligible for automatic forensic preservation. "
            "The most likely cause is insufficient alert severity or missing forensic-intervention recommendation.",
            ["observed_alerts_not_eligible_for_forensic_intervention"],
        )

    return (
        "No alert matching the controlled OT attack profile was observed during the repeated trigger-arming attempts, so automatic forensic preservation never started.",
        ["no_matching_alert_observed_during_trigger_arming"],
    )


def _active_case_dir() -> Path | None:
    try:
        raw = ACTIVE_CASE_PTR.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if not raw:
        return None
    path = Path(raw).expanduser().resolve()
    return path if path.exists() else None


def _detect_background_case_during_trigger_arming() -> tuple[Path | None, str | None]:
    _prune_stale_placeholder_cases()
    guard = _active_preservation_guard()
    guard_case_dir = Path(str(guard.get("case_dir") or "")).resolve() if guard.get("case_dir") else None
    if not guard.get("allowed") and guard_case_dir and _is_background_case_candidate(guard_case_dir):
        return guard_case_dir, "active_preservation_guard_detected_case"

    active_case_dir = _active_case_dir()
    if active_case_dir and _is_background_case_candidate(active_case_dir):
        return active_case_dir, "active_case_pointer_detected_case"

    candidates = [
        item.resolve()
        for item in EVIDENCE_STORE_ROOT.glob("CASE-*")
        if item.exists() and item.is_dir() and _is_background_case_candidate(item.resolve())
    ]
    if not candidates:
        return None, None
    candidates.sort(key=lambda item: _recent_case_age_seconds(item) if _recent_case_age_seconds(item) is not None else 10**12)
    return candidates[0], "existing_case_detected_during_trigger_arming"


def _cleanup_previous_heavy_case_before_next_repetition(
    *,
    job_id: str,
    job_path: Path,
    campaign_id: str,
    repetition_number: int,
    total_repetitions: int,
    previous_result: dict | None,
    acquisition_targets: list[dict] | None,
) -> dict:
    _prune_stale_placeholder_cases()
    active_case_dir = _active_case_dir()
    if not active_case_dir:
        return {"status": "skipped", "reason": "no_active_case_present"}

    previous_case_id = str((previous_result or {}).get("case_id") or "").strip()
    previous_execution_id = str((previous_result or {}).get("execution_id") or "").strip()
    active_case_id = _case_id_for_case_dir(str(active_case_dir))
    case_id = active_case_id or previous_case_id
    if not case_id or not previous_execution_id:
        return {
            "status": "failed",
            "reason": "could_not_resolve_previous_case_or_execution",
            "active_case_dir": str(active_case_dir),
            "active_case_id": active_case_id,
            "previous_case_id": previous_case_id,
            "previous_execution_id": previous_execution_id,
        }

    try:
        ACTIVE_CASE_PTR.write_text("", encoding="utf-8")
    except Exception:
        pass

    _emit_phase(
        job_id,
        job_path,
        phase_key=f"repetition_{repetition_number}_cleanup_previous",
        phase_label="Clean previous heavy case before next repetition",
        status="running",
        detail=(
            f"Previous heavy case {case_id} is still present before repetition {repetition_number}/{total_repetitions}. "
            "Cleaning it now so a new heavy case can be created without coexisting storage pressure."
        ),
        category="repetition",
        index=0,
        repetition_number=repetition_number,
        total_repetitions=total_repetitions,
        extra={"previous_case_id": case_id, "previous_execution_id": previous_execution_id},
    )
    cleanup = delete_generated_case_artifacts(
        previous_execution_id,
        campaign_id=campaign_id,
        case_id=case_id,
        confirmation="OK",
        operator="level_b_repetition_runner_pre_next_cleanup",
    )
    if cleanup.get("error") == "case_id_mismatch" and active_case_dir.exists():
        try:
            shutil.rmtree(active_case_dir)
            try:
                ACTIVE_CASE_PTR.write_text("", encoding="utf-8")
            except Exception:
                pass
            try:
                _clear_active_preservation_state(str(active_case_dir), final_state="cleaned_as_orphan", reason="pre_next_repetition_orphan_case_cleanup")
            except Exception:
                pass
            cleanup = {
                "status": "ok",
                "message": "The previous heavy case was no longer linked consistently to the execution workspace and was deleted directly as an orphan heavy case before the next repetition.",
                "fallback_cleanup": "direct_orphan_case_delete",
                "deleted_case_dir": str(active_case_dir),
                "deleted_case_id": case_id,
            }
        except Exception as exc:
            cleanup = {
                "error": "orphan_case_cleanup_failed",
                "message": str(exc),
            }
    if cleanup.get("error"):
        _emit_phase(
            job_id,
            job_path,
            phase_key=f"repetition_{repetition_number}_cleanup_previous",
            phase_label="Clean previous heavy case before next repetition",
            status="failed",
            detail=f"Could not clean previous heavy case {case_id} before repetition {repetition_number}: {cleanup.get('error')}",
            category="repetition",
            index=0,
            repetition_number=repetition_number,
            total_repetitions=total_repetitions,
            extra={"previous_case_id": case_id, "previous_execution_id": previous_execution_id},
        )
        return {
            "status": "failed",
            "reason": str(cleanup.get("error") or "cleanup_failed"),
            "case_id": case_id,
            "execution_id": previous_execution_id,
            "cleanup": cleanup,
        }

    bundle_manifest = str(cleanup.get("lightweight_case_bundle_manifest_path") or "")
    _emit_phase(
        job_id,
        job_path,
        phase_key=f"repetition_{repetition_number}_cleanup_previous",
        phase_label="Clean previous heavy case before next repetition",
        status="completed",
        detail=(
            f"Previous heavy case {case_id} was removed before creating the new case for repetition {repetition_number}. "
            f"Lightweight retained bundle: {bundle_manifest or 'not_available'}."
        ),
        category="repetition",
        index=0,
        repetition_number=repetition_number,
        total_repetitions=total_repetitions,
        extra={"previous_case_id": case_id, "previous_execution_id": previous_execution_id, "lightweight_case_bundle_manifest_path": bundle_manifest or None},
    )
    free_space_cleanup = _run_level_b_free_space_cleanup(acquisition_targets)
    free_space_status = "completed" if free_space_cleanup.get("status") == "completed" else "completed_with_degradation"
    free_space_detail = (
        f"Applied safe free-space cleanup on fuxa/plc after deleting previous heavy case {case_id}. "
        f"Cleaned roles: {', '.join(free_space_cleanup.get('cleaned_roles') or []) or 'none'}."
    )
    if free_space_cleanup.get("status") != "completed":
        free_space_detail = (
            f"Previous heavy case {case_id} was deleted, but the follow-up free-space cleanup on fuxa/plc was not fully successful. "
            f"Failed roles: {', '.join(free_space_cleanup.get('failed_roles') or []) or 'unknown'}."
        )
    _emit_phase(
        job_id,
        job_path,
        phase_key=f"repetition_{repetition_number}_cleanup_previous_node_space",
        phase_label="Free space cleanup on fuxa/plc",
        status=free_space_status,
        detail=free_space_detail,
        category="repetition",
        index=0,
        repetition_number=repetition_number,
        total_repetitions=total_repetitions,
        extra={"previous_case_id": case_id, "free_space_cleanup": free_space_cleanup},
    )
    return {
        "status": "completed",
        "case_id": case_id,
        "execution_id": previous_execution_id,
        "cleanup": cleanup,
        "post_case_free_space_cleanup": free_space_cleanup,
    }


def _wait_for_active_preservation_release(
    *,
    expected_case_dir: Path,
    timeout_seconds: int = 1800,
    poll_seconds: int = 5,
) -> dict:
    started = time.time()
    expected_resolved = expected_case_dir.resolve()
    last_guard: dict | None = None
    while (time.time() - started) <= timeout_seconds:
        guard = _active_preservation_guard()
        last_guard = guard
        if guard.get("allowed"):
            return {
                "status": "completed",
                "elapsed_seconds": round(time.time() - started, 3),
                "guard": guard,
            }
        guard_case_dir = Path(str(guard.get("case_dir") or "")).resolve() if guard.get("case_dir") else None
        if guard_case_dir and guard_case_dir != expected_resolved:
            return {
                "status": "failed",
                "reason": "different_active_preservation_case_detected",
                "elapsed_seconds": round(time.time() - started, 3),
                "guard": guard,
            }
        time.sleep(max(1, int(poll_seconds)))
    return {
        "status": "failed",
        "reason": "active_preservation_timeout",
        "elapsed_seconds": round(time.time() - started, 3),
        "guard": last_guard or {},
    }


def _resolve_level_b_acquisition_targets() -> list[dict]:
    preferred_roles = ["fuxa", "plc", "victim"]
    resolved = _resolve_dfir_targets_from_openstack(preferred_roles)
    by_role = {
        str(item.get("role") or "").lower(): item
        for item in (resolved or [])
        if item.get("vm_id") and item.get("vm_ip")
    }
    missing = [role for role in preferred_roles if role not in by_role]
    if missing:
        raise RuntimeError(
            "Level B multi-host preservation requires fuxa, plc, and victim to be resolvable. "
            f"Missing roles: {', '.join(missing)}."
        )
    return [by_role[role] for role in preferred_roles]


def _resolve_level_b_free_space_cleanup_targets(acquisition_targets: list[dict] | None) -> list[dict]:
    by_role = {
        str(item.get("role") or "").lower(): item
        for item in (acquisition_targets or [])
        if item.get("vm_ip")
    }
    missing = [role for role in LEVEL_B_FREE_SPACE_CLEANUP_ROLES if role not in by_role]
    if missing:
        raise RuntimeError(
            "Level B free-space cleanup requires fuxa and plc to be resolvable. "
            f"Missing roles: {', '.join(missing)}."
        )
    return [by_role[role] for role in LEVEL_B_FREE_SPACE_CLEANUP_ROLES]


def _run_free_space_cleanup_on_target(target: dict, *, timeout_seconds: int = 900) -> dict:
    role = str(target.get("role") or "").lower()
    vm_name = str(target.get("vm_name") or target.get("name") or role or "unknown")
    vm_ip = str(target.get("vm_ip") or "").strip()
    started_at = time.time()
    result = cleanup_node_free_space(
        instance_id=str(target.get("vm_id") or "").strip() or None,
        vm_ip=vm_ip or None,
        timeout=min(int(timeout_seconds), 120),
        minimum_free_mb=1200,
        max_attempts=2,
    )
    result["role"] = role
    result["vm_name"] = vm_name
    result["vm_ip"] = vm_ip
    result["elapsed_seconds"] = round(time.time() - started_at, 3)
    return result


def _run_level_b_free_space_cleanup(acquisition_targets: list[dict] | None) -> dict:
    try:
        cleanup_targets = _resolve_level_b_free_space_cleanup_targets(acquisition_targets)
    except Exception as exc:
        return {
            "status": "failed",
            "reason": str(exc),
            "per_target": [],
            "cleaned_roles": [],
            "failed_roles": [],
        }

    per_target = [_run_free_space_cleanup_on_target(target) for target in cleanup_targets]
    failed = [item for item in per_target if item.get("status") != "completed"]
    cleaned_roles = [str(item.get("role") or "unknown") for item in per_target if item.get("status") == "completed"]
    failed_roles = [str(item.get("role") or "unknown") for item in failed]
    return {
        "status": "completed" if not failed else "failed",
        "per_target": per_target,
        "cleaned_roles": cleaned_roles,
        "failed_roles": failed_roles,
    }


def _load_campaign(campaign_id: str) -> tuple[dict, dict]:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    config = _json_load(campaign_config_path(campaign_id)) or {}
    return manifest, config


def _resolve_repetition_count(config: dict, requested_repetitions: int | None, *, default: int = 3, minimum: int = 1) -> int:
    value = requested_repetitions
    if value in {None, "", 0}:
        value = config.get("repetitions")
    try:
        resolved = int(value or default)
    except Exception:
        resolved = default
    return max(resolved, minimum)


def _resolve_nested_level_a_repetition_count(
    config: dict,
    requested_nested_level_a_repetitions: int | None,
    *,
    requested_level_b_repetitions: int | None = None,
    default: int = 3,
    minimum: int = 1,
) -> int:
    value = requested_nested_level_a_repetitions
    if value in {None, "", 0}:
        value = config.get("nested_level_a_repetitions")
    if value in {None, "", 0}:
        value = requested_level_b_repetitions
    try:
        resolved = int(value or default)
    except Exception:
        resolved = default
    return max(resolved, minimum)


def _safe_git_commit() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(project_path()),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        value = (proc.stdout or "").strip()
        return value or "not_available"
    except Exception:
        return "not_available"


def _report_dir_for_timestamp(timestamp: str) -> Path:
    safe = timestamp.replace(":", "").replace("+", "_")
    return VALIDATION_REPORTS_ROOT / f"level_b_repetition_report_{safe}"


def _best_effort_rmtree(path: Path, deleted_paths: list[str], warnings: list[str]) -> None:
    try:
        if not path.exists():
            return
        shutil.rmtree(path)
        deleted_paths.append(relative_path(path))
    except Exception as exc:
        warnings.append(f"{relative_path(path)}: {exc}")


def _remove_execution_dir(campaign_id: str, execution_id: str, deleted_paths: list[str], warnings: list[str]) -> None:
    execution = load_execution(execution_id, campaign_id=campaign_id) or {}
    execution_abs_path = str(execution.get("execution_abs_path") or "").strip()
    if not execution_abs_path:
        return
    _best_effort_rmtree(Path(execution_abs_path), deleted_paths, warnings)


def _remove_case_dir(case_id: str | None, case_path: str | None, deleted_paths: list[str], warnings: list[str]) -> None:
    candidate = None
    if case_path:
        raw = Path(str(case_path))
        candidate = (Path.cwd() / raw).resolve() if not raw.is_absolute() else raw.resolve()
    elif case_id:
        entry = get_case_entry(case_id)
        if entry:
            candidate = _case_dir_from_entry(entry)
    if candidate:
        _best_effort_rmtree(candidate, deleted_paths, warnings)


def _drop_latest_level_b_report_reference(campaign_id: str, report_dir_rel: str | None) -> None:
    manifest_path = campaign_manifest_path(campaign_id)
    manifest = _json_load(manifest_path) or {}
    if not manifest:
        return
    reports = dict(manifest.get("validation_reports") or {})
    history = list(reports.get("level_b_history") or [])
    latest = reports.get("latest_level_b") or {}
    if report_dir_rel and str((latest or {}).get("report_dir") or "") == str(report_dir_rel):
        reports.pop("latest_level_b", None)
    if report_dir_rel:
        history = [item for item in history if str((item or {}).get("report_dir") or "") != str(report_dir_rel)]
    reports["level_b_history"] = history
    manifest["validation_reports"] = reports
    _write_json(manifest_path, manifest)
    try:
        aggregate_campaign_state(campaign_id, manifest)
    except Exception:
        pass


def _cleanup_candidates() -> list[dict]:
    active_case = _active_case_dir()
    indexed_by_path: dict[str, dict] = {}
    candidates: list[dict] = []
    for item in cases_with_analysis_state().get("cases", []):
        raw_path = str(item.get("path") or "").strip()
        if not raw_path:
            continue
        case_path = project_path(*Path(raw_path).parts) if not Path(raw_path).is_absolute() else Path(raw_path)
        case_path = case_path.resolve()
        if not case_path.exists() or not case_path.is_dir():
            continue
        indexed_by_path[str(case_path)] = item

    for case_path in sorted(EVIDENCE_STORE_ROOT.glob("CASE-*")):
        case_path = case_path.resolve()
        if not case_path.exists() or not case_path.is_dir():
            continue
        item = indexed_by_path.get(str(case_path), {})
        size_bytes = _dir_size_bytes(case_path)
        candidates.append(
            {
                "case_id": item.get("case_id") or _case_id_for_case_dir(str(case_path)) or case_path.name,
                "case_path": relative_path(case_path),
                "analysis_status": item.get("analysis_status") or "not_indexed",
                "available_layers": item.get("available_layers") or [],
                "is_active_case": bool(active_case and case_path == active_case),
                "size_bytes": size_bytes,
                "size_human": _human_bytes(size_bytes),
                "preserved_metadata": {
                    "inventory_summary": item.get("inventory_summary") or {},
                    "analysis_report_path": item.get("analysis_report_path"),
                    "indexed": bool(item),
                },
            }
        )
    candidates.sort(key=lambda row: int(row.get("size_bytes") or 0), reverse=True)
    return candidates


def preview_level_b_repetitions(
    campaign_id: str,
    *,
    requested_repetitions: int | None = None,
    requested_nested_level_a_repetitions: int | None = None,
) -> dict:
    manifest, config = _load_campaign(campaign_id)
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    level = str(config.get("level") or manifest.get("level") or "B").upper()
    if level != "B":
        raise ValueError("level_b_repetition_runner_requires_level_b_campaign")
    attack_id = str(config.get("attack_id") or "").strip()
    if not attack_id:
        return {
            "ready": False,
            "campaign_id": campaign_id,
            "error": "attack_profile_required",
            "message": "Select an attack profile for this Level B campaign before launching repetitions.",
            "cleanup_preview": {
                "candidates": _cleanup_candidates(),
            },
        }
    attack = find_attack_by_id(attack_id)
    if not attack:
        return {
            "ready": False,
            "campaign_id": campaign_id,
            "error": "attack_profile_not_found",
            "message": f"Attack profile not found: {attack_id}",
            "cleanup_preview": {
                "candidates": _cleanup_candidates(),
            },
        }
    targets = _resolve_real_targets(attack)
    target = targets.get("target")
    monitor = targets.get("monitor")
    try:
        acquisition_targets = _resolve_level_b_acquisition_targets()
        acquisition_ready = True
        acquisition_error = ""
    except Exception as exc:
        acquisition_targets = []
        acquisition_ready = False
        acquisition_error = str(exc)
    candidates = _cleanup_candidates()
    estimated = sum(int(item.get("size_bytes") or 0) for item in candidates)
    repetitions = _resolve_repetition_count(config, requested_repetitions, default=3, minimum=1)
    nested_level_a_repetitions = _resolve_nested_level_a_repetition_count(
        config,
        requested_nested_level_a_repetitions,
        requested_level_b_repetitions=repetitions,
        default=repetitions,
        minimum=1,
    )
    return {
        "ready": bool(target and monitor and acquisition_ready and str((target or {}).get("role") or "").lower() == "plc"),
        "campaign_id": campaign_id,
        "requested_repetitions": repetitions,
        "nested_level_a_repetitions": nested_level_a_repetitions,
        "scenario_id": config.get("scenario_id") or manifest.get("scenario_id") or "not_available",
        "attack_profile_id": attack.get("attack_id"),
        "attack_name": attack.get("display_name"),
        "mitre_id": attack.get("mitre_id"),
        "script": attack.get("script"),
        "expected_alerts": attack.get("expected_alerts") or [],
        "expected_artifacts": attack.get("expected_artifacts") or [],
        "cleanup_preview": {
            "count": len(candidates),
            "freed_bytes_estimated": estimated,
            "freed_human_estimated": _human_bytes(estimated),
            "candidates": candidates,
        },
        "resolved_target": target,
        "resolved_monitor": monitor,
        "resolved_acquisition_targets": acquisition_targets,
        "message": (
            f"The Level B repetition batch is ready for {repetitions} requested Level B repetitions with multi-host preservation over fuxa, plc, and victim."
            if (target and monitor and acquisition_ready and str((target or {}).get("role") or "").lower() == "plc")
            else acquisition_error or "The active deployed scenario does not currently expose a resolvable PLC target, monitor, and preservation scope over fuxa/plc/victim for this attack."
        ),
    }


def _phase_progress(
    category: str,
    index: int,
    *,
    completed: bool,
    repetition_number: int | None = None,
    total_repetitions: int = 5,
) -> float:
    if category == "setup":
        start = (index / max(len(SETUP_PHASES), 1)) * 20.0
        end = ((index + 1) / max(len(SETUP_PHASES), 1)) * 20.0
        return round(end if completed else start, 2)
    if category == "repetition":
        rep_slot = 70.0 / max(total_repetitions, 1)
        rep_index = max((repetition_number or 1) - 1, 0)
        rep_start = 20.0 + (rep_index * rep_slot)
        phase_start = rep_start + ((index / max(len(REPETITION_PHASES), 1)) * rep_slot)
        phase_end = rep_start + (((index + 1) / max(len(REPETITION_PHASES), 1)) * rep_slot)
        return round(phase_end if completed else phase_start, 2)
    if category == "final":
        start = 90.0 + ((index / max(len(FINAL_PHASES), 1)) * 10.0)
        end = 90.0 + (((index + 1) / max(len(FINAL_PHASES), 1)) * 10.0)
        return round(end if completed else start, 2)
    return 0.0


def _emit_phase(
    job_id: str,
    job_path: Path,
    *,
    phase_key: str,
    phase_label: str,
    status: str,
    detail: str,
    category: str,
    index: int,
    repetition_number: int | None = None,
    total_repetitions: int = 5,
    extra: dict | None = None,
) -> None:
    progress = _phase_progress(
        category,
        index,
        completed=status in {"completed", "completed_with_degradation", "failed", "skipped"},
        repetition_number=repetition_number,
        total_repetitions=total_repetitions,
    )
    append_phase(
        job_id,
        job_path,
        phase_key=phase_key,
        phase_label=phase_label,
        status=status,
        progress_percent=progress,
        detail=detail,
    )
    changes = {
        "current_phase": phase_key,
        "current_phase_label": phase_label,
        "current_phase_detail": detail,
        "progress_percent": progress,
    }
    if extra:
        changes.update(extra)
    update_job(job_id, job_path, **changes)


def _cleanup_runtime_manifest(runtime_dir: Path, *, candidates: list[dict], status: str, warnings: list[str], deleted_cases: list[str], deleted_paths: list[str], estimated: int, actual: int, preserved_metadata: list[dict]) -> dict:
    payload = {
        "deleted_cases": deleted_cases,
        "deleted_paths": deleted_paths,
        "freed_bytes_estimated": estimated,
        "freed_bytes_actual": actual,
        "preserved_metadata": preserved_metadata,
        "cleanup_status": status,
        "warnings": warnings,
    }
    _write_json(runtime_dir / "cleanup_manifest.json", payload)
    return payload


def _run_cleanup(runtime_dir: Path, *, enabled: bool) -> dict:
    candidates = _cleanup_candidates()
    estimated = sum(int(item.get("size_bytes") or 0) for item in candidates)
    if not enabled:
        return _cleanup_runtime_manifest(
            runtime_dir,
            candidates=candidates,
            status="skipped",
            warnings=[],
            deleted_cases=[],
            deleted_paths=[],
            estimated=estimated,
            actual=0,
            preserved_metadata=[{"case_id": item.get("case_id"), "case_path": item.get("case_path")} for item in candidates],
        )

    deleted_cases: list[str] = []
    deleted_paths: list[str] = []
    warnings: list[str] = []
    actual = 0
    preserved_metadata: list[dict] = []
    for item in candidates:
        case_id = str(item.get("case_id") or "")
        case_path = project_path(*Path(item.get("case_path") or "").parts)
        preserved_metadata.append({"case_id": case_id, "case_path": item.get("case_path"), "size_bytes": item.get("size_bytes")})
        if not case_path.exists():
            warnings.append(f"{case_id}: case path no longer exists.")
            continue
        size_before = int(item.get("size_bytes") or 0)
        try:
            from .retention_service import _copy_lightweight_case_bundle
            bundle = _copy_lightweight_case_bundle(original_case_path=case_path, execution_base=runtime_dir, case_id=case_id)
            preserved_metadata[-1]["lightweight_bundle_path"] = bundle.get("bundle_root")
            preserved_metadata[-1]["lightweight_bundle_copied_files"] = len(bundle.get("copied_files") or [])
        except Exception as exc:
            warnings.append(f"{case_id}: could not preserve lightweight bundle before deletion: {exc}")
        try:
            shutil.rmtree(case_path)
            deleted_cases.append(case_id)
            deleted_paths.append(relative_path(case_path))
            actual += size_before
        except Exception as exc:
            warnings.append(f"{case_id}: {exc}")
            return _cleanup_runtime_manifest(
                runtime_dir,
                candidates=candidates,
                status="failed",
                warnings=warnings,
                deleted_cases=deleted_cases,
                deleted_paths=deleted_paths,
                estimated=estimated,
                actual=actual,
                preserved_metadata=preserved_metadata,
            )
    return _cleanup_runtime_manifest(
        runtime_dir,
        candidates=candidates,
        status="completed",
        warnings=warnings,
        deleted_cases=deleted_cases,
        deleted_paths=deleted_paths,
        estimated=estimated,
        actual=actual,
        preserved_metadata=preserved_metadata,
    )


def _attack_parameter_status(attack_result: dict) -> dict:
    output_dir = Path(str(attack_result.get("_output_dir") or "")).resolve() if attack_result.get("_output_dir") else None
    modbus_log = _json_load(output_dir / "modbus_transaction_log.json") if output_dir and output_dir.is_dir() else None
    write_command = ((modbus_log or {}).get("write_command") or {}).get("command")
    parsed = _parse_mbpoll_command(write_command or "")
    return {
        "protocol": "modbus_tcp",
        "destination_port": 502,
        "function_code": "confirmed" if parsed.get("modbus_function") else "unknown",
        "register": "confirmed" if parsed.get("register_reference") is not None else "unknown",
        "value": "confirmed" if parsed.get("value") is not None else "unknown",
        "parsed_write_command": parsed,
        "modbus_log_path": relative_path(output_dir / "modbus_transaction_log.json") if output_dir and (output_dir / "modbus_transaction_log.json").is_file() else None,
    }


def _network_context_payload(case_dir: Path) -> dict:
    manifest = _json_load(case_dir / "network" / "traffic_preserved" / "network_context_manifest.json") or {}
    preserved = list(manifest.get("preserved_segments") or [])
    pending = list(manifest.get("pending_segments") or [])
    if preserved and pending:
        status = "partial"
    elif preserved:
        status = "completed"
    elif pending:
        status = "pending"
    else:
        status = "failed"
    return {
        "status": status,
        "manifest": manifest,
        "preserved_segments": len(preserved),
        "pending_segments": len(pending),
    }


def _manifest_artifact_sizes(case_dir: Path) -> dict[str, list[int]]:
    artifacts = _manifest_artifacts(case_dir)
    sizes: dict[str, list[int]] = {"pcap": [], "memory": [], "disk": [], "ot": []}
    for artifact in artifacts:
        rel_path = str(artifact.get("rel_path") or "")
        try:
            size = int(artifact.get("size") or 0)
        except Exception:
            size = 0
        if size <= 0:
            continue
        low = rel_path.lower()
        if low.startswith("network/") and (low.endswith(".pcap") or low.endswith(".pcapng")):
            sizes["pcap"].append(size)
        elif low.startswith("memory/") and (low.endswith(".lime") or "memdump" in low):
            sizes["memory"].append(size)
        elif low.startswith("disk/") and (low.endswith(".raw") or low.endswith(".qcow2")):
            sizes["disk"].append(size)
        elif low.startswith("industrial/"):
            sizes["ot"].append(size)
    return sizes


def _bytes_to_gib(value: int | float | None) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return round(float(value) / (1024.0 ** 3), 6)
    except Exception:
        return None


def _count_failures_for_run(events: list[dict], run_id: str) -> int:
    count = 0
    for event in events:
        if str(event.get("run_id") or "") != str(run_id or ""):
            continue
        name = str(event.get("event") or event.get("event_type") or "")
        if name.endswith("_failed") or "failed" in name:
            count += 1
    return count


def _observed_case_state(case_id: str | None, case_dir: Path | None) -> dict:
    if not case_dir or not case_dir.exists():
        return {
            "case_exists": False,
            "pcap_segments_imported": 0,
            "alerts_preserved": 0,
            "memory_acquisition_status": "skipped",
            "network_context_status": "skipped",
            "disk_acquisition_status": "skipped",
            "custody_status": "skipped",
            "case_sealed_status": "skipped",
            "analysis_status": "failed",
            "layers_total": 0,
            "layers_completed": 0,
            "layers_partial": 0,
            "layers_failed": 0,
            "memory_analysis_status": "not_started",
            "network_analysis_status": "not_started",
            "disk_analysis_status": "not_started",
            "ot_analysis_status": "not_started",
            "alert_analysis_status": "not_started",
            "timeline_status": "not_started",
            "artifacts": {},
        }

    acquisition_profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") or {}
    network_context = _network_context_payload(case_dir)
    alerts_preserved = len(list((case_dir / "alerts").glob("*.json"))) if (case_dir / "alerts").is_dir() else 0
    analysis_status = load_analysis_status(case_id) if case_id else {}
    if not analysis_status:
        direct_status = _json_load(case_dir / "analysis" / "analysis_status.json") or {}
        if isinstance(direct_status, dict):
            analysis_status = direct_status
    layers = _analysis_layer_counts(analysis_status or {})
    manifest_present = (case_dir / "manifest.json").is_file()
    custody_present = (case_dir / "chain_of_custody.log").is_file()
    case_digest_present = (case_dir / "metadata" / "case_digest.json").is_file()
    memory_dump_present = (case_dir / "memory").is_dir() and any((case_dir / "memory").glob("*.lime"))
    disk_present = (case_dir / "disk").is_dir() and any((case_dir / "disk").glob("*.raw"))
    analysis_dir = case_dir / "analysis"
    return {
        "case_exists": True,
        "pcap_segments_imported": int(network_context.get("preserved_segments") or 0),
        "alerts_preserved": alerts_preserved,
        "memory_acquisition_status": "completed" if (acquisition_profile.get("memory_completed_utc") or memory_dump_present) else "failed",
        "network_context_status": network_context.get("status"),
        "disk_acquisition_status": "completed" if (acquisition_profile.get("disk_completed_utc") or disk_present) else "failed",
        "custody_status": "valid" if custody_present else "failed",
        "case_sealed_status": "sealed" if (manifest_present and case_digest_present) else ("partial" if manifest_present else "failed"),
        "analysis_status": str((analysis_status or {}).get("status") or ("partial" if analysis_dir.exists() else "failed")),
        **layers,
        "memory_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("memory_analysis") or {}).get("status") or ("completed" if (analysis_dir / "04_memory" / "memory_findings.json").is_file() else "not_started")),
        "network_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("network_analysis") or {}).get("status") or ("completed" if (analysis_dir / "03_network" / "network_findings.json").is_file() else "not_started")),
        "disk_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("disk_analysis") or {}).get("status") or ("completed" if (analysis_dir / "05_disk" / "disk_findings.json").is_file() else "not_started")),
        "ot_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("ot_export_analysis") or {}).get("status") or ("completed" if (analysis_dir / "06_ot" / "ot_findings.json").is_file() else "not_started")),
        "alert_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("alerts_detection_analysis") or {}).get("status") or ("completed" if (analysis_dir / "07_alerts" / "alert_findings.json").is_file() else "not_started")),
        "timeline_status": str((((analysis_status or {}).get("phases") or {}).get("unified_forensic_timeline") or {}).get("status") or ("completed" if (analysis_dir / "09_timeline" / "unified_forensic_timeline.json").is_file() else "not_started")),
        "artifacts": {
            "analysis_status": relative_path(case_dir / "analysis" / "analysis_status.json") if (case_dir / "analysis" / "analysis_status.json").is_file() else None,
            "forensic_analysis_report": relative_path(case_dir / "analysis" / "forensic_analysis_report.json") if (case_dir / "analysis" / "forensic_analysis_report.json").is_file() else None,
            "forensic_analysis_manifest": relative_path(case_dir / "analysis" / "forensic_analysis_manifest.json") if (case_dir / "analysis" / "forensic_analysis_manifest.json").is_file() else None,
            "network_context_manifest": relative_path(case_dir / "network" / "traffic_preserved" / "network_context_manifest.json") if (case_dir / "network" / "traffic_preserved" / "network_context_manifest.json").is_file() else None,
            "acquisition_profile": relative_path(case_dir / "metadata" / "acquisition_profile.json") if (case_dir / "metadata" / "acquisition_profile.json").is_file() else None,
            "pipeline_events": relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if (case_dir / "metadata" / "pipeline_events.jsonl").is_file() else None,
        },
    }


def _current_rss_mb() -> float | None:
    """Memoria residente (RSS) real del proceso actual, leida directamente de
    /proc/self/status -- sin depender de psutil (no instalado en este entorno).
    Solo funciona en Linux; devuelve None en cualquier otro caso, sin lanzar nunca."""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except Exception:
        pass
    return None


def _tracemalloc_events_path(job_id: str) -> Path:
    return RUNTIME_ROOT / job_id / "tracemalloc_diff.jsonl"


def _append_tracemalloc_diff(job_id: str, phase_hint: str, baseline, snapshot, rss_mb: float | None) -> None:
    """Diffs a tracemalloc snapshot against the baseline taken when this
    `_heartbeat_during` block started, and appends the top 15 growers (by
    real bytes, not guessed) to a per-job JSONL file. Read-only/append-only,
    never raises -- this is pure diagnostics, must never affect the actual
    job. Motivated directly by the 2026-09-24 incident: five consecutive
    real campaign failures with the same RSS-climbs-then-worker-dies shape,
    across TWO different phases (analysis, then reconstruction after the
    first fix), where reading the code by eye correctly found one real bug
    (`foc_indexer.py`) but missed a second one -- this gives a live,
    per-line answer instead of guessing again."""
    try:
        top_stats = snapshot.compare_to(baseline, "lineno")[:15]
        path = _tracemalloc_events_path(job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "phase_hint": phase_hint,
            "rss_mb": rss_mb,
            "top_growers": [
                {
                    "traceback": str(stat.traceback),
                    "size_diff_mb": round(stat.size_diff / (1024 * 1024), 2),
                    "size_mb": round(stat.size / (1024 * 1024), 2),
                    "count_diff": stat.count_diff,
                    "count": stat.count,
                }
                for stat in top_stats
            ],
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except Exception:
        pass


@contextlib.contextmanager
def _heartbeat_during(job_id: str, job_path: Path, interval: int = 30):
    """Keep a job's heartbeat (`updated_at`) fresh for the duration of a long
    blocking call that has no interim `update_job()` calls of its own —
    e.g. `acquire_memory`/`acquire_disk` below, which can each legitimately
    run for many minutes per node with nothing touching the job's own
    heartbeat in between (their `update_acquisition_profile` calls write to
    the CASE's acquisition_profile.json, not the job's job_state.json).

    Without this, a `get_job()` read from a different gunicorn worker than
    the one actually running this job (e.g. a dashboard poll) can't verify
    the thread is alive (per-worker `_THREADS`) and falls back to heartbeat
    staleness, wrongly declaring a genuinely-running acquisition orphaned
    once `_ORPHAN_JOB_GRACE_SECONDS` (180s) elapses. Confirmed live
    2026-07-17 as a real bug in this exact class, one module over
    (`level_c_orchestrator._phase_deploy_ot` — see that module's README and
    `job_runner.py`'s gotchas) — this is the same fix applied here since the
    acquisition loop below has the identical shape (a single long blocking
    call, no wait loop of its own to piggyback a heartbeat onto).

    `update_job(job_id, job_path)` with zero changes still stamps
    `updated_at` unconditionally, so this is a true heartbeat-only touch —
    it does not alter any other job field.

    2026-09-23: cada latido ahora tambien persiste `heartbeat_rss_mb` (memoria residente real del
    proceso, ver _current_rss_mb) y lo registra en app.log -- puramente informativo, no cambia el
    comportamiento del heartbeat en si. Motivado por un fallo real donde el hilo entero (heartbeat
    incluido) dejo de responder sin ningun aviso previo; con esto, la proxima vez habria un rastro
    real de memoria justo antes de que ocurriera, sin depender de reconstruirlo a posteriori.

    2026-09-24: si `tracemalloc` esta activo en este proceso (ver app.py::create_app()), cada latido
    tambien toma un snapshot y lo compara contra el snapshot tomado al ENTRAR a este bloque
    concreto -- es decir, el diff acumulado de asignaciones Python vivas desde que empezo justo esta
    llamada (adquisicion, espera del ciclo de vida, adjuntar el caso, etc.), no desde el arranque del
    proceso. El top-15 de "quien crecio mas" (fichero:linea, MB reales) se anexa a
    runtime/level_b_repetitions/<job_id>/tracemalloc_diff.jsonl. Motivado por: el fix del
    2026-09-24 en foc_indexer.py arreglo el crecimiento de memoria durante `repetition_1_analysis`,
    pero el MISMO patron reaparecio inmediatamente despues en `repetition_1_reconstruction` (RSS
    21GB->38GB, worker muerto) -- la lectura de codigo encontro un culpable real pero no el unico, y
    seguir adivinando por lectura de codigo no escala. Coste: tracemalloc tiene overhead real de
    memoria/CPU mientras esta activo -- aceptado deliberadamente por el usuario para esta
    investigacion, no es el estado por defecto deseado a largo plazo."""
    stop = threading.Event()
    tracing_active = False
    try:
        tracing_active = tracemalloc.is_tracing()
    except Exception:
        tracing_active = False
    baseline_snapshot = None
    if tracing_active:
        try:
            baseline_snapshot = tracemalloc.take_snapshot()
        except Exception:
            baseline_snapshot = None

    def _beat():
        while not stop.wait(interval):
            rss_mb = None
            try:
                rss_mb = _current_rss_mb()
                extra = {"heartbeat_rss_mb": round(rss_mb, 1)} if rss_mb is not None else {}
                update_job(job_id, job_path, **extra)
                if rss_mb is not None:
                    logging.getLogger("app_logger").info(
                        f"[HEARTBEAT] job_id={job_id} rss_mb={rss_mb:.1f}"
                    )
            except Exception:
                pass
            if baseline_snapshot is not None:
                try:
                    snapshot = tracemalloc.take_snapshot()
                    _append_tracemalloc_diff(job_id, job_path.stem if hasattr(job_path, "stem") else str(job_path), baseline_snapshot, snapshot, rss_mb)
                except Exception:
                    pass

    t = threading.Thread(target=_beat, daemon=True, name=f"heartbeat-{job_id}")
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join(timeout=2)


def _wait_for_child_job(
    child_job_id: str,
    *,
    parent_job_id: str,
    parent_job_path: Path,
    current_phase: str,
    current_phase_label: str,
    current_detail_prefix: str,
) -> dict:
    """Wait for a nested scientific job (e.g. a Level A report generation) to
    reach a terminal state — driven by the child's own heartbeat, not a fixed
    deadline. 2026-07-17: this used to force-cancel the child after a flat
    5400s (90min), which killed real work — a nested Level A report over a
    large preserved case legitimately runs several dry-run repetitions, each
    doing a full causal-reconstruction pass, and their combined real duration
    routinely exceeds 90min without anything actually being stuck (confirmed
    live: `child_job_timeout: stuck at 'Refresh or load multilayer analysis'`
    fired mid-reconstruction on rep 2/2, not on a dead job). Same philosophy
    as level_c_orchestrator._phase_wait_level_b: no invented ceiling here. If
    the child's thread genuinely dies, job_runner.get_job()'s own orphan
    watchdog (_recover_orphaned_job, ~180s heartbeat grace) already flips it
    to 'failed' on its own the next time it's read below — nothing extra to
    add for that case.
    """
    while True:
        if job_cancel_requested(parent_job_id, parent_job_path):
            request_cancel(child_job_id)
            raise_if_cancelled(parent_job_id, parent_job_path, phase_key=current_phase, phase_label=current_phase_label, detail=f"{current_phase_label} was cancelled by the operator.")
        child = get_job(child_job_id) or {}
        child_status = str(child.get("status") or "").lower()
        update_job(
            parent_job_id,
            parent_job_path,
            current_child_job_id=child_job_id,
            current_phase=current_phase,
            current_phase_label=current_phase_label,
            current_phase_detail=f"{current_detail_prefix}: {child.get('current_phase_label') or child.get('current_phase') or child_status or 'running'} — {child.get('current_phase_detail') or 'waiting for nested scientific job to finish.'}",
        )
        if child_status in {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}:
            return child
        time.sleep(2.5)


def _analysis_layer_counts(analysis_status: dict) -> dict:
    phases = analysis_status.get("phases") or {}
    completed = partial = failed = 0
    for payload in phases.values():
        raw = str((payload or {}).get("status") or "").lower()
        if raw == "completed":
            completed += 1
        elif raw in {"partial", "completed_with_degradation"}:
            partial += 1
        elif raw == "failed":
            failed += 1
    return {
        "layers_total": len(phases),
        "layers_completed": completed,
        "layers_partial": partial,
        "layers_failed": failed,
    }


def _find_event_time(events: list[dict], event_name: str) -> str | None:
    for item in events:
        if str(item.get("event") or item.get("event_type") or "") == event_name:
            return item.get("ts_utc_ms") or item.get("ts_utc") or item.get("timestamp")
    return None


def _latest_event_time(events: list[dict], event_name: str) -> str | None:
    matching = [
        item.get("ts_utc_ms") or item.get("ts_utc") or item.get("timestamp")
        for item in events
        if str(item.get("event") or item.get("event_type") or "") == event_name
    ]
    return matching[-1] if matching else None


# 2026-09-10: these paths are each rewritten a second time later in the
# pipeline (a richer per-node time-sync aggregation overwrites the early
# time_sync.json; acquisition finalization overwrites acquisition_profile.json;
# the analysis inventory/integrity-custody reports and the workflow phase
# summary are all regenerated once analysis completes) by code paths that
# update the file's content but never call _add_artifact_fast() again -- so
# the manifest's recorded digest for these paths is an earlier version, not
# the final one. Confirmed real (not tampering): every affected file's
# on-disk mtime predates case sealing, in the original live run.
_MANIFEST_REFRESH_TARGETS = (
    ("metadata/time_sync.json", "time_sync"),
    ("metadata/acquisition_profile.json", "acquisition_profile"),
    ("analysis/00_inventory/evidence_inventory.json", "evidence_inventory"),
    ("analysis/01_integrity_custody/integrity_custody_report.json", "integrity_custody_report"),
    ("metadata/workflow_phase_summary.json", "workflow_phase_summary"),
)


def _refresh_manifest_hash_if_stale(case_dir: Path, rel_path: str, artifact_type: str) -> None:
    """Best-effort, purely additive: if rel_path's current content hash
    differs from the most recent manifest entry already on record for it,
    registers one fresh entry (and a matching custody entry) reflecting the
    real current content. Never rewrites or removes any existing entry, and
    never touches the artifact's own content -- mirrors the append-only
    pattern already used for chain_of_custody.log/case_digest.json, whose
    manifest history already has multiple entries by design."""
    try:
        abs_path = case_dir / rel_path
        if not abs_path.is_file():
            return
        current_hash = _sha256_path(abs_path)
        manifest_path = case_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
        entries = [a for a in (manifest.get("artifacts") or []) if a.get("rel_path") == rel_path]
        if entries and entries[-1].get("sha256") == current_hash:
            return
        _add_artifact_fast(str(case_dir), rel_path, artifact_type, sha256=current_hash, size=abs_path.stat().st_size)
        _append_custody_entry(
            str(case_dir),
            "artifact_manifest_refreshed",
            "level_b_repetition_runner",
            artifact_rel=rel_path,
            details={"reason": "artifact content changed after its last manifest registration"},
        )
    except Exception:
        pass


def _fresh_causal_view(case_id: str | None, case_dir: Path | None, stale_causal: dict, stale_warnings: list) -> tuple[dict, list]:
    """Prefers the REAL, current on-disk causal-reconstruction state over
    whatever snapshot was frozen into forensic_comparison_profile.json /
    forensic_result_card.json by the attach step -- confirmed live
    (2026-10-05, campaign CMP-20261005-162758-9477) that those are written
    BEFORE causal reconstruction actually finishes, so a case that completed
    successfully (CPR=0.875) kept reporting "reconstruction blocked, 0
    recovered" forever afterward in this report, because
    summarize_case_causal_state() -- the function that already self-heals by
    re-reading the real on-disk causal_status.json -- was never called again
    after reconstruction completed. Falls back to the original frozen
    snapshot unchanged if anything here fails or the fresh state isn't
    actually more complete, so this can only correct a report, never make it
    worse than before."""
    if not case_id or not case_dir:
        return stale_causal, stale_warnings
    try:
        from ..foc_causal_reconstruction.service import summarize_case_causal_state
        fresh = summarize_case_causal_state(case_id, case_dir)
    except Exception:
        return stale_causal, stale_warnings
    fresh_status = str(fresh.get("status") or fresh.get("state") or "")
    if fresh_status not in {"completed", "completed_with_degradation"}:
        return stale_causal, stale_warnings
    metrics = fresh.get("metrics_preview") or {}
    fresh_causal = {
        "status": fresh_status,
        "expected_edges": metrics.get("expected_edges"),
        "recovered_edges": metrics.get("recovered_edges"),
        "degraded_edges": metrics.get("degraded_edges"),
        "ambiguous_edges": metrics.get("ambiguous_edges"),
        "missing_edges": metrics.get("missing_edges"),
        "cpr": metrics.get("causal_path_recoverability"),
        "weighted_cpr": metrics.get("weighted_cpr"),
        "reconstruction_confidence": metrics.get("reconstruction_confidence"),
    }
    # The stale result_card's "scientific_limitations" can include a
    # "Causal reconstruction is blocked..."/"has not been generated" message
    # left over from before reconstruction ran -- now factually false once we
    # know it completed. Drop only those specific stale lines; every other
    # real warning (temporal ambiguity, etc.) passes through unchanged.
    fresh_warnings = [
        w for w in stale_warnings
        if "reconstruction is blocked" not in str(w).lower()
        and "has not been generated" not in str(w).lower()
    ]
    return fresh_causal, fresh_warnings


def _repetition_result_from_case(
    *,
    repetition_number: int,
    campaign_id: str,
    execution_id: str,
    case_id: str | None,
    case_dir: Path | None,
    attack: dict,
    attack_result: dict,
    attack_started_at: str,
    attack_completed_at: str,
    target: dict,
    matched_alert: dict | None,
    memory_result: dict | None,
    network_result: dict | None,
    disk_result: dict | None,
    lifecycle_result: dict | None,
    attach_result: dict | None,
    dfir_mode_before: str,
    dfir_mode_after: str,
    nested_level_a: dict | None = None,
    trigger_attempt_trace: list[dict] | None = None,
) -> dict:
    output_dir = Path(str(attack_result.get("_output_dir") or "")).resolve() if attack_result.get("_output_dir") else None
    params = _attack_parameter_status(attack_result)
    trigger_primary = (matched_alert or {}).get("primary") or {}
    trigger_triage = (matched_alert or {}).get("triage") or {}
    case_path_rel = relative_path(case_dir) if case_dir else None
    acquisition_profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") if case_dir else None
    events = _read_jsonl(case_dir / "metadata" / "pipeline_events.jsonl") if case_dir else []
    comparison_profile = _json_load(Path((attach_result or {}).get("artifacts", {}).get("forensic_comparison_profile") or "")) if attach_result else None
    result_card = _json_load(Path((attach_result or {}).get("artifacts", {}).get("forensic_result_card") or "")) if attach_result else None
    analysis_status = load_analysis_status(case_id) if case_id else {}
    critical_evidence_gate = _json_load(case_dir / CRITICAL_EVIDENCE_GATE_REL) if case_dir else None
    layers = _analysis_layer_counts(analysis_status or {})
    network_context = _network_context_payload(case_dir) if case_dir else {"status": "failed", "preserved_segments": 0, "pending_segments": 0, "manifest": {}}
    summary = ((comparison_profile or {}).get("final_conclusion") or {})
    causal = (comparison_profile or {}).get("causal_reconstruction") or {}
    memory_hash = (memory_result or {}).get("sha256")
    case_sealed_time = (
        _latest_event_time(events, "dfir_orchestration_done")
        or _latest_event_time(events, "case_digest_written")
        or (acquisition_profile or {}).get("disk_completed_utc")
        or (acquisition_profile or {}).get("memory_completed_utc")
    )
    analysis_started_at = (analysis_status or {}).get("started_at")
    analysis_completed_at = (analysis_status or {}).get("finished_at")
    reconstruction_completed_at = (lifecycle_result or {}).get("finished_at")
    warnings = []
    warnings.extend(list((lifecycle_result or {}).get("warnings") or []))
    warnings.extend(list((result_card or {}).get("scientific_limitations") or []))
    if nested_level_a and str(nested_level_a.get("status") or "").lower() not in {"completed", "completed_with_degradation"}:
        nested_errs = [str((e or {}).get("message") if isinstance(e, dict) else e) for e in (nested_level_a.get("errors") or [])]
        reason = f" — reason: {'; '.join(nested_errs)}" if nested_errs else ""
        warnings.append(
            f"nested Level A scientific report did not complete successfully for this Level B case "
            f"(status={nested_level_a.get('status') or 'unknown'}){reason}"
        )
    causal, warnings = _fresh_causal_view(case_id, case_dir, causal, warnings)
    blockers = []
    blockers.extend([str(item) for item in ((lifecycle_result or {}).get("errors") or []) if item])
    trigger_ts = trigger_primary.get("ts_utc") or trigger_primary.get("timestamp")
    memory_started_at = (acquisition_profile or {}).get("memory_started_utc") or _find_event_time(events, "memory_start")
    memory_completed_at = (acquisition_profile or {}).get("memory_completed_utc") or _find_event_time(events, "memory_preserved")
    disk_started_at = (acquisition_profile or {}).get("disk_started_utc") or _find_event_time(events, "disk_start")
    disk_completed_at = (acquisition_profile or {}).get("disk_completed_utc") or _find_event_time(events, "disk_preserved")
    network_started_at = (acquisition_profile or {}).get("network_context_import_started_utc")
    network_completed_at = (acquisition_profile or {}).get("network_context_import_completed_utc")
    ot_started_at = (acquisition_profile or {}).get("ot_export_started_utc") or _find_event_time(events, "ot_export_start")
    ot_completed_at = (acquisition_profile or {}).get("ot_export_completed_utc") or _latest_event_time(events, "ot_export_preserved")
    first_seal_at = _latest_event_time(events, "case_digest_written") or memory_completed_at
    artifact_sizes = _manifest_artifact_sizes(case_dir) if case_dir else {"pcap": [], "memory": [], "disk": [], "ot": []}
    pcap_periodic_total_bytes = sum(artifact_sizes.get("pcap") or [])
    memory_total_bytes = sum(artifact_sizes.get("memory") or [])
    disk_total_bytes = sum(artifact_sizes.get("disk") or [])
    ot_paths = [
        str(item.get("rel_path") or "")
        for item in (_manifest_artifacts(case_dir) if case_dir else [])
        if _artifact_matches(item, rel_prefix="industrial/", type_tokens=("industrial_ot_export", "ot_export"))
    ]
    retries_or_failures_count = _count_failures_for_run(events, execution_id)

    repetition_status = "completed"
    if (lifecycle_result or {}).get("status") in {"completed_with_degradation"} or str((attach_result or {}).get("status") or "").lower() == "completed_with_degradation":
        repetition_status = "partial"
    if isinstance(critical_evidence_gate, dict) and str(critical_evidence_gate.get("gate_status") or "") == "diagnostic_failed":
        repetition_status = "partial"
    if not case_id or not attach_result:
        repetition_status = "failed"

    # Durable per-case C1-C5/E1-E4/IR-gate snapshot (metadata/fsr/fsr_eval_<execution_id>.json),
    # mirroring the sibling metadata/ir/ir_snapshot.json write. Best-effort: must never
    # break repetition result assembly if evidence is partial or the case dir is gone.
    if case_dir:
        try:
            from ..forensics.fsr_verdict import write_fsr_verdict
            write_fsr_verdict(case_dir, run_id=execution_id)
        except Exception:
            pass
        # Durable per-execution plain-language narrative explaining WHY each causal
        # relation ended up recovered/degraded/ambiguous/missing (derived/executive/
        # execution_narrative_report.{json,md}), cross-referencing the general network
        # analysis, the OT-specific export, temporal-uncertainty inputs, and the
        # independent attack ground truth. Best-effort, never blocks the pipeline.
        try:
            from ..foc_causal_reconstruction.narrative_report import generate_execution_narrative_report
            generate_execution_narrative_report(case_id, case_dir, execution_id=execution_id)
        except Exception:
            pass
        for rel_path, artifact_type in _MANIFEST_REFRESH_TARGETS:
            _refresh_manifest_hash_if_stale(case_dir, rel_path, artifact_type)

    return {
        "repetition_number": repetition_number,
        "campaign_id": campaign_id,
        "execution_id": execution_id,
        "execution_status": repetition_status,
        "dfir_mode_before": dfir_mode_before,
        "dfir_mode_after": dfir_mode_after,
        "dfir_mode_enabled_successfully": dfir_mode_after == "on",
        "dfir_mode_blocker": None if dfir_mode_after == "on" else "DFIR mode is not ON.",
        "attack_profile_id": attack.get("attack_id"),
        "attack_name": attack.get("display_name"),
        "target_role": "PLC",
        "target_node": target.get("vm_name"),
        "target_ip": params.get("parsed_write_command", {}).get("target_ip"),
        "protocol": params.get("protocol"),
        "destination_port": params.get("destination_port"),
        "function_code": params.get("function_code"),
        "register": params.get("register"),
        "value": params.get("value"),
        "attack_started_at": attack_started_at,
        "attack_completed_at": attack_completed_at,
        "attack_output_path": relative_path(output_dir) if output_dir and output_dir.exists() else None,
        "attack_output_sha256": _sha256_path(output_dir / "result.json") if output_dir and (output_dir / "result.json").is_file() else "not_available",
        "trigger_alert_detected": bool(matched_alert),
        "trigger_alert_id": trigger_primary.get("event_id"),
        "trigger_alert_rule": trigger_primary.get("rule_id"),
        "trigger_alert_severity": str(trigger_triage.get("severity") or "unknown").lower(),
        "trigger_alert_timestamp": trigger_ts,
        "trigger_alert_mitre": ((trigger_primary.get("raw") or {}).get("mitre_mapping")) or None,
        "forensic_intervention_required": bool(trigger_triage.get("recommend_forensics")),
        "automatic_acquisition_started": bool(case_id),
        "alert_to_acquisition_start_seconds": _seconds_between(trigger_ts, (acquisition_profile or {}).get("acquisition_started_utc") or (acquisition_profile or {}).get("case_created_utc")),
        "case_id": case_id,
        "case_path": case_path_rel,
        "memory_acquisition_status": "completed" if (memory_result or {}).get("ok") else ("failed" if memory_result else "skipped"),
        "memory_hash": memory_hash,
        "network_context_status": network_context.get("status"),
        "pcap_segments_imported": network_context.get("preserved_segments", 0),
        "disk_acquisition_status": "completed" if (disk_result or {}).get("ok") else ("failed" if disk_result else "skipped"),
        "ot_export_status": "completed" if ((comparison_profile or {}).get("reports") or {}).get("ot") else "partial",
        "alerts_preserved": int((((comparison_profile or {}).get("multilayer_analysis") or {}).get("alert_events_indexed")) or (((comparison_profile or {}).get("claimability") or {}).get("evidence_summary", {}).get("alerts_observed") or 0)),
        "custody_status": "valid" if ((comparison_profile or {}).get("preservation") or {}).get("chain_of_custody_available") else "partial",
        "case_sealed_status": "sealed" if ((comparison_profile or {}).get("preservation") or {}).get("manifest_available") else "partial",
        "analysis_status": str((analysis_status or {}).get("status") or "failed"),
        **layers,
        "memory_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("memory_analysis") or {}).get("status") or "not_started"),
        "network_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("network_analysis") or {}).get("status") or "not_started"),
        "disk_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("disk_analysis") or {}).get("status") or "not_started"),
        "ot_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("ot_export_analysis") or {}).get("status") or "not_started"),
        "alert_analysis_status": str((((analysis_status or {}).get("phases") or {}).get("alerts_detection_analysis") or {}).get("status") or "not_started"),
        "timeline_status": str((((analysis_status or {}).get("phases") or {}).get("unified_forensic_timeline") or {}).get("status") or "not_started"),
        "reconstruction_status": str(causal.get("status") or (lifecycle_result or {}).get("status") or "failed"),
        "timing_metrics": {
            "deploy_time_seconds": 0.0,
            "teardown_redeploy_time_seconds": 0.0,
            "network_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            "alert_to_acquisition_start_seconds": _seconds_between(trigger_ts, (acquisition_profile or {}).get("acquisition_started_utc") or (acquisition_profile or {}).get("case_created_utc")),
            "alert_to_memory_start_seconds": _seconds_between(trigger_ts, memory_started_at),
            "alert_to_memory_preserved_seconds": _seconds_between(trigger_ts, memory_completed_at),
            "alert_to_ot_export_preserved_seconds": _seconds_between(trigger_ts, ot_completed_at),
            "alert_to_disk_snapshot_start_seconds": _seconds_between(trigger_ts, disk_started_at),
            "alert_to_disk_snapshot_preserved_seconds": _seconds_between(trigger_ts, disk_completed_at),
            "alert_to_case_sealed_seconds": _seconds_between(trigger_ts, case_sealed_time),
            "t_first_sealed_seconds": _seconds_between(trigger_ts, first_seal_at),
            "t_case_sealed_seconds": _seconds_between(trigger_ts, case_sealed_time),
            "memory_acquisition_duration_seconds": _seconds_between(memory_started_at, memory_completed_at),
            "pcap_import_duration_seconds": _seconds_between(network_started_at, network_completed_at),
            "disk_acquisition_duration_seconds": _seconds_between(disk_started_at, disk_completed_at),
            "case_sealed_to_analysis_completed_seconds": _seconds_between(case_sealed_time, analysis_completed_at),
            "total_repetition_duration_seconds": _seconds_between(attack_started_at, reconstruction_completed_at or analysis_completed_at or case_sealed_time),
            "pcap_periodic_context_size_gib": _bytes_to_gib(pcap_periodic_total_bytes),
            "pcap_reactive_capture_size_bytes": 0,
            "memory_dump_size_bytes": memory_total_bytes,
            "disk_snapshot_size_bytes": disk_total_bytes,
            "retries_or_failures_count": retries_or_failures_count,
            "ot_export_present_in_manifest": bool(ot_paths),
            "ot_export_paths": ot_paths,
            "evidence_completeness_gate": str((critical_evidence_gate or {}).get("gate_status") or "not_available"),
        },
        "reconstruction_metrics": {
            "expected_relations": result_card.get("expected_causal_edges") and len(result_card.get("expected_causal_edges") or []) or causal.get("expected_edges"),
            "recovered_relations": causal.get("recovered_edges"),
            "degraded_relations": causal.get("degraded_edges"),
            "ambiguous_relations": causal.get("ambiguous_edges"),
            "missing_relations": causal.get("missing_edges"),
            "recoverability_score": result_card.get("CPR") or causal.get("cpr"),
            "weighted_recoverability_score": result_card.get("Weighted_CPR") or causal.get("weighted_cpr"),
            "reconstruction_confidence": result_card.get("reconstruction_confidence") or causal.get("reconstruction_confidence"),
            "recoverability_label": result_card.get("recoverability_label") or summary.get("recoverability_label"),
            "scientific_confidence_label": result_card.get("scientific_confidence_label") or result_card.get("reconstruction_confidence") or causal.get("reconstruction_confidence"),
            "warnings": warnings,
            "blockers": blockers,
        },
        "comparison_family_id": result_card.get("comparison_family_id") if result_card else None,
        "scenario_fingerprint": result_card.get("scenario_fingerprint") if result_card else (((comparison_profile or {}).get("scenario_profile") or {}).get("scenario_fingerprint")),
        "final_case_status": summary.get("summary_class") or result_card.get("final_conclusion_class") if result_card else None,
        "scientific_case_status": (
            str(critical_evidence_gate.get("gate_status"))
            if isinstance(critical_evidence_gate, dict)
            else ("scientifically_complete" if repetition_status == "completed" else "diagnostic_failed")
        ),
        "critical_evidence_gate": critical_evidence_gate or {},
        "nested_level_a": nested_level_a or {},
        "trigger_attempt_trace": list(trigger_attempt_trace or []),
        "trigger_attempts_total": len(trigger_attempt_trace or []),
        "artifacts": {
            "forensic_result_card": relative_path(Path((attach_result or {}).get("artifacts", {}).get("forensic_result_card") or "")) if (attach_result or {}).get("artifacts", {}).get("forensic_result_card") else None,
            "forensic_comparison_profile": relative_path(Path((attach_result or {}).get("artifacts", {}).get("forensic_comparison_profile") or "")) if (attach_result or {}).get("artifacts", {}).get("forensic_comparison_profile") else None,
            "acquisition_profile": relative_path(case_dir / "metadata" / "acquisition_profile.json") if case_dir and (case_dir / "metadata" / "acquisition_profile.json").is_file() else None,
            "network_context_manifest": relative_path(case_dir / "network" / "traffic_preserved" / "network_context_manifest.json") if case_dir and (case_dir / "network" / "traffic_preserved" / "network_context_manifest.json").is_file() else None,
            "pipeline_events": relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if case_dir and (case_dir / "metadata" / "pipeline_events.jsonl").is_file() else None,
        },
        "warnings": warnings,
        "blockers": blockers,
    }


def _failed_repetition_result(
    *,
    repetition_number: int,
    campaign_id: str,
    execution_id: str,
    attack: dict,
    dfir_mode_before: str,
    dfir_mode_after: str,
    attack_started_at: str | None,
    attack_completed_at: str | None,
    reason: str,
    blockers: list[str],
    target: dict | None = None,
    attack_result: dict | None = None,
    matched_alert: dict | None = None,
    case_id: str | None = None,
    case_dir: Path | None = None,
    nested_level_a: dict | None = None,
    trigger_attempt_trace: list[dict] | None = None,
) -> dict:
    params = _attack_parameter_status(attack_result or {})
    trigger_primary = (matched_alert or {}).get("primary") or {}
    trigger_triage = (matched_alert or {}).get("triage") or {}
    observed = _observed_case_state(case_id, case_dir)
    critical_evidence_gate = _json_load(case_dir / CRITICAL_EVIDENCE_GATE_REL) if case_dir else None
    return {
        "repetition_number": repetition_number,
        "campaign_id": campaign_id,
        "execution_id": execution_id,
        "execution_status": "failed",
        "dfir_mode_before": dfir_mode_before,
        "dfir_mode_after": dfir_mode_after,
        "dfir_mode_enabled_successfully": dfir_mode_after == "on",
        "dfir_mode_blocker": None if dfir_mode_after == "on" else "DFIR mode is not ON.",
        "attack_profile_id": attack.get("attack_id"),
        "attack_name": attack.get("display_name"),
        "target_role": "PLC",
        "target_node": (target or {}).get("vm_name"),
        "target_ip": params.get("parsed_write_command", {}).get("target_ip"),
        "protocol": "modbus_tcp",
        "destination_port": 502,
        "function_code": params.get("function_code"),
        "register": params.get("register"),
        "value": params.get("value"),
        "attack_started_at": attack_started_at,
        "attack_completed_at": attack_completed_at,
        "attack_output_path": relative_path(Path(str((attack_result or {}).get("_output_dir") or "")).resolve()) if (attack_result or {}).get("_output_dir") else None,
        "trigger_alert_detected": bool(matched_alert),
        "trigger_alert_id": trigger_primary.get("event_id"),
        "trigger_alert_rule": trigger_primary.get("rule_id"),
        "trigger_alert_severity": str(trigger_triage.get("severity") or "unknown").lower(),
        "trigger_alert_timestamp": trigger_primary.get("ts_utc") or trigger_primary.get("timestamp"),
        "trigger_alert_mitre": ((trigger_primary.get("raw") or {}).get("mitre_mapping")) or None,
        "forensic_intervention_required": bool(trigger_triage.get("recommend_forensics")),
        "automatic_acquisition_started": bool(case_id),
        "case_id": case_id,
        "case_path": relative_path(case_dir) if case_dir else None,
        "memory_acquisition_status": observed.get("memory_acquisition_status"),
        "network_context_status": observed.get("network_context_status"),
        "pcap_segments_imported": int(observed.get("pcap_segments_imported") or 0),
        "disk_acquisition_status": observed.get("disk_acquisition_status"),
        "ot_export_status": "skipped",
        "alerts_preserved": int(observed.get("alerts_preserved") or 0),
        "custody_status": observed.get("custody_status"),
        "case_sealed_status": observed.get("case_sealed_status"),
        "analysis_status": observed.get("analysis_status"),
        "layers_total": observed.get("layers_total"),
        "layers_completed": observed.get("layers_completed"),
        "layers_partial": observed.get("layers_partial"),
        "layers_failed": observed.get("layers_failed"),
        "memory_analysis_status": observed.get("memory_analysis_status"),
        "network_analysis_status": observed.get("network_analysis_status"),
        "disk_analysis_status": observed.get("disk_analysis_status"),
        "ot_analysis_status": observed.get("ot_analysis_status"),
        "alert_analysis_status": observed.get("alert_analysis_status"),
        "timeline_status": observed.get("timeline_status"),
        "reconstruction_status": "failed",
        "timing_metrics": {
            "deploy_time_seconds": 0.0,
            "teardown_redeploy_time_seconds": 0.0,
            "network_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            "alert_to_acquisition_start_seconds": None,
            "alert_to_memory_start_seconds": None,
            "alert_to_memory_preserved_seconds": None,
            "alert_to_ot_export_preserved_seconds": None,
            "alert_to_disk_snapshot_start_seconds": None,
            "alert_to_disk_snapshot_preserved_seconds": None,
            "alert_to_case_sealed_seconds": None,
            "t_first_sealed_seconds": None,
            "t_case_sealed_seconds": None,
            "memory_acquisition_duration_seconds": None,
            "pcap_import_duration_seconds": None,
            "disk_acquisition_duration_seconds": None,
            "case_sealed_to_analysis_completed_seconds": None,
            "total_repetition_duration_seconds": _seconds_between(attack_started_at, attack_completed_at) if attack_started_at and attack_completed_at else None,
            "pcap_periodic_context_size_gib": None,
            "pcap_reactive_capture_size_bytes": 0,
            "memory_dump_size_bytes": None,
            "disk_snapshot_size_bytes": None,
            "retries_or_failures_count": 0,
            "ot_export_present_in_manifest": False,
            "ot_export_paths": [],
            "evidence_completeness_gate": str((critical_evidence_gate or {}).get("gate_status") or "not_available"),
        },
        "reconstruction_metrics": {
            "expected_relations": 0,
            "recovered_relations": 0,
            "degraded_relations": 0,
            "ambiguous_relations": 0,
            "missing_relations": 0,
            "recoverability_score": None,
            "weighted_recoverability_score": None,
            "reconstruction_confidence": None,
            "recoverability_label": None,
            "scientific_confidence_label": None,
            "warnings": [reason],
            "blockers": blockers,
        },
        "comparison_family_id": None,
        "scenario_fingerprint": None,
        "final_case_status": "failed",
        "scientific_case_status": str((critical_evidence_gate or {}).get("gate_status") or "diagnostic_failed"),
        "critical_evidence_gate": critical_evidence_gate or {},
        "nested_level_a": nested_level_a or {},
        "trigger_attempt_trace": list(trigger_attempt_trace or []),
        "trigger_attempts_total": len(trigger_attempt_trace or []),
        "artifacts": observed.get("artifacts") or {},
        "warnings": [reason] + ([f"Observed preserved case state exists at {relative_path(case_dir)} and should be reviewed against the failure point."] if observed.get("case_exists") else []),
        "blockers": blockers,
    }


def _run_nested_level_a_report_for_case(
    *,
    parent_campaign_id: str,
    parent_execution_id: str,
    parent_config: dict,
    case_id: str,
    repetition_number: int,
    nested_level_a_repetitions: int,
    job_id: str,
    job_path: Path,
    rep_idx: int,
    total_repetitions: int,
    phase_extra: dict,
) -> dict:
    child_campaign = create_campaign(
        {
            "level": "A",
            "name": f"Nested Level A · {parent_execution_id}",
            "description": f"Automatically generated nested Level A repeatability audit for Level B execution {parent_execution_id}.",
            "notes": f"Nested Level A scientific report for Level B parent campaign {parent_campaign_id}, execution {parent_execution_id}.",
            "scenario_id": parent_config.get("scenario_id") or "not_available",
            "base_case_id": case_id,
            "run_case_id": case_id,
            "repetitions": nested_level_a_repetitions,
            "baseline_noise_threshold": parent_config.get("baseline_noise_threshold"),
            "baseline_window_seconds": parent_config.get("baseline_window_seconds"),
            "delta_wcpr_allowed": parent_config.get("delta_wcpr_allowed"),
            "analysis_profile_id": parent_config.get("analysis_profile_id"),
            "foc_profile_id": parent_config.get("foc_profile_id"),
            "detection_policy_id": parent_config.get("detection_policy_id"),
            "trigger_policy_id": parent_config.get("trigger_policy_id"),
            "acquisition_profile_id": parent_config.get("acquisition_profile_id"),
            "retention_policy": "original_case_retained",
            "dry_run": False,
            "parent_campaign_id": parent_campaign_id,
            "parent_execution_id": parent_execution_id,
            "parent_level": "B",
        }
    )
    child_campaign_id = str(((child_campaign or {}).get("campaign") or {}).get("campaign_id") or "").strip()
    if not child_campaign_id:
        return {"status": "failed", "reason": "nested_level_a_campaign_creation_failed"}

    _emit_phase(
        job_id,
        job_path,
        phase_key=f"repetition_{rep_idx}_store",
        phase_label="Store repetition result",
        status="running",
        detail=f"Launching nested Level A scientific report for case {case_id} using {nested_level_a_repetitions} dry-run repetitions inside child campaign {child_campaign_id}.",
        category="repetition",
        index=8,
        repetition_number=rep_idx,
        total_repetitions=total_repetitions,
        extra={"nested_level_a_campaign_id": child_campaign_id, **phase_extra},
    )
    child_job = start_level_a_scientific_report_job(child_campaign_id)
    child_job_id = str(child_job.get("job_id") or "").strip()
    if not child_job_id:
        return {"status": "failed", "reason": "nested_level_a_job_not_created", "campaign_id": child_campaign_id}

    # Sin _heartbeat_during aqui, este job PADRE (el propio Level B, no el hijo Level A) se queda
    # sin ningun update_job() propio durante toda la espera de abajo -- confirmado en vivo
    # (2026-09-22/23): _wait_for_child_job's docstring ya avisaba de que un informe Level A
    # anidado "rutinariamente supera 90 minutos", pero solo cubria el caso de que el HIJO muriera
    # de verdad; no cubria que el propio PADRE se quede con `updated_at` viejo mientras espera,
    # que un get_job() desde OTRO worker de gunicorn (p.ej. un chequeo de estado periodico) lee
    # como huerfano via _ORPHAN_JOB_GRACE_SECONDS (180s) y lo declara `failed` -- exactamente el
    # mismo patron de bug ya identificado y arreglado dos veces en este fichero (adquisicion,
    # linea ~3339; espera del analisis, linea ~3879), aqui simplemente sin aplicar todavia a este
    # tercer punto de espera bloqueante.
    with _heartbeat_during(job_id, job_path):
        child = _wait_for_child_job(
            child_job_id,
            parent_job_id=job_id,
            parent_job_path=job_path,
            current_phase=f"repetition_{rep_idx}_store",
            current_phase_label="Store repetition result",
            current_detail_prefix=f"Nested Level A {repetition_number}/{total_repetitions}",
        )
    child_status = str(child.get("status") or "failed").lower()
    report = dict(child.get("level_a_report") or {})
    return {
        "status": child_status,
        "campaign_id": child_campaign_id,
        "job_id": child_job_id,
        "report": report,
        "warnings": list(child.get("warnings") or []),
        "errors": list(child.get("errors") or []),
        "comparison_status": report.get("comparison_status"),
        "comparison_type": report.get("comparison_type"),
        "generated_execution_ids": list(report.get("generated_execution_ids") or []),
        "report_output_path": report.get("report_output_path"),
        "report_markdown_path": report.get("report_markdown_path"),
        "completed_repetitions": report.get("completed_repetitions"),
        "requested_repetitions": report.get("requested_repetitions") or nested_level_a_repetitions,
    }


def _attach_and_aggregate_twin_verdicts(campaign_id: str, results: list[dict]) -> dict:
    """Adjunta a cada repeticion su veredicto de corroboracion del gemelo digital
    (ot_state_twin::compute_corroboration_verdict, seccion 'novedad cientifica' de
    investigacion_y_novedad/05_nombre_y_evolucion.md) bajo la clave nueva
    `ot_state_twin_verdict`, y devuelve un agregado de campana para `aggregate_twin_metrics`.
    Puramente aditivo: nunca modifica ninguna clave ya existente de `results`, y un fallo al
    calcular el veredicto de una repeticion concreta (gemelo no disponible, sin datos para ese
    scope, etc.) solo dota a esa repeticion de `ot_state_twin_verdict: None` -- nunca rompe la
    generacion del informe."""
    verdicts: list[dict] = []
    for item in results:
        execution_id = item.get("execution_id")
        verdict = None
        if execution_id:
            try:
                scope_id = repetition_scope_id(campaign_id, execution_id)
                verdict = compute_corroboration_verdict(scope_id)
            except Exception:
                verdict = None
        item["ot_state_twin_verdict"] = verdict
        if verdict is not None:
            verdicts.append(verdict)

    verdict_counts: dict[str, int] = {}
    total_control_law_violations = 0
    total_state_divergences = 0
    for v in verdicts:
        key = str(v.get("verdict") or "unknown")
        verdict_counts[key] = verdict_counts.get(key, 0) + 1
        total_control_law_violations += int(v.get("control_law_violation_count") or 0)
        total_state_divergences += int(v.get("state_divergence_count") or 0)

    known_window_verdicts = [v for v in verdicts if v.get("verdict") != "attack_window_unknown"]
    corroborated = verdict_counts.get("corroborado", 0)
    corroboration_rate = (
        corroborated / len(known_window_verdicts) if known_window_verdicts else None
    )

    return {
        "n_repetitions_with_twin_data": len(verdicts),
        "verdict_counts": verdict_counts,
        "corroboration_rate": corroboration_rate,
        "total_control_law_violations": total_control_law_violations,
        "total_state_divergences": total_state_divergences,
        "note": (
            "corroboration_rate = repeticiones con veredicto 'corroborado' / repeticiones con "
            "ventana de ataque conocida (excluye 'attack_window_unknown'). None si ninguna "
            "repeticion tuvo ventana de ataque conocida."
        ),
    }


def _aggregate_metrics(results: list[dict]) -> tuple[dict, dict]:
    timing_fields = [
        "deploy_time_seconds",
        "teardown_redeploy_time_seconds",
        "alert_to_acquisition_start_seconds",
        "alert_to_memory_start_seconds",
        "alert_to_memory_preserved_seconds",
        "alert_to_ot_export_preserved_seconds",
        "alert_to_disk_snapshot_start_seconds",
        "alert_to_disk_snapshot_preserved_seconds",
        "alert_to_case_sealed_seconds",
        "t_first_sealed_seconds",
        "t_case_sealed_seconds",
        "total_repetition_duration_seconds",
        "pcap_periodic_context_size_gib",
        "pcap_reactive_capture_size_bytes",
        "memory_dump_size_bytes",
        "disk_snapshot_size_bytes",
        "retries_or_failures_count",
    ]
    timing_values: dict[str, list[float]] = {key: [] for key in timing_fields}
    for item in results:
        timing = item.get("timing_metrics") or {}
        for key in timing_fields:
            value = _safe_float(timing.get(key))
            if value is not None:
                timing_values[key].append(value)

    aggregate_timing = {
        "N_B": len(results),
        "deploy_time_mean_seconds": _mean(timing_values["deploy_time_seconds"]),
        "deploy_time_std_seconds": _sample_std(timing_values["deploy_time_seconds"]),
        "teardown_redeploy_time_mean_seconds": _mean(timing_values["teardown_redeploy_time_seconds"]),
        "teardown_redeploy_time_std_seconds": _sample_std(timing_values["teardown_redeploy_time_seconds"]),
        "alert_to_acquisition_start_mean_seconds": _mean(timing_values["alert_to_acquisition_start_seconds"]),
        "alert_to_acquisition_start_std_seconds": _sample_std(timing_values["alert_to_acquisition_start_seconds"]),
        "alert_to_memory_start_mean_seconds": _mean(timing_values["alert_to_memory_start_seconds"]),
        "alert_to_memory_start_std_seconds": _sample_std(timing_values["alert_to_memory_start_seconds"]),
        "alert_to_memory_preserved_mean_seconds": _mean(timing_values["alert_to_memory_preserved_seconds"]),
        "alert_to_memory_preserved_std_seconds": _sample_std(timing_values["alert_to_memory_preserved_seconds"]),
        "alert_to_ot_export_preserved_mean_seconds": _mean(timing_values["alert_to_ot_export_preserved_seconds"]),
        "alert_to_ot_export_preserved_std_seconds": _sample_std(timing_values["alert_to_ot_export_preserved_seconds"]),
        "alert_to_disk_snapshot_start_mean_seconds": _mean(timing_values["alert_to_disk_snapshot_start_seconds"]),
        "alert_to_disk_snapshot_start_std_seconds": _sample_std(timing_values["alert_to_disk_snapshot_start_seconds"]),
        "alert_to_disk_snapshot_preserved_mean_seconds": _mean(timing_values["alert_to_disk_snapshot_preserved_seconds"]),
        "alert_to_disk_snapshot_preserved_std_seconds": _sample_std(timing_values["alert_to_disk_snapshot_preserved_seconds"]),
        "alert_to_case_sealed_mean_seconds": _mean(timing_values["alert_to_case_sealed_seconds"]),
        "alert_to_case_sealed_std_seconds": _sample_std(timing_values["alert_to_case_sealed_seconds"]),
        "t_first_sealed_mean_seconds": _mean(timing_values["t_first_sealed_seconds"]),
        "t_first_sealed_std_seconds": _sample_std(timing_values["t_first_sealed_seconds"]),
        "t_case_sealed_mean_seconds": _mean(timing_values["t_case_sealed_seconds"]),
        "t_case_sealed_std_seconds": _sample_std(timing_values["t_case_sealed_seconds"]),
        "total_duration_mean_seconds": _mean(timing_values["total_repetition_duration_seconds"]),
        "total_duration_std_seconds": _sample_std(timing_values["total_repetition_duration_seconds"]),
        "pcap_periodic_context_size_gib_mean": _mean(timing_values["pcap_periodic_context_size_gib"]),
        "pcap_periodic_context_size_gib_std": _sample_std(timing_values["pcap_periodic_context_size_gib"]),
        "pcap_reactive_capture_size_bytes_mean": _mean(timing_values["pcap_reactive_capture_size_bytes"]),
        "pcap_reactive_capture_size_bytes_std": _sample_std(timing_values["pcap_reactive_capture_size_bytes"]),
        "memory_dump_size_bytes_mean": _mean(timing_values["memory_dump_size_bytes"]),
        "memory_dump_size_bytes_std": _sample_std(timing_values["memory_dump_size_bytes"]),
        "disk_snapshot_size_bytes_mean": _mean(timing_values["disk_snapshot_size_bytes"]),
        "disk_snapshot_size_bytes_std": _sample_std(timing_values["disk_snapshot_size_bytes"]),
        "retries_or_failures_count_mean": _mean(timing_values["retries_or_failures_count"]),
        "retries_or_failures_count_std": _sample_std(timing_values["retries_or_failures_count"]),
        "network_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
    }

    recoverability = []
    weighted = []
    degraded = ambiguous = missing = 0
    expected = recovered = 0
    for item in results:
        reconstruction = item.get("reconstruction_metrics") or {}
        if _safe_float(reconstruction.get("recoverability_score")) is not None:
            recoverability.append(float(reconstruction["recoverability_score"]))
        if _safe_float(reconstruction.get("weighted_recoverability_score")) is not None:
            weighted.append(float(reconstruction["weighted_recoverability_score"]))
        expected += int(reconstruction.get("expected_relations") or 0)
        recovered += int(reconstruction.get("recovered_relations") or 0)
        degraded += int(reconstruction.get("degraded_relations") or 0)
        ambiguous += int(reconstruction.get("ambiguous_relations") or 0)
        missing += int(reconstruction.get("missing_relations") or 0)
    aggregate_reconstruction = {
        "expected_relations_total": expected,
        "recovered_relations_total": recovered,
        "recoverability_mean": _mean(recoverability),
        "recoverability_std": _sample_std(recoverability),
        "weighted_recoverability_mean": _mean(weighted),
        "weighted_recoverability_std": _sample_std(weighted),
        "degraded_relations_total": degraded,
        "ambiguous_relations_total": ambiguous,
        "missing_relations_total": missing,
    }
    return aggregate_timing, aggregate_reconstruction


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _report_markdown(payload: dict) -> str:
    lines = [
        "# Level B Repetition Report",
        "",
        f"- Generated at: `{payload.get('generated_at')}`",
        f"- Scenario ID: `{payload.get('scenario_id')}`",
        f"- Scenario fingerprint: `{payload.get('scenario_fingerprint')}`",
        f"- Attack profile: `{payload.get('attack_profile_id')}`",
        f"- Requested repetitions: `{payload.get('requested_repetitions')}`",
        f"- Nested Level A repetitions per Level B case: `{payload.get('nested_level_a_requested_repetitions')}`",
        f"- Completed repetitions: `{payload.get('completed_repetitions')}`",
        f"- Partial repetitions: `{payload.get('partial_repetitions')}`",
        f"- Failed repetitions: `{payload.get('failed_repetitions')}`",
        "",
        "## Higher-Level Level B Comparability",
        "",
        f"- Comparison status: `{((payload.get('higher_level_comparison') or {}).get('status') or 'not_available')}`",
        f"- Comparison type: `{((payload.get('higher_level_comparison') or {}).get('comparison_type') or 'not_available')}`",
        f"- Compared executions: `{', '.join((payload.get('higher_level_comparison') or {}).get('execution_ids') or []) or 'not_available'}`",
        "",
        "## Nested Level A Repeatability",
        "",
        f"- Completed nested reports: `{((payload.get('nested_level_a_aggregate') or {}).get('completed_nested_reports') or 0)}`",
        f"- Failed nested reports: `{((payload.get('nested_level_a_aggregate') or {}).get('failed_nested_reports') or 0)}`",
        f"- Nested comparison statuses: `{', '.join((payload.get('nested_level_a_aggregate') or {}).get('comparison_statuses') or []) or 'not_available'}`",
        "",
        "## Aggregate Timing Metrics",
        "",
        f"- `N_B`: `{payload.get('aggregate_timing_metrics', {}).get('N_B')}`",
        f"- Alert -> memory start mean/std: `{payload.get('aggregate_timing_metrics', {}).get('alert_to_memory_start_mean_seconds')}` / `{payload.get('aggregate_timing_metrics', {}).get('alert_to_memory_start_std_seconds')}`",
        f"- Alert -> memory preserved mean/std: `{payload.get('aggregate_timing_metrics', {}).get('alert_to_memory_preserved_mean_seconds')}` / `{payload.get('aggregate_timing_metrics', {}).get('alert_to_memory_preserved_std_seconds')}`",
        f"- Alert -> case sealed mean/std: `{payload.get('aggregate_timing_metrics', {}).get('alert_to_case_sealed_mean_seconds')}` / `{payload.get('aggregate_timing_metrics', {}).get('alert_to_case_sealed_std_seconds')}`",
        f"- Total duration mean/std: `{payload.get('aggregate_timing_metrics', {}).get('total_duration_mean_seconds')}` / `{payload.get('aggregate_timing_metrics', {}).get('total_duration_std_seconds')}`",
        "",
        "## Aggregate Reconstruction Metrics",
        "",
        f"- Recoverability mean/std: `{payload.get('aggregate_reconstruction_metrics', {}).get('recoverability_mean')}` / `{payload.get('aggregate_reconstruction_metrics', {}).get('recoverability_std')}`",
        f"- Weighted recoverability mean/std: `{payload.get('aggregate_reconstruction_metrics', {}).get('weighted_recoverability_mean')}` / `{payload.get('aggregate_reconstruction_metrics', {}).get('weighted_recoverability_std')}`",
        f"- Degraded relations total: `{payload.get('aggregate_reconstruction_metrics', {}).get('degraded_relations_total')}`",
        f"- Ambiguous relations total: `{payload.get('aggregate_reconstruction_metrics', {}).get('ambiguous_relations_total')}`",
        f"- Missing relations total: `{payload.get('aggregate_reconstruction_metrics', {}).get('missing_relations_total')}`",
        "",
        "## Per-Repetition Results",
        "",
    ]
    for item in payload.get("per_repetition_results") or []:
        timing = item.get("timing_metrics") or {}
        reconstruction = item.get("reconstruction_metrics") or {}
        lines.extend(
            [
                f"### Repetition {item.get('repetition_number')}",
                "",
                f"- Execution ID: `{item.get('execution_id')}`",
                f"- Case ID: `{item.get('case_id') or 'not_created'}`",
                f"- Status: `{item.get('execution_status')}`",
                f"- Scientific case status: `{item.get('scientific_case_status') or 'not_available'}`",
                f"- Attack output: `{item.get('attack_output_path') or 'not_available'}`",
                f"- Trigger arming attempts: `{item.get('trigger_attempts_total') or 0}`",
                f"- Trigger alert detected: `{item.get('trigger_alert_detected')}`",
                f"- Trigger rule/severity: `{item.get('trigger_alert_rule')}` / `{item.get('trigger_alert_severity')}`",
                f"- Automatic acquisition started: `{item.get('automatic_acquisition_started')}`",
                f"- Memory / network / disk acquisition: `{item.get('memory_acquisition_status')}` / `{item.get('network_context_status')}` / `{item.get('disk_acquisition_status')}`",
                f"- Analysis status: `{item.get('analysis_status')}`",
                f"- Reconstruction status: `{item.get('reconstruction_status')}`",
                f"- Nested Level A status: `{((item.get('nested_level_a') or {}).get('status') or 'not_available')}`",
                f"- Nested Level A comparison: `{((item.get('nested_level_a') or {}).get('comparison_status') or 'not_available')}` / `{((item.get('nested_level_a') or {}).get('comparison_type') or 'not_available')}`",
                f"- Previous heavy case cleaned before next repetition: `{((item.get('pre_next_repetition_cleanup') or {}).get('status') or 'not_applicable')}`",
                f"- Recoverability / weighted / confidence: `{reconstruction.get('recoverability_score')}` / `{reconstruction.get('weighted_recoverability_score')}` / `{reconstruction.get('reconstruction_confidence')}`",
                f"- Relations recovered/degraded/ambiguous/missing: `{reconstruction.get('recovered_relations')}` / `{reconstruction.get('degraded_relations')}` / `{reconstruction.get('ambiguous_relations')}` / `{reconstruction.get('missing_relations')}`",
                f"- Alert -> memory start: `{timing.get('alert_to_memory_start_seconds')}` seconds",
                f"- Alert -> case sealed: `{timing.get('alert_to_case_sealed_seconds')}` seconds",
                f"- Total repetition duration: `{timing.get('total_repetition_duration_seconds')}` seconds",
            ]
        )
        if (item.get("pre_next_repetition_cleanup") or {}).get("status") == "completed":
            lines.append(
                f"- Previous case cleanup detail: `The previous heavy case was deleted before creating the next case to avoid storage pressure, and the lightweight retained bundle was preserved for comparison.`"
            )
        if item.get("warnings"):
            lines.append(f"- Warnings: `{' | '.join(str(v) for v in item.get('warnings') or [])}`")
        if item.get("blockers"):
            lines.append(f"- Blockers: `{' | '.join(str(v) for v in item.get('blockers') or [])}`")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _build_level_b_execution_audit(payload: dict, job_snapshot: dict) -> dict:
    results = list(payload.get("per_repetition_results") or [])
    requested = int(payload.get("requested_repetitions") or 0)
    attempted = len(results)
    not_started = max(requested - attempted, 0)
    generated_cases = [item.get("case_id") for item in results if item.get("case_id")]
    nested_runs = [dict(item.get("nested_level_a") or {}) for item in results if isinstance(item.get("nested_level_a"), dict)]
    nested_completed = [item for item in nested_runs if str(item.get("status") or "").lower() in {"completed", "completed_with_degradation"}]
    heavy_cleanups_completed = [
        item for item in results
        if str(((item.get("post_report_case_cleanup") or {}).get("status") or "")).lower() in {"completed", "ok"}
        and (item.get("post_report_case_cleanup") or {}).get("lightweight_case_bundle_manifest_path")
    ]
    last_failed = next((item for item in reversed(results) if item.get("execution_status") == "failed"), None)
    generated_outputs = {
        "campaign_created": True,
        "level_b_execution_workspaces": [item.get("execution_id") for item in results if item.get("execution_id")],
        "forensic_cases_created": generated_cases,
        "analysis_outputs_present_cases": [item.get("case_id") for item in results if (item.get("analysis_status") not in {None, "failed", "not_started"})],
        "nested_level_a_reports_completed": [item.get("campaign_id") for item in nested_completed if item.get("campaign_id")],
        "lightweight_cleanup_bundles_completed": [item.get("case_id") for item in results if str(((item.get("post_report_case_cleanup") or {}).get("status") or "")).lower() in {"completed", "ok"}],
        "level_b_report_bundle": True,
    }
    missing_outputs = {
        "remaining_level_b_repetitions_not_started": not_started,
        "nested_level_a_reports_missing": max(len(generated_cases) - len(nested_completed), 0),
        "heavy_case_cleanups_missing": max(len(generated_cases) - len(heavy_cleanups_completed), 0),
        "higher_level_comparison_ready": str(((payload.get("higher_level_comparison") or {}).get("status") or "")).lower() == "comparable",
    }
    return {
        "audit_type": "level_b_execution_audit",
        "generated_at": utc_now(),
        "campaign_id": str((job_snapshot.get("meta") or {}).get("campaign_id") or payload.get("campaign_id") or "not_available"),
        "requested_repetitions": requested,
        "attempted_repetitions": attempted,
        "not_started_repetitions": not_started,
        "completed_repetitions": int(payload.get("completed_repetitions") or 0),
        "partial_repetitions": int(payload.get("partial_repetitions") or 0),
        "failed_repetitions": int(payload.get("failed_repetitions") or 0),
        "current_job_status": job_snapshot.get("status"),
        "stop_context": {
            "current_phase": job_snapshot.get("current_phase"),
            "current_phase_label": job_snapshot.get("current_phase_label"),
            "current_phase_detail": job_snapshot.get("current_phase_detail"),
            "errors": list(job_snapshot.get("errors") or []),
            "warnings": list(job_snapshot.get("warnings") or []),
        },
        "expected_flow": {
            "per_level_b_repetition": [
                "execute controlled OT attack",
                "observe eligible high-severity alert",
                "create and preserve one fresh forensic case",
                "run multilayer analysis and reconstruction",
                "run nested Level A scientific repetitions over that same preserved case",
                "clean heavy case artifacts while retaining lightweight comparison bundle",
            ],
            "batch_finalization": [
                "repeat until requested repetition count is reached",
                "compare Level B repetitions",
                "emit final Level B JSON/CSV/Markdown report bundle",
            ],
        },
        "generated_outputs": generated_outputs,
        "missing_or_pending_outputs": missing_outputs,
        "last_failed_repetition": last_failed or {},
    }


def _level_b_execution_audit_markdown(audit: dict, payload: dict) -> str:
    lines = [
        "# Level B Execution Audit",
        "",
        "## Executive Summary",
        "",
        f"- Campaign ID: `{audit.get('campaign_id')}`",
        f"- Requested Level B repetitions: `{audit.get('requested_repetitions')}`",
        f"- Attempted repetitions: `{audit.get('attempted_repetitions')}`",
        f"- Not-started repetitions: `{audit.get('not_started_repetitions')}`",
        f"- Completed / partial / failed: `{audit.get('completed_repetitions')}` / `{audit.get('partial_repetitions')}` / `{audit.get('failed_repetitions')}`",
        f"- Job status: `{audit.get('current_job_status')}`",
        "",
        "## Where The Workflow Stopped",
        "",
        f"- Phase: `{((audit.get('stop_context') or {}).get('current_phase_label') or 'not_available')}`",
        f"- Detail: `{((audit.get('stop_context') or {}).get('current_phase_detail') or 'not_available')}`",
        "",
        "## Generated Outputs",
        "",
        f"- Level B execution workspaces: `{', '.join((audit.get('generated_outputs') or {}).get('level_b_execution_workspaces') or []) or 'none'}`",
        f"- Forensic cases created: `{', '.join((audit.get('generated_outputs') or {}).get('forensic_cases_created') or []) or 'none'}`",
        f"- Cases with analysis outputs present: `{', '.join((audit.get('generated_outputs') or {}).get('analysis_outputs_present_cases') or []) or 'none'}`",
        f"- Nested Level A reports completed: `{', '.join((audit.get('generated_outputs') or {}).get('nested_level_a_reports_completed') or []) or 'none'}`",
        f"- Heavy-case cleanups completed: `{', '.join((audit.get('generated_outputs') or {}).get('lightweight_cleanup_bundles_completed') or []) or 'none'}`",
        f"- Final Level B report bundle emitted: `{(audit.get('generated_outputs') or {}).get('level_b_report_bundle')}`",
        "",
        "## Missing Or Pending Outputs",
        "",
        f"- Remaining Level B repetitions not started: `{(audit.get('missing_or_pending_outputs') or {}).get('remaining_level_b_repetitions_not_started')}`",
        f"- Missing nested Level A reports: `{(audit.get('missing_or_pending_outputs') or {}).get('nested_level_a_reports_missing')}`",
        f"- Missing heavy-case cleanups: `{(audit.get('missing_or_pending_outputs') or {}).get('heavy_case_cleanups_missing')}`",
        f"- Higher-level comparison ready: `{(audit.get('missing_or_pending_outputs') or {}).get('higher_level_comparison_ready')}`",
        "",
        "## Reviewer-Facing Interpretation",
        "",
        "This audit distinguishes between physical preservation success and full Level B scientific completion. A preserved case may already contain memory, disk, network, alerts, and partial or complete analysis outputs while the orchestration still fails before nested Level A, cleanup, or cross-run comparison complete.",
        "",
    ]
    last_failed = audit.get("last_failed_repetition") or {}
    if last_failed:
        lines.extend(
            [
                "## Last Failed Repetition",
                "",
                f"- Repetition number: `{last_failed.get('repetition_number')}`",
                f"- Execution ID: `{last_failed.get('execution_id')}`",
                f"- Case ID: `{last_failed.get('case_id') or 'not_available'}`",
                f"- Case path: `{last_failed.get('case_path') or 'not_available'}`",
                f"- Analysis status observed: `{last_failed.get('analysis_status')}`",
                f"- Nested Level A status: `{((last_failed.get('nested_level_a') or {}).get('status') or 'not_generated')}`",
                f"- Cleanup status: `{((last_failed.get('post_report_case_cleanup') or {}).get('status') or 'not_generated')}`",
            ]
        )
        if last_failed.get("warnings"):
            lines.append(f"- Warnings: `{' | '.join(str(v) for v in last_failed.get('warnings') or [])}`")
        if last_failed.get("blockers"):
            lines.append(f"- Blockers: `{' | '.join(str(v) for v in last_failed.get('blockers') or [])}`")
        lines.append("")
    lines.extend(
        [
            "## Expected Professional End State",
            "",
            "For a successful Level B batch, every requested repetition should create a fresh case, complete multilayer analysis, complete nested Level A reporting, clean the heavy case while retaining a lightweight bundle, and then continue to the next repetition until the batch report can compare all runs.",
            "",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def _store_level_b_report(
    *,
    job_id: str,
    campaign_id: str,
    config: dict,
    cleanup_manifest: dict,
    results: list[dict],
    requested_repetitions: int,
    report_dir: Path,
    nested_level_a_repetitions: int,
    higher_level_comparison: dict,
) -> dict:
    generated_at = utc_now()
    job_snapshot = get_job(job_id) or {}
    aggregate_timing, aggregate_reconstruction = _aggregate_metrics(results)
    aggregate_twin = _attach_and_aggregate_twin_verdicts(campaign_id, results)
    completed_repetitions = sum(1 for item in results if item.get("execution_status") == "completed")
    partial_repetitions = sum(1 for item in results if item.get("execution_status") == "partial")
    failed_repetitions = sum(1 for item in results if item.get("execution_status") == "failed")
    first_result = next((item for item in results if item.get("case_id")), None)
    cases_created = [item.get("case_id") for item in results if item.get("case_id")]
    warnings = [warning for item in results for warning in (item.get("warnings") or [])]
    blockers = [blocker for item in results for blocker in (item.get("blockers") or [])]
    nested_runs = [item.get("nested_level_a") or {} for item in results]
    nested_completed = sum(1 for item in nested_runs if str(item.get("status") or "").lower() in {"completed", "completed_with_degradation"})
    nested_failed = sum(1 for item in nested_runs if item and str(item.get("status") or "").lower() not in {"completed", "completed_with_degradation"})
    nested_comparison_statuses = [str(item.get("comparison_status") or "not_available") for item in nested_runs if item]
    nested_comparison_types = [str(item.get("comparison_type") or "not_available") for item in nested_runs if item]
    payload = {
        "report_type": "level_b_repetition_report",
        "level": "B",
        "definition": "Independent repeated execution of the same controlled incident in the same deployed scenario, producing new forensic cases and new preserved evidence.",
        "requested_repetitions": requested_repetitions,
        "completed_repetitions": completed_repetitions,
        "failed_repetitions": failed_repetitions,
        "partial_repetitions": partial_repetitions,
        "scenario_id": config.get("scenario_id") or "not_available",
        "scenario_fingerprint": first_result.get("scenario_fingerprint") if first_result else "not_available",
        "attack_profile_id": config.get("attack_id") or "not_available",
        "dfir_mode_required": True,
        "dfir_mode_verified": all(bool(item.get("dfir_mode_enabled_successfully")) for item in results),
        "cases_created": cases_created,
        "nested_level_a_requested_repetitions": nested_level_a_repetitions,
        "higher_level_comparison": higher_level_comparison,
        "nested_level_a_aggregate": {
            "completed_nested_reports": nested_completed,
            "failed_nested_reports": nested_failed,
            "comparison_statuses": nested_comparison_statuses,
            "comparison_types": nested_comparison_types,
        },
        "aggregate_timing_metrics": aggregate_timing,
        "aggregate_reconstruction_metrics": aggregate_reconstruction,
        "aggregate_twin_metrics": aggregate_twin,
        "structured_metrics": {
            "level": "B",
            "n_repetitions": len(results),
            "metrics_per_repetition": results,
            "aggregate": {
                "timing": aggregate_timing,
                "reconstruction": aggregate_reconstruction,
            },
        },
        "per_repetition_results": results,
        "warnings": warnings,
        "blockers": blockers,
        "generated_at": generated_at,
        "git_commit": _safe_git_commit(),
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    _write_json(report_dir / "level_b_repetition_report.json", payload)

    summary_rows = []
    timing_rows = []
    reconstruction_rows = []
    paper_metrics_rows = []
    cases_index = []
    for item in results:
        summary_rows.append(
            {
                "repetition_number": item.get("repetition_number"),
                "execution_id": item.get("execution_id"),
                "case_id": item.get("case_id"),
                "execution_status": item.get("execution_status"),
                "scientific_case_status": item.get("scientific_case_status"),
                "trigger_alert_detected": item.get("trigger_alert_detected"),
                "memory_acquisition_status": item.get("memory_acquisition_status"),
                "network_context_status": item.get("network_context_status"),
                "disk_acquisition_status": item.get("disk_acquisition_status"),
                "analysis_status": item.get("analysis_status"),
                "reconstruction_status": item.get("reconstruction_status"),
                "comparison_family_id": item.get("comparison_family_id"),
                "nested_level_a_status": ((item.get("nested_level_a") or {}).get("status")),
                "nested_level_a_comparison_status": ((item.get("nested_level_a") or {}).get("comparison_status")),
            }
        )
        timing_rows.append({"repetition_number": item.get("repetition_number"), **(item.get("timing_metrics") or {})})
        reconstruction_rows.append({"repetition_number": item.get("repetition_number"), **(item.get("reconstruction_metrics") or {})})
        paper_metrics_rows.append(
            {
                "repetition_number": item.get("repetition_number"),
                "execution_id": item.get("execution_id"),
                "case_id": item.get("case_id"),
                **(item.get("timing_metrics") or {}),
                **{f"gate_{k}": v for k, v in (((item.get("critical_evidence_gate") or {}).get("checks") or {}).items())},
                "missing_critical_evidence": ";".join((item.get("critical_evidence_gate") or {}).get("missing_critical_evidence") or []),
                "expected_failed_paths": ";".join(
                    "; ".join(detail.get("expected_paths") or [])
                    for detail in ((item.get("critical_evidence_gate") or {}).get("failure_details") or [])
                ),
                "found_failed_paths": ";".join(
                    "; ".join(detail.get("found_paths") or [])
                    for detail in ((item.get("critical_evidence_gate") or {}).get("failure_details") or [])
                ),
                "expected_relations": ((item.get("reconstruction_metrics") or {}).get("expected_relations")),
                "recovered_relations": ((item.get("reconstruction_metrics") or {}).get("recovered_relations")),
                "degraded_relations": ((item.get("reconstruction_metrics") or {}).get("degraded_relations")),
                "ambiguous_relations": ((item.get("reconstruction_metrics") or {}).get("ambiguous_relations")),
                "missing_relations": ((item.get("reconstruction_metrics") or {}).get("missing_relations")),
                "cpr": ((item.get("reconstruction_metrics") or {}).get("recoverability_score")),
                "wcpr": ((item.get("reconstruction_metrics") or {}).get("weighted_recoverability_score")),
                "recoverability_label": ((item.get("reconstruction_metrics") or {}).get("recoverability_label")),
                "scientific_confidence_label": ((item.get("reconstruction_metrics") or {}).get("scientific_confidence_label")),
            }
        )
        cases_index.append(
            {
                "repetition_number": item.get("repetition_number"),
                "execution_id": item.get("execution_id"),
                "case_id": item.get("case_id"),
                "case_path": item.get("case_path"),
                "forensic_result_card": (item.get("artifacts") or {}).get("forensic_result_card"),
                "forensic_comparison_profile": (item.get("artifacts") or {}).get("forensic_comparison_profile"),
                "nested_level_a_campaign_id": ((item.get("nested_level_a") or {}).get("campaign_id")),
                "nested_level_a_report_path": ((item.get("nested_level_a") or {}).get("report_output_path")),
            }
        )

    _write_csv(
        report_dir / "level_b_repetition_summary.csv",
        summary_rows,
        [
            "repetition_number",
            "execution_id",
            "case_id",
            "execution_status",
            "scientific_case_status",
            "trigger_alert_detected",
            "memory_acquisition_status",
            "network_context_status",
            "disk_acquisition_status",
            "analysis_status",
            "reconstruction_status",
            "comparison_family_id",
            "nested_level_a_status",
            "nested_level_a_comparison_status",
        ],
    )
    _write_csv(
        report_dir / "level_b_timing_metrics.csv",
        timing_rows,
        [
            "repetition_number",
            "deploy_time_seconds",
            "teardown_redeploy_time_seconds",
            "network_mode",
            "alert_to_acquisition_start_seconds",
            "alert_to_memory_start_seconds",
            "alert_to_memory_preserved_seconds",
            "alert_to_ot_export_preserved_seconds",
            "alert_to_disk_snapshot_start_seconds",
            "alert_to_disk_snapshot_preserved_seconds",
            "alert_to_case_sealed_seconds",
            "t_first_sealed_seconds",
            "t_case_sealed_seconds",
            "memory_acquisition_duration_seconds",
            "pcap_import_duration_seconds",
            "disk_acquisition_duration_seconds",
            "case_sealed_to_analysis_completed_seconds",
            "total_repetition_duration_seconds",
            "pcap_periodic_context_size_gib",
            "pcap_reactive_capture_size_bytes",
            "memory_dump_size_bytes",
            "disk_snapshot_size_bytes",
            "retries_or_failures_count",
            "ot_export_present_in_manifest",
            "ot_export_paths",
            "evidence_completeness_gate",
        ],
    )
    _write_csv(
        report_dir / "level_b_reconstruction_metrics.csv",
        reconstruction_rows,
        [
            "repetition_number",
            "expected_relations",
            "recovered_relations",
            "degraded_relations",
            "ambiguous_relations",
            "missing_relations",
            "recoverability_score",
            "weighted_recoverability_score",
            "reconstruction_confidence",
            "recoverability_label",
            "scientific_confidence_label",
        ],
    )
    _write_csv(
        report_dir / "level_b_paper_metrics.csv",
        paper_metrics_rows,
        [
            "repetition_number",
            "execution_id",
            "case_id",
            "deploy_time_seconds",
            "teardown_redeploy_time_seconds",
            "network_mode",
            "alert_to_acquisition_start_seconds",
            "alert_to_memory_start_seconds",
            "alert_to_memory_preserved_seconds",
            "alert_to_ot_export_preserved_seconds",
            "alert_to_disk_snapshot_start_seconds",
            "alert_to_disk_snapshot_preserved_seconds",
            "t_first_sealed_seconds",
            "t_case_sealed_seconds",
            "pcap_periodic_context_size_gib",
            "pcap_reactive_capture_size_bytes",
            "memory_dump_size_bytes",
            "disk_snapshot_size_bytes",
            "retries_or_failures_count",
            "ot_export_present_in_manifest",
            "ot_export_paths",
            "evidence_completeness_gate",
            "missing_critical_evidence",
            "expected_failed_paths",
            "found_failed_paths",
            "expected_relations",
            "recovered_relations",
            "degraded_relations",
            "ambiguous_relations",
            "missing_relations",
            "cpr",
            "wcpr",
            "recoverability_label",
            "scientific_confidence_label",
        ],
    )
    _write_json(report_dir / "level_b_structured_metrics.json", payload["structured_metrics"])
    _write_json(report_dir / "level_b_cases_index.json", {"generated_at": generated_at, "cases": cases_index})
    _write_json(report_dir / "level_b_warnings_and_blockers.json", {"generated_at": generated_at, "warnings": warnings, "blockers": blockers})
    _write_json(report_dir / "cleanup_manifest.json", cleanup_manifest)
    _write_text(report_dir / "level_b_repetition_summary.md", _report_markdown(payload))
    audit_payload = _build_level_b_execution_audit(payload, job_snapshot)
    _write_json(report_dir / "level_b_execution_audit.json", audit_payload)
    _write_text(report_dir / "LEVEL_B_EXECUTION_AUDIT_README.md", _level_b_execution_audit_markdown(audit_payload, payload))
    return {
        "report_dir": relative_path(report_dir),
        "main_report_path": relative_path(report_dir / "level_b_repetition_report.json"),
        "summary_markdown_path": relative_path(report_dir / "level_b_repetition_summary.md"),
        "execution_audit_json_path": relative_path(report_dir / "level_b_execution_audit.json"),
        "execution_audit_markdown_path": relative_path(report_dir / "LEVEL_B_EXECUTION_AUDIT_README.md"),
        "summary_csv_path": relative_path(report_dir / "level_b_repetition_summary.csv"),
        "timing_csv_path": relative_path(report_dir / "level_b_timing_metrics.csv"),
        "reconstruction_csv_path": relative_path(report_dir / "level_b_reconstruction_metrics.csv"),
        "paper_metrics_csv_path": relative_path(report_dir / "level_b_paper_metrics.csv"),
        "structured_metrics_json_path": relative_path(report_dir / "level_b_structured_metrics.json"),
        "cases_index_path": relative_path(report_dir / "level_b_cases_index.json"),
        "warnings_path": relative_path(report_dir / "level_b_warnings_and_blockers.json"),
        "cleanup_manifest_path": relative_path(report_dir / "cleanup_manifest.json"),
        "payload": payload,
    }


def _persist_report_in_campaign(campaign_id: str, report_meta: dict) -> None:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    reports = dict(manifest.get("validation_reports") or {})
    history = list(reports.get("level_b_history") or [])
    entry = {
        "generated_at": utc_now(),
        "report_dir": report_meta.get("report_dir"),
        "main_report_path": report_meta.get("main_report_path"),
        "summary_markdown_path": report_meta.get("summary_markdown_path"),
        "job_id": report_meta.get("job_id"),
    }
    history.append(entry)
    reports["latest_level_b"] = entry
    reports["level_b_history"] = history[-12:]
    manifest["validation_reports"] = reports
    manifest["updated_at"] = utc_now()
    _write_json(campaign_manifest_path(campaign_id), manifest)


def _run_single_repetition(
    job_id: str,
    job_path: Path,
    *,
    campaign_id: str,
    config: dict,
    attack: dict,
    repetition_number: int,
    total_repetitions: int,
    target: dict,
    monitor: dict,
    acquisition_targets: list[dict],
    detection_timeout_seconds: int,
    dfir_mode_before: str,
    dfir_mode_after: str,
    nested_level_a_repetitions: int,
    preserve_as_final_sample: bool = False,
) -> dict:
    raise_if_cancelled(job_id, job_path, phase_key=f"repetition_{repetition_number}_start", phase_label=f"Start repetition {repetition_number}/{total_repetitions}", detail="Level B repetition batch cancellation was requested before starting the next repetition.")
    phase_extra = {"current_repetition": repetition_number, "requested_repetitions": total_repetitions}
    execution = create_execution_from_campaign(campaign_id, overrides={})
    execution_id = execution["execution_id"]
    update_job(
        job_id,
        job_path,
        current_execution_id=execution_id,
        current_case_id=None,
        current_attack_status="queued",
        current_alert_status="queued",
        current_acquisition_status="queued",
        current_preservation_status="queued",
        current_analysis_status="queued",
        current_reconstruction_status="queued",
        **phase_extra,
    )

    rep_idx = repetition_number
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_start", phase_label=f"Start repetition {rep_idx}/{total_repetitions}", status="running", detail=f"Execution workspace {execution_id} created. Starting independent Level B repetition {rep_idx} of {total_repetitions}.", category="repetition", index=0, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_execution_id": execution_id, **phase_extra})

    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_start", phase_label=f"Start repetition {rep_idx}/{total_repetitions}", status="completed", detail=f"Independent Level B repetition {rep_idx} has started with execution {execution_id}.", category="repetition", index=0, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_execution_id": execution_id, **phase_extra})
    pruned_placeholders = _prune_stale_placeholder_cases()
    if pruned_placeholders:
        append_job_list(
            job_id,
            job_path,
            "warnings",
            {
                "message": (
                    "Stale placeholder forensic case directories were pruned before trigger arming so they could not block or be reused by this repetition."
                ),
                "repetition": repetition_number,
                "pruned_case_dirs": pruned_placeholders,
            },
        )
    trigger_attempt_trace: list[dict] = []
    matched_alert: dict = {}
    attack_result: dict = {}
    attack_started_at: str | None = None
    attack_completed_at: str | None = None
    successful_attempt_number: int | None = None
    adopted_case_dir_from_trigger_arming: Path | None = None
    adopted_case_reason: str | None = None
    effective_attack_status = "queued"
    effective_alert_status = "queued"

    # OT State Twin (piloto): captura del estado real del PLC como "esperado" de ESTA
    # repeticion, justo antes de su ataque -- nunca bloquea ni falla la repeticion si el PLC
    # no es alcanzable o el modulo no esta disponible, solo queda como aviso no bloqueante.
    ot_twin_baseline = capture_baseline_for_repetition(campaign_id, execution_id)
    if not ot_twin_baseline.get("ok"):
        append_job_list(
            job_id,
            job_path,
            "warnings",
            {
                "message": (
                    "OT state twin baseline capture failed before this repetition's attack; "
                    "state-divergence detection will be unavailable for this repetition."
                ),
                "repetition": repetition_number,
                "reason": ot_twin_baseline.get("reason"),
            },
        )

    for attempt_number in range(1, MAX_TRIGGER_ARMING_ATTEMPTS + 1):
        raise_if_cancelled(job_id, job_path, phase_key=f"repetition_{rep_idx}_attack", phase_label="Execute OT register-modification attack", detail="Level B repetition batch cancellation was requested during repeated trigger arming attempts.")
        attempt_suffix = f"attempt {attempt_number}/{MAX_TRIGGER_ARMING_ATTEMPTS}"
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_attack", phase_label="Execute OT register-modification attack", status="running", detail=f"Launching {attack.get('attack_id')} against PLC target {target.get('vm_ip')} ({attempt_suffix}).", category="repetition", index=1, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_attack_status": "running", "trigger_attempt": attempt_number, **phase_extra})
        current_attack_started_at = utc_now()
        # Same fix as level_b_orchestrator._run_real_level_b_execution: reads
        # config["injected_faults"] (fault_injection module) to decide whether
        # this attack carries a real, explicit `value` or the usual {} --
        # ensures Level C campaigns (which arrive here, not through
        # level_b_orchestrator) also respect the fault-injection
        # configuration.
        current_attack_result = _launch_attack(attack, target.get("vm_ip"), target.get("role"), parameters=_resolve_injected_attack_parameters(config, attack))
        current_attack_completed_at = utc_now()
        if not current_attack_result.get("ok"):
            reason = current_attack_result.get("reason") or "Attack execution failed."
            trigger_attempt_trace.append({
                "attempt_number": attempt_number,
                "attack_started_at": current_attack_started_at,
                "attack_completed_at": current_attack_completed_at,
                "attack_status": "failed",
                "reason": reason,
                "dfir_mode_after": dfir_mode_after,
                "trigger_alert_detected": False,
                "forensic_intervention_eligible": False,
                "automatic_preservation_armed": False,
            })
            effective_attack_status = "failed"
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_attack", phase_label="Execute OT register-modification attack", status="completed_with_degradation" if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS else "failed", detail=f"{reason} ({attempt_suffix}).", category="repetition", index=1, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_attack_status": "failed", "trigger_attempt": attempt_number, **phase_extra})
            if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS:
                time.sleep(TRIGGER_ARMING_INTERVAL_SECONDS)
                continue
            return _failed_repetition_result(
                repetition_number=repetition_number,
                campaign_id=campaign_id,
                execution_id=execution_id,
                attack=attack,
                dfir_mode_before=dfir_mode_before,
                dfir_mode_after=dfir_mode_after,
                attack_started_at=current_attack_started_at,
                attack_completed_at=current_attack_completed_at,
                reason=reason,
                blockers=[reason],
                target=target,
                attack_result=current_attack_result,
                trigger_attempt_trace=trigger_attempt_trace,
            )

        attack_started_at = current_attack_started_at
        attack_completed_at = current_attack_completed_at
        attack_result = current_attack_result
        effective_attack_status = "completed"
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_attack", phase_label="Execute OT register-modification attack", status="completed", detail=f"Attack completed successfully ({attempt_suffix}). Output directory: {attack_result.get('_output_dir') or 'not_available'}.", category="repetition", index=1, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_attack_status": "completed", "trigger_attempt": attempt_number, **phase_extra})

        # OT State Twin (piloto): una rafaga de varias lecturas reales en sucesion rapida justo
        # tras el ataque (no "durante" -- _launch_attack() es sincrono/bloqueante, ver
        # poll_burst_and_compare() para el porque), cada una comparada contra el baseline
        # capturado antes de este ataque y contra la ley de control real del tanque. Nunca bloquea
        # ni falla la repeticion; una divergencia detectada queda como aviso informativo -- es
        # evidencia adicional de la capa "ot", separada a proposito de las alertas de
        # Suricata/Wazuh (seccion 12).
        ot_twin_result = poll_burst_and_compare_for_repetition(
            campaign_id,
            execution_id,
            attack_started_at=current_attack_started_at,
            attack_completed_at=current_attack_completed_at,
        )
        if not ot_twin_result.get("ok"):
            append_job_list(
                job_id,
                job_path,
                "warnings",
                {
                    "message": "OT state twin poll burst failed after this repetition's attack.",
                    "repetition": repetition_number,
                    "reason": ot_twin_result.get("reason"),
                },
            )
        elif ot_twin_result.get("diverged_any"):
            diffs = []
            for poll_result in ot_twin_result.get("results") or []:
                diffs.extend((poll_result.get("comparison") or {}).get("differences") or [])
                diffs.extend((poll_result.get("control_law_check") or {}).get("differences") or [])
            append_job_list(
                job_id,
                job_path,
                "warnings",
                {
                    "message": (
                        "OT state twin detected a real-state divergence (baseline and/or control-law "
                        "consistency) during the post-attack poll burst for this repetition "
                        "(evidence_layer=ot, independent of IDS/SIEM alerts)."
                    ),
                    "repetition": repetition_number,
                    "burst_count": ot_twin_result.get("burst_count"),
                    "differences": diffs,
                },
            )

        raise_if_cancelled(job_id, job_path, phase_key=f"repetition_{rep_idx}_alert", phase_label="Wait for high-severity alert", detail="Level B repetition batch cancellation was requested before alert waiting.")
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_alert", phase_label="Wait for high-severity alert", status="running", detail=f"Watching monitor {monitor.get('vm_ip')} for a HIGH/CRITICAL alert matching the OT attack profile ({attempt_suffix}).", category="repetition", index=2, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_alert_status": "running", "trigger_attempt": attempt_number, **phase_extra})
        matched = run_monitor_session(
            monitor.get("vm_ip"),
            ssh_user="ubuntu",
            ssh_key=os.environ.get("NICS_DFIR_SSH_KEY") or os.path.expanduser("~/.ssh/my_key"),
            on_alert=_build_alert_matcher(
                attack,
                attack_started_utc=current_attack_started_at,
                attack_completed_utc=current_attack_completed_at,
            ),
            stop_after_seconds=detection_timeout_seconds,
        )
        current_matched_alert = matched.get("matched_alert") or {}
        alert_fallback_reasons: list[str] = []
        if matched.get("status") != "matched":
            fallback_alert, fallback_reasons = _best_observed_alert_for_attack(
                list(matched.get("observed_alerts") or []),
                attack,
                attack_started_at=current_attack_started_at,
                attack_completed_at=current_attack_completed_at,
            )
            if fallback_alert:
                current_matched_alert = fallback_alert
                alert_fallback_reasons = list(fallback_reasons or [])
                matched["status"] = "matched"
                matched["matched_alert"] = fallback_alert

        current_trigger_detected = matched.get("status") == "matched"
        effective_alert_status = "completed" if current_trigger_detected else "failed"
        eligible, eligibility_reason = _trigger_eligibility(current_matched_alert)
        automatic_preservation_armed = bool(current_trigger_detected and eligible and str(dfir_mode_after or "").lower() == "on")
        trigger_attempt_trace.append({
            "attempt_number": attempt_number,
            "attack_started_at": current_attack_started_at,
            "attack_completed_at": current_attack_completed_at,
            "attack_status": "completed",
            "dfir_mode_after": dfir_mode_after,
            "trigger_alert_detected": current_trigger_detected,
            "trigger_alert_id": ((current_matched_alert.get("primary") or {}).get("event_id")),
            "trigger_alert_rule": ((current_matched_alert.get("primary") or {}).get("rule_id")),
            "trigger_alert_severity": str(((current_matched_alert.get("triage") or {}).get("severity") or "unknown")).lower(),
            "forensic_intervention_eligible": eligible,
            "automatic_preservation_armed": automatic_preservation_armed,
            "eligibility_reason": eligibility_reason,
            "fallback_reasons": list(alert_fallback_reasons or []),
            "observed_alerts_count": len(list(matched.get("observed_alerts") or [])),
        })

        background_case_dir, background_case_reason = _detect_background_case_during_trigger_arming()
        background_case_id = _case_id_for_case_dir(str(background_case_dir)) if background_case_dir else None
        background_case_trigger_time = None
        if background_case_dir:
            background_profile = _json_load(background_case_dir / "metadata" / "acquisition_profile.json") or {}
            background_case_trigger_time = background_profile.get("trigger_time_utc") or background_profile.get("acquisition_started_utc")
            if not matched.get("status") == "matched":
                trigger_attempt_trace[-1]["background_case_detected"] = {
                    "case_id": background_case_id,
                    "case_path": relative_path(background_case_dir),
                    "reason": background_case_reason,
                }

        if not current_trigger_detected:
            if background_case_dir:
                adopted_case_dir_from_trigger_arming = background_case_dir
                adopted_case_reason = background_case_reason
                matched_alert = {
                    "primary": {
                        "event_id": None,
                        "rule_id": None,
                        "ts_utc": background_case_trigger_time or attack_completed_at,
                        "timestamp": background_case_trigger_time or attack_completed_at,
                        "raw": {},
                    },
                    "triage": {
                        "severity": "HIGH",
                        "recommend_forensics": True,
                    },
                    "derived_from_background_case": True,
                    "background_case_id": background_case_id,
                }
                successful_attempt_number = attempt_number
                effective_alert_status = "completed_with_degradation"
                reason = (
                    f"No exact alert match was recognized by the Level B matcher within the configured timeout ({attempt_suffix}), "
                    f"but DFIR had already opened forensic case {background_case_id or 'not_available'} "
                    f"at {relative_path(background_case_dir)}. Re-arming another attack would violate the single-heavy-case invariant, "
                    "so the batch is adopting that case instead of launching another attempt."
                )
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_alert", phase_label="Wait for high-severity alert", status="completed_with_degradation", detail=reason, category="repetition", index=2, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_alert_status": "completed_with_degradation", "trigger_attempt": attempt_number, "adopted_background_case": background_case_id, **phase_extra})
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_trigger", phase_label="Verify forensic intervention trigger", status="completed_with_degradation", detail=f"Automatic forensic preservation has already started for case {background_case_id or 'not_available'} even though the explicit Level B alert matcher did not align perfectly with the observed alert taxonomy. The workflow will adopt the background DFIR case and continue with analysis instead of launching another case.", category="repetition", index=3, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"trigger_attempt": attempt_number, "adopted_background_case": background_case_id, **phase_extra})
                break
            observed_count = len(list(matched.get("observed_alerts") or []))
            if observed_count == 0:
                # The Wazuh stream emitted zero events — Suricata/Wazuh chain is silent,
                # not just non-matching. Retrying the attack won't fix infrastructure.
                # Stop early after 2 consecutive silent attempts to avoid 100-minute waits.
                consecutive_silent = sum(
                    1 for t in trigger_attempt_trace
                    if t.get("observed_alerts_count", 0) == 0
                )
                reason = (
                    f"Detection stream silent for attempt {attempt_number}/{MAX_TRIGGER_ARMING_ATTEMPTS}: "
                    f"zero Wazuh/Suricata events received during the {int(detection_timeout_seconds)}s window. "
                    f"This indicates an infrastructure issue — Suricata may not be running, "
                    f"the Wazuh integration may be broken, or the monitored interface (tap) is not "
                    f"receiving the attack traffic. Retrying the attack will not resolve this. "
                    f"Check Suricata status on monitor node {monitor.get('vm_ip')} and verify "
                    f"that /var/ossec/logs/alerts/alerts.json is being updated by Suricata events."
                )
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_alert", phase_label="Wait for high-severity alert", status="completed_with_degradation", detail=reason, category="repetition", index=2, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_alert_status": "detection_stream_silent", "trigger_attempt": attempt_number, "observed_alerts_count": 0, "consecutive_silent_attempts": consecutive_silent, **phase_extra})
                if consecutive_silent >= 2:
                    # Infrastructure confirmed down — stop immediately, don't burn 8 more attempts
                    final_reason, derived_blockers = _diagnose_trigger_failure(trigger_attempt_trace, dfir_mode_after)
                    final_reason = (
                        f"Detection stream silent for {consecutive_silent} consecutive attempts. "
                        f"{final_reason}"
                    )
                    return _failed_repetition_result(
                        repetition_number=repetition_number,
                        campaign_id=campaign_id,
                        execution_id=execution_id,
                        attack=attack,
                        dfir_mode_before=dfir_mode_before,
                        dfir_mode_after=dfir_mode_after,
                        attack_started_at=attack_started_at,
                        attack_completed_at=attack_completed_at,
                        reason=final_reason,
                        blockers=["detection_stream_silent"] + derived_blockers,
                        target=target,
                        attack_result=attack_result,
                        matched_alert=None,
                        trigger_attempt_trace=trigger_attempt_trace,
                    )
                time.sleep(TRIGGER_ARMING_INTERVAL_SECONDS)
                continue
            reason = f"No alert matching this attack's detection criteria was observed within the configured timeout ({attempt_suffix}). Wazuh emitted {observed_count} event(s) but none matched severity=HIGH/CRITICAL with forensic recommendation and attack content."
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_alert", phase_label="Wait for high-severity alert", status="completed_with_degradation" if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS else "failed", detail=reason, category="repetition", index=2, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_alert_status": "failed", "trigger_attempt": attempt_number, "observed_alerts_count": observed_count, **phase_extra})
            if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS:
                time.sleep(TRIGGER_ARMING_INTERVAL_SECONDS)
                continue
            final_reason, derived_blockers = _diagnose_trigger_failure(trigger_attempt_trace, dfir_mode_after)
            return _failed_repetition_result(
                repetition_number=repetition_number,
                campaign_id=campaign_id,
                execution_id=execution_id,
                attack=attack,
                dfir_mode_before=dfir_mode_before,
                dfir_mode_after=dfir_mode_after,
                attack_started_at=attack_started_at,
                attack_completed_at=attack_completed_at,
                reason=final_reason,
                blockers=derived_blockers,
                target=target,
                attack_result=attack_result,
                trigger_attempt_trace=trigger_attempt_trace,
            )

        alert_detail = f"Matched alert {(current_matched_alert.get('primary') or {}).get('event_id') or 'not_available'} with severity {((current_matched_alert.get('triage') or {}).get('severity') or 'unknown')} ({attempt_suffix})."
        if alert_fallback_reasons:
            alert_detail += f" Fallback matcher used because the attack dashboard alert taxonomy and the Level B expected-alert tokens did not align exactly. Reasons: {'; '.join(alert_fallback_reasons[:4])}."
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_alert", phase_label="Wait for high-severity alert", status="completed", detail=alert_detail, category="repetition", index=2, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_alert_status": "completed", "trigger_attempt": attempt_number, **phase_extra})

        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_trigger", phase_label="Verify forensic intervention trigger", status="running", detail=f"Verifying that the matched alert is eligible for forensic intervention and that automatic acquisition may start from this trigger ({attempt_suffix}).", category="repetition", index=3, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"trigger_attempt": attempt_number, **phase_extra})
        if not eligible:
            if background_case_dir:
                adopted_case_dir_from_trigger_arming = background_case_dir
                adopted_case_reason = background_case_reason
                matched_alert = current_matched_alert or matched_alert
                successful_attempt_number = attempt_number
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_trigger", phase_label="Verify forensic intervention trigger", status="completed_with_degradation", detail=f"The observed alert was not classified as directly eligible by the Level B matcher ({eligibility_reason}), but forensic case {background_case_id or 'not_available'} is already being or has already been preserved in the background. The workflow will adopt that case and will not launch another attack.", category="repetition", index=3, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"trigger_attempt": attempt_number, "adopted_background_case": background_case_id, **phase_extra})
                break
            reason = f"The matched alert is not eligible for forensic intervention: {eligibility_reason}."
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_trigger", phase_label="Verify forensic intervention trigger", status="completed_with_degradation" if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS else "failed", detail=reason, category="repetition", index=3, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"trigger_attempt": attempt_number, **phase_extra})
            if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS:
                time.sleep(TRIGGER_ARMING_INTERVAL_SECONDS)
                continue
            final_reason, derived_blockers = _diagnose_trigger_failure(trigger_attempt_trace, dfir_mode_after)
            return _failed_repetition_result(
                repetition_number=repetition_number,
                campaign_id=campaign_id,
                execution_id=execution_id,
                attack=attack,
                dfir_mode_before=dfir_mode_before,
                dfir_mode_after=dfir_mode_after,
                attack_started_at=attack_started_at,
                attack_completed_at=attack_completed_at,
                reason=final_reason,
                blockers=derived_blockers,
                target=target,
                attack_result=attack_result,
                matched_alert=current_matched_alert,
                trigger_attempt_trace=trigger_attempt_trace,
            )

        if str(dfir_mode_after or "").lower() != "on":
            if background_case_dir:
                adopted_case_dir_from_trigger_arming = background_case_dir
                adopted_case_reason = background_case_reason
                matched_alert = current_matched_alert or matched_alert
                successful_attempt_number = attempt_number
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_trigger", phase_label="Verify forensic intervention trigger", status="completed_with_degradation", detail=f"DFIR mode was reported as {dfir_mode_after or 'unknown'} for the explicit Level B trigger check, but forensic case {background_case_id or 'not_available'} already exists in the evidence store. The workflow will adopt that background case and stop re-arming attacks.", category="repetition", index=3, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"trigger_attempt": attempt_number, "adopted_background_case": background_case_id, **phase_extra})
                break
            reason = f"The alert is eligible, but DFIR mode is {dfir_mode_after or 'unknown'} so automatic forensic preservation is not armed ({attempt_suffix})."
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_trigger", phase_label="Verify forensic intervention trigger", status="completed_with_degradation" if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS else "failed", detail=reason, category="repetition", index=3, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"trigger_attempt": attempt_number, **phase_extra})
            if attempt_number < MAX_TRIGGER_ARMING_ATTEMPTS:
                time.sleep(TRIGGER_ARMING_INTERVAL_SECONDS)
                continue
            final_reason, derived_blockers = _diagnose_trigger_failure(trigger_attempt_trace, dfir_mode_after)
            return _failed_repetition_result(
                repetition_number=repetition_number,
                campaign_id=campaign_id,
                execution_id=execution_id,
                attack=attack,
                dfir_mode_before=dfir_mode_before,
                dfir_mode_after=dfir_mode_after,
                attack_started_at=attack_started_at,
                attack_completed_at=attack_completed_at,
                reason=final_reason,
                blockers=derived_blockers,
                target=target,
                attack_result=attack_result,
                matched_alert=current_matched_alert,
                trigger_attempt_trace=trigger_attempt_trace,
            )

        matched_alert = current_matched_alert
        successful_attempt_number = attempt_number
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_trigger", phase_label="Verify forensic intervention trigger", status="completed", detail=f"The matched high-severity alert is eligible for automatic forensic intervention and DFIR mode is ON ({attempt_suffix}).", category="repetition", index=3, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"trigger_attempt": attempt_number, **phase_extra})
        break

    if (not matched_alert and not adopted_case_dir_from_trigger_arming) or successful_attempt_number is None:
        final_reason, derived_blockers = _diagnose_trigger_failure(trigger_attempt_trace, dfir_mode_after)
        return _failed_repetition_result(
            repetition_number=repetition_number,
            campaign_id=campaign_id,
            execution_id=execution_id,
            attack=attack,
            dfir_mode_before=dfir_mode_before,
            dfir_mode_after=dfir_mode_after,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
            reason=final_reason,
            blockers=derived_blockers,
            target=target,
            attack_result=attack_result,
            matched_alert=matched_alert,
            trigger_attempt_trace=trigger_attempt_trace,
        )

    raise_if_cancelled(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", detail="Level B repetition batch cancellation was requested before automatic acquisition.")
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="running", detail="Creating a fresh forensic case and starting volatility-first DFIR acquisition over fuxa, plc, and victim: memory first, rolling-PCAP context import second, disk third.", category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": "running", **phase_extra})
    trigger_time_utc = ((matched_alert.get("primary") or {}).get("ts_utc")) or ((matched_alert.get("primary") or {}).get("timestamp")) or attack_completed_at
    adopted_existing_case = False
    try:
        if adopted_case_dir_from_trigger_arming:
            adopted_existing_case = True
            case_dir = adopted_case_dir_from_trigger_arming.resolve()
            case_id = _case_id_for_case_dir(str(case_dir))
            if not case_id or not (case_dir / "manifest.json").is_file():
                reason = f"Background case adoption was rejected because {relative_path(case_dir)} is not a complete preserved case directory."
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="failed", detail=reason, category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": "failed", **phase_extra})
                return _failed_repetition_result(
                    repetition_number=repetition_number,
                    campaign_id=campaign_id,
                    execution_id=execution_id,
                    attack=attack,
                    dfir_mode_before=dfir_mode_before,
                    dfir_mode_after=dfir_mode_after,
                    attack_started_at=attack_started_at,
                    attack_completed_at=attack_completed_at,
                    reason=reason,
                    blockers=[reason],
                    target=target,
                    attack_result=attack_result,
                    matched_alert=matched_alert,
                    case_dir=case_dir,
                    trigger_attempt_trace=trigger_attempt_trace,
                )
            update_job(job_id, job_path, current_case_id=case_id)
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="running", detail=f"A background DFIR preservation case already exists for this repetition. Reusing case {case_id} and refusing to create a second heavy case. Source: {adopted_case_reason or 'background_case_detected'}.", category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": "running", "adopted_active_case": case_id, **phase_extra})
            guard = _active_preservation_guard()
            guard_case_dir = Path(str(guard.get("case_dir") or "")).resolve() if guard.get("case_dir") else None
            if not guard.get("allowed") and guard_case_dir and guard_case_dir == case_dir:
                wait_result = _wait_for_active_preservation_release(expected_case_dir=case_dir)
                if wait_result.get("status") != "completed":
                    reason = (
                        f"Automatic preservation started a case for this alert, but it did not finish cleanly: "
                        f"{wait_result.get('reason') or 'active_preservation_wait_failed'}."
                    )
                    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="failed", detail=reason, category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": "failed", **phase_extra})
                    return _failed_repetition_result(
                        repetition_number=repetition_number,
                        campaign_id=campaign_id,
                        execution_id=execution_id,
                        attack=attack,
                        dfir_mode_before=dfir_mode_before,
                        dfir_mode_after=dfir_mode_after,
                        attack_started_at=attack_started_at,
                        attack_completed_at=attack_completed_at,
                        reason=reason,
                        blockers=[reason],
                        target=target,
                        attack_result=attack_result,
                        matched_alert=matched_alert,
                        case_id=case_id,
                        case_dir=case_dir,
                        trigger_attempt_trace=trigger_attempt_trace,
                    )
            profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") or {}
            network_manifest = _json_load(case_dir / "network" / "traffic_preserved" / "network_context_manifest.json") or {}
            preserved_segments = len(network_manifest.get("preserved_segments") or [])
            pending_segments = len(network_manifest.get("pending_segments") or [])
            memory_result = {
                "ok": bool(profile.get("memory_completed_utc")),
                "result": "ok" if profile.get("memory_completed_utc") else "error",
            }
            disk_result = {
                "ok": bool(profile.get("disk_completed_utc")),
                "result": "ok" if profile.get("disk_completed_utc") else "error",
            }
            network_result = {
                "error": None if preserved_segments or pending_segments or profile.get("network_context_import_completed_utc") else "network_context_not_observed",
                "preserved_segments": preserved_segments,
                "pending_segments": pending_segments,
            }
            acquisition_note = f"Background DFIR preservation reused case {case_id}. Memory={'ok' if memory_result.get('ok') else 'missing'}; network_import preserved={preserved_segments} pending={pending_segments}; disk={'ok' if disk_result.get('ok') else 'missing'}."
        else:
            case_dir = Path(_dfir_create_case_internal(run_id=execution_id, source="level_b_repetition_runner")).resolve()
            case_id = _case_id_for_case_dir(str(case_dir))
            acquisition_targets = _resolve_level_b_acquisition_targets()
            acquisition_roles = ", ".join(str(item.get("role") or "unknown") for item in acquisition_targets)
            initialize_volatile_first_acquisition(
                str(case_dir),
                run_id=execution_id,
                case_created_utc=utc_now(),
                acquisition_started_utc=utc_now(),
                trigger_time_utc=trigger_time_utc,
            )
            update_job(job_id, job_path, current_case_id=case_id)

            def _emit_acquisition_progress(text: str) -> None:
                _emit_phase(
                    job_id, job_path,
                    phase_key=f"repetition_{rep_idx}_acquisition",
                    phase_label="Run automatic acquisition",
                    status="running",
                    detail=text,
                    category="repetition",
                    index=4,
                    repetition_number=rep_idx,
                    total_repetitions=total_repetitions,
                    extra={"current_acquisition_status": "running", **phase_extra},
                )

            n_targets = len(acquisition_targets)
            with _heartbeat_during(job_id, job_path):
                update_acquisition_profile(str(case_dir), run_id=execution_id, merge_fields={"memory_started_utc": utc_now()})
                memory_items = []
                ssh_key = os.environ.get("NICS_DFIR_SSH_KEY") or os.path.expanduser("~/.ssh/my_key")
                for i, node in enumerate(acquisition_targets, start=1):
                    _emit_acquisition_progress(
                        f"Stage: MEMORY ({i}/{n_targets}) — acquiring volatile memory from "
                        f"{node.get('role') or 'unknown'} ({node.get('vm_ip') or node.get('vm_id') or 'unknown'})."
                    )
                    memory_items.append(
                        acquire_memory(
                            str(case_dir),
                            node.get("vm_id"),
                            node.get("vm_ip"),
                            ssh_key,
                            ssh_user=_dfir_ssh_user_for_role(node.get("role")),
                            mode="build",
                            run_id=execution_id,
                        )
                    )
                update_acquisition_profile(str(case_dir), run_id=execution_id, merge_fields={"memory_completed_utc": utc_now()})
                memory_result = {
                    "ok": bool(memory_items) and all(bool(item.get("ok")) for item in memory_items),
                    "result": "ok" if memory_items and all(bool(item.get("ok")) for item in memory_items) else "error",
                    "items": memory_items,
                }
                update_acquisition_profile(str(case_dir), run_id=execution_id, merge_fields={"network_context_import_started_utc": utc_now()})
                _emit_acquisition_progress("Stage: NETWORK — importing rolling-PCAP context across fuxa, plc, and victim (post-memory).")
                try:
                    network_result = import_continuous_network_context(str(case_dir), run_id=execution_id, trigger_time_utc=trigger_time_utc)
                except Exception as exc:
                    network_result = {"error": str(exc), "preserved_segments": 0, "pending_segments": 0}
                update_acquisition_profile(str(case_dir), run_id=execution_id, merge_fields={"network_context_import_completed_utc": utc_now()})
                update_acquisition_profile(str(case_dir), run_id=execution_id, merge_fields={"disk_started_utc": utc_now()})
                disk_items = []
                for i, node in enumerate(acquisition_targets, start=1):
                    _emit_acquisition_progress(
                        f"Stage: DISK ({i}/{n_targets}) — acquiring disk image from "
                        f"{node.get('role') or 'unknown'} ({node.get('vm_ip') or node.get('vm_id') or 'unknown'})."
                    )
                    disk_items.append(
                        acquire_disk(
                            str(case_dir),
                            node.get("vm_id"),
                            "nova_libvirt",
                            run_id=execution_id,
                            noninteractive=True,
                        )
                    )
                update_acquisition_profile(str(case_dir), run_id=execution_id, merge_fields={"disk_completed_utc": utc_now()})
                disk_result = {
                    "ok": bool(disk_items) and all(bool(item.get("ok")) for item in disk_items),
                    "result": "ok" if disk_items and all(bool(item.get("ok")) for item in disk_items) else "error",
                    "items": disk_items,
                }
            acquisition_note = (
                f"Case {case_id} created. Acquisition scope={acquisition_roles}. "
                f"Memory={memory_result.get('result')} ({len(memory_items)} host(s)); "
                f"network_import preserved={network_result.get('preserved_segments', 0)} pending={network_result.get('pending_segments', 0)}; "
                f"disk={disk_result.get('result')} ({len(disk_items)} host(s))."
            )
    except RuntimeError as exc:
        guard = _active_preservation_guard()
        guard_case_dir = Path(str(guard.get("case_dir") or "")).resolve() if guard.get("case_dir") else None
        if not guard.get("allowed") and guard_case_dir and guard_case_dir.exists():
            adopted_existing_case = True
            case_dir = guard_case_dir
            case_id = _case_id_for_case_dir(str(case_dir))
            if not case_id or not (case_dir / "manifest.json").is_file():
                reason = f"Active preserved case adoption was rejected because {relative_path(case_dir)} is not a complete preserved case directory."
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="failed", detail=reason, category="repetition", index=4, repetition_number=repetition_number, total_repetitions=total_repetitions, extra={"current_acquisition_status": "failed", **phase_extra})
                return _failed_repetition_result(
                    repetition_number=repetition_number,
                    campaign_id=campaign_id,
                    execution_id=execution_id,
                    attack=attack,
                    dfir_mode_before=dfir_mode_before,
                    dfir_mode_after=dfir_mode_after,
                    attack_started_at=attack_started_at,
                    attack_completed_at=attack_completed_at,
                    reason=reason,
                    blockers=[reason],
                    target=target,
                    attack_result=attack_result,
                    matched_alert=matched_alert,
                    case_dir=case_dir,
                    trigger_attempt_trace=trigger_attempt_trace,
                )
            update_job(job_id, job_path, current_case_id=case_id)
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="running", detail=f"An automatic forensic preservation case is already being created for the matched alert. Reusing active case {case_id} instead of creating a second case, and waiting until preservation finishes.", category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": "running", "adopted_active_case": case_id, **phase_extra})
            wait_result = _wait_for_active_preservation_release(expected_case_dir=case_dir)
            if wait_result.get("status") != "completed":
                reason = (
                    f"Automatic preservation started a case for this alert, but it did not finish cleanly: "
                    f"{wait_result.get('reason') or 'active_preservation_wait_failed'}."
                )
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="failed", detail=reason, category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": "failed", **phase_extra})
                return _failed_repetition_result(
                    repetition_number=repetition_number,
                    campaign_id=campaign_id,
                    execution_id=execution_id,
                    attack=attack,
                    dfir_mode_before=dfir_mode_before,
                    dfir_mode_after=dfir_mode_after,
                    attack_started_at=attack_started_at,
                    attack_completed_at=attack_completed_at,
                    reason=reason,
                    blockers=[reason],
                    target=target,
                    attack_result=attack_result,
                    matched_alert=matched_alert,
                    case_id=case_id,
                    case_dir=case_dir,
                    trigger_attempt_trace=trigger_attempt_trace,
                )
            profile = _json_load(case_dir / "metadata" / "acquisition_profile.json") or {}
            network_manifest = _json_load(case_dir / "network" / "traffic_preserved" / "network_context_manifest.json") or {}
            preserved_segments = len(network_manifest.get("preserved_segments") or [])
            pending_segments = len(network_manifest.get("pending_segments") or [])
            memory_result = {
                "ok": bool(profile.get("memory_completed_utc")),
                "result": "ok" if profile.get("memory_completed_utc") else "error",
            }
            disk_result = {
                "ok": bool(profile.get("disk_completed_utc")),
                "result": "ok" if profile.get("disk_completed_utc") else "error",
            }
            network_result = {
                "error": None if preserved_segments or pending_segments or profile.get("network_context_import_completed_utc") else "network_context_not_observed",
                "preserved_segments": preserved_segments,
                "pending_segments": pending_segments,
            }
            acquisition_note = f"Automatic alert-driven preservation reused active case {case_id}. Memory={'ok' if memory_result.get('ok') else 'missing'}; network_import preserved={preserved_segments} pending={pending_segments}; disk={'ok' if disk_result.get('ok') else 'missing'}."
        else:
            reason = str(exc)
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status="failed", detail=reason, category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": "failed", **phase_extra})
            return _failed_repetition_result(
                repetition_number=repetition_number,
                campaign_id=campaign_id,
                execution_id=execution_id,
                attack=attack,
                dfir_mode_before=dfir_mode_before,
                dfir_mode_after="off",
                attack_started_at=attack_started_at,
                attack_completed_at=attack_completed_at,
                reason=reason,
                blockers=["active_preservation_in_progress", reason],
                target=target,
                attack_result=attack_result,
                matched_alert=matched_alert,
                trigger_attempt_trace=trigger_attempt_trace,
            )
    acq_status = "completed"
    if not memory_result.get("ok") or not disk_result.get("ok") or network_result.get("error"):
        acq_status = "completed_with_degradation"
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_acquisition", phase_label="Run automatic acquisition", status=acq_status, detail=acquisition_note, category="repetition", index=4, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_acquisition_status": acq_status, **phase_extra})

    acquisition_profile_id = str(config.get("acquisition_profile_id") or "not_available")
    trigger_binding = _persist_trigger_alert_binding(
        case_dir=case_dir,
        run_id=execution_id,
        execution_id=execution_id,
        case_id=case_id,
        attack=attack,
        matched_alert=matched_alert,
    )
    intervention_started_at = (
        ((_json_load(case_dir / "metadata" / "acquisition_profile.json") or {}).get("acquisition_started_utc"))
        or trigger_time_utc
    )
    intervention_completed_at = utc_now()
    _persist_forensic_intervention_artifact(
        case_dir=case_dir,
        run_id=execution_id,
        execution_id=execution_id,
        case_id=case_id,
        acquisition_profile_id=acquisition_profile_id,
        trigger_binding=trigger_binding,
        memory_result=memory_result,
        network_result=network_result,
        disk_result=disk_result,
        intervention_started_at=intervention_started_at,
        intervention_completed_at=intervention_completed_at,
    )
    _persist_normalized_causal_timestamps(
        case_dir=case_dir,
        run_id=execution_id,
        execution_id=execution_id,
        case_id=case_id,
        attack_started_at=attack_started_at,
        attack_completed_at=attack_completed_at,
        matched_alert=matched_alert,
    )
    critical_gate = _critical_evidence_gate(
        case_dir=case_dir,
        run_id=execution_id,
        execution_id=execution_id,
        case_id=case_id,
    )
    if str(critical_gate.get("gate_status") or "") == "diagnostic_failed":
        acquisition_note = (
            acquisition_note
            + " Critical evidence gate failed: "
            + ", ".join(list(critical_gate.get("missing_critical_evidence") or []))
            + ". The case remains diagnostic/audit only and must not be treated as scientifically complete."
        )

    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_seal", phase_label="Seal and register case", status="running", detail="Finalizing custody/digest state so the new case can feed the scientific analysis and reconstruction pipeline.", category="repetition", index=5, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "running", **phase_extra})
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_seal", phase_label="Seal and register case", status="completed" if memory_result.get("ok") or disk_result.get("ok") else "completed_with_degradation", detail=f"Case {case_id} is registered for downstream analysis.", category="repetition", index=5, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "completed", **phase_extra})
    _clear_active_preservation_state(str(case_dir), run_id=execution_id, final_state="completed", reason="case_sealed_for_downstream_analysis")
    try:
        _ensure_case_registered_in_cases_index(case_dir, case_id)
        _link_real_case_into_execution_scaffold(campaign_id, execution_id, case_id, case_dir)
    except Exception as exc:
        reason = f"Could not register sealed case {case_id} for lifecycle/indexed analysis: {exc}"
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_analysis", phase_label="Run multilayer analysis", status="failed", detail=reason, category="repetition", index=6, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_analysis_status": "failed", **phase_extra})
        return _failed_repetition_result(
            repetition_number=repetition_number,
            campaign_id=campaign_id,
            execution_id=execution_id,
            attack=attack,
            dfir_mode_before=dfir_mode_before,
            dfir_mode_after=dfir_mode_after,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
            reason=reason,
            blockers=[reason],
            target=target,
            attack_result=attack_result,
            matched_alert=matched_alert,
            case_id=case_id,
            case_dir=case_dir,
            trigger_attempt_trace=trigger_attempt_trace,
        )

    raise_if_cancelled(job_id, job_path, phase_key=f"repetition_{rep_idx}_analysis", phase_label="Run multilayer analysis", detail="Level B repetition batch cancellation was requested before lifecycle analysis.")
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_analysis", phase_label="Run multilayer analysis", status="running", detail=f"Running the existing preserved-case lifecycle backend over {case_id}.", category="repetition", index=6, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_analysis_status": "running", **phase_extra})
    lifecycle_job = start_full_lifecycle_job(case_id, force_analysis=True, strict=False, degraded_ok=True)
    if lifecycle_job.get("error"):
        reason = f"Could not start lifecycle analysis: {lifecycle_job.get('error')}"
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_analysis", phase_label="Run multilayer analysis", status="failed", detail=reason, category="repetition", index=6, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_analysis_status": "failed", **phase_extra})
        return _failed_repetition_result(
            repetition_number=repetition_number,
            campaign_id=campaign_id,
            execution_id=execution_id,
            attack=attack,
            dfir_mode_before=dfir_mode_before,
            dfir_mode_after=dfir_mode_after,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
            reason=reason,
            blockers=[reason],
            target=target,
            attack_result=attack_result,
            matched_alert=matched_alert,
            case_id=case_id,
            case_dir=case_dir,
            trigger_attempt_trace=trigger_attempt_trace,
        )
    update_job(job_id, job_path, current_lifecycle_job_id=str(lifecycle_job.get("job_id") or ""))
    # _wait_for_lifecycle_job (level_b_orchestrator.py) is a plain poll loop
    # with no knowledge of THIS job_id/job_path — it can't touch our own
    # heartbeat itself. Without _heartbeat_during, this call can block for
    # 20-35+ minutes (the case's own multilayer analysis, confirmed live
    # 2026-07-19: repetition_1_analysis went quiet for 18+ minutes) with zero
    # update_job() calls in between, so a get_job() read landing on a
    # different gunicorn worker mid-wait can't verify the thread is alive and
    # wrongly declares this job orphaned via _ORPHAN_JOB_GRACE_SECONDS —
    # confirmed live the same day: the job briefly flipped to status=failed
    # with "no active worker exists anymore", then self-corrected back to
    # running on its own next natural update, since the owning worker's
    # thread was never actually dead. Same fix already applied to the
    # acquisition block above (line ~3339) — this call site was simply
    # missed when that fix landed.
    with _heartbeat_during(job_id, job_path):
        lifecycle_result = _wait_for_lifecycle_job(lifecycle_job.get("job_id"))
    update_job(job_id, job_path, current_lifecycle_job_id=None)
    lifecycle_status = str(lifecycle_result.get("status") or "unknown")
    if lifecycle_status == "failed":
        reason = "; ".join(str(item) for item in (lifecycle_result.get("errors") or []) if item) or "Lifecycle analysis failed."
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_analysis", phase_label="Run multilayer analysis", status="failed", detail=reason, category="repetition", index=6, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_analysis_status": "failed", **phase_extra})
        return _failed_repetition_result(
            repetition_number=repetition_number,
            campaign_id=campaign_id,
            execution_id=execution_id,
            attack=attack,
            dfir_mode_before=dfir_mode_before,
            dfir_mode_after=dfir_mode_after,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
            reason=reason,
            blockers=[reason],
            target=target,
            attack_result=attack_result,
            matched_alert=matched_alert,
            case_id=case_id,
            case_dir=case_dir,
            trigger_attempt_trace=trigger_attempt_trace,
        )
    analysis_detail = "Lifecycle analysis finished successfully." if lifecycle_status == "completed" else "Lifecycle analysis finished with warnings or scientific degradation."
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_analysis", phase_label="Run multilayer analysis", status="completed" if lifecycle_status == "completed" else "completed_with_degradation", detail=analysis_detail, category="repetition", index=6, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_analysis_status": lifecycle_status, **phase_extra})

    raise_if_cancelled(job_id, job_path, phase_key=f"repetition_{rep_idx}_reconstruction", phase_label="Run reconstruction/dependency analysis", detail="Level B repetition batch cancellation was requested before repetition result registration.")
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_reconstruction", phase_label="Run reconstruction/dependency analysis", status="running", detail="Attaching the fresh case back into the repetition workspace and generating the normalized comparison/result-card outputs.", category="repetition", index=7, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_reconstruction_status": "running", **phase_extra})
    attack_record_override = {
        "attack_id": attack.get("attack_id"),
        "mitre": {"technique_id": attack.get("mitre_id"), "technique_name": attack.get("mitre_technique")},
        "operation": {
            "tool_used": attack.get("script"),
            "tool_version": "not_available",
            "protocol": "modbus_tcp",
            "modbus_function": params.get("parsed_write_command", {}).get("modbus_function") if (params := _attack_parameter_status(attack_result)) else "not_available",
            "register_reference": params.get("parsed_write_command", {}).get("register_reference") if params else None,
            "value": params.get("parsed_write_command", {}).get("value") if params else None,
        },
        "execution": {"started_at": attack_started_at, "completed_at": attack_completed_at},
        "source_reference": os.path.join("app_core", "infrastructure", "attack", "outputs", Path(str(attack_result.get("_output_dir") or "")).name, "result.json") if attack_result.get("_output_dir") else attack.get("script"),
    }
    stage_overrides = {
        "environment_deployed": {"status": "completed", "reason": "scenario was reused in-place for this independent Level B repetition"},
        "tools_installed_or_validated": {"status": "completed", "reason": "target and monitor nodes were validated before attack launch"},
        "attack_executed": {"status": "completed", "reason": f"attack {attack.get('attack_id')} was executed against the PLC target"},
        "detection_observed": {"status": "completed", "reason": "a real matching high-severity alert was observed"},
        "trigger_selected": {"status": "completed", "reason": "the matched alert was used as the automatic forensic trigger"},
        "acquisition_executed": {"status": "completed" if (memory_result.get("ok") or disk_result.get("ok")) else "completed_with_degradation", "reason": "automatic forensic acquisition ran after the trigger"},
        "evidence_preserved": {"status": "completed", "reason": "the generated case preserves the fresh evidence set and custody records"},
    }
    # Confirmado en vivo (2026-09-22/23): esta llamada construye los perfiles reales de la
    # ejecucion (build_execution_profiles -> baseline_noise/ground_truth_seal sobre el caso recien
    # adquirido, potencialmente varios hosts de memoria/disco/red) sin ningun update_job() propio
    # mientras tanto -- el job PADRE se quedo con `updated_at` viejo aqui mismo (fase quedo
    # congelada en "repetition_1_reconstruction" con este mismo detalle) y un get_job() desde otro
    # worker de gunicorn lo declaro huerfano/`failed` via _ORPHAN_JOB_GRACE_SECONDS (180s), aunque
    # el hilo seguia vivo. Mismo patron de bug ya arreglado dos veces en este fichero (adquisicion,
    # espera del analisis) -- aqui era la tercera llamada bloqueante sin proteger.
    with _heartbeat_during(job_id, job_path):
        attach_result = attach_real_case_to_execution(
            campaign_id,
            execution_id,
            case_id=case_id,
            attack_record_override=attack_record_override,
            stage_overrides=stage_overrides,
        )
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_reconstruction", phase_label="Run reconstruction/dependency analysis", status="completed" if attach_result.get("status") == "completed" else "completed_with_degradation", detail=f"Execution {execution_id} now points to case {case_id} with comparison family {attach_result.get('comparison_family_id')}.", category="repetition", index=7, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_reconstruction_status": attach_result.get("status"), **phase_extra})

    nested_level_a = _run_nested_level_a_report_for_case(
        parent_campaign_id=campaign_id,
        parent_execution_id=execution_id,
        parent_config=config,
        case_id=case_id,
        repetition_number=repetition_number,
        nested_level_a_repetitions=max(int(nested_level_a_repetitions or total_repetitions or 1), 1),
        job_id=job_id,
        job_path=job_path,
        rep_idx=rep_idx,
        total_repetitions=total_repetitions,
        phase_extra=phase_extra,
    )

    result = _repetition_result_from_case(
        repetition_number=repetition_number,
        campaign_id=campaign_id,
        execution_id=execution_id,
        case_id=case_id,
        case_dir=case_dir,
        attack=attack,
        attack_result=attack_result,
        attack_started_at=attack_started_at,
        attack_completed_at=attack_completed_at,
        target=target,
        matched_alert=matched_alert,
        memory_result=memory_result,
        network_result=network_result,
        disk_result=disk_result,
        lifecycle_result=lifecycle_result,
        attach_result=attach_result,
        dfir_mode_before=dfir_mode_before,
        dfir_mode_after=dfir_mode_after,
        nested_level_a=nested_level_a,
        trigger_attempt_trace=trigger_attempt_trace,
    )
    if str(((result.get("critical_evidence_gate") or {}).get("gate_status") or "")) == "diagnostic_failed":
        missing_critical = list((result.get("critical_evidence_gate") or {}).get("missing_critical_evidence") or [])
        result.setdefault("warnings", []).append(
            "Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete."
        )
        if missing_critical:
            result.setdefault("blockers", []).append(
                "missing_critical_evidence=" + ", ".join(missing_critical)
            )
    try:
        ACTIVE_CASE_PTR.write_text("", encoding="utf-8")
    except Exception:
        pass
    # 2026-09-01: when this is the final repetition of the whole requested
    # campaign (standalone Level B's own last rep, or -- when wrapped by
    # Level C -- the last Level C repetition specifically, not just the last
    # inner Level B rep of every batch), keep this ONE case fully intact
    # instead of reducing it to the lightweight bundle like every other
    # repetition. Reuses delete_generated_case_artifacts's existing
    # action_type="archive_case_directory" path (already does a plain
    # shutil.move of the untouched case directory, no new deletion/parsing
    # logic), just pointed at this campaign's own folder instead of the
    # shared ARCHIVED_CASES_ROOT, via archive_destination. Placed under
    # campaign_dir() (not directly under EVIDENCE_STORE_ROOT), so it is
    # permanently outside the "CASE-*" glob _cleanup_candidates() scans --
    # no future campaign's mandatory cleanup can ever find or touch it.
    if preserve_as_final_sample:
        archive_destination = campaign_dir(campaign_id) / "final_sample_case" / case_dir.name
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_cleanup", phase_label="Preserve final case as full sample", status="running", detail=f"This is the final repetition of the campaign -- preserving case {case_id} fully intact (raw disk, memory, network, everything) as a real, complete result sample, instead of reducing it to the lightweight bundle.", category="repetition", index=8, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "final_sample_preserving", **phase_extra})
        cleanup_after_report = delete_generated_case_artifacts(
            execution_id,
            campaign_id=campaign_id,
            case_id=case_id,
            confirmation="OK",
            operator="level_b_repetition_runner_final_sample",
            action_type="archive_case_directory",
            archive_destination=archive_destination,
        )
    else:
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_cleanup", phase_label="Clean heavy generated case", status="running", detail=f"Cleaning heavy artifacts for case {case_id} after nested Level A analysis so the next Level B repetition can create a fresh case without coexisting heavy cases.", category="repetition", index=8, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "cleanup_running", **phase_extra})
        cleanup_after_report = delete_generated_case_artifacts(
            execution_id,
            campaign_id=campaign_id,
            case_id=case_id,
            confirmation="OK",
            operator="level_b_repetition_runner",
        )
    if cleanup_after_report.get("error"):
        _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_cleanup", phase_label="Clean heavy generated case", status="failed", detail=f"Heavy-case cleanup failed for {case_id}: {cleanup_after_report.get('error')}", category="repetition", index=8, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "cleanup_failed", **phase_extra})
        result.setdefault("warnings", []).append(
            f"Post-report generated-case cleanup was not completed for {case_id}: {cleanup_after_report.get('error')}"
        )
        result.setdefault("blockers", []).append(
            f"Heavy generated case cleanup failed for {case_id}; the next Level B repetition must not start until this case is cleaned."
        )
    else:
        result["post_report_case_cleanup"] = {
            "status": cleanup_after_report.get("status") or "completed",
            "action_type": cleanup_after_report.get("action_type") or "delete_case_directory",
            "retention_manifest_path": cleanup_after_report.get("manifest_path"),
            "archive_target": cleanup_after_report.get("archive_target"),
            "lightweight_case_bundle_path": cleanup_after_report.get("lightweight_case_bundle_path"),
            "lightweight_case_bundle_manifest_path": cleanup_after_report.get("lightweight_case_bundle_manifest_path"),
        }
        result["warnings"] = list(result.get("warnings") or [])
        if preserve_as_final_sample:
            result["warnings"].append(f"This was the final repetition of the campaign -- case {case_id} was kept fully intact as a complete result sample instead of being reduced to the lightweight bundle.")
        else:
            result["warnings"].append("Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.")
        cleanup_manifest_path = str((result.get("post_report_case_cleanup") or {}).get("lightweight_case_bundle_manifest_path") or "")
        if cleanup_manifest_path:
            if preserve_as_final_sample:
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_cleanup", phase_label="Preserve final case as full sample", status="completed", detail=f"Final case {case_id} preserved intact at {cleanup_after_report.get('archive_target')}.", category="repetition", index=8, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "final_sample_preserved", **phase_extra})
            else:
                _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_cleanup", phase_label="Clean heavy generated case", status="completed", detail=f"Heavy generated case {case_id} was cleaned after nested Level A analysis. Lightweight retained bundle: {cleanup_manifest_path}.", category="repetition", index=8, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "cleanup_completed", **phase_extra})
            post_case_free_space_cleanup = _run_level_b_free_space_cleanup(acquisition_targets)
            result["post_case_free_space_cleanup"] = post_case_free_space_cleanup
            post_cleanup_status = "completed" if post_case_free_space_cleanup.get("status") == "completed" else "completed_with_degradation"
            post_cleanup_detail = (
                f"Applied safe free-space cleanup on fuxa/plc after deleting heavy case {case_id}. "
                f"Cleaned roles: {', '.join(post_case_free_space_cleanup.get('cleaned_roles') or []) or 'none'}."
            )
            if post_case_free_space_cleanup.get("status") != "completed":
                post_cleanup_detail = (
                    f"Heavy case {case_id} was deleted, but the follow-up free-space cleanup on fuxa/plc did not fully succeed. "
                    f"Failed roles: {', '.join(post_case_free_space_cleanup.get('failed_roles') or []) or 'unknown'}."
                )
                result.setdefault("warnings", []).append(
                    "Post-delete free-space cleanup on fuxa/plc did not fully succeed; the next repetition will retry it before launching the next attack."
                )
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_post_cleanup_node_space", phase_label="Free space cleanup on fuxa/plc", status=post_cleanup_status, detail=post_cleanup_detail, category="repetition", index=8, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "cleanup_completed", "free_space_cleanup": post_case_free_space_cleanup, **phase_extra})
        else:
            _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_cleanup", phase_label="Clean heavy generated case", status="failed", detail=f"Cleanup for {case_id} did not produce the required lightweight retained bundle. The next Level B repetition must be blocked.", category="repetition", index=8, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_preservation_status": "cleanup_failed", **phase_extra})
            result.setdefault("blockers", []).append(
                f"Cleanup for {case_id} did not produce the required lightweight retained bundle."
            )
    if any(list(item.get("fallback_reasons") or []) for item in trigger_attempt_trace):
        result.setdefault("warnings", []).append("Level B alert match required a fallback OT-aware matcher because the expected-alert taxonomy did not match the observed alert text exactly.")
    if result.get("blockers") and result.get("execution_status") == "completed":
        result["execution_status"] = "partial"
    _emit_phase(job_id, job_path, phase_key=f"repetition_{rep_idx}_store", phase_label="Store repetition result", status="completed" if result.get("execution_status") == "completed" else "completed_with_degradation", detail=f"Stored repetition {rep_idx}/{total_repetitions} result with status {result.get('execution_status')} and case {case_id}.", category="repetition", index=9, repetition_number=rep_idx, total_repetitions=total_repetitions, extra={"current_analysis_status": "completed", "current_reconstruction_status": result.get("reconstruction_status"), **phase_extra})
    return result


def _run_level_b_repetitions_job(
    job_id: str,
    job_path: Path,
    *,
    campaign_id: str,
    requested_repetitions: int,
    cleanup_old_cases: bool,
    detection_timeout_seconds: int,
    dfir_mode_before: str,
    dfir_mode_after: str,
    nested_level_a_repetitions: int,
    preserve_final_case: bool = True,
) -> None:
    raise_if_cancelled(job_id, job_path, phase_key="prepare_level_b_job", phase_label="Prepare Level B job", detail="Level B repetition batch was cancelled before startup.")
    manifest, config = _load_campaign(campaign_id)
    attack = find_attack_by_id(str(config.get("attack_id") or "").strip())
    if not manifest or not attack:
        update_job(job_id, job_path, status="failed", finished_at=utc_now(), current_phase="failed", progress_percent=100.0, errors=[{"message": "campaign_or_attack_not_found"}])
        return

    runtime_dir = RUNTIME_ROOT / job_id
    runtime_dir.mkdir(parents=True, exist_ok=True)
    report_timestamp = utc_now()
    report_dir = _report_dir_for_timestamp(report_timestamp)
    update_job(job_id, job_path, report_output_path=relative_path(report_dir), requested_repetitions=requested_repetitions)

    _emit_phase(job_id, job_path, phase_key="prepare_level_b_job", phase_label="Prepare Level B job", status="running", detail="Preparing Level B batch execution, runtime workspace, and deterministic scientific progress plan.", category="setup", index=0, total_repetitions=requested_repetitions, extra={"requested_repetitions": requested_repetitions})
    _emit_phase(job_id, job_path, phase_key="prepare_level_b_job", phase_label="Prepare Level B job", status="completed", detail=f"Prepared Level B batch job for campaign {campaign_id}.", category="setup", index=0, total_repetitions=requested_repetitions, extra={"requested_repetitions": requested_repetitions})

    raise_if_cancelled(job_id, job_path, phase_key="optional_cleanup", phase_label="Clean previous heavy cases", detail="Level B repetition batch was cancelled before mandatory cleanup of previous heavy cases.")
    _emit_phase(job_id, job_path, phase_key="optional_cleanup", phase_label="Clean previous heavy cases", status="running", detail="Inspecting and deleting previous heavy forensic cases before launching the independent Level B repetitions. This is mandatory so two heavy cases never coexist.", category="setup", index=1, total_repetitions=requested_repetitions)
    # 2026-09-24: envuelto en _heartbeat_during -- fallo real observado: este borrado
    # (decenas de GB, un solo caso pesado) puede tardar mas de los 900s de gracia del
    # vigilante de trabajos huerfanos sin tocar el heartbeat del job ni una sola vez,
    # ya que _run_cleanup() es una unica llamada bloqueante sin progreso intermedio --
    # misma forma exacta que acquisition/attach_real_case_to_execution/etc., que ya
    # tenian este mismo arreglo; a este punto de llamada se le habia olvidado antes.
    with _heartbeat_during(job_id, job_path):
        cleanup_manifest = _run_cleanup(runtime_dir, enabled=True)
    if cleanup_manifest.get("cleanup_status") == "failed":
        _emit_phase(job_id, job_path, phase_key="optional_cleanup", phase_label="Clean previous heavy cases", status="failed", detail="Mandatory cleanup of previous heavy cases failed. The workflow stops before launching any repetition to avoid coexistence of two heavy cases.", category="setup", index=1, total_repetitions=requested_repetitions)
        update_job(job_id, job_path, status="failed", finished_at=utc_now(), current_phase="optional_cleanup", current_phase_label="Clean previous heavy cases", current_phase_detail="Mandatory cleanup of previous heavy cases failed. No repetition was launched.", progress_percent=100.0, level_b_cleanup_manifest_path=relative_path(runtime_dir / "cleanup_manifest.json"))
        return
    cleanup_detail = (
        f"Mandatory cleanup {cleanup_manifest.get('cleanup_status')}. Estimated freed space: {_human_bytes(cleanup_manifest.get('freed_bytes_estimated'))}. "
        f"Actual freed space: {_human_bytes(cleanup_manifest.get('freed_bytes_actual'))}. Deleted cases: {len(cleanup_manifest.get('deleted_cases') or [])}."
    )
    _emit_phase(job_id, job_path, phase_key="optional_cleanup", phase_label="Clean previous heavy cases", status="completed", detail=cleanup_detail, category="setup", index=1, total_repetitions=requested_repetitions, extra={"level_b_cleanup_manifest_path": relative_path(runtime_dir / "cleanup_manifest.json")})

    _emit_phase(job_id, job_path, phase_key="resolve_active_scenario", phase_label="Resolve active scenario", status="running", detail=f"Resolving the already deployed scenario that will host all {requested_repetitions} independent Level B repetitions.", category="setup", index=2, total_repetitions=requested_repetitions)
    targets = _resolve_real_targets(attack)
    target = targets.get("target")
    monitor = targets.get("monitor")
    if not target or not monitor:
        reason = "The active deployed scenario does not expose a resolvable target node and monitor node for the selected OT attack profile."
        _emit_phase(job_id, job_path, phase_key="resolve_active_scenario", phase_label="Resolve active scenario", status="failed", detail=reason, category="setup", index=2, total_repetitions=requested_repetitions)
        update_job(job_id, job_path, status="failed", finished_at=utc_now(), current_phase="resolve_active_scenario", current_phase_label="Resolve active scenario", current_phase_detail=reason, progress_percent=100.0, blockers=[reason])
        return
    _emit_phase(job_id, job_path, phase_key="resolve_active_scenario", phase_label="Resolve active scenario", status="completed", detail=f"Resolved target {target.get('vm_name')} ({target.get('vm_ip')}) and monitor {monitor.get('vm_name')} ({monitor.get('vm_ip')}).", category="setup", index=2, total_repetitions=requested_repetitions)

    _emit_phase(job_id, job_path, phase_key="verify_plc_target", phase_label="Verify PLC target", status="running", detail="Checking that the selected target is really the PLC node used by the controlled OT register-modification profile.", category="setup", index=3, total_repetitions=requested_repetitions)
    if str(target.get("role") or "").lower() != "plc":
        reason = f"Resolved target role is {target.get('role')}, not PLC. Level B OT repetitions are blocked."
        _emit_phase(job_id, job_path, phase_key="verify_plc_target", phase_label="Verify PLC target", status="failed", detail=reason, category="setup", index=3, total_repetitions=requested_repetitions)
        update_job(job_id, job_path, status="failed", finished_at=utc_now(), current_phase="verify_plc_target", current_phase_label="Verify PLC target", current_phase_detail=reason, progress_percent=100.0, blockers=[reason])
        return
    try:
        acquisition_targets = _resolve_level_b_acquisition_targets()
    except Exception as exc:
        reason = str(exc)
        _emit_phase(job_id, job_path, phase_key="verify_plc_target", phase_label="Verify PLC target", status="failed", detail=reason, category="setup", index=3, total_repetitions=requested_repetitions)
        update_job(job_id, job_path, status="failed", finished_at=utc_now(), current_phase="verify_plc_target", current_phase_label="Verify PLC target", current_phase_detail=reason, progress_percent=100.0, blockers=[reason])
        return
    acquisition_scope_detail = ", ".join(f"{item.get('role')}={item.get('vm_ip')}" for item in acquisition_targets)
    _emit_phase(job_id, job_path, phase_key="verify_plc_target", phase_label="Verify PLC target", status="completed", detail=f"PLC target verified: {target.get('vm_name')} ({target.get('vm_ip')}). Multi-host preservation scope resolved: {acquisition_scope_detail}.", category="setup", index=3, total_repetitions=requested_repetitions)

    _emit_phase(job_id, job_path, phase_key="enable_dfir_mode", phase_label="Enable DFIR mode", status="running", detail="Verifying that DFIR mode is ON before the first OT attack is launched.", category="setup", index=4, total_repetitions=requested_repetitions, extra={"dfir_mode_before": dfir_mode_before, "dfir_mode_after": dfir_mode_after})
    preservation_guard = _active_preservation_guard()
    if not preservation_guard.get("allowed"):
        reason = (
            f"{preservation_guard.get('reason')} "
            f"Current preservation case: {preservation_guard.get('case_id') or 'not_available'}."
        )
        _emit_phase(job_id, job_path, phase_key="enable_dfir_mode", phase_label="Enable DFIR mode", status="failed", detail=reason, category="setup", index=4, total_repetitions=requested_repetitions, extra={"dfir_mode_before": dfir_mode_before, "dfir_mode_after": "off", "active_preservation_case_id": preservation_guard.get("case_id")})
        update_job(job_id, job_path, status="failed", finished_at=utc_now(), current_phase="enable_dfir_mode", current_phase_label="Enable DFIR mode", current_phase_detail=reason, progress_percent=100.0, blockers=[reason], active_preservation_case_id=preservation_guard.get("case_id"))
        return
    if dfir_mode_after != "on":
        reason = "DFIR mode could not be verified as ON. The workflow will still run controlled trigger-arming attempts, but automatic preservation cannot start until DFIR mode is ON."
        _emit_phase(job_id, job_path, phase_key="enable_dfir_mode", phase_label="Enable DFIR mode", status="completed_with_degradation", detail=reason, category="setup", index=4, total_repetitions=requested_repetitions, extra={"dfir_mode_before": dfir_mode_before, "dfir_mode_after": dfir_mode_after})
    else:
        _emit_phase(job_id, job_path, phase_key="enable_dfir_mode", phase_label="Enable DFIR mode", status="completed", detail=f"DFIR mode verified ON. Browser mode transitioned from {dfir_mode_before} to {dfir_mode_after}.", category="setup", index=4, total_repetitions=requested_repetitions, extra={"dfir_mode_before": dfir_mode_before, "dfir_mode_after": dfir_mode_after})

    _emit_phase(job_id, job_path, phase_key="verify_disk_acquisition", phase_label="Verify disk acquisition prerequisites", status="running", detail="Checking whether disk preservation can run in stable non-interactive mode for a long Level B batch.", category="setup", index=5, total_repetitions=requested_repetitions)
    disk_preflight = disk_acquisition_preflight("nova_libvirt", require_stable_noninteractive=True)
    if not disk_preflight.get("ok"):
        blockers = [str(item) for item in (disk_preflight.get("blockers") or []) if item]
        if "sudo_noninteractive_unavailable" in blockers:
            blocker_explanation = (
                "stable non-interactive sudo/root privileges are not available. "
                "This backend still depends on an interactive password entry, which is unsafe for multi-repetition Level B batches "
                "because nested Level A analysis can outlive the sudo timestamp"
            )
        elif "sudo_nopasswd_not_granted_for_disk_helper" in blockers:
            blocker_explanation = (
                "stable NOPASSWD sudo privileges are not granted for the disk acquisition helper. "
                "A cached sudo session is not considered reliable enough for a long Level B batch"
            )
        elif "docker_access_unavailable" in blockers:
            blocker_explanation = (
                "the backend cannot access Docker in the privilege context required by the disk acquisition helper"
            )
        else:
            blocker_explanation = (
                "required disk-preservation prerequisites are missing"
            )
        reason = (
            "Disk acquisition for Level B batches is blocked because "
            f"{blocker_explanation}. "
            f"Blockers: {', '.join(blockers)}."
        )
        _emit_phase(job_id, job_path, phase_key="verify_disk_acquisition", phase_label="Verify disk acquisition prerequisites", status="failed", detail=reason, category="setup", index=5, total_repetitions=requested_repetitions, extra={"disk_preflight": disk_preflight})
        update_job(job_id, job_path, status="failed", finished_at=utc_now(), current_phase="verify_disk_acquisition", current_phase_label="Verify disk acquisition prerequisites", current_phase_detail=reason, progress_percent=100.0, blockers=[reason], disk_preflight=disk_preflight)
        return
    _emit_phase(job_id, job_path, phase_key="verify_disk_acquisition", phase_label="Verify disk acquisition prerequisites", status="completed", detail="Stable non-interactive disk acquisition prerequisites verified for Level B batch execution.", category="setup", index=5, total_repetitions=requested_repetitions, extra={"disk_preflight": disk_preflight})

    results: list[dict] = []
    early_stop_reason: str | None = None
    early_stop_repetition: int | None = None

    for repetition_number in range(1, requested_repetitions + 1):
        raise_if_cancelled(job_id, job_path, phase_key="start_repetition", phase_label=f"Start repetition {repetition_number}/{requested_repetitions}", detail="Level B repetition batch cancellation was requested before launching the next repetition.")
        # Re-reads config.json on every repetition (previously loaded ONCE for
        # the whole job) -- a cheap read of an already-trusted file, and this
        # is what lets the Fault Injection dashboard toggle `injected_faults`
        # (e.g. modbus_payload_precision) mid-campaign across several
        # repetitions and have the change actually apply starting from the
        # next repetition, instead of staying frozen at whatever value was
        # set when the job was launched.
        config = _json_load(campaign_config_path(campaign_id)) or config
        if repetition_number > 1 and results:
            pre_cleanup = _cleanup_previous_heavy_case_before_next_repetition(
                job_id=job_id,
                job_path=job_path,
                campaign_id=campaign_id,
                repetition_number=repetition_number,
                total_repetitions=requested_repetitions,
                previous_result=results[-1],
                acquisition_targets=acquisition_targets,
            )
            results[-1]["pre_next_repetition_cleanup"] = pre_cleanup
            if pre_cleanup.get("status") == "failed":
                blocker = (
                    f"Previous heavy case could not be cleaned before repetition {repetition_number}. "
                    f"Reason: {pre_cleanup.get('reason') or 'cleanup_failed'}."
                )
                append_job_list(job_id, job_path, "errors", {"message": blocker, "repetition": repetition_number})
                results[-1].setdefault("blockers", []).append(blocker)
                break
            _emit_phase(
                job_id,
                job_path,
                phase_key=f"repetition_{repetition_number}_pre_attack_node_space",
                phase_label="Free space cleanup before next attack",
                status="running",
                detail=(
                    f"Running mandatory free-space cleanup on fuxa/plc before launching repetition {repetition_number}/{requested_repetitions}. "
                    "This ensures node-local storage is reclaimed before the next Level B attack."
                ),
                category="repetition",
                index=0,
                repetition_number=repetition_number,
                total_repetitions=requested_repetitions,
            )
            pre_attack_node_cleanup = _run_level_b_free_space_cleanup(acquisition_targets)
            results[-1]["pre_next_repetition_node_cleanup"] = pre_attack_node_cleanup
            if pre_attack_node_cleanup.get("status") != "completed":
                _emit_phase(
                    job_id,
                    job_path,
                    phase_key=f"repetition_{repetition_number}_pre_attack_node_space",
                    phase_label="Free space cleanup before next attack",
                    status="failed",
                    detail=(
                        f"Mandatory free-space cleanup on fuxa/plc failed before repetition {repetition_number}. "
                        f"Failed roles: {', '.join(pre_attack_node_cleanup.get('failed_roles') or []) or 'unknown'}."
                    ),
                    category="repetition",
                    index=0,
                    repetition_number=repetition_number,
                    total_repetitions=requested_repetitions,
                    extra={"free_space_cleanup": pre_attack_node_cleanup},
                )
                blocker = (
                    f"Mandatory free-space cleanup failed before repetition {repetition_number}; "
                    f"failed_roles={','.join(pre_attack_node_cleanup.get('failed_roles') or []) or 'unknown'}."
                )
                append_job_list(job_id, job_path, "errors", {"message": blocker, "repetition": repetition_number})
                results[-1].setdefault("blockers", []).append(blocker)
                break
            _emit_phase(
                job_id,
                job_path,
                phase_key=f"repetition_{repetition_number}_pre_attack_node_space",
                phase_label="Free space cleanup before next attack",
                status="completed",
                detail=(
                    f"Mandatory free-space cleanup completed on fuxa/plc before repetition {repetition_number}. "
                    f"Cleaned roles: {', '.join(pre_attack_node_cleanup.get('cleaned_roles') or []) or 'none'}."
                ),
                category="repetition",
                index=0,
                repetition_number=repetition_number,
                total_repetitions=requested_repetitions,
                extra={"free_space_cleanup": pre_attack_node_cleanup},
            )
        try:
            result = _run_single_repetition(
                job_id,
                job_path,
                campaign_id=campaign_id,
                config=config,
                attack=attack,
                repetition_number=repetition_number,
                total_repetitions=requested_repetitions,
                target=target,
                monitor=monitor,
                acquisition_targets=acquisition_targets,
                detection_timeout_seconds=detection_timeout_seconds,
                dfir_mode_before=dfir_mode_before,
                dfir_mode_after=dfir_mode_after,
                nested_level_a_repetitions=nested_level_a_repetitions,
                preserve_as_final_sample=(preserve_final_case and repetition_number == requested_repetitions),
            )
        except Exception as exc:
            result = _failed_repetition_result(
                repetition_number=repetition_number,
                campaign_id=campaign_id,
                execution_id=f"EXEC-UNKNOWN-{repetition_number}",
                attack=attack,
                dfir_mode_before=dfir_mode_before,
                dfir_mode_after=dfir_mode_after,
                attack_started_at=None,
                attack_completed_at=None,
                reason=f"Unexpected repetition failure: {exc}",
                blockers=[str(exc)],
                target=target,
            )
        results.append(result)
        append_job_list(job_id, job_path, "per_repetition_results", result)
        if result.get("warnings"):
            for warning in result.get("warnings") or []:
                append_job_list(job_id, job_path, "warnings", warning)
        if result.get("blockers"):
            for blocker in result.get("blockers") or []:
                append_job_list(job_id, job_path, "errors", {"message": blocker, "repetition": repetition_number})
        if str(result.get("execution_status") or "") == "failed":
            early_stop_repetition = repetition_number
            early_stop_reason = (
                f"Repetition {repetition_number}/{requested_repetitions} failed. "
                "The Level B campaign is being closed immediately; no further attacks or acquisitions will be launched. "
                "Final reporting will be generated only from the repetitions already executed."
            )
            _emit_phase(
                job_id,
                job_path,
                phase_key=f"repetition_{repetition_number}_close_campaign_after_error",
                phase_label="Close campaign after failed repetition",
                status="completed_with_degradation",
                detail=early_stop_reason,
                category="repetition",
                index=9,
                repetition_number=repetition_number,
                total_repetitions=requested_repetitions,
                extra={
                    "execution_id": result.get("execution_id"),
                    "case_id": result.get("case_id"),
                    "execution_status": result.get("execution_status"),
                },
            )
            append_job_list(job_id, job_path, "errors", {"message": early_stop_reason, "repetition": repetition_number})
            break
        cleanup_state = dict(result.get("post_report_case_cleanup") or {})
        if result.get("case_id") and not cleanup_state.get("lightweight_case_bundle_manifest_path"):
            blocker = f"Post-report heavy-case cleanup did not complete for repetition {repetition_number}. The next Level B repetition is blocked to avoid coexisting heavy cases."
            append_job_list(job_id, job_path, "errors", {"message": blocker, "repetition": repetition_number})
            result.setdefault("blockers", []).append(blocker)
            break

    raise_if_cancelled(job_id, job_path, phase_key="generate_report", phase_label="Generate Level B report", detail="Level B repetition batch cancellation was requested before final report generation.")
    _emit_phase(job_id, job_path, phase_key="generate_report", phase_label="Generate Level B report", status="running", detail="Aggregating per-repetition timing, acquisition, reconstruction, warnings, blockers, and case outputs into the final Level B validation report bundle.", category="final", index=0, total_repetitions=requested_repetitions)
    # 2026-09-04: compare across the WHOLE campaign (comparable_execution_ids_for_campaign),
    # not just this job's own local `results` -- see that function's docstring for why a
    # local-only comparison silently never reached >= 2 executions for Level C-launched campaigns.
    local_comparable_ids = [str(item.get("execution_id") or "") for item in results if item.get("execution_id") and (item.get("artifacts") or {}).get("forensic_comparison_profile")]
    comparable_execution_ids = list(dict.fromkeys(comparable_execution_ids_for_campaign(campaign_id, level="B") + local_comparable_ids))
    higher_level_comparison = compare_executions(comparable_execution_ids, campaign_id=campaign_id) if len(comparable_execution_ids) >= 2 else {
        "status": "Insufficient Data",
        "reason": "not_enough_completed_level_b_executions_for_direct_comparison",
        "execution_ids": comparable_execution_ids,
    }
    report_meta = _store_level_b_report(
        job_id=job_id,
        campaign_id=campaign_id,
        config=config,
        cleanup_manifest=cleanup_manifest,
        results=results,
        requested_repetitions=requested_repetitions,
        report_dir=report_dir,
        nested_level_a_repetitions=nested_level_a_repetitions,
        higher_level_comparison=higher_level_comparison,
    )
    report_meta["job_id"] = job_id
    _persist_report_in_campaign(campaign_id, report_meta)
    _write_json(Path.cwd() / report_meta["report_dir"] / "job_status.json", get_job(job_id) or {})
    _emit_phase(job_id, job_path, phase_key="generate_report", phase_label="Generate Level B report", status="completed", detail=f"Level B report bundle written to {report_meta['report_dir']}.", category="final", index=0, total_repetitions=requested_repetitions, extra={"level_b_report_dir": report_meta["report_dir"], "level_b_report_path": report_meta["main_report_path"]})

    # 2026-09-04: rebuild the consolidated forensic package after EVERY job
    # invocation, not just the final one -- at the user's explicit request
    # ("do it automatically when the campaign finishes or while the campaign
    # is still running"), so the package folder updates
    # incrementally as repetitions complete instead of only appearing once
    # at the very end. Safe to call this often: build_campaign_forensic_package
    # is idempotent (copytree with dirs_exist_ok=True, and it simply finds
    # nothing to move for final_sample_case/ until the truly final
    # repetition creates it -- see `preserve_final_case` above). The one
    # invocation where `preserve_final_case` is True is the real end of the
    # outer campaign (its own last repetition for a standalone Level B
    # batch, or the last Level C repetition specifically when wrapped by
    # Level C -- see level_c_orchestrator._phase_run_level_b's
    # is_final_level_c_rep) -- that's the run where the preserved case
    # actually gets moved in. Best-effort throughout: a package-build
    # failure must never fail the campaign it's reporting on.
    try:
        from .campaign_package_builder import build_campaign_forensic_package

        package_summary = build_campaign_forensic_package(campaign_id)
        stage = "Final" if preserve_final_case else "Incremental"
        append_job_list(
            job_id, job_path, "warnings",
            f"{stage} consolidated forensic package update at {package_summary['package_dir']} "
            f"({package_summary['execution_count']} Level B executions, "
            f"{package_summary['nested_level_a_count']} nested Level A reports, "
            f"dashboard capture: {package_summary['dashboard_capture_included']}, "
            f"final case included: {package_summary['final_sample_case_included']}).",
        )
    except Exception as exc:
        append_job_list(
            job_id, job_path, "warnings",
            f"Consolidated forensic package update failed (non-fatal, campaign result is unaffected): {exc}",
        )

    completed = sum(1 for item in results if item.get("execution_status") == "completed")
    partial = sum(1 for item in results if item.get("execution_status") == "partial")
    failed = sum(1 for item in results if item.get("execution_status") == "failed")
    final_status = "completed"
    if failed:
        final_status = "completed_with_failures"
    elif partial:
        final_status = "completed_with_degradation"
    completion_detail = f"Level B repetition workflow finished: completed={completed}, partial={partial}, failed={failed}."
    if early_stop_reason:
        completion_detail += f" Campaign stopped early after repetition {early_stop_repetition}: {early_stop_reason}"
    _emit_phase(job_id, job_path, phase_key="complete", phase_label="Complete", status="completed", detail=completion_detail, category="final", index=1, total_repetitions=requested_repetitions, extra={"level_b_report_dir": report_meta["report_dir"], "level_b_report_path": report_meta["main_report_path"], "stopped_early": bool(early_stop_reason), "stopped_after_repetition": early_stop_repetition})
    update_job(
        job_id,
        job_path,
        status=final_status,
        finished_at=utc_now(),
        current_phase="complete",
        current_phase_label="Complete",
        current_phase_detail=f"{completion_detail} Report: {report_meta['report_dir']}",
        progress_percent=100.0,
        level_b_report_dir=report_meta["report_dir"],
        level_b_report_path=report_meta["main_report_path"],
        level_b_summary_markdown_path=report_meta["summary_markdown_path"],
        level_b_execution_audit_json_path=report_meta["execution_audit_json_path"],
        level_b_execution_audit_markdown_path=report_meta["execution_audit_markdown_path"],
        cleanup_manifest_path=report_meta["cleanup_manifest_path"],
        completed_repetitions=completed,
        partial_repetitions=partial,
        failed_repetitions=failed,
        stopped_early=bool(early_stop_reason),
        stopped_after_repetition=early_stop_repetition,
    )


_ACTIVE_JOB_TERMINAL_STATUSES = {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}


def find_active_level_b_job() -> dict | None:
    """Scan every campaign's jobs/ directory on disk for a Level B job that
    hasn't reached a terminal status yet.

    Jobs run as a background thread inside whichever gunicorn worker started
    them and are invisible to other workers' in-memory job_runner state, so
    this reads the persisted job JSON files directly rather than relying on
    job_runner.list_jobs() (process-local only).

    Level B repetitions drive real attacks and evidence acquisition against
    the one shared physical lab scenario — running two at once means two
    attacks/acquisitions racing over the same VMs, which is exactly the
    'doble estado' (double state) this guards against.
    """
    if not CAMPAIGNS_ROOT.is_dir():
        return None
    candidates: list[tuple[float, dict]] = []
    for job_file in CAMPAIGNS_ROOT.glob("*/jobs/*.json"):
        try:
            payload = json.loads(job_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if payload.get("job_type") not in ("level_b_repetitions", "level_b_real_execution"):
            continue
        if str(payload.get("status") or "").lower() in _ACTIVE_JOB_TERMINAL_STATUSES:
            continue
        candidates.append((job_file.stat().st_mtime, payload))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    # The raw file's own status can be a stale lie: a job whose thread died
    # before job_runner's heartbeat/orphan-recovery fix landed (or was never
    # read since) can sit with status="running" on disk indefinitely --
    # nothing lazily corrects it until something calls get_job() on it.
    # Confirmed live 2026-07-19: a Level A job from 2026-07-16 (updated_at:
    # None, i.e. predates that fix entirely) was still being reported as
    # "the active job" three days later by the read-raw-file-only version of
    # this function. Re-validate through get_job() (safe to call now that
    # its own cross-worker caching bug is fixed -- see job_runner.py) so a
    # dead ghost gets corrected to its real terminal status here instead of
    # silently blocking every future launch check forever.
    for _, payload in candidates:
        job_id = payload.get("job_id")
        revalidated = get_job(job_id) if job_id else None
        current = revalidated if revalidated else payload
        if str(current.get("status") or "").lower() in _ACTIVE_JOB_TERMINAL_STATUSES:
            continue
        return {
            "job_id": current.get("job_id") or job_id,
            "job_type": current.get("job_type") or payload.get("job_type"),
            "campaign_id": (current.get("meta") or payload.get("meta") or {}).get("campaign_id"),
            "status": current.get("status"),
            "current_phase": current.get("current_phase"),
            "current_phase_label": current.get("current_phase_label"),
            "current_phase_detail": current.get("current_phase_detail"),
            "started_at": current.get("started_at") or current.get("requested_at"),
            "current_case_id": current.get("current_case_id"),
            "job_path": current.get("job_path") or payload.get("job_path"),
        }
    return None


def _force_replace_active_level_b_job(active_job: dict) -> dict:
    """Force-stop a still-active Level B job and clean up the incomplete
    forensic case it left behind, so a fresh launch doesn't inherit stale
    scenario/case state alongside it.
    """
    result = {
        "stopped_job_id": active_job.get("job_id"),
        "force_stop_applied": False,
        "case_cleanup": None,
    }
    job_id = active_job.get("job_id")
    if job_id:
        stopped = request_force_stop(job_id)
        result["force_stop_applied"] = bool(stopped)
    case_id = active_job.get("current_case_id")
    if case_id:
        try:
            from .global_cleanup_service import execute_cleanup
            cleanup = execute_cleanup(
                selected_item_ids=[f"case:{case_id}"],
                confirmation="OK",
                operator="level_b_repetitions_force_replace",
            )
            result["case_cleanup"] = cleanup
        except Exception as exc:
            result["case_cleanup"] = {"error": str(exc)}
    return result


def start_level_b_repetitions_job(
    campaign_id: str,
    *,
    confirmation: str,
    requested_repetitions: int | None = None,
    requested_nested_level_a_repetitions: int | None = None,
    cleanup_old_cases: bool = False,
    detection_timeout_seconds: int | None = None,
    dfir_mode_before: str = "unknown",
    dfir_mode_after: str = "unknown",
    force_replace_active: bool = False,
    preserve_final_case: bool = True,
) -> dict:
    if str(confirmation or "").strip() != CONFIRMATION_TOKEN:
        return {"error": "confirmation_required", "message": 'Type exactly "OK" to confirm the Level B repetition batch. This launches real OT attacks, waits for real alerts, creates new forensic cases, and runs real acquisition and analysis.'}
    active_job = find_active_level_b_job()
    replaced_job_info = None
    if active_job:
        if not force_replace_active:
            return {
                "error": "active_job_running",
                "message": (
                    f"A Level B job is already running (campaign {active_job.get('campaign_id')}, "
                    f"phase '{active_job.get('current_phase_label') or active_job.get('current_phase')}', "
                    f"started {active_job.get('started_at')}). Finish or stop it before launching another one — "
                    "running two at once against the same lab scenario corrupts both. Pass force_replace_active=True "
                    "to stop it and clean up its case before launching this one."
                ),
                "active_job": active_job,
            }
        replaced_job_info = _force_replace_active_level_b_job(active_job)
        replaced_job_info["active_job"] = active_job
    manifest, config = _load_campaign(campaign_id)
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    level = str(config.get("level") or manifest.get("level") or "B").upper()
    if level != "B":
        return {"error": "not_level_b", "message": "This workflow is only defined for Level B campaigns."}
    attack_id = str(config.get("attack_id") or "").strip()
    if not attack_id:
        return {"error": "attack_profile_required", "message": "Select an OT attack profile before launching Level B repetitions."}
    if not find_attack_by_id(attack_id):
        return {"error": "attack_profile_not_found", "message": f"Attack profile not found: {attack_id}"}
    repetitions = _resolve_repetition_count(config, requested_repetitions, default=3, minimum=1)
    nested_level_a_repetitions = _resolve_nested_level_a_repetition_count(
        config,
        requested_nested_level_a_repetitions,
        requested_level_b_repetitions=repetitions,
        default=repetitions,
        minimum=1,
    )
    jobs_dir = campaign_dir(campaign_id) / "jobs"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    job = new_job(
        job_type="level_b_repetitions",
        title=f"Run Level B repetitions for {campaign_id}",
        job_path=jobs_dir / f"level-b-repetitions-{utc_now().replace(':', '').replace('+', '_')}.json",
        meta={
            "campaign_id": campaign_id,
            "level": "B",
            "attack_id": attack_id,
            "requested_repetitions": repetitions,
            "nested_level_a_repetitions": nested_level_a_repetitions,
            "replaced_active_job": replaced_job_info,
        },
    )
    timeout = int(detection_timeout_seconds or DEFAULT_DETECTION_TIMEOUT_SECONDS)
    return start_job(
        job,
        lambda job_id, job_path: _run_level_b_repetitions_job(
            job_id,
            job_path,
            campaign_id=campaign_id,
            requested_repetitions=repetitions,
            cleanup_old_cases=bool(cleanup_old_cases),
            detection_timeout_seconds=timeout,
            dfir_mode_before=str(dfir_mode_before or "unknown").strip().lower() or "unknown",
            dfir_mode_after=str(dfir_mode_after or "unknown").strip().lower() or "unknown",
            nested_level_a_repetitions=nested_level_a_repetitions,
            preserve_final_case=bool(preserve_final_case),
        ),
    )


def get_level_b_repetition_status(job_id: str) -> dict | None:
    return get_job(job_id)


def get_level_b_repetition_report(job_id: str) -> dict | None:
    payload = get_job(job_id)
    if not payload:
        return None
    report_path = payload.get("level_b_report_path")
    report_dir = payload.get("level_b_report_dir")
    if not report_path or not report_dir:
        return {"job_id": job_id, "status": payload.get("status"), "report_ready": False}
    main_path = Path.cwd() / report_path
    summary_md_path = Path.cwd() / str(payload.get("level_b_summary_markdown_path") or "")
    audit_json_path = Path.cwd() / str(payload.get("level_b_execution_audit_json_path") or "")
    audit_md_path = Path.cwd() / str(payload.get("level_b_execution_audit_markdown_path") or "")
    cleanup_manifest_path = Path.cwd() / str(payload.get("cleanup_manifest_path") or "")
    return {
        "job_id": job_id,
        "status": payload.get("status"),
        "report_ready": main_path.is_file(),
        "report_dir": report_dir,
        "report_path": report_path,
        "report_json": _json_load(main_path) or {},
        "summary_markdown": summary_md_path.read_text(encoding="utf-8") if summary_md_path.is_file() else None,
        "execution_audit_json": _json_load(audit_json_path) or {},
        "execution_audit_markdown": audit_md_path.read_text(encoding="utf-8") if audit_md_path.is_file() else None,
        "cleanup_manifest": _json_load(cleanup_manifest_path) or {},
        "generated_at": (_json_load(main_path) or {}).get("generated_at"),
    }


def cleanup_level_b_repetition_job(job_id: str, *, confirmation: str) -> dict:
    if str(confirmation or "").strip() != CONFIRMATION_TOKEN:
        return {
            "error": "confirmation_required",
            "message": 'Type exactly "OK" to delete everything created by this Level B batch job.',
        }
    payload = get_job(job_id)
    if not payload:
        return {"error": "job_not_found", "job_id": job_id}

    request_force_stop(job_id)
    meta = dict(payload.get("meta") or {})
    campaign_id = str(meta.get("campaign_id") or "").strip()
    deleted_paths: list[str] = []
    warnings: list[str] = []
    deleted_cases: list[str] = []
    deleted_executions: list[str] = []
    deleted_nested_campaigns: list[str] = []

    for item in list(payload.get("per_repetition_results") or []):
        if not isinstance(item, dict):
            continue
        execution_id = str(item.get("execution_id") or "").strip()
        case_id = str(item.get("case_id") or "").strip() or None
        case_path = str(item.get("case_path") or "").strip() or None
        nested = dict(item.get("nested_level_a") or {})
        nested_campaign_id = str(nested.get("campaign_id") or "").strip()
        if case_id or case_path:
            _remove_case_dir(case_id, case_path, deleted_paths, warnings)
            if case_id:
                deleted_cases.append(case_id)
        if execution_id and campaign_id:
            _remove_execution_dir(campaign_id, execution_id, deleted_paths, warnings)
            deleted_executions.append(execution_id)
        if nested_campaign_id:
            _best_effort_rmtree(campaign_dir(nested_campaign_id), deleted_paths, warnings)
            deleted_nested_campaigns.append(nested_campaign_id)

    report_dir_rel = str(payload.get("level_b_report_dir") or payload.get("report_output_path") or "").strip()
    if report_dir_rel:
        report_dir = (Path.cwd() / Path(report_dir_rel)).resolve()
        _best_effort_rmtree(report_dir, deleted_paths, warnings)

    runtime_dir = RUNTIME_ROOT / job_id
    _best_effort_rmtree(runtime_dir, deleted_paths, warnings)

    if campaign_id:
        _drop_latest_level_b_report_reference(campaign_id, report_dir_rel or None)

    return {
        "status": "completed" if not warnings else "completed_with_warnings",
        "job_id": job_id,
        "campaign_id": campaign_id or None,
        "deleted_cases": list(dict.fromkeys(deleted_cases)),
        "deleted_executions": list(dict.fromkeys(deleted_executions)),
        "deleted_nested_campaigns": list(dict.fromkeys(deleted_nested_campaigns)),
        "deleted_paths": list(dict.fromkeys(deleted_paths)),
        "warnings": warnings,
        "message": "Level B batch cleanup finished. The workflow artifacts created by this job were removed as far as possible.",
    }
