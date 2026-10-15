from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import campaign_config_path, campaign_dir, campaign_manifest_path, rel
from .execution_service import attach_real_case_to_execution, create_execution_from_campaign
from .job_runner import append_phase, new_job, start_job, update_job
from ..attack import ssh_launcher as attack_launcher
from ..attack.catalog import find_attack_by_id
from ..attack.executor import stream_attack_execution, stream_local_attack_execution
from ..forensics.forensics_api import (
    _active_preservation_guard,
    _clear_active_preservation_state,
    _dfir_create_case_internal,
    _dfir_ssh_user_for_role,
    _resolve_dfir_targets_from_openstack,
    acquire_disk,
    acquire_memory,
)
from ..forensics.network_context_importer import (
    import_continuous_network_context,
    initialize_volatile_first_acquisition,
    update_acquisition_profile,
)
from ..foc_reconstruction.evidence_lifecycle_dashboard import get_lifecycle_job, start_full_lifecycle_job
from ..foc_reconstruction.foc_sources import utc_now
from ..monitor.alerts_logger import run_monitor_session

# Real controlled-incident-execution orchestrator for Level B.
#
# This module is what distinguishes "Run Real Level B Execution" from the
# existing dry-run scaffold (create_execution_from_campaign, unchanged): it
# actually arms DFIR auto-acquisition, launches the selected attack, waits
# for a real detection, creates a brand-new forensic case, acquires evidence
# in volatility order, runs the real analysis/causal/executive-summary chain,
# and registers a real (non-degraded) result card -- see the approved plan
# "Level B: real controlled incident execution orchestrator" for the full
# rationale and the existing building blocks this reuses.
#
# Honest scope notes:
#  - "Arming DFIR auto" here means resolving and validating every parameter
#    the rest of the flow needs (target node, monitor node, ssh credentials,
#    attack script, expected alerts) BEFORE the attack is launched. There is
#    no separate, callable "DFIR auto-acquisition service" in this codebase
#    to invoke -- api_dfir_orchestrator_trigger() in forensics_api.py requires
#    an already-created case_dir, so it cannot run before the case exists.
#  - Disk acquisition (Kolla/libvirt) is treated as best-effort/degraded
#    rather than fatal, matching the "disk acquisition, if applicable"
#    framing already used in the approved spec -- some lab environments do
#    not expose a reachable libvirt/Kolla backend.
#  - Detection waiting reuses the exact same SSH monitor script
#    (monitor_ataques.sh) and AlertsLogger pipeline the manual "Central
#    Monitor" live dashboard already uses (via the new, Flask-free
#    run_monitor_session() helper in alerts_logger.py), instead of building a
#    new Wazuh API client.

CONFIRMATION_TOKEN = "OK"
DEFAULT_DETECTION_TIMEOUT_SECONDS = 600
DEFAULT_LIFECYCLE_POLL_SECONDS = 3.0
DEFAULT_LIFECYCLE_TIMEOUT_SECONDS = 3600
PREFERRED_TARGET_ROLE_ORDER = ["plc", "scada", "victim", "fuxa"]
ALERT_MATCH_MAX_PRE_SECONDS = 30
ALERT_MATCH_MAX_POST_SECONDS = 300


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


def _load_campaign(campaign_id: str) -> tuple[dict, dict]:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    config = _json_load(campaign_config_path(campaign_id)) or {}
    return manifest, config


def _sha256_path(path) -> str:
    if not path:
        return "not_available"
    candidate = Path(path)
    if not candidate.is_file():
        return "not_available"
    digest = hashlib.sha256()
    with candidate.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _case_id_for_case_dir(case_dir: str) -> str:
    case_path = Path(case_dir).resolve()
    for candidate in (
        case_path / "analysis" / "analysis_status.json",
        case_path / "analysis" / "forensic_analysis_report.json",
        case_path / "analysis" / "forensic_analysis_manifest.json",
        case_path / "derived" / "reconstruction" / "causal_status.json",
    ):
        payload = _json_load(candidate)
        if isinstance(payload, dict):
            value = str(payload.get("case_id") or "").strip()
            if value:
                return value

    try:
        cases_index = _json_load(Path("foc-reconstruction") / "indexes" / "cases_index.json") or {}
        for entry in list(cases_index.get("cases") or []):
            raw_path = str((entry or {}).get("path") or "").strip()
            if not raw_path:
                continue
            entry_path = (Path.cwd() / raw_path).resolve() if not Path(raw_path).is_absolute() else Path(raw_path).resolve()
            if entry_path == case_path:
                value = str((entry or {}).get("case_id") or "").strip()
                if value:
                    return value
    except Exception:
        pass

    # Fallback synthesis rule used by FOC when no richer on-disk identity is available.
    name = case_path.name
    return f"case-{hashlib.sha1(name.encode('utf-8')).hexdigest()[:8]}"


def _phase(job_id: str, job_path: Path, key: str, label: str, status: str, percent: float, detail: str | None = None) -> None:
    append_phase(job_id, job_path, phase_key=key, phase_label=label, status=status, progress_percent=percent, detail=detail)


def _fail(job_id: str, job_path: Path, phase_key: str, phase_label: str, percent: float, reason: str, final_status: str = "failed") -> None:
    _phase(job_id, job_path, phase_key, phase_label, "failed", percent, reason)
    update_job(job_id, job_path, status=final_status, finished_at=utc_now(), current_phase=phase_key, current_phase_detail=reason, progress_percent=100.0, errors=[{"message": reason}])


def _resolve_real_targets(attack: dict) -> dict:
    target_role_tokens = [str(role).strip().lower() for role in (attack.get("target_roles") or []) if str(role).strip()]
    if not target_role_tokens:
        target_role_tokens = ["victim"]
    search_tokens = sorted(set(target_role_tokens), key=lambda role: PREFERRED_TARGET_ROLE_ORDER.index(role) if role in PREFERRED_TARGET_ROLE_ORDER else 99)
    resolved = _resolve_dfir_targets_from_openstack(search_tokens + ["monitor"])
    monitor_target = next((item for item in resolved if item.get("role") == "monitor" and item.get("vm_ip")), None)
    target_candidates = [item for item in resolved if item.get("role") in target_role_tokens and item.get("vm_id") and item.get("vm_ip")]
    target_candidates.sort(key=lambda item: PREFERRED_TARGET_ROLE_ORDER.index(item["role"]) if item["role"] in PREFERRED_TARGET_ROLE_ORDER else 99)
    return {
        "target": target_candidates[0] if target_candidates else None,
        "monitor": monitor_target,
        "all_resolved": resolved,
    }


def _consume_attack_stream(generator) -> dict:
    output_dir = None
    raw_lines: list[str] = []
    for event in generator:
        if not isinstance(event, str):
            continue
        clean = event[len("data:"):].strip() if event.startswith("data:") else event.strip()
        if clean:
            raw_lines.append(clean)
        if clean.startswith("[OUTPUT DIR]"):
            output_dir = clean.replace("[OUTPUT DIR]", "", 1).strip()
    result = dict(_json_load(Path(output_dir) / "result.json") or {}) if output_dir else {}
    result["_output_dir"] = output_dir
    result["_raw_event_lines"] = raw_lines
    return result


def _resolve_injected_attack_parameters(config: dict, attack: dict) -> dict:
    """Reads `config["injected_faults"]` (see app_core/infrastructure/fault_injection)
    looking for a `modbus_payload_precision` entry for THIS attack_id.
    mode="degraded" (or no injection config at all) leaves the parameters
    empty -- byte-identical to the always-existing behavior.
    mode="fixed" passes a real, explicit `value`, the scientific control
    condition against the fault reproduced by default."""
    faults = config.get("injected_faults") or []
    for fault in faults:
        if fault.get("type") != "modbus_payload_precision":
            continue
        if fault.get("attack_id") and fault["attack_id"] != attack.get("attack_id"):
            continue
        params = fault.get("params") or {}
        if params.get("mode") == "fixed":
            value = params.get("value", 30)
            return {"value": value}
        return {}
    return {}


def _launch_attack(attack: dict, target_ip: str, target_role: str, ssh_key: str | None = None, parameters: dict | None = None) -> dict:
    # `parameters` defaults to empty -- byte-identical to the previous
    # behavior for every other caller. Verified end-to-end (2026-09-28):
    # executor.py:313 does json.dumps(payload["parameters"]) into argv[3], and
    # t0831_manipulation_of_control_modbus.py:98 itself ALREADY reads
    # params.get("value", default_attack_value) -- the plumbing for a real
    # value already existed in full, nobody ever just passed anything other
    # than {}. This is the real, reproducible root cause of the degradation
    # observed in repetition 6 of a historical Level C campaign (see
    # investigacion_y_novedad/09_inyeccion_de_fallos.md): with empty
    # parameters, the script falls back to the OpenPLC catalog's default
    # value instead of a deliberately requested one, and register/value
    # precision at the packet level is left unconfirmed.
    attacker_ip, attacker_user = attack_launcher._resolve_attacker_context("")
    if not attacker_ip:
        return {"ok": False, "reason": "No attacker instance with a floating IP was found."}
    server, image_name, victim_user = attack_launcher._resolve_target_context(target_ip, "")
    local_script = os.path.join(attack_launcher.SCRIPTS_DIR, attack["script"])
    if not os.path.exists(local_script):
        return {"ok": False, "reason": f"Backend attack script not found: {attack['script']}"}

    stream_payload = {
        "attack_id": attack["attack_id"],
        "target_ip": target_ip,
        "target_role": target_role,
        "attacker_ip": attacker_ip,
        "case_dir": "",
        "parameters": parameters or {},
    }

    if attack.get("execution_backend") == "local":
        generator = stream_local_attack_execution(
            attack=attack,
            local_script=local_script,
            attacker_ip=attacker_ip,
            attacker_user=attacker_user,
            target_user=victim_user,
            target_image=image_name,
            payload=stream_payload,
        )
    else:
        generator = stream_attack_execution(
            manager=attack_launcher.manager,
            attack=attack,
            local_script=local_script,
            attacker_ip=attacker_ip,
            attacker_user=attacker_user,
            target_user=victim_user,
            target_image=image_name,
            payload=stream_payload,
        )

    result = _consume_attack_stream(generator)
    result["ok"] = bool(result.get("success"))
    result["attacker_ip"] = attacker_ip
    result["attacker_user"] = attacker_user
    result["local_script"] = local_script
    return result


def _parse_alert_dt(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
        if len(raw) >= 5 and raw[-5] in {"+", "-"} and raw[-3] != ":":
            raw = raw[:-2] + ":" + raw[-2:]
        return datetime.fromisoformat(raw).astimezone(timezone.utc)
    except Exception:
        return None


def _alert_candidate_dts(alert_payload: dict) -> list[datetime]:
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
        dt = _parse_alert_dt(raw_value)
        if not dt:
            continue
        key = dt.isoformat()
        if key in seen:
            continue
        seen.add(key)
        candidates.append(dt)
    return candidates


def _best_alert_dt(
    alert_payload: dict,
    *,
    attack_started_utc: str | None = None,
    attack_completed_utc: str | None = None,
    max_pre_seconds: int = ALERT_MATCH_MAX_PRE_SECONDS,
    max_post_seconds: int = ALERT_MATCH_MAX_POST_SECONDS,
) -> datetime | None:
    candidates = _alert_candidate_dts(alert_payload)
    if not candidates:
        return None
    attack_started_dt = _parse_alert_dt(attack_started_utc)
    attack_completed_dt = _parse_alert_dt(attack_completed_utc) or attack_started_dt
    if not attack_started_dt or not attack_completed_dt:
        return candidates[0]
    earliest = attack_started_dt - timedelta(seconds=int(max_pre_seconds))
    latest = attack_completed_dt + timedelta(seconds=int(max_post_seconds))
    in_window = [dt for dt in candidates if earliest <= dt <= latest]
    if in_window:
        return min(in_window, key=lambda dt: abs((dt - attack_completed_dt).total_seconds()))
    return min(candidates, key=lambda dt: abs((dt - attack_completed_dt).total_seconds()))


def _alert_is_within_attack_window(
    alert_payload: dict,
    *,
    attack_started_utc: str | None = None,
    attack_completed_utc: str | None = None,
    max_pre_seconds: int = ALERT_MATCH_MAX_PRE_SECONDS,
    max_post_seconds: int = ALERT_MATCH_MAX_POST_SECONDS,
) -> bool:
    if not attack_started_utc and not attack_completed_utc:
        return True
    attack_started_dt = _parse_alert_dt(attack_started_utc)
    attack_completed_dt = _parse_alert_dt(attack_completed_utc) or attack_started_dt
    alert_dt = _best_alert_dt(
        alert_payload,
        attack_started_utc=attack_started_utc,
        attack_completed_utc=attack_completed_utc,
        max_pre_seconds=max_pre_seconds,
        max_post_seconds=max_post_seconds,
    )
    if not alert_dt or not attack_started_dt or not attack_completed_dt:
        return False
    earliest = attack_started_dt - timedelta(seconds=int(max_pre_seconds))
    latest = attack_completed_dt + timedelta(seconds=int(max_post_seconds))
    return earliest <= alert_dt <= latest


def _build_alert_matcher(
    attack: dict,
    *,
    attack_started_utc: str | None = None,
    attack_completed_utc: str | None = None,
):
    expected_alert_tokens = {
        str(item).strip().lower().replace("_", " ")
        for item in (attack.get("expected_alerts") or [])
        if str(item).strip()
    }
    attack_mitre = str(attack.get("mitre_id") or "").strip().upper()

    def matcher(out: dict) -> bool:
        triage = out.get("triage") or {}
        primary = out.get("primary") or {}
        if triage.get("severity") not in {"HIGH", "CRITICAL"} or not triage.get("recommend_forensics"):
            return False
        if not _alert_is_within_attack_window(
            out,
            attack_started_utc=attack_started_utc,
            attack_completed_utc=attack_completed_utc,
        ):
            return False
        raw = primary.get("raw") or {}
        raw_data = raw.get("data") or {}
        raw_alert = raw_data.get("alert") or {}
        haystack = " ".join(
            [
                str(primary.get("signature") or ""),
                str(primary.get("alert_type") or ""),
                str(primary.get("description") or ""),
                str(primary.get("rule_id") or ""),
                str(raw_alert.get("signature") or ""),
                str(raw_alert.get("signature_id") or ""),
                json.dumps(raw_alert.get("metadata") or {}, ensure_ascii=False),
            ]
        ).lower()
        if expected_alert_tokens and any(token in haystack for token in expected_alert_tokens):
            return True
        raw_mitre = raw.get("mitre_mapping")
        if attack_mitre and (
            (isinstance(raw_mitre, str) and attack_mitre in raw_mitre.upper())
            or (isinstance(raw_mitre, list) and any(attack_mitre in str(item or "").upper() for item in raw_mitre))
        ):
            return True
        return "modbus" in haystack and any(token in haystack for token in ["write", "register", "control"])

    return matcher


def _wait_for_lifecycle_job(job_id: str, *, timeout_seconds: float = DEFAULT_LIFECYCLE_TIMEOUT_SECONDS, poll_seconds: float = DEFAULT_LIFECYCLE_POLL_SECONDS) -> dict:
    deadline = time.time() + timeout_seconds
    last = {"status": "unknown"}
    while time.time() < deadline:
        payload = get_lifecycle_job(job_id)
        if isinstance(payload, dict):
            last = payload
            if str(payload.get("status")) not in {"queued", "running"}:
                return payload
        time.sleep(poll_seconds)
    last["status"] = last.get("status") or "timeout"
    return last


def start_real_level_b_execution_job(campaign_id: str, *, confirmation: str, detection_timeout_seconds: int | None = None, overrides: dict | None = None) -> dict:
    """
    Entry point backing the "Run Real Level B Execution" UI action. Requires
    confirmation == "OK", the same explicit-typed-confirmation convention
    already used by retention_service.delete_generated_case_artifacts and
    scenario_destruction_service.destroy_full_scenario, since this launches a
    real attack against real lab infrastructure and performs real evidence
    acquisition.
    """
    if str(confirmation or "").strip() != CONFIRMATION_TOKEN:
        return {"error": "confirmation_required", "message": 'Type exactly "OK" to confirm a real Level B execution. This will launch a real attack, wait for a real alert, and create a new forensic case.'}

    manifest, config = _load_campaign(campaign_id)
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    level = str(config.get("level") or manifest.get("level") or "B").upper()
    if level != "B":
        return {"error": "not_level_b", "message": "Real controlled incident execution is only defined for Level B campaigns."}

    attack_id = str(config.get("attack_id") or "").strip()
    if not attack_id:
        return {"error": "attack_profile_required", "message": "Select an attack profile for this campaign before running a real Level B execution."}
    attack = find_attack_by_id(attack_id)
    if not attack:
        return {"error": "attack_profile_not_found", "attack_id": attack_id}

    overrides = dict(overrides or {})
    resolved_timeout = int(detection_timeout_seconds or overrides.get("detection_timeout_seconds") or DEFAULT_DETECTION_TIMEOUT_SECONDS)

    job = new_job(
        job_type="level_b_real_execution",
        title=f"Run real Level B execution for {campaign_id}",
        job_path=campaign_dir(campaign_id) / "jobs" / f"job-{uuid.uuid4().hex[:8]}.json",
        meta={"campaign_id": campaign_id, "level": level, "attack_id": attack_id},
    )

    def runner(job_id: str, job_path: Path) -> None:
        _run_real_level_b_execution(job_id, job_path, campaign_id, config, attack, resolved_timeout)

    return start_job(job, runner)


def _run_real_level_b_execution(job_id: str, job_path: Path, campaign_id: str, config: dict, attack: dict, detection_timeout_seconds: int) -> None:
    # Step 1 -- execution_workspace_created. Reuses the existing dry-run
    # scaffold builder verbatim: it creates EXEC-NNNN, execution_manifest.json,
    # execution_plan.json, ground_truth_seal.json, etc. with no case_bundle,
    # exactly like "Run Dry-Run Execution" does today.
    _phase(job_id, job_path, "execution_workspace_created", "Create execution workspace", "running", 2.0, "Creating the execution workspace and planning artifacts.")
    scaffold = create_execution_from_campaign(campaign_id, overrides={})
    execution_id = scaffold["execution_id"]
    update_job(job_id, job_path, meta={"campaign_id": campaign_id, "execution_id": execution_id, "attack_id": attack.get("attack_id")})
    _phase(job_id, job_path, "execution_workspace_created", "Create execution workspace", "completed", 5.0, f"Execution workspace {execution_id} created.")

    # Step 2 -- scenario_validated. Resolves the real target node (matching
    # the attack's allowed target_roles) and the monitor node via the same
    # OpenStack name-fuzzy-match helper the manual DFIR auto-acquisition route
    # already uses.
    _phase(job_id, job_path, "scenario_validated", "Validate scenario and resolve targets", "running", 8.0, "Resolving target and monitor nodes from OpenStack.")
    try:
        targets = _resolve_real_targets(attack)
    except Exception as exc:
        reason = f"DFIR auto-acquisition could not be armed. OpenStack target resolution failed: {exc}"
        _fail(job_id, job_path, "scenario_validated", "Validate scenario and resolve targets", 10.0, reason, final_status="blocked_before_attack")
        return
    target = targets.get("target")
    monitor = targets.get("monitor")
    if not target or not monitor:
        reason = "DFIR auto-acquisition could not be armed. Could not resolve a real target node and monitor node in OpenStack for this attack's target roles."
        _fail(job_id, job_path, "scenario_validated", "Validate scenario and resolve targets", 10.0, reason, final_status="blocked_before_attack")
        return
    _phase(job_id, job_path, "scenario_validated", "Validate scenario and resolve targets", "completed", 12.0, f"Resolved target {target.get('vm_name')} ({target.get('vm_ip')}) and monitor {monitor.get('vm_name')} ({monitor.get('vm_ip')}).")

    # Step 3 -- attack_profile_validated.
    _phase(job_id, job_path, "attack_profile_validated", "Validate attack profile", "running", 14.0)
    local_script = os.path.join(attack_launcher.SCRIPTS_DIR, attack.get("script") or "")
    if not attack.get("script") or not os.path.exists(local_script):
        reason = f"Attack script not found for {attack.get('attack_id')}: {attack.get('script')}"
        _fail(job_id, job_path, "attack_profile_validated", "Validate attack profile", 14.0, reason, final_status="blocked_before_attack")
        return
    attack_script_sha256 = _sha256_path(local_script)
    _phase(job_id, job_path, "attack_profile_validated", "Validate attack profile", "completed", 16.0, f"Attack script resolved: {attack.get('script')} (sha256={attack_script_sha256[:12]}...).")

    # Step 4 -- dfir_auto_armed. There is no separate callable "arm" service
    # in this codebase (api_dfir_orchestrator_trigger requires a pre-existing
    # case_dir), so arming means: every parameter the rest of this flow needs
    # is now resolved and validated. ssh_key resolution mirrors the existing
    # NICS_DFIR_SSH_KEY / ~/.ssh/my_key convention used by the manual DFIR
    # auto-acquisition route.
    _phase(job_id, job_path, "dfir_auto_armed", "Arm DFIR auto-acquisition", "running", 18.0)
    ssh_key = os.environ.get("NICS_DFIR_SSH_KEY") or os.path.expanduser("~/.ssh/my_key")
    if not os.path.isfile(ssh_key):
        reason = "DFIR auto-acquisition could not be armed."
        _fail(job_id, job_path, "dfir_auto_armed", "Arm DFIR auto-acquisition", 18.0, f"{reason} (ssh_key not found: {ssh_key})", final_status="blocked_before_attack")
        return
    target_ssh_user = _dfir_ssh_user_for_role(target.get("role"))
    armed_context = {
        "campaign_id": campaign_id,
        "execution_id": execution_id,
        "attack_id": attack.get("attack_id"),
        "target": target,
        "monitor": monitor,
        "ssh_key": ssh_key,
        "target_ssh_user": target_ssh_user,
        "expected_alerts": attack.get("expected_alerts") or [],
        "attack_script_sha256": attack_script_sha256,
    }
    _phase(job_id, job_path, "dfir_auto_armed", "Arm DFIR auto-acquisition", "completed", 20.0, "DFIR auto-acquisition armed: target, monitor, credentials, and detection criteria resolved.")

    # Step 5/6 -- attack_launched / attack_completed.
    _phase(job_id, job_path, "attack_launched", "Launch comparable attack", "running", 22.0, f"Launching {attack.get('attack_id')} against {target.get('vm_ip')}.")
    attack_started_utc = utc_now()
    attack_parameters = _resolve_injected_attack_parameters(config, attack)
    attack_result = _launch_attack(attack, target.get("vm_ip"), target.get("role"), ssh_key=ssh_key, parameters=attack_parameters)
    attack_completed_utc = utc_now()
    if not attack_result.get("ok"):
        reason = attack_result.get("reason") or "Attack execution did not complete successfully."
        _fail(job_id, job_path, "attack_launched", "Launch comparable attack", 24.0, reason, final_status="blocked_before_attack")
        return
    _phase(job_id, job_path, "attack_completed", "Attack completed", "completed", 28.0, f"Attack {attack.get('attack_id')} completed (exit_code={attack_result.get('exit_code')}).")

    # Step 7 -- detection_waiting -> detection_observed / failed_detection.
    _phase(job_id, job_path, "detection_waiting", "Wait for real detection", "running", 30.0, f"Watching {monitor.get('vm_ip')} for an alert matching this attack for up to {detection_timeout_seconds}s.")
    matcher = _build_alert_matcher(
        attack,
        attack_started_utc=attack_started_utc,
        attack_completed_utc=attack_completed_utc,
    )
    session = run_monitor_session(
        monitor.get("vm_ip"),
        ssh_user="ubuntu",
        ssh_key=ssh_key,
        on_alert=matcher,
        stop_after_seconds=detection_timeout_seconds,
    )
    if session.get("status") != "matched":
        reason = "No alert matching this attack's detection criteria was observed within the configured timeout. The execution is not marked successful; no forensic case was created."
        _fail(job_id, job_path, "detection_waiting", "Wait for real detection", 32.0, reason, final_status="failed_detection")
        return
    matched_alert = session.get("matched_alert") or {}
    _phase(job_id, job_path, "detection_observed", "Detection observed", "completed", 35.0, f"Matched alert event_id={((matched_alert.get('primary') or {}).get('event_id'))} severity={((matched_alert.get('triage') or {}).get('severity'))}.")
    _phase(job_id, job_path, "trigger_selected", "Trigger selected", "completed", 37.0, "Highest-severity matching alert selected as the acquisition trigger.")

    # Step 8 -- forensic_case_created. Always a brand-new case; never reuses
    # or links a previous case as evidence.
    _phase(job_id, job_path, "forensic_case_created", "Create new forensic case", "running", 40.0)
    preservation_guard = _active_preservation_guard()
    if not preservation_guard.get("allowed"):
        reason = (
            f"{preservation_guard.get('reason')} "
            f"Current preservation case: {preservation_guard.get('case_id') or 'not_available'}."
        )
        _fail(job_id, job_path, "forensic_case_created", "Create new forensic case", 40.0, reason, final_status="blocked_active_preservation")
        return
    try:
        case_dir = _dfir_create_case_internal(run_id=execution_id, source="level_b_orchestrator")
    except RuntimeError as exc:
        _fail(job_id, job_path, "forensic_case_created", "Create new forensic case", 40.0, str(exc), final_status="blocked_active_preservation")
        return
    case_id = _case_id_for_case_dir(case_dir)
    _phase(job_id, job_path, "forensic_case_created", "Create new forensic case", "completed", 42.0, f"Created {case_id} at {case_dir}.")
    trigger_time_utc = (
        ((matched_alert.get("primary") or {}).get("ts_utc"))
        or ((matched_alert.get("primary") or {}).get("timestamp"))
        or attack_completed_utc
    )
    initialize_volatile_first_acquisition(
        case_dir,
        run_id=execution_id,
        case_created_utc=utc_now(),
        acquisition_started_utc=utc_now(),
        trigger_time_utc=trigger_time_utc,
    )

    # Step 9 -- acquisition in strict volatility order: memory, network
    # (relevant buffer segment only), disk (best-effort/degraded).
    _phase(job_id, job_path, "memory_acquisition_started", "Acquire memory (LiME)", "running", 45.0)
    update_acquisition_profile(case_dir, run_id=execution_id, merge_fields={"memory_started_utc": utc_now()})
    memory_result = acquire_memory(case_dir, target.get("vm_id"), target.get("vm_ip"), ssh_key, ssh_user=target_ssh_user, mode="build", run_id=execution_id)
    update_acquisition_profile(case_dir, run_id=execution_id, merge_fields={"memory_completed_utc": utc_now()})
    if memory_result.get("ok"):
        _phase(job_id, job_path, "memory_acquisition_completed", "Memory acquisition completed", "completed", 55.0, f"Memory image preserved: {memory_result.get('mem_dump')}.")
    else:
        _phase(job_id, job_path, "memory_acquisition_completed", "Memory acquisition completed", "completed_with_degradation", 55.0, memory_result.get("error") or memory_result.get("stderr") or "Memory acquisition failed.")

    _phase(job_id, job_path, "network_context_import_started", "Import network context", "running", 58.0, "Importing only the rolling PCAP segments that overlap the case window, without delaying RAM acquisition.")
    try:
        traffic_result = import_continuous_network_context(
            case_dir,
            run_id=execution_id,
            trigger_time_utc=trigger_time_utc,
            acquisition_started_utc=None,
            memory_started_utc=None,
            memory_completed_utc=None,
        )
        _phase(
            job_id,
            job_path,
            "network_context_import_completed",
            "Network context import completed",
            "completed",
            63.0,
            f"Imported {traffic_result.get('preserved_segments')} preserved segment(s); {traffic_result.get('pending_segments')} segment(s) remain pending rotation closure.",
        )
    except Exception as exc:
        _phase(job_id, job_path, "network_context_import_completed", "Network context import completed", "completed_with_degradation", 63.0, f"Network context import failed: {exc}")

    _phase(job_id, job_path, "disk_acquisition_started", "Acquire disk (Kolla/libvirt)", "running", 66.0)
    update_acquisition_profile(case_dir, run_id=execution_id, merge_fields={"disk_started_utc": utc_now()})
    disk_result = acquire_disk(case_dir, target.get("vm_id"), "nova_libvirt", run_id=execution_id, noninteractive=True)
    if disk_result.get("ok"):
        _phase(job_id, job_path, "disk_acquisition_completed", "Disk acquisition completed", "completed", 72.0, f"Disk image preserved: {disk_result.get('disk_raw')}.")
    else:
        _phase(job_id, job_path, "disk_acquisition_completed", "Disk acquisition completed", "completed_with_degradation", 72.0, disk_result.get("error") or disk_result.get("stderr") or "Disk acquisition was not available in this environment (treated as degraded, not fatal, per the disk-acquisition-if-applicable policy).")

    _phase(job_id, job_path, "preservation_completed", "Preservation completed", "completed", 74.0, "Chain-of-custody entries were appended by each acquisition step.")
    _clear_active_preservation_state(case_dir, run_id=execution_id, final_state="completed", reason="preservation_completed_for_level_b_execution")

    # Step 10 -- multilayer analysis, FOC/causal reconstruction, executive
    # summary. Reuses the existing single-call chain instead of orchestrating
    # time-sync/analysis/causal/summary separately.
    _phase(job_id, job_path, "multilayer_analysis_started", "Run multilayer analysis and reconstruction", "running", 76.0)
    lifecycle_job = start_full_lifecycle_job(case_id, force_analysis=True, strict=False, degraded_ok=True)
    if lifecycle_job.get("error"):
        reason = f"Could not start the analysis/reconstruction lifecycle: {lifecycle_job.get('error')}"
        _fail(job_id, job_path, "multilayer_analysis_started", "Run multilayer analysis and reconstruction", 76.0, reason)
        return
    lifecycle_result = _wait_for_lifecycle_job(lifecycle_job.get("job_id"))
    lifecycle_status = str(lifecycle_result.get("status") or "unknown")
    if lifecycle_status == "failed":
        reason = "; ".join(str(item) for item in (lifecycle_result.get("errors") or []) if item) or "Multilayer analysis/reconstruction failed."
        _fail(job_id, job_path, "multilayer_analysis_started", "Run multilayer analysis and reconstruction", 80.0, reason)
        return
    degraded_analysis = lifecycle_status == "completed_with_degradation"
    _phase(job_id, job_path, "multilayer_analysis_completed", "Multilayer analysis completed", "completed_with_degradation" if degraded_analysis else "completed", 85.0, "; ".join(str(item) for item in (lifecycle_result.get("warnings") or [])) or None)
    _phase(job_id, job_path, "foc_reconstruction_completed", "FOC reconstruction completed", "completed", 88.0)
    _phase(job_id, job_path, "causal_reconstruction_completed", "Causal reconstruction completed", "completed_with_degradation" if degraded_analysis else "completed", 90.0)
    _phase(job_id, job_path, "executive_summary_generated", "Executive lifecycle summary generated", "completed", 92.0)

    # Step 11 -- comparison_profile_generated / forensic_result_card_registered.
    # Reuses build_execution_profiles() (via attach_real_case_to_execution)
    # exactly as the dry-run path does, but against the real case_bundle, and
    # with the real attack metadata this orchestrator captured first-hand
    # (rather than whatever the global, possibly-stale attack_attestation.json
    # would have inferred).
    _phase(job_id, job_path, "comparison_profile_generated", "Generate comparison profile and result card", "running", 94.0)
    attack_record_override = {
        "attack_id": attack.get("attack_id"),
        "mitre": {"technique_id": attack.get("mitre_id"), "technique_name": attack.get("mitre_technique")},
        "operation": {
            "tool_used": attack.get("script"),
            "tool_version": "not_available",
            "protocol": "modbus" if "modbus" in str(attack.get("category") or "").lower() or "modbus" in str(attack.get("attack_id") or "").lower() else "not_available",
            "modbus_function": "not_available",
        },
        "execution": {"started_at": attack_started_utc, "completed_at": attack_completed_utc},
        "source_reference": local_script,
    }
    real_stage_overrides = {
        "environment_deployed": {"status": "completed", "reason": "scenario targets were resolved live from OpenStack for this real execution"},
        "tools_installed_or_validated": {"status": "completed", "reason": "target and monitor nodes were validated live before the attack was launched"},
        "attack_executed": {"status": "completed", "reason": f"attack {attack.get('attack_id')} was launched and completed by level_b_orchestrator"},
        "detection_observed": {"status": "completed", "reason": "a real alert matching this attack's detection criteria was observed by the live monitor session"},
        "trigger_selected": {"status": "completed", "reason": "the matching alert was selected as the acquisition trigger"},
        "acquisition_executed": {"status": "completed" if (memory_result.get("ok") or disk_result.get("ok")) else "completed_with_degradation", "reason": "memory/network/disk acquisition was executed against the real target node"},
        "evidence_preserved": {"status": "completed", "reason": "acquisition scripts appended chain-of-custody entries for each preserved artifact"},
    }
    attach_result = attach_real_case_to_execution(
        campaign_id,
        execution_id,
        case_id=case_id,
        attack_record_override=attack_record_override,
        stage_overrides=real_stage_overrides,
    )
    _phase(job_id, job_path, "forensic_result_card_registered", "Result card registered", "completed", 99.0, f"Registered result card for case {case_id} (comparison_family_id={attach_result.get('comparison_family_id')}).")

    final_status = "completed_with_degradation" if (degraded_analysis or not disk_result.get("ok") or not memory_result.get("ok")) else "completed"
    update_job(
        job_id,
        job_path,
        status=final_status,
        finished_at=utc_now(),
        current_phase="forensic_result_card_registered",
        current_phase_label="Result card registered",
        progress_percent=100.0,
        meta={
            "campaign_id": campaign_id,
            "execution_id": execution_id,
            "case_id": case_id,
            "case_dir": rel(Path(case_dir)),
            "attack_id": attack.get("attack_id"),
            "comparison_family_id": attach_result.get("comparison_family_id"),
        },
        generated_artifacts=list((attach_result.get("artifacts") or {}).values()),
    )
