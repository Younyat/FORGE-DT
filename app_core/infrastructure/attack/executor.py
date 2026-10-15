from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app_core.infrastructure.attack.catalog import find_attack_by_id


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def slugify_attack_id(attack_id: str) -> str:
    return (
        str(attack_id or "attack")
        .replace(".", "_")
        .replace("/", "_")
        .replace(" ", "_")
    )


def get_output_dir(attack_id: str, case_dir: str = "") -> str:
    root = case_dir or OUTPUTS_DIR
    ensure_dir(root)
    return ensure_dir(os.path.join(root, f"{utc_timestamp()}_{slugify_attack_id(attack_id)}"))


def severity_requires_dfir(severity: str) -> bool:
    return str(severity or "").upper() in {"HIGH", "CRITICAL"}


def build_execution_result(
    attack: Dict[str, Any],
    payload: Dict[str, Any],
    attacker_ip: str,
    target_user: str,
    target_image: str,
    output_dir: str,
) -> Dict[str, Any]:
    return {
        "attack_id": attack["attack_id"],
        "display_name": attack["display_name"],
        "mitre_id": attack["mitre_id"],
        "mitre_technique": attack["mitre_technique"],
        "mitre_domain": attack["mitre_domain"],
        "tactic": attack["tactic"],
        "detection_engine": attack["detection_engine"],
        "severity": attack["severity"],
        "execution_mode": attack["execution_mode"],
        "requested_target_ip": payload.get("target_ip") or payload.get("target"),
        "requested_target_role": payload.get("target_role", ""),
        "target_ip": payload.get("target_ip") or payload.get("target"),
        "target_role": payload.get("target_role", ""),
        "effective_target_ip": payload.get("target_ip") or payload.get("target"),
        "effective_target_role": payload.get("target_role", ""),
        "target_user": target_user,
        "target_image": target_image,
        "attacker_ip": attacker_ip,
        "case_dir": payload.get("case_dir", ""),
        "parameters": payload.get("parameters", {}) or {},
        "expected_alerts": attack.get("expected_alerts", []),
        "expected_artifacts": attack.get("expected_artifacts", []),
        "rollback_required": bool(attack.get("rollback_required")),
        "dfir_escalation": bool(attack.get("dfir_escalation") or severity_requires_dfir(attack.get("severity"))),
        "safety_policy": attack.get("safety_policy", ""),
        "output_dir": output_dir,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "stdout": [],
        "stderr": [],
        "timeline_event": {
            "event_type": "attack_execution",
            "severity": attack.get("severity", "LOW"),
            "dfir_relevant": bool(attack.get("dfir_escalation") or severity_requires_dfir(attack.get("severity"))),
        },
        "chain_of_custody": [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "attack_execution_started",
                "operator": "dashboard_tactical_hud",
                "artifact": "result.json",
            }
        ],
    }


def _normalize_target_role(role: str) -> str:
    role_map = {
        "industrial_plc": "plc",
        "industrial_scada": "scada",
    }
    normalized = str(role or "").strip().lower()
    return role_map.get(normalized, normalized)


def _load_effective_target_metadata(output_dir: str) -> Dict[str, Any]:
    scenario_chain = Path(output_dir) / "scenario_attack_chain.json"
    if not scenario_chain.is_file():
        return {}
    try:
        payload = json.loads(scenario_chain.read_text(encoding="utf-8"))
    except Exception:
        return {}
    target_ip = payload.get("effective_target_ip") or payload.get("target_ip")
    target_role = payload.get("effective_target_role") or payload.get("target_role")
    requested_ip = payload.get("requested_target_ip")
    requested_role = payload.get("requested_target_role")
    return {
        "requested_target_ip": requested_ip,
        "requested_target_role": _normalize_target_role(requested_role),
        "effective_target_ip": target_ip,
        "effective_target_role": _normalize_target_role(target_role),
    }


def _notify_intervention_ledger(output_dir: str, result: Dict[str, Any]) -> None:
    """M1 (Intervention Ledger, investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md):
    projects this real attack execution into the shared, hash-chained
    ledger -- same adapter principle as fault_injection's own
    _notify_intervention_ledger, an adapter over an already-real record,
    never a second source of truth (source_record_ref points at this exact
    execution's own result.json). intervention_id reuses output_dir's own
    basename (executor.py's own `{utc_timestamp()}_{slugify_attack_id}`,
    already a stable, unique-per-execution identifier -- no new ID scheme
    invented). Best-effort: never allowed to affect a real attack
    execution."""
    try:
        from app_core.infrastructure.intervention_ledger.service import record_intervention
        from app_core.infrastructure.attack.effect_verifiers import verify_attack_effect
        case_dir = result.get("case_dir") or ""
        # M2: real, content-based effect verification (see effect_verifiers.py)
        # -- replaces the earlier placeholder of just exit_code/success,
        # which the study's own baseline audit flagged as insufficient
        # ("no se deduce sólo del exit code", section 8.1 step 3).
        verification = verify_attack_effect(result.get("attack_id"), result, output_dir)
        record_intervention(
            source="attack_lab",
            source_record_ref=os.path.join(output_dir, "result.json"),
            class_="cyberattack",
            type_=result.get("attack_id"),
            phase="executed",
            intervention_id=f"atk-{Path(output_dir).name}",
            target_ip=result.get("effective_target_ip") or result.get("target_ip"),
            case_id=os.path.basename(case_dir.rstrip("/")) if case_dir else None,
            params=result.get("parameters"),
            requested_at=result.get("started_at"),
            applied_at=result.get("started_at"),
            effect_verified_at=result.get("completed_at"),
            effect_verification=verification,
        )
    except Exception:
        pass


def _resolve_node_id_for_ip(target_ip: str | None) -> Optional[str]:
    if not target_ip:
        return None
    from app_core.infrastructure.intervention_ledger.linker import _resolve_node_id_for_entry
    return _resolve_node_id_for_entry({"target_ip": target_ip})


def _start_twin_followup_window(result: Dict[str, Any]) -> None:
    """Real gap measured this session (TOR=0.0 for source=attack_lab,
    see intervention_ledger/README.md's "Open gap" note on linker.py):
    unlike fault_injection (FAULT_RELEVANT_CHECKS), an Attack Lab execution
    never triggered any forensic_twin follow-up on its own, so a real
    divergence it caused could sit unnoticed until the continuous monitor's
    next heavy tick. Fixed with the SAME real M3 experimental window
    mechanism built for exactly this purpose -- started here, unconditionally
    for every attack (never keyed by attack_id/type, so it cannot leak which
    attack is running, only that some attack just started, same as any
    other M3 window). Best-effort: a window failing to start must never
    affect the real attack execution."""
    try:
        node_id = _resolve_node_id_for_ip(result.get("target_ip") or result.get("requested_target_ip"))
        if not node_id:
            return
        from app_core.infrastructure.forensic_twin.experimental_window import start_experimental_window
        start_experimental_window([node_id], sensors=["resources", "network_latency"], interval_seconds=10.0, duration_seconds=180.0)
    except Exception:
        pass


def _trigger_twin_followup_check(result: Dict[str, Any]) -> None:
    """The other half of the same fix: resources/network_latency are cheap
    enough for the repeating M3 window above, but clock/PLC/config_integrity/
    network_exposure are deliberately NOT (experimental_window.py's own
    docstring: "heavy, on-demand-only"). The sanctioned way to cover those
    is a single on-demand check_node_state call -- exactly what
    fault_injection's FAULT_RELEVANT_CHECKS already does per-fault, done
    here unconditionally per-attack instead (same non-leaking reasoning as
    the window above). This is what actually catches a real
    plc_baseline_divergence from an attack like T0831 (Modbus
    manipulation) -- the window's two allowed sensors never would."""
    try:
        node_id = _resolve_node_id_for_ip(result.get("effective_target_ip") or result.get("target_ip"))
        if not node_id:
            return
        from app_core.infrastructure.forensic_twin import service as ft
        ft.check_node_state(node_id, source="attack_lab_followup")
    except Exception:
        pass


def persist_execution_result(output_dir: str, result: Dict[str, Any]) -> None:
    ensure_dir(output_dir)
    with open(os.path.join(output_dir, "result.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    # Only the FINAL persist (after the attack actually ran) has
    # completed_at -- the initial persist (written before execution, see
    # the two call sites above each pair) deliberately does not trigger a
    # ledger entry, since nothing happened yet to record.
    if result.get("completed_at"):
        _notify_intervention_ledger(output_dir, result)
        _trigger_twin_followup_check(result)
    else:
        _start_twin_followup_window(result)


def _collect_generated_artifacts(output_dir: str) -> list[dict]:
    base = Path(output_dir)
    artifacts: list[dict] = []
    if not base.is_dir():
        return artifacts
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.name == "result.json":
            continue
        sha256 = None
        try:
            import hashlib

            h = hashlib.sha256()
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        except Exception:
            sha256 = None
        artifacts.append(
            {
                "path": str(path.relative_to(base)).replace("\\", "/"),
                "size": path.stat().st_size,
                "sha256": sha256,
            }
        )
    return artifacts


def _python_invocation(local_script: str) -> list[str]:
    path = Path(local_script).resolve()
    try:
        project_root = Path(BASE_DIR).parent.parent.parent.resolve()
        rel = path.relative_to(project_root)
        module = ".".join(rel.with_suffix("").parts)
        return [sys.executable, "-m", module]
    except Exception:
        return [sys.executable, local_script]


def _safe_notify_foc(event_type: str, payload: Dict[str, Any]) -> None:
    try:
        from app_core.infrastructure.foc_reconstruction import safe_notify_foc

        safe_notify_foc(event_type, payload)
    except Exception:
        return


def stream_attack_execution(
    manager: Any,
    attack: Dict[str, Any],
    local_script: str,
    attacker_ip: str,
    attacker_user: str,
    target_user: str,
    target_image: str,
    payload: Dict[str, Any],
) -> Iterable[str]:
    output_dir = get_output_dir(attack["attack_id"], payload.get("case_dir", ""))
    result = build_execution_result(
        attack=attack,
        payload=payload,
        attacker_ip=attacker_ip,
        target_user=target_user,
        target_image=target_image,
        output_dir=output_dir,
    )
    persist_execution_result(output_dir, result)
    _safe_notify_foc(
        "attack_executed",
        {
            "attack_id": result.get("attack_id"),
            "display_name": result.get("display_name"),
            "mitre_id": result.get("mitre_id"),
            "target_ip": result.get("target_ip"),
            "target_role": result.get("target_role"),
            "output_dir": output_dir,
            "started_at": result.get("started_at"),
        },
    )

    args: List[str] = [
        payload.get("target_ip") or payload.get("target") or "",
        target_user,
        json.dumps(payload.get("parameters", {}) or {}, separators=(",", ":")),
        output_dir,
    ]

    exit_code: Optional[int] = None
    raw_lines: List[str] = []

    yield f"data: [ATTACK PROFILE] {attack['attack_id']} | {attack['mitre_id']} | {attack['mitre_technique']}\n\n"
    yield f"data: [DETECTION ENGINE] {attack['detection_engine']}\n\n"
    yield f"data: [EXECUTION MODE] {attack['execution_mode']}\n\n"
    yield f"data: [OUTPUT DIR] {output_dir}\n\n"

    for event in manager.execute_remote_stream(attacker_ip, attacker_user, local_script, args):
        if event.startswith("data:"):
            clean = event.replace("data:", "", 1).strip()
            raw_lines.append(clean)
            if clean.startswith("[EXIT CODE]"):
                try:
                    exit_code = int(clean.replace("[EXIT CODE]", "", 1).strip())
                except ValueError:
                    exit_code = 1
            elif clean.startswith("[SSH ERROR]") or clean.startswith("[FAIL]"):
                result["stderr"].append(clean)
            elif clean:
                result["stdout"].append(clean)
        yield event

    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    result["exit_code"] = exit_code if exit_code is not None else 1
    result["success"] = result["exit_code"] == 0 and not result["stderr"]
    result["raw_event_stream"] = raw_lines
    result["forensic_case_event"] = result["dfir_escalation"]
    result["chain_of_custody"].append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "attack_execution_completed",
            "operator": "dashboard_tactical_hud",
            "artifact": "result.json",
        }
    )
    persist_execution_result(output_dir, result)
    _safe_notify_foc(
        "attack_execution_completed",
        {
            "attack_id": result.get("attack_id"),
            "display_name": result.get("display_name"),
            "mitre_id": result.get("mitre_id"),
            "target_ip": result.get("target_ip"),
            "target_role": result.get("target_role"),
            "output_dir": output_dir,
            "completed_at": result.get("completed_at"),
            "success": result.get("success"),
            "exit_code": result.get("exit_code"),
            "expected_alerts": result.get("expected_alerts", []),
        },
    )


def stream_local_attack_execution(
    attack: Dict[str, Any],
    local_script: str,
    attacker_ip: str,
    attacker_user: str,
    target_user: str,
    target_image: str,
    payload: Dict[str, Any],
) -> Iterable[str]:
    output_dir = get_output_dir(attack["attack_id"], payload.get("case_dir", ""))
    result = build_execution_result(
        attack=attack,
        payload=payload,
        attacker_ip=attacker_ip,
        target_user=target_user,
        target_image=target_image,
        output_dir=output_dir,
    )
    persist_execution_result(output_dir, result)
    _safe_notify_foc(
        "attack_executed",
        {
            "attack_id": result.get("attack_id"),
            "display_name": result.get("display_name"),
            "mitre_id": result.get("mitre_id"),
            "target_ip": result.get("target_ip"),
            "target_role": result.get("target_role"),
            "output_dir": output_dir,
            "started_at": result.get("started_at"),
        },
    )

    args: List[str] = [
        payload.get("target_ip") or payload.get("target") or "",
        target_user,
        json.dumps(payload.get("parameters", {}) or {}, separators=(",", ":")),
        output_dir,
        attacker_ip or "",
        attacker_user or "",
    ]
    command = _python_invocation(local_script) if local_script.endswith(".py") else [local_script]
    command.extend(args)

    yield f"data: [ATTACK PROFILE] {attack['attack_id']} | {attack['mitre_id']} | {attack['mitre_technique']}\n\n"
    yield f"data: [DETECTION ENGINE] {attack['detection_engine']}\n\n"
    yield f"data: [EXECUTION MODE] {attack['execution_mode']}\n\n"
    yield f"data: [OUTPUT DIR] {output_dir}\n\n"
    yield f"data: [EXECUTION BACKEND] LOCAL\n\n"

    proc = subprocess.Popen(
        command,
        cwd=str(Path(BASE_DIR).parent.parent.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    raw_lines: list[str] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            clean = line.rstrip("\n")
            raw_lines.append(clean)
            if clean.startswith("[FAIL]") or clean.startswith("[SSH ERROR]") or clean.startswith("[CRITICAL]"):
                result["stderr"].append(clean)
            elif clean:
                result["stdout"].append(clean)
            yield f"data: {clean}\n\n"
    finally:
        exit_code = proc.wait()

    yield f"data: [EXIT CODE] {exit_code}\n\n"
    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    result["exit_code"] = exit_code
    result["success"] = exit_code == 0 and not result["stderr"]
    result["raw_event_stream"] = raw_lines
    result["generated_artifacts"] = _collect_generated_artifacts(output_dir)
    effective_target = _load_effective_target_metadata(output_dir)
    if effective_target:
        if effective_target.get("requested_target_ip"):
            result["requested_target_ip"] = effective_target["requested_target_ip"]
        if effective_target.get("requested_target_role"):
            result["requested_target_role"] = effective_target["requested_target_role"]
        if effective_target.get("effective_target_ip"):
            result["effective_target_ip"] = effective_target["effective_target_ip"]
            result["target_ip"] = effective_target["effective_target_ip"]
        if effective_target.get("effective_target_role"):
            result["effective_target_role"] = effective_target["effective_target_role"]
            result["target_role"] = effective_target["effective_target_role"]
        if (
            result.get("requested_target_ip")
            and result.get("effective_target_ip")
            and result["requested_target_ip"] != result["effective_target_ip"]
        ):
            result["target_resolution_status"] = "effective_target_differs_from_requested_target"
            result["target_resolution_note"] = (
                "The requested UI target differs from the effective industrial control endpoint used by the attack script."
            )
    result["forensic_case_event"] = result["dfir_escalation"]
    result["chain_of_custody"].append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "attack_execution_completed",
            "operator": "dashboard_tactical_hud",
            "artifact": "result.json",
        }
    )
    persist_execution_result(output_dir, result)
    _safe_notify_foc(
        "attack_execution_completed",
        {
            "attack_id": result.get("attack_id"),
            "display_name": result.get("display_name"),
            "mitre_id": result.get("mitre_id"),
            "target_ip": result.get("target_ip"),
            "target_role": result.get("target_role"),
            "output_dir": output_dir,
            "completed_at": result.get("completed_at"),
            "success": result.get("success"),
            "exit_code": result.get("exit_code"),
            "expected_alerts": result.get("expected_alerts", []),
            "generated_artifacts": result.get("generated_artifacts", []),
        },
    )


def resolve_requested_attack(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    attack_id = payload.get("attack_id", "")
    return find_attack_by_id(attack_id)
