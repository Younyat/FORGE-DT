from __future__ import annotations

"""Reversible fault injection -- only reads sensors that ALREADY exist to
measure effectiveness, and reuses the EXISTING SSH transport
(node_health_api._run_remote_script_capture) to apply/revert. See
investigacion_y_novedad/07_inyeccion_de_fallos.md (section "Implementacion
2026-09-28") for the full research (real literature + code findings) and
catalog.py for the 5 types. Every application goes through a real Python
try/finally: if the revert fails, it is recorded as revert_failed, never
hidden.
"""

import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .catalog import FAULT_CATALOG, get_fault

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = PROJECT_ROOT / "runtime" / "fault_injection"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()
_active_injections: dict[str, dict] = {}  # injection_id -> record (in-memory, mirrored to disk)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe(fn, default=None):
    try:
        return fn()
    except Exception as exc:
        return default


def _notify_forensic_twin(node_id: str, fault_id: str, phase: str, injection_id: str, **extra) -> None:
    """Best-effort visualization hook so a real apply/revert shows up in the
    3D twin views (Digital Twin View + Live Attack View, both poll
    forensic_twin's event store) -- never allowed to affect the fault
    injection flow itself, hence always called via _safe() by the caller."""
    from app_core.infrastructure.forensic_twin.service import record_fault_injection_lifecycle
    record_fault_injection_lifecycle(node_id, fault_id, phase, injection_id, **extra)


def _notify_intervention_ledger(record: dict, phase: str) -> None:
    """M1 (Intervention Ledger, investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md):
    projects this already-real fault_injection record into the shared,
    hash-chained ledger -- an adapter call, never a second source of truth
    (source_record_ref points back at this exact record's own file, nothing
    is copied beyond what the ledger itself needs). Always called via
    _safe() by the caller, same principle as _notify_forensic_twin: a
    ledger failure must never affect the fault injection flow itself."""
    from app_core.infrastructure.intervention_ledger.service import record_intervention
    record_intervention(
        source="fault_injection",
        source_record_ref=str(_record_path(record["injection_id"])),
        class_="fault",
        type_=record["fault_id"],
        phase=phase,
        intervention_id=record["injection_id"],
        target_node_id=record.get("node_id"),
        target_node_name=record.get("node_name"),
        campaign_id=record.get("campaign_id"),
        params=record.get("params"),
        requested_at=record.get("started_at"),
        applied_at=record.get("started_at") if phase == "applied" else None,
        effect_verified_at=_utc_now() if record.get("effective") is not None else None,
        effect_verification={"effective": record.get("effective"), "evidence": record.get("effectiveness_evidence")} if record.get("effective") is not None else None,
        rollback_requested_at=record.get("reverted_at") if phase == "reverted" else None,
        rollback_at=record.get("reverted_at") if phase == "reverted" else None,
        rollback_verified=(record.get("status") == "reverted") if phase == "reverted" else None,
    )


def _record_path(injection_id: str) -> Path:
    return RUNTIME_DIR / f"{injection_id}.json"


def _save_record(record: dict) -> None:
    with _lock:
        _active_injections[record["injection_id"]] = record
    _record_path(record["injection_id"]).write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")


def list_injections(campaign_id: str | None = None) -> list[dict]:
    """Reads all records from disk (survives worker restarts, unlike an
    in-memory dict) -- capped to the last 200 for cost."""
    records = []
    for p in sorted(RUNTIME_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:200]:
        data = _safe(lambda: json.loads(p.read_text(encoding="utf-8")))
        if isinstance(data, dict):
            records.append(data)
    if campaign_id:
        records = [r for r in records if r.get("campaign_id") == campaign_id]
    return records


def _resolve_node(node_id: str) -> dict | None:
    from app_core.infrastructure.node_health import node_health_api
    nodes = _safe(node_health_api._list_nodes, [])
    return next((n for n in nodes if n.get("id") == node_id), None)


def _run_injection_script(node: dict, script_name: str, env_vars: dict, *, timeout: int = 60):
    """Reuses node_health_api._run_remote_script_capture (the same already-
    proven SSH transport) -- variables are injected as shell assignments
    prepended to a local temp copy of the script, since that function only
    accepts a single special env var (REMOTE_DUMP). SSH is never
    reimplemented here."""
    from app_core.infrastructure.node_health import node_health_api
    script_path = SCRIPTS_DIR / script_name
    base = script_path.read_text(encoding="utf-8")
    prefix = "".join(f"{k}={shlex.quote(str(v))}\n" for k, v in env_vars.items())
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tmp:
        tmp.write(prefix + base)
        tmp_path = Path(tmp.name)
    try:
        return node_health_api._run_remote_script_capture(node, tmp_path, timeout=timeout)
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# "Before/after" snapshots per type -- ONLY reads of sensors already computed
# by other modules, never a new measurement invented here.
# ---------------------------------------------------------------------------

def _snapshot_clock(node: dict) -> dict:
    """A genuinely fresh, synchronous, measure-only reading for this one
    node -- runs the exact same script Node Health uses
    (time_sync_preflight.sh) with DO_FIX_TIME=0 (never applies a chronyc
    makestep), instead of node_health_api._node_time_sync_summary(), which
    only reads whatever time_sync.json Node Health's own async job last
    happened to write for this node (verified: it can be hours old, or not
    exist at all, if nobody has clicked "Measure Clock"/"Fix Time Sync" for
    this node recently) -- a stale cache defeats the whole point of a
    before/after comparison around an injected offset. Output is written to
    its own scratch path so this never collides with Node Health's own
    cached state or its async job."""
    from app_core.infrastructure.node_health.node_health_api import SSH_KEY_PATH, TIME_SYNC_SCRIPT_PATH
    instance_id = node.get("id")
    # Unique per call (not just per node_id): forensic_twin's own "full"
    # followup check and the Digital Twin View's bootstrap on-demand check
    # can legitimately both target the same node within the same ~20-30s
    # window, and a shared path risked one call's write/read interleaving
    # with the other's.
    out_path = RUNTIME_DIR / "time_sync_scratch" / f"{instance_id}-{uuid.uuid4().hex[:8]}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["SSH_KEY"] = SSH_KEY_PATH
    env["FILTER_INSTANCE_ID"] = instance_id
    env["TIME_SYNC_OUT"] = str(out_path)
    env["DO_FIX_TIME"] = "0"
    cmd = ["bash", str(TIME_SYNC_SCRIPT_PATH), "--instance-id", instance_id, "--out", str(out_path)]
    _safe(lambda: subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True, timeout=90))
    data = _safe(lambda: json.loads(out_path.read_text(encoding="utf-8")), {}) or {}
    _safe(lambda: out_path.unlink())
    selected = next((n for n in (data.get("nodes") or []) if n.get("vm_id") == instance_id), None)
    offset_ms = (selected or {}).get("abs_offset_ms")
    if offset_ms is None:
        offset_ms = data.get("max_clock_offset_ms")
    return {"max_clock_offset_ms": offset_ms, "temporal_sync_status": data.get("temporal_sync_status", "not_measured")}


def _snapshot_resources(node: dict) -> dict:
    from app_core.infrastructure.node_health import node_health_api
    row = _safe(lambda: node_health_api._probe_cached_or_refresh(node, refresh=True, max_age_seconds=0), {})
    return {"cpu_usage_pct": (row or {}).get("cpu_usage_pct"), "memory_usage_pct": (row or {}).get("memory_usage_pct")}


def _snapshot_network_rtt(node: dict) -> dict:
    from app_core.infrastructure.node_health import node_health_api
    proc = _safe(lambda: node_health_api._run_remote_text_capture(node, "ping -c 4 -W 2 8.8.8.8 2>/dev/null | tail -1", timeout=15))
    line = (proc.stdout.strip() if proc else "") or ""
    avg_ms = None
    try:
        # "rtt min/avg/max/mdev = 0.5/0.6/0.8/0.1 ms"
        stats = line.split("=")[1].strip().split()[0]
        avg_ms = float(stats.split("/")[1])
    except Exception:
        pass
    return {"ping_avg_ms": avg_ms, "raw": line or None}


def _snapshot_alerts() -> dict:
    from app_core.infrastructure.node_health import node_health_api
    if not node_health_api.HEALTH_SUMMARY_CACHE_PATH.is_file():
        return {"alert_count": None}
    data = _safe(lambda: json.loads(node_health_api.HEALTH_SUMMARY_CACHE_PATH.read_text(encoding="utf-8")), {})
    return {"alert_count": (data or {}).get("alert_count"), "generated_at": (data or {}).get("generated_at")}


def _snapshot_disk(node: dict) -> dict:
    from app_core.infrastructure.node_health import node_health_api
    row = _safe(lambda: node_health_api._probe_cached_or_refresh(node, refresh=True, max_age_seconds=0), {})
    return {"disk_root_use_pct": (row or {}).get("disk_root_use_pct")}


def _snapshot_listening_ports(node: dict) -> dict:
    """Live `ss -tulwn`, same signal forensic_twin's own check_network_exposure
    already diffs against a captured baseline (NIST SP 800-86 Section 5.1.2)
    -- read directly here too, so this fault's own before/after comparison
    never depends on whether a forensic_twin baseline happens to exist."""
    from app_core.infrastructure.node_health import node_health_api
    proc = _safe(lambda: node_health_api._run_remote_text_capture(node, "ss -tulwn 2>/dev/null | awk 'NR>1{print $1, $5}'", timeout=15))
    lines = [l.strip() for l in ((proc.stdout or "").splitlines() if proc else []) if l.strip()]
    return {"listening_ports": sorted(set(lines))}


_CONFIG_TAMPER_PATHS = {
    "suricata_rules": "/var/lib/suricata/rules/suricata.rules",
    "wazuh_ossec_conf": "/var/ossec/etc/ossec.conf",
}


def _snapshot_config_hash(node: dict, target_file: str = "suricata_rules") -> dict:
    import hashlib
    from app_core.infrastructure.node_health import node_health_api
    real_path = _CONFIG_TAMPER_PATHS.get(target_file, _CONFIG_TAMPER_PATHS["suricata_rules"])
    proc = _safe(lambda: node_health_api._run_remote_text_capture(node, f"cat {real_path} 2>/dev/null", timeout=15))
    content = (proc.stdout or "") if proc else ""
    return {"path": real_path, "sha256": hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest() if content else None}


def _snapshot_login_sessions(node: dict) -> dict:
    from app_core.infrastructure.node_health import node_health_api
    proc = _safe(lambda: node_health_api._run_remote_text_capture(node, "who 2>/dev/null", timeout=15))
    lines = [l.strip() for l in ((proc.stdout or "").splitlines() if proc else []) if l.strip()]
    return {"login_sessions": lines}


_SNAPSHOT_FN = {
    "clock_skew": _snapshot_clock,
    "cpu_ram_stress": _snapshot_resources,
    "network_fault": _snapshot_network_rtt,
    "detection_outage": lambda node: _snapshot_alerts(),
    "disk_fill": _snapshot_disk,
    "rogue_port": _snapshot_listening_ports,
    "config_tamper": lambda node: _snapshot_config_hash(node, "suricata_rules"),
    "credential_session": _snapshot_login_sessions,
}

_INJECT_SCRIPT = {
    "clock_skew": ("inject_clock_skew.sh", {"offset_seconds": "OFFSET_SECONDS"}),
    "cpu_ram_stress": ("inject_cpu_stress.sh", {"duration_seconds": "DURATION_SECONDS", "workers": "WORKERS"}),
    "network_fault": ("inject_network_fault.sh", {"delay_ms": "DELAY_MS", "loss_pct": "LOSS_PCT"}),
    "detection_outage": ("inject_detection_outage.sh", {"duration_seconds": "DURATION_SECONDS"}),
    "disk_fill": ("inject_disk_fill.sh", {"target_pct": "TARGET_PCT", "duration_seconds": "DURATION_SECONDS"}),
    "rogue_port": ("inject_rogue_port.sh", {"port": "PORT", "duration_seconds": "DURATION_SECONDS"}),
    "config_tamper": ("inject_config_tamper.sh", {"target_file": "TARGET_FILE"}),
}
_REVERT_SCRIPT = {
    "clock_skew": "revert_clock_skew.sh",
    "network_fault": "revert_network_fault.sh",
    "detection_outage": "revert_detection_outage.sh",
    "disk_fill": "revert_disk_fill.sh",
    "rogue_port": "revert_rogue_port.sh",
    "config_tamper": "revert_config_tamper.sh",
    # cpu_ram_stress: nothing to revert, it self-terminates via --timeout.
}


# ---------------------------------------------------------------------------
# Python-handled faults -- for the two types that don't fit the "SSH in and
# run a bash script ON the node" model the 7 script-based faults above all
# share: credential_session needs an SSH session held open FROM this host
# (the thing being tested IS an incoming session, not a script running
# inside one), and plc_io_manipulation needs the same structured Modbus
# register resolution ot_state_twin/industrial_ops already build and trust
# (never a raw mbpoll re-derived here). Each handler returns
# {"ok": bool, "stdout": str, "error": str|None}, the same shape
# _run_injection_script's result is normalized into below.
# ---------------------------------------------------------------------------

def _apply_credential_session(node: dict, params: dict, injection_id: str) -> dict:
    """Holds one real, idle SSH session open against the node (MITRE ATT&CK
    for ICS T1694/T0859) for a bounded window -- runs FROM this host, not as
    a script executed ON the node. `-tt` forces a real pseudo-terminal:
    verified live that a plain non-interactive `ssh host "sleep N"` leaves
    zero trace in `who` (confirmed empty before/after snapshots on a first
    live test), while a pty-allocated session shows up exactly like a real
    interactive login -- without -tt this fault would apply successfully
    but be permanently invisible to its own effectiveness signal."""
    from app_core.infrastructure.node_health import node_health_api
    duration = int(params.get("duration_seconds", 60))
    ip = node.get("ip_floating") or node.get("ip_private")
    user = node.get("ssh_user") or "debian"
    if not ip:
        return {"ok": False, "error": "node has no reachable IP"}
    cmd = [
        "ssh", "-tt", "-i", node_health_api.SSH_KEY_PATH, "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", f"{user}@{ip}", f"sleep {duration}",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    (RUNTIME_DIR / f"{injection_id}.session.pid").write_text(str(proc.pid), encoding="utf-8")
    return {"ok": True, "stdout": f"session held open (local ssh pid={proc.pid}) for up to {duration}s"}


def _revert_credential_session(node: dict, record: dict) -> dict:
    pid_path = RUNTIME_DIR / f"{record['injection_id']}.session.pid"
    if pid_path.is_file():
        try:
            os.kill(int(pid_path.read_text(encoding="utf-8").strip()), signal.SIGTERM)
        except Exception:
            pass
        pid_path.unlink(missing_ok=True)
    return {"ok": True, "stdout": "session closed"}


def _resolve_plc_modbus_context() -> dict:
    from app_core.infrastructure.attack import industrial_ops
    output_dir = RUNTIME_DIR / "plc_io_manipulation_scratch"
    output_dir.mkdir(parents=True, exist_ok=True)
    return industrial_ops.ensure_validated_context(output_dir, require_validation=True)


def _apply_plc_io_manipulation(node: dict, params: dict, injection_id: str) -> dict:
    """Direct Modbus write to level_max, independent of any attack script
    (MITRE ATT&CK for ICS T0835 'Manipulate I/O Image') -- the ONLY register
    ics_attack_policy.json's own allowed_write_targets authorizes for a
    direct write (confirmed by reading the real policy file before writing
    this; a coil/valve write was considered and rejected: its register-map
    entry carries "write_allowed": false). Reuses industrial_ops' own
    validated register map + mbpoll_write -- the exact same transport the
    real T0831 attack script and ot_state_twin already use."""
    from app_core.infrastructure.attack import industrial_ops
    from app_core.infrastructure.node_health import node_health_api
    forced_value = int(params.get("forced_value", 50))
    attacker = next((n for n in _safe(node_health_api._list_nodes, []) if str(n.get("role") or "").lower() == "attacker"), None)
    if not attacker:
        return {"ok": False, "error": "no live attacker node found to run mbpoll from"}
    source_ip = attacker.get("ip_floating") or attacker.get("ip_private")
    source_user = attacker.get("ssh_user") or "debian"
    try:
        context = _resolve_plc_modbus_context()
        policy_target = industrial_ops.policy_write_target(context, "level_max")
        if not policy_target:
            return {"ok": False, "error": "level_max is not an allowed_write_target in ics_attack_policy.json -- refusing to write"}
        safe_min, safe_max = policy_target.get("safe_min", 10), policy_target.get("safe_max", 90)
        if not (safe_min <= forced_value <= safe_max):
            return {"ok": False, "error": f"forced_value {forced_value} outside policy safe range [{safe_min}, {safe_max}]"}
        register = industrial_ops.find_register(context, "level_max")
        validated = industrial_ops.validated_address(context, "level_max")
        if not register or not validated:
            return {"ok": False, "error": "level_max register mapping not validated"}
        plc_ip = context["register_map"]["plc"]["ip"]
        slave_id = 1
        devices = context.get("scada_map", {}).get("modbus_devices", []) or []
        if devices:
            slave_id = int(devices[0].get("slaveid") or 1)
        result = industrial_ops.mbpoll_write(
            plc_ip, slave_id, register.get("modbus_table", "holding_register"), int(validated["validated_modbus_address"]),
            forced_value, source_ip=source_ip, source_user=source_user,
        )
        return {"ok": bool(result.get("ok")), "stdout": json.dumps(result)[:2000], "error": None if result.get("ok") else result.get("stderr")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _revert_plc_io_manipulation(node: dict, record: dict) -> dict:
    """Writes back the exact value read in `before` -- never a guessed
    default, matching the "exact revert" principle every other fault in
    this module already follows."""
    from app_core.infrastructure.attack import industrial_ops
    from app_core.infrastructure.node_health import node_health_api
    before_value = (record.get("before") or {}).get("level_max")
    if before_value is None:
        return {"ok": False, "error": "no 'before' value recorded to restore -- cannot revert safely"}
    attacker = next((n for n in _safe(node_health_api._list_nodes, []) if str(n.get("role") or "").lower() == "attacker"), None)
    if not attacker:
        return {"ok": False, "error": "no live attacker node found to run mbpoll from"}
    source_ip = attacker.get("ip_floating") or attacker.get("ip_private")
    source_user = attacker.get("ssh_user") or "debian"
    try:
        context = _resolve_plc_modbus_context()
        register = industrial_ops.find_register(context, "level_max")
        validated = industrial_ops.validated_address(context, "level_max")
        if not register or not validated:
            return {"ok": False, "error": "level_max register mapping not validated"}
        plc_ip = context["register_map"]["plc"]["ip"]
        slave_id = 1
        devices = context.get("scada_map", {}).get("modbus_devices", []) or []
        if devices:
            slave_id = int(devices[0].get("slaveid") or 1)
        result = industrial_ops.mbpoll_write(
            plc_ip, slave_id, register.get("modbus_table", "holding_register"), int(validated["validated_modbus_address"]),
            int(before_value), source_ip=source_ip, source_user=source_user,
        )
        return {"ok": bool(result.get("ok")), "stdout": json.dumps(result)[:2000]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _snapshot_plc_level_max(node: dict) -> dict:
    from app_core.infrastructure.node_health import node_health_api
    attacker = next((n for n in _safe(node_health_api._list_nodes, []) if str(n.get("role") or "").lower() == "attacker"), None)
    if not attacker:
        return {"level_max": None}
    try:
        from app_core.infrastructure.attack import industrial_ops
        context = _resolve_plc_modbus_context()
        state = industrial_ops.collect_state(
            context, ["level_max"],
            source_ip=attacker.get("ip_floating") or attacker.get("ip_private"),
            source_user=attacker.get("ssh_user") or "debian",
        )
    except Exception:
        return {"level_max": None}
    return {"level_max": (state.get("variables", {}).get("level_max") or {}).get("value")}


_SNAPSHOT_FN["plc_io_manipulation"] = _snapshot_plc_level_max


def _snapshot_acquisition_failure(node: dict) -> dict:
    """Not node-specific -- this fault targets the orchestrator's OWN local
    acquisition pipeline (scenario_snapshot.capture_snapshot), not anything
    running on a remote node. Records whether the single-shot flag is
    armed, for an honest before/after pair even though no node state is
    actually touched."""
    from app_core.infrastructure.scenario_snapshot.service import is_capture_snapshot_failure_armed
    return {"flag_armed": is_capture_snapshot_failure_armed()}


def _apply_acquisition_failure(node: dict, params: dict, injection_id: str) -> dict:
    """Arms scenario_snapshot's own single-shot forced-failure flag -- see
    force_capture_snapshot_failure_once()'s own docstring for the full
    design. Deliberately ignores `node`: the gap this fault tests
    (g17_chaos_engineering_forensic_pipeline) is explicitly about the
    forensic PIPELINE, not about any specific infrastructure node."""
    from app_core.infrastructure.scenario_snapshot.service import force_capture_snapshot_failure_once
    force_capture_snapshot_failure_once()
    return {"ok": True, "stdout": "armed a single-shot forced failure for the next capture_snapshot() call"}


def _revert_acquisition_failure(node: dict, record: dict) -> dict:
    """Disarms the flag if it is still armed (e.g. nobody ever triggered a
    capture_snapshot() call between apply and revert) -- idempotent, never
    an error either way."""
    from app_core.infrastructure.scenario_snapshot.service import disarm_capture_snapshot_failure_once
    disarm_capture_snapshot_failure_once()
    return {"ok": True, "stdout": "disarmed (if it was still armed)"}


_SNAPSHOT_FN["acquisition_failure"] = _snapshot_acquisition_failure


def _snapshot_orchestrator_failure(node: dict) -> dict:
    """Not node-specific, same reasoning as acquisition_failure -- this
    fault targets gap_validation's OWN orchestrator loop, never a node."""
    from app_core.infrastructure.gap_validation.orchestrator import is_orchestrator_failure_armed
    return {"flag_armed": is_orchestrator_failure_armed()}


def _apply_orchestrator_failure(node: dict, params: dict, injection_id: str) -> dict:
    """Arms gap_validation's own single-shot orchestrator-crash flag -- see
    force_orchestrator_failure_once()'s own docstring (gap_validation/
    orchestrator.py) for the full design and the structural (not just
    runtime-checked) guarantee that this can never reach a real Level C
    campaign."""
    from app_core.infrastructure.gap_validation.orchestrator import force_orchestrator_failure_once
    force_orchestrator_failure_once()
    return {"ok": True, "stdout": "armed a single-shot forced orchestrator failure for gap_validation's own next repetition step"}


def _revert_orchestrator_failure(node: dict, record: dict) -> dict:
    """Disarms defensively -- in practice the orchestrator's own crash
    already consumes/disarms the flag itself before this is ever called,
    so this is normally a no-op; idempotent either way."""
    from app_core.infrastructure.gap_validation.orchestrator import disarm_orchestrator_failure_once
    disarm_orchestrator_failure_once()
    return {"ok": True, "stdout": "disarmed (if it was still armed)"}


_SNAPSHOT_FN["orchestrator_failure"] = _snapshot_orchestrator_failure

_PYTHON_FAULT_HANDLERS = {
    "credential_session": (_apply_credential_session, _revert_credential_session),
    "plc_io_manipulation": (_apply_plc_io_manipulation, _revert_plc_io_manipulation),
    "acquisition_failure": (_apply_acquisition_failure, _revert_acquisition_failure),
    "orchestrator_failure": (_apply_orchestrator_failure, _revert_orchestrator_failure),
}


def apply_fault(fault_id: str, node_id: str, params: dict, *, campaign_id: str | None = None) -> dict:
    fault = get_fault(fault_id)
    if not fault:
        return {"ok": False, "error": f"unknown fault_id: {fault_id}"}
    # clock_skew is "pre_attack" in the catalog (that's how its normal use as
    # a campaign config is documented), but the user also wants to be able to
    # produce/counteract it on demand against a node, outside of any
    # campaign -- the real constraint isn't applicable_phase, it's simply
    # whether an injection script is registered for this type.
    if fault_id not in _INJECT_SCRIPT and fault_id not in _PYTHON_FAULT_HANDLERS:
        return {"ok": False, "error": f"{fault_id} has no on-demand injection script (applicable_phase={fault['applicable_phase']}); it is a launch-time-only campaign config"}
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}

    injection_id = f"fi-{uuid.uuid4().hex[:10]}"
    record = {
        "injection_id": injection_id, "fault_id": fault_id, "label": fault["label"],
        "node_id": node_id, "node_name": node.get("name"), "campaign_id": campaign_id,
        "params": params, "status": "applying", "started_at": _utc_now(),
        "before": None, "after_apply": None, "after_revert": None, "effective": None,
        "revert_failed": False, "errors": [],
    }
    _save_record(record)

    snapshot_fn = _SNAPSHOT_FN[fault_id]

    try:
        record["before"] = snapshot_fn(node)
        if fault_id in _PYTHON_FAULT_HANDLERS:
            apply_fn, _ = _PYTHON_FAULT_HANDLERS[fault_id]
            result = apply_fn(node, params, injection_id)
            record["apply_stdout"] = (result.get("stdout") or "")[-2000:]
            record["apply_rc"] = 0 if result.get("ok") else 1
            if not result.get("ok"):
                record["status"] = "apply_failed"
                record["errors"].append(result.get("error") or "python fault handler failed")
                _save_record(record)
                return {"ok": False, "record": record}
        else:
            script_name, param_env_map = _INJECT_SCRIPT[fault_id]
            env_vars = {param_env_map[k]: v for k, v in params.items() if k in param_env_map}
            proc = _run_injection_script(node, script_name, env_vars, timeout=60)
            record["apply_stdout"] = (proc.stdout or "")[-2000:]
            record["apply_stderr"] = (proc.stderr or "")[-2000:]
            record["apply_rc"] = proc.returncode
            if proc.returncode != 0:
                record["status"] = "apply_failed"
                record["errors"].append(f"inject script exit code {proc.returncode}")
                _save_record(record)
                return {"ok": False, "record": record}
        record["status"] = "active"
        record["after_apply"] = snapshot_fn(node)
        _save_record(record)
        # Compute effectiveness right away, not only after a later revert --
        # both snapshots already exist at this point, so the dashboard's
        # Effective/Evidence columns should never sit at "n/a" just because
        # nobody has reverted yet.
        eff = _safe(lambda: measure_effectiveness(injection_id))
        final_record = (eff or {}).get("record", record)
        _safe(lambda: _notify_forensic_twin(node_id, fault_id, "applied", injection_id, params=params))
        _safe(lambda: _notify_intervention_ledger(final_record, "applied"))
        return {"ok": True, "record": final_record}
    except Exception as exc:
        record["status"] = "apply_failed"
        record["errors"].append(str(exc))
        _save_record(record)
        return {"ok": False, "record": record, "error": str(exc)}


def revert_fault(injection_id: str) -> dict:
    record = _safe(lambda: json.loads(_record_path(injection_id).read_text(encoding="utf-8")))
    if not record:
        return {"ok": False, "error": f"injection not found: {injection_id}"}
    fault_id = record["fault_id"]
    node = _resolve_node(record["node_id"])
    revert_script = _REVERT_SCRIPT.get(fault_id)
    snapshot_fn = _SNAPSHOT_FN.get(fault_id)
    python_revert_fn = _PYTHON_FAULT_HANDLERS.get(fault_id, (None, None))[1]

    if not revert_script and not python_revert_fn:
        # cpu_ram_stress: nothing to revert, it self-terminates. Marked the
        # same way so the record stays complete.
        record["status"] = "self_terminated"
        record["reverted_at"] = _utc_now()
        _save_record(record)
        return {"ok": True, "record": record}

    if not node:
        record["status"] = "revert_failed"
        record["revert_failed"] = True
        record["errors"].append("node not found or not live at revert time")
        _save_record(record)
        return {"ok": False, "record": record}

    try:
        if python_revert_fn:
            result = python_revert_fn(node, record)
            record["revert_stdout"] = (result.get("stdout") or "")[-2000:]
            record["revert_rc"] = 0 if result.get("ok") else 1
            if not result.get("ok"):
                record["status"] = "revert_failed"
                record["revert_failed"] = True
                record["errors"].append(result.get("error") or "python fault revert handler failed")
            else:
                record["status"] = "reverted"
                record["after_revert"] = snapshot_fn(node) if snapshot_fn else None
        else:
            proc = _run_injection_script(node, revert_script, {}, timeout=60)
            record["revert_stdout"] = (proc.stdout or "")[-2000:]
            record["revert_rc"] = proc.returncode
            if proc.returncode != 0:
                record["status"] = "revert_failed"
                record["revert_failed"] = True
                record["errors"].append(f"revert script exit code {proc.returncode}")
            else:
                record["status"] = "reverted"
                record["after_revert"] = snapshot_fn(node) if snapshot_fn else None
        record["reverted_at"] = _utc_now()
        _save_record(record)
        if record["status"] == "reverted":
            _safe(lambda: _notify_forensic_twin(record["node_id"], fault_id, "reverted", injection_id))
            _safe(lambda: _notify_intervention_ledger(record, "reverted"))
        return {"ok": record["status"] == "reverted", "record": record}
    except Exception as exc:
        record["status"] = "revert_failed"
        record["revert_failed"] = True
        record["errors"].append(str(exc))
        _save_record(record)
        return {"ok": False, "record": record, "error": str(exc)}


def measure_effectiveness(injection_id: str) -> dict:
    """Compares before/after_apply against each type's real thresholds --
    never invents a number, only interprets what apply_fault/revert_fault
    already captured."""
    record = _safe(lambda: json.loads(_record_path(injection_id).read_text(encoding="utf-8")))
    if not record:
        return {"ok": False, "error": f"injection not found: {injection_id}"}
    fault_id = record["fault_id"]
    before, after = record.get("before") or {}, record.get("after_apply") or {}
    effective, evidence = None, None

    if fault_id == "clock_skew":
        b, a = before.get("max_clock_offset_ms"), after.get("max_clock_offset_ms")
        requested_seconds = (record.get("params") or {}).get("offset_seconds")
        if b is not None and a is not None and requested_seconds is not None:
            requested_ms = abs(float(requested_seconds)) * 1000
            delta_ms = a - b
            # Real check requested by the user: not just "some change
            # happened", but "did the specific requested offset actually
            # show up" (baseline + what the injection added). A 50%
            # tolerance absorbs the few seconds of SSH round-trip between
            # the before/after measurements and any correction that may
            # already be underway (e.g. an unrelated Level C campaign
            # repetition running its own automatic clock-sync phase) --
            # below that, the injection is honestly reported as not
            # confirmed rather than assumed to have worked.
            effective = delta_ms >= (requested_ms * 0.5)
            evidence = f"offset before={b}ms after={a}ms delta={delta_ms:.0f}ms (requested {requested_ms:.0f}ms)"
        elif b is not None and a is not None:
            effective = (a - b) > 1000
            evidence = f"offset before={b}ms after={a}ms delta={a-b:.0f}ms"
    elif fault_id == "cpu_ram_stress":
        b, a = before.get("cpu_usage_pct"), after.get("cpu_usage_pct")
        if b is not None and a is not None:
            effective = (a - b) > 15
            evidence = f"cpu before={b}% after={a}% delta={a-b}pp"
    elif fault_id == "network_fault":
        b, a = before.get("ping_avg_ms"), after.get("ping_avg_ms")
        if b is not None and a is not None:
            effective = (a - b) > 50
            evidence = f"ping RTT before={b}ms after={a}ms delta={a-b}ms"
    elif fault_id == "detection_outage":
        # Real service name parsed from the script's own dynamic detection
        # output (service=suricata or service=wazuh-manager -- whichever
        # was actually active on this node, see inject_detection_outage.sh)
        # -- never hardcoded, fixed 2026-10-14 after this text said
        # "suricata" even when the node only had Wazuh installed.
        stopped_service_match = re.search(r"service=(\S+)", record.get("apply_stdout") or "")
        stopped_service = stopped_service_match.group(1) if stopped_service_match else "detection service"
        effective = record.get("apply_rc") == 0
        evidence = f"{stopped_service} stop_rc=0 (service confirmed active before stopping)" if effective else f"could not confirm {stopped_service} outage"
    elif fault_id == "plc_io_manipulation":
        # Real gap found live via the Intervention Ledger/M7 metrics (M9
        # verification campaign, 2026-10-07): this fault_id had no entry
        # here at all, so `effective` stayed None even for a run where
        # forensic_twin independently confirmed the real divergence 3
        # times over ~3h15m (level_max really held at the forced value).
        # Simple, real check: did the real Modbus readback actually land on
        # the forced value, using the exact same before/after_apply
        # snapshot _apply_plc_io_manipulation already captures.
        b, a = before.get("level_max"), after.get("level_max")
        forced_value = (record.get("params") or {}).get("forced_value")
        if b is not None and a is not None:
            effective = (a != b) and (forced_value is None or a == forced_value)
            evidence = f"level_max before={b} after={a}" + (f" (forced_value requested={forced_value})" if forced_value is not None else "")

    record["effective"] = effective
    record["effectiveness_evidence"] = evidence
    _save_record(record)
    return {"ok": True, "effective": effective, "evidence": evidence, "record": record}


def get_modbus_precision_effectiveness(job_id: str) -> dict:
    """For type 2 (a launch-time config, not on-demand): reuses the
    comparison_report ALREADY computed by level_c_orchestrator, never builds
    new statistics."""
    from app_core.infrastructure.level_c_orchestrator.service import get_comparison_report
    report = _safe(lambda: get_comparison_report(job_id))
    if not report:
        return {"ok": False, "error": "no comparison_report available for this job yet"}
    comparisons = report.get("comparisons") or []
    degraded = [c for c in comparisons if not c.get("delta_wcpr_acceptable")]
    return {
        "ok": True,
        "comparisons_count": len(comparisons),
        "degraded_count": len(degraded),
        "reproducibility_index": report.get("reproducibility_index"),
        "verdict": report.get("verdict"),
    }


# ---------------------------------------------------------------------------
# "Pilot lamp" live status -- explicit user request: before/after applying an
# injection there must be a visible green (all normal, measured) or red
# (fault applied/detected) indicator, not just text.
# ---------------------------------------------------------------------------

def measure_clock_status(node_id: str) -> dict:
    """Green = clock in sync (or offset < 1s, normal noise). Red = a real
    offset is detected right now. Reuses the same sensor that already
    computes the offset (_node_time_sync_summary), never a new one."""
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}
    snap = _snapshot_clock(node)
    offset = snap.get("max_clock_offset_ms")
    in_sync = offset is None or abs(offset) < 1000
    return {"ok": True, "lamp": "green" if in_sync else "red", "offset_ms": offset, "temporal_sync_status": snap.get("temporal_sync_status")}


def get_modbus_precision_status(campaign_id: str) -> dict:
    """Red = the campaign has the fault active right now (mode=degraded, or
    no config at all, which is the real default behavior). Green =
    mode=fixed (an explicit real value is configured)."""
    from app_core.infrastructure.foc_experimentation.config import campaign_config_path
    path = campaign_config_path(campaign_id)
    if not path.is_file():
        return {"ok": False, "error": f"campaign not found: {campaign_id}"}
    config = _safe(lambda: json.loads(path.read_text(encoding="utf-8")), {})
    faults = (config or {}).get("injected_faults") or []
    entry = next((f for f in faults if f.get("type") == "modbus_payload_precision"), None)
    mode = (entry or {}).get("params", {}).get("mode", "degraded")
    return {"ok": True, "lamp": "red" if mode == "degraded" else "green", "mode": mode, "value": (entry or {}).get("params", {}).get("value")}


def set_modbus_precision_mode(campaign_id: str, mode: str, value: int | None = None) -> dict:
    """Writes for real into the campaign's config.json -- thanks to the fix
    in level_b_repetition_runner.py (config.json is re-read every
    repetition), this takes effect starting from the NEXT repetition, even
    while the campaign is already running. It never affects a repetition
    that is already executing."""
    from app_core.infrastructure.foc_experimentation.config import campaign_config_path
    path = campaign_config_path(campaign_id)
    if not path.is_file():
        return {"ok": False, "error": f"campaign not found: {campaign_id}"}
    config = _safe(lambda: json.loads(path.read_text(encoding="utf-8")), {}) or {}
    faults = [f for f in (config.get("injected_faults") or []) if f.get("type") != "modbus_payload_precision"]
    faults.append({
        "type": "modbus_payload_precision", "attack_id": "T0831_MANIPULATION_OF_CONTROL_MODBUS",
        "phase": "pre_attack", "params": {"mode": mode, "value": value if value is not None else 30},
    })
    config["injected_faults"] = faults
    path.write_text(json.dumps(config, indent=2, default=str), encoding="utf-8")
    return {"ok": True, "mode": mode}
