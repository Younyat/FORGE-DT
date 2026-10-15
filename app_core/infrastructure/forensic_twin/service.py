from __future__ import annotations

"""Forensic digital twin aggregator -- composes signals that ALREADY exist in
other modules (tool inventory, a live clock-offset reading, PLC control-law
state, Level C reproducibility) into one expected-vs-real state view per
node/campaign, and records formal divergence events. Nothing here recomputes
a signal another module already owns; nothing here writes to any node --
strictly read + compare + record, the same design constraint as
ot_state_twin (writing back to an investigated system contaminates chain of
custody).

Divergence storage is 100% reused from ot_state_twin
(app_core/infrastructure/ot_state_twin/service.py: _scope_dir, _divergence_path,
_append_jsonl, get_divergence_events) -- this module writes its own event
types into the SAME per-scope JSONL file instead of building a second event
log format. `scope_id` follows the same generic string-namespace convention
ot_state_twin already uses (a campaign+repetition scope there; here either
`node:<instance_id>` or a campaign/job id).

See investigacion_y_novedad/09_veredicto_tiempo_real_vs_forense.md and
10_factores_construccion_gemelo_digital.md for the research this implements,
and investigaciones_y_implementacion/00_estado_implementacion.md for the
build log.
"""

import fcntl
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = PROJECT_ROOT / "runtime" / "forensic_twin"
STATE_HISTORY_DIR = RUNTIME_DIR / "state_history"
KNOWN_SCOPES_PATH = RUNTIME_DIR / "known_scopes.json"
LEADER_LOCK_PATH = RUNTIME_DIR / "continuous_monitor.leader.lock"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
STATE_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()

# Same default threshold already used by forensics/scripts/time_sync_preflight.sh:13
# (TIME_SYNC_THRESHOLD_MS) -- not a new, separately invented number.
CLOCK_OFFSET_DEGRADED_MS = 1000

# Deliberately long and deliberately conservative: this host also runs the
# rest of the platform (gunicorn, the attack lab, live campaigns) and has hit
# real memory/swap pressure before this development effort (see
# memory_watchdog). The continuous tick itself is kept cheap (tools + a
# handful of fast `systemctl is-active` calls; the two genuinely expensive
# signals -- the full clock time-sync script and the PLC's batch of mbpoll
# reads -- are excluded from it entirely, see check_node_state's
# include_clock/include_plc), but the interval is still long on purpose:
# this is "continuous" in the sense of "nobody has to click a button", never
# "real-time" or "frequent".
CONTINUOUS_CHECK_INTERVAL_SECONDS = 1800


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _node_scope_id(node_id: str) -> str:
    return f"node:{node_id}"


def _state_history_path(key: str) -> Path:
    """`key` is a node_id for a per-node check, or "scenario" for the
    scenario-wide snapshot check -- both are just string history keys, same
    generic mechanism."""
    return STATE_HISTORY_DIR / f"{key}.jsonl"


def _append_state_history(key: str, entry: dict) -> None:
    with _lock:
        with _state_history_path(key).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")


def _last_state(key: str) -> dict | None:
    path = _state_history_path(key)
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        return json.loads(lines[-1]) if lines else None
    except Exception:
        return None


def get_state_history_before(key: str, before_iso: str) -> dict | None:
    """Most recent real state-history entry for `key` strictly before
    `before_iso` (an ISO-8601 'checked_at' string) -- used by evidence_bridge
    to find a genuine prior reading to compare a *_degraded event against,
    without accidentally matching the very reading that triggered the event
    itself (which, by the time evidence_bridge's auto-link runs, is already
    the LAST line `_last_state()` would return). Public (unlike `_last_state`)
    because evidence_bridge is a different module needing this same
    already-real history, not a second one."""
    path = _state_history_path(key)
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
    except Exception:
        return None
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if (entry.get("checked_at") or "") < before_iso:
            return entry
    return None


def _register_scope(scope_id: str, kind: str, label: str) -> None:
    with _lock:
        known = _safe(lambda: json.loads(KNOWN_SCOPES_PATH.read_text(encoding="utf-8")), {}) or {}
        known[scope_id] = {"kind": kind, "label": label, "last_seen": _utc_now()}
        KNOWN_SCOPES_PATH.write_text(json.dumps(known, indent=2, default=str), encoding="utf-8")


# MITRE ATT&CK for ICS mapping per divergence type (investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md,
# gap #4 -- Kampourakis et al., "Digital Twin-Assisted Mapping of ICS Telemetry to ATT&CK for ICS",
# arXiv:2610.02955: prior ICS security work rarely bridges numerical telemetry divergence to a
# standardized adversarial-behavior framework; Attack Lab's own attacks were already MITRE-mapped, the
# twin's OWN divergence detections were not -- this closes that asymmetry). IDs verified against the
# official technique list at https://attack.mitre.org/techniques/ics/ (2026-10-09), never guessed.
# `None` for a divergence type means an honest "no ICS ATT&CK technique fits" -- those two are meta/
# experimental-validity signals (is the environment still reproducible / still matches its own
# ground-truth model), not an adversary behavior, so forcing a technique ID onto them would overclaim.
MITRE_ATTCK_ICS_MAPPING: dict[str, dict | None] = {
    "tool_regression": {"technique_id": "T0872", "technique_name": "Indicator Removal on Host", "tactic": "Defense Evasion"},
    "service_down": {"technique_id": "T0881", "technique_name": "Service Stop", "tactic": "Impact"},
    "clock_offset_degraded": {"technique_id": "T0872", "technique_name": "Indicator Removal on Host", "tactic": "Defense Evasion", "note": "approximate -- ICS ATT&CK has no dedicated timestamp-tampering technique"},
    "plc_control_law_violation": {"technique_id": "T0831", "technique_name": "Manipulation of Control", "tactic": "Impair Process Control"},
    "plc_baseline_divergence": {"technique_id": "T0836", "technique_name": "Modify Parameter", "tactic": "Impair Process Control"},
    "config_integrity_changed": {"technique_id": "T0872", "technique_name": "Indicator Removal on Host", "tactic": "Defense Evasion", "note": "approximate -- closest official ICS technique for weakening detection-rule config"},
    "listening_port_added": {"technique_id": "T0886", "technique_name": "Remote Services", "tactic": "Lateral Movement"},
    "resource_exhaustion_degraded": {"technique_id": "T0814", "technique_name": "Denial of Service", "tactic": "Impact"},
    "network_latency_degraded": {"technique_id": "T0814", "technique_name": "Denial of Service", "tactic": "Impact"},
    "reproducibility_degraded": None,
    "scenario_validation_degraded": None,
}


def _mitre_attck_ics_for(event_type: str) -> dict | None:
    return MITRE_ATTCK_ICS_MAPPING.get(event_type)


def _record_event(scope_id: str, event_type: str, **fields) -> dict:
    """Writes into the exact same per-scope JSONL file ot_state_twin already
    owns (_divergence_path), via its already-generic append helper -- never a
    second event-log format. Does not go through ot_state_twin's own
    record_divergence_event() wrapper because that one hardcodes an
    OT-specific event_type/evidence_layer label and an alert-correlation
    side effect meant for PLC/Modbus divergences specifically."""
    from app_core.infrastructure.ot_state_twin.service import _append_jsonl, _divergence_path
    event = {
        "event_type": event_type,
        "evidence_layer": "forensic_twin",
        "scope_id": scope_id,
        "generated_at_utc": _utc_now(),
        "mitre_attck_ics": _mitre_attck_ics_for(event_type),
        **fields,
    }
    _append_jsonl(_divergence_path(scope_id), event)
    return event


def get_events(scope_id: str, limit: int = 50) -> list[dict]:
    from app_core.infrastructure.ot_state_twin.service import get_divergence_events
    return get_divergence_events(scope_id, limit=limit)


def _resolve_node(node_id: str) -> dict | None:
    from app_core.infrastructure.node_health.node_health_api import _list_nodes
    nodes = _safe(_list_nodes, [])
    return next((n for n in nodes if n.get("id") == node_id), None)


def _resolve_node_by_name(node_name: str) -> dict | None:
    """Same live node list as _resolve_node, matched by NAME instead of
    instance_id -- needed for Reality Gap, which must compare "this
    conceptual node, whichever VM currently plays that role" across
    redeployments (a historical repetition's own instance_id is for a VM
    already destroyed and never resolves to anything live)."""
    from app_core.infrastructure.node_health.node_health_api import _list_nodes
    nodes = _safe(_list_nodes, [])
    return next((n for n in nodes if n.get("name") == node_name), None)


def _expected_tools_for_node(node_name: str) -> list[str]:
    """Reuses the SAME authoritative role->tools table the real orchestrator
    uses to install tools (level_c_orchestrator._TOOL_SCIENTIFIC_ORDER),
    matched by the exact same name-substring rule _build_instance_tool_map()
    already uses -- never a second, invented expected-tools list. Matching
    by node NAME (not node_health's `role`, which collapses "attack"/"fuxa"
    into "attacker"/"scada") keeps this identical to the real install logic."""
    from app_core.infrastructure.level_c_orchestrator.service import _NODE_INSTALL_ORDER, _TOOL_SCIENTIFIC_ORDER
    name = (node_name or "").lower()
    for role in _NODE_INSTALL_ORDER:
        if role in name:
            tools: list[str] = []
            for role_pattern, tool, _phase in _TOOL_SCIENTIFIC_ORDER:
                if role_pattern == role and tool not in tools:
                    tools.append(tool)
            return tools
    return []


def _check_tools(node: dict) -> dict:
    expected = _expected_tools_for_node(node.get("name"))
    inventory = (node.get("tool_inventory") or {}).get("tools") or []
    installed_names = sorted({t.get("id") for t in inventory if t.get("inventory_status") == "installed"})
    missing = [t for t in expected if t not in installed_names]
    return {"expected_tools": expected, "installed_tools": installed_names, "missing_tools": missing}


# Only tool names with a CONFIRMED real systemd unit name (grepped from
# tools-installer/scripts/*.sh and fault_injection/scripts/inject_detection_outage.sh:10,
# never guessed) map to a service-liveness check -- deliberately narrower
# than the full tool inventory, since "is this installed" and "is this
# currently running" are two different real questions this module did not
# distinguish until now.
SERVICE_TOOL_TO_UNIT = {
    "suricata": "suricata",
    "wazuh_agent": "wazuh-agent",
    "wazuh": "wazuh-manager",
}


def _check_services(node: dict) -> dict:
    """A real `systemctl is-active <unit>` per confirmed service already
    marked as installed on this node -- reuses the same remote-command
    transport already used elsewhere in this module
    (node_health_api._run_remote_text_capture, same function
    fault_injection._snapshot_network_rtt already uses). Distinguishes
    "installed" (a historical fact, from _check_tools) from "running right
    now" (a live fact) -- fault_injection's own detection_outage fault stops
    suricata without erasing its install record, so before this check
    existed, forensic_twin had no way to notice that fault at all."""
    from app_core.infrastructure.node_health.node_health_api import _run_remote_text_capture
    inventory = (node.get("tool_inventory") or {}).get("tools") or []
    installed_names = {t.get("id") for t in inventory if t.get("inventory_status") == "installed"}
    relevant_units = sorted({SERVICE_TOOL_TO_UNIT[t] for t in installed_names if t in SERVICE_TOOL_TO_UNIT})
    checked = []
    down = []
    for unit in relevant_units:
        proc = _safe(lambda u=unit: _run_remote_text_capture(node, f"systemctl is-active {u}", timeout=15))
        status = (proc.stdout.strip() if proc else "") or "unknown"
        checked.append({"unit": unit, "status": status})
        if status != "active":
            down.append(unit)
    return {"checked": checked, "down": down}


def _check_clock(node: dict) -> dict:
    """Live measure-only reading -- reuses fault_injection's own clock
    snapshot (built and verified earlier this session), never a second
    implementation of the same SSH+chronyc measurement."""
    from app_core.infrastructure.fault_injection.service import _snapshot_clock
    snap = _snapshot_clock(node)
    offset = snap.get("max_clock_offset_ms")
    degraded = offset is not None and abs(offset) > CLOCK_OFFSET_DEGRADED_MS
    return {"offset_ms": offset, "temporal_sync_status": snap.get("temporal_sync_status"), "degraded": degraded}


def _check_plc_state(node: dict) -> dict | None:
    """Only meaningful for the Tank Control PLC node -- ot_state_twin models
    that one PLC's real ladder-logic registers, never generalized here.
    Never captures a baseline as a side effect: if none exists yet, the
    baseline-comparison piece is simply reported absent, exactly like
    ot_state_twin's own design (baseline capture is a deliberate, separate
    action)."""
    if node.get("role") != "plc":
        return None
    from app_core.infrastructure.ot_state_twin.service import (
        MANUAL_SCOPE,
        capture_state_sample,
        compare_against_baseline,
        evaluate_control_law_consistency,
        get_baseline,
    )
    sample = _safe(capture_state_sample)
    if not sample:
        return {"available": False, "reason": "could not capture a live PLC state sample"}
    baseline = _safe(lambda: get_baseline(MANUAL_SCOPE))
    comparison = _safe(lambda: compare_against_baseline(sample, baseline)) if baseline else None
    control_law = _safe(lambda: evaluate_control_law_consistency(sample))
    return {
        "available": True,
        "baseline_present": bool(baseline),
        "comparison": comparison,
        "control_law": control_law,
    }


CONFIG_BASELINES_DIR = RUNTIME_DIR / "config_baselines"
CONFIG_BASELINES_DIR.mkdir(parents=True, exist_ok=True)


def _config_baseline_path(node_id: str) -> Path:
    return CONFIG_BASELINES_DIR / f"{node_id}.json"


def _sha256_hex(text: str) -> str:
    import hashlib
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def _collect_config_files(node: dict) -> dict:
    """Real Suricata/Wazuh rule+config file contents, reusing node_health's
    own tooling probe (node_health_api._build_tooling_payload) -- the SAME
    remote script already SSHes in and reads these exact files for its own
    inventory display (probe_node_tooling_inside_node.sh, suricata_rule_contents/
    wazuh_rule_contents sections). No new remote-command capability is
    introduced here, only hashing + comparing what it already returns.
    Returns {file_path: sha256_hex}. The PLC's own program file is
    deliberately NOT included here: it has no known, confirmed remote path on
    the PLC VM in this codebase (grepped before writing this -- only a LOCAL
    reference copy exists, industrial-scenario/PLC/plc_programs/TankControl.st,
    used elsewhere purely as a label/model_source, never read over SSH), so
    adding it would mean guessing a path rather than reusing a verified one."""
    from app_core.infrastructure.node_health.node_health_api import _build_tooling_payload
    payload = _safe(lambda: _build_tooling_payload(node)) or {}
    runtime = payload.get("runtime") or {}
    files: dict[str, str] = {}
    for section in ("suricata", "wazuh"):
        for entry in (runtime.get(section) or {}).get("rule_contents") or []:
            path = entry.get("path")
            if not path:
                continue
            content = "\n".join(entry.get("content_lines") or [])
            files[path] = _sha256_hex(content)
    return files


# --- Baseline history (Reality Gap, 2026-10-11) ----------------------------
# The config/network baselines above are captured manually, on demand, and
# OVERWRITTEN in place every time someone re-captures them -- unlike the PLC
# baseline (ot_state_twin.capture_state_sample), which is already scoped per
# campaign+repetition and never overwritten (so it has no reality-gap
# problem: every case already got its own dedicated baseline right before
# its own attack). This IS exactly Sammartino & Pasquini's "contextual
# reality gap" (investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md,
# hueco #5): if the reference model silently drifts and nobody notices,
# every later divergence check is being compared against a possibly-stale
# "normal", with no way to tell. Archiving the OUTGOING baseline before each
# overwrite -- keyed by node NAME, not instance_id, since VMs are redeployed
# fresh every repetition and a historical instance_id would never resolve to
# anything live -- lets a later check honestly answer "was the reference
# model itself still faithful at the time this historical case was built,
# or had it already drifted since".
BASELINE_HISTORY_DIR = RUNTIME_DIR / "baseline_history"
(BASELINE_HISTORY_DIR / "config").mkdir(parents=True, exist_ok=True)
(BASELINE_HISTORY_DIR / "network").mkdir(parents=True, exist_ok=True)

_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_name(value: str) -> str:
    return _NAME_SAFE_RE.sub("_", str(value or "").strip()) or "unknown"


def _baseline_history_path(kind: str, node_name: str) -> Path:
    return BASELINE_HISTORY_DIR / kind / f"{_safe_name(node_name)}.jsonl"


def _archive_outgoing_baseline(kind: str, outgoing: dict | None) -> None:
    """Appends the baseline that is ABOUT TO BE overwritten -- call this
    BEFORE writing a new one. A no-op the first time a baseline is ever
    captured for a node (nothing to archive yet) -- honest, not a bug."""
    node_name = (outgoing or {}).get("node_name")
    if not outgoing or not node_name:
        return
    with _lock:
        with _baseline_history_path(kind, node_name).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(outgoing, default=str) + "\n")


def _baseline_history_entries(kind: str, node_name: str) -> list[dict]:
    path = _baseline_history_path(kind, node_name)
    if not path.is_file():
        return []
    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = _safe(lambda l=line: json.loads(l))
        if parsed:
            entries.append(parsed)
    return entries


def _orphaned_baselines_by_name(kind: str, node_name: str) -> list[dict]:
    """Baselines captured for an OLD instance_id of this same conceptual
    node, from before a redeployment, that were never re-captured since --
    they sit in CONFIG_BASELINES_DIR/NETWORK_BASELINES_DIR keyed by an
    instance_id that no longer matches any live node, so `get_config_baseline
    (current_node_id)` alone would never find them, honestly but
    incompletely. A full directory scan is cheap here: this project has at
    most a handful of these files (one per node ever manually baselined),
    not thousands. Without this, a real, still-meaningful baseline would be
    reported as "unknown" purely because of which VM happened to be live
    when it was captured -- exactly the kind of gap this feature exists to
    catch, so it would be self-defeating to leave it open."""
    directory = CONFIG_BASELINES_DIR if kind == "config" else NETWORK_BASELINES_DIR
    found: list[dict] = []
    for path in directory.glob("*.json"):
        data = _safe(lambda p=path: json.loads(p.read_text(encoding="utf-8")))
        if data and data.get("node_name") == node_name:
            found.append(data)
    return found


def _baseline_as_of(kind: str, node_name: str, as_of_iso: str, current: dict | None) -> dict | None:
    """The baseline really in effect at `as_of_iso` -- the latest archived
    (or current, or orphaned-by-redeployment) baseline whose own
    captured_at_utc is <= as_of_iso. `None`, honestly, if no baseline that
    old is known (the reference model might not have existed yet, or
    archiving wasn't live back then) -- never falls back to the current
    baseline just because it's the only one we have, since that would
    silently hide a real "can't tell" as a false "no gap"."""
    candidates = list(_baseline_history_entries(kind, node_name))
    candidates.extend(_orphaned_baselines_by_name(kind, node_name))
    if current:
        candidates.append(current)
    candidates = [c for c in candidates if c.get("captured_at_utc") and str(c["captured_at_utc"]) <= as_of_iso]
    if not candidates:
        return None
    return max(candidates, key=lambda c: c["captured_at_utc"])


def capture_config_baseline(node_id: str) -> dict:
    """Deliberate, separate action -- never captured as a side effect of a
    routine check, same principle already used for the PLC baseline (see
    _check_plc_state's docstring)."""
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}
    files = _collect_config_files(node)
    if not files:
        return {"ok": False, "error": "no Suricata/Wazuh rule files were readable on this node -- is the tooling probe reachable?"}
    _archive_outgoing_baseline("config", get_config_baseline(node_id))
    baseline = {"node_id": node_id, "node_name": node.get("name"), "captured_at_utc": _utc_now(), "files": files}
    _config_baseline_path(node_id).write_text(json.dumps(baseline, indent=2, default=str), encoding="utf-8")
    return {"ok": True, "baseline": baseline}


def get_config_baseline(node_id: str) -> dict | None:
    path = _config_baseline_path(node_id)
    if not path.is_file():
        return None
    return _safe(lambda: json.loads(path.read_text(encoding="utf-8")))


def check_config_integrity(node_id: str) -> dict:
    """On-demand only -- deliberately NEVER folded into check_node_state() or
    the continuous monitor loop. node_health's tooling probe this reuses runs
    a full remote script with a 120s timeout reading several files over SSH
    (node_health_api.py:1435) -- by far the heaviest single signal this
    module touches, heavier even than the live clock read. A human (or the
    dashboard's own button) must ask for this explicitly, exactly like the
    campaign-reproducibility and scenario-snapshot checks already work."""
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}

    baseline = get_config_baseline(node_id)
    if not baseline:
        return {"ok": False, "error": f"no config baseline captured yet for {node_id} -- capture one first"}

    scope_id = _node_scope_id(node_id)
    _register_scope(scope_id, "node", node.get("name") or node_id)

    current_files = _collect_config_files(node)
    baseline_files = baseline.get("files") or {}

    differences = []
    for path, baseline_hash in baseline_files.items():
        current_hash = current_files.get(path)
        if current_hash is None:
            differences.append({"path": path, "reason": "no_longer_readable", "baseline_hash": baseline_hash[:16], "current_hash": None})
        elif current_hash != baseline_hash:
            differences.append({"path": path, "reason": "content_changed", "baseline_hash": baseline_hash[:16], "current_hash": current_hash[:16]})
    # A brand-new file not present at baseline time is not itself flagged --
    # only files present at baseline time that changed or disappeared are a
    # real integrity concern; a new rule file is a routine deployment event.

    diverged = bool(differences)
    state = {
        "node_id": node_id,
        "node_name": node.get("name"),
        "checked_at": _utc_now(),
        "baseline_captured_at_utc": baseline.get("captured_at_utc"),
        "files_tracked": len(baseline_files),
        "diverged": diverged,
        "differences": differences,
    }

    events: list[dict] = []
    if diverged:
        events.append(_record_event(
            scope_id, "config_integrity_changed",
            node_id=node_id, node_name=node.get("name"),
            differences=differences,
            evidence=f"{len(differences)} Suricata/Wazuh file(s) changed vs. the baseline captured {baseline.get('captured_at_utc')}",
        ))
    state["new_events"] = events
    _append_state_history(f"{node_id}:config", state)
    return {"ok": True, "state": state}


def get_config_integrity_state(node_id: str) -> dict:
    last = _last_state(f"{node_id}:config")
    if not last:
        return {"ok": False, "error": f"no config integrity check recorded yet for {node_id} -- capture a baseline and run a check first"}
    events = get_events(_node_scope_id(node_id), limit=50)
    return {"ok": True, "state": last, "recent_events": events}


# Two volatile-evidence categories NIST SP 800-86 ("Guide to Integrating
# Forensic Techniques into Incident Response", Section 5.1.2 "Volatile
# Data") names explicitly as significant types to collect during live
# response: "Network Connections" -- "a list of the ports and IP addresses
# at which the system is listening for connections" -- and "Login Sessions"
# -- "information about currently logged-in users... Some OSs have built-in
# commands for listing the currently logged on users, such as the w command
# for UNIX systems" (Section 5.2). Confirmed via a real Explore pass before
# writing any code that neither existed anywhere in this platform. Reuses
# node_health's probe script (now extended with `ss -tulwn`/`who`, same SSH
# session as everything else it already reads) -- a FRESH, non-cached read
# every time, same "never trust a stale cache" principle already used for
# the clock check, since a stale port list could hide a backdoor opened
# since the last probe.
NETWORK_BASELINES_DIR = RUNTIME_DIR / "network_baselines"
NETWORK_BASELINES_DIR.mkdir(parents=True, exist_ok=True)


def _network_baseline_path(node_id: str) -> Path:
    return NETWORK_BASELINES_DIR / f"{node_id}.json"


def _parse_listening_ports(lines: list[str]) -> list[str]:
    """Reduces raw `ss -tulwn` rows to a stable, comparable
    "<proto> <local_address:port>" list -- skips the header row (starts with
    "Netid") and anything too short to be a real data row."""
    ports: set[str] = set()
    for line in lines or []:
        parts = line.split()
        if not parts or parts[0] == "Netid" or len(parts) < 5:
            continue
        ports.add(f"{parts[0]} {parts[4]}")
    return sorted(ports)


def _check_network_exposure(node: dict) -> dict:
    """_probe_node_live's real parsed data lives one level deeper than its
    own top-level return (payload["probe"]["tables"], not payload["tables"]
    -- confirmed against node_health_api._node_metrics_row's own real usage
    of the same function, node_health_api.py:1297-1298, after an empty-result
    bug surfaced this during live verification)."""
    from app_core.infrastructure.node_health.node_health_api import _probe_node_live
    payload = _safe(lambda: _probe_node_live(node, timeout=30)) or {}
    tables = (payload.get("probe") or {}).get("tables") or {}
    return {
        "listening_ports": _parse_listening_ports(tables.get("listening_ports")),
        "login_sessions": [line.strip() for line in (tables.get("login_sessions") or []) if line.strip()],
    }


def capture_network_baseline(node_id: str) -> dict:
    """Deliberate, separate action -- same principle as the PLC and config
    baselines (never captured as a side effect of a routine check)."""
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}
    exposure = _check_network_exposure(node)
    _archive_outgoing_baseline("network", get_network_baseline(node_id))
    baseline = {
        "node_id": node_id, "node_name": node.get("name"), "captured_at_utc": _utc_now(),
        "listening_ports": exposure["listening_ports"],
    }
    _network_baseline_path(node_id).write_text(json.dumps(baseline, indent=2, default=str), encoding="utf-8")
    return {"ok": True, "baseline": baseline}


def get_network_baseline(node_id: str) -> dict | None:
    path = _network_baseline_path(node_id)
    if not path.is_file():
        return None
    return _safe(lambda: json.loads(path.read_text(encoding="utf-8")))


def check_network_exposure(node_id: str) -> dict:
    """On-demand only -- same tier as check_config_integrity, for the same
    reason: a fresh SSH probe, deliberately excluded from check_node_state()
    and the continuous monitor.

    Listening ports get a real divergence check against an explicit
    baseline (a NEW listening port is a classic backdoor/persistence
    indicator -- a port that DISAPPEARED is not flagged, same "only a
    regression is a problem" principle as tool_regression). Login sessions
    are deliberately NOT compared against a baseline or auto-flagged as a
    divergence: unlike a listening port, a legitimate investigator SSHing in
    to administer the lab is a routine, expected event here, not an anomaly
    -- flagging every login would be noise, not evidence. They are still
    recorded as real, honest data (who was logged in, when) for a human or
    the reconstruction pipeline to interpret in context, exactly the
    forensic question NIST SP 800-86 describes this data as answering
    ("confirm whether a user account was active when a given event
    occurred")."""
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}

    baseline = get_network_baseline(node_id)
    if not baseline:
        return {"ok": False, "error": f"no network baseline captured yet for {node_id} -- capture one first"}

    scope_id = _node_scope_id(node_id)
    _register_scope(scope_id, "node", node.get("name") or node_id)

    exposure = _check_network_exposure(node)
    baseline_ports = set(baseline.get("listening_ports") or [])
    current_ports = set(exposure["listening_ports"])
    new_ports = sorted(current_ports - baseline_ports)

    diverged = bool(new_ports)
    state = {
        "node_id": node_id,
        "node_name": node.get("name"),
        "checked_at": _utc_now(),
        "baseline_captured_at_utc": baseline.get("captured_at_utc"),
        "listening_ports": exposure["listening_ports"],
        "new_listening_ports": new_ports,
        "login_sessions": exposure["login_sessions"],
        "diverged": diverged,
    }

    events: list[dict] = []
    if diverged:
        events.append(_record_event(
            scope_id, "listening_port_added",
            node_id=node_id, node_name=node.get("name"),
            new_listening_ports=new_ports,
            evidence=f"{len(new_ports)} new listening port(s) vs. the baseline captured {baseline.get('captured_at_utc')}: {', '.join(new_ports)}",
        ))
    state["new_events"] = events
    _append_state_history(f"{node_id}:network", state)
    return {"ok": True, "state": state}


def get_network_exposure_state(node_id: str) -> dict:
    last = _last_state(f"{node_id}:network")
    if not last:
        return {"ok": False, "error": f"no network exposure check recorded yet for {node_id} -- capture a baseline and run a check first"}
    events = get_events(_node_scope_id(node_id), limit=50)
    return {"ok": True, "state": last, "recent_events": events}


def _reality_gap_for_kind(kind: str, node: dict, node_id: str, as_of_iso: str, current_files_or_ports) -> dict:
    """Shared comparison core for both baseline kinds -- `current_files_or_ports`
    is already-collected real data (files dict for "config", ports list for
    "network"), fetched once by the caller so config+network never trigger
    two separate SSH probes when both are requested together."""
    node_name = node.get("name") or node_id
    current = (get_config_baseline(node_id) if kind == "config" else get_network_baseline(node_id)) or {}
    as_of_baseline = _baseline_as_of(kind, node_name, as_of_iso, current or None)
    if as_of_baseline is None:
        return {
            "kind": kind, "ok": True, "comparable": False,
            "reason": f"no {kind} baseline is known to have existed at or before this case's own time -- cannot say whether the reference model drifted since then.",
        }
    if kind == "config":
        as_of_files = as_of_baseline.get("files") or {}
        current_files = current_files_or_ports or {}
        changed = sorted(p for p in as_of_files if current_files.get(p) != as_of_files.get(p))
        removed = sorted(p for p in as_of_files if p not in current_files)
        added = sorted(p for p in current_files if p not in as_of_files)
        drifted = bool(changed or removed)
    else:
        as_of_ports = set(as_of_baseline.get("listening_ports") or [])
        current_ports = set(current_files_or_ports or [])
        added = sorted(current_ports - as_of_ports)
        removed = sorted(as_of_ports - current_ports)
        changed = []
        drifted = bool(added or removed)
    return {
        "kind": kind, "ok": True, "comparable": True,
        "as_of_baseline_captured_at_utc": as_of_baseline.get("captured_at_utc"),
        "current_baseline_captured_at_utc": current.get("captured_at_utc"),
        "same_baseline": as_of_baseline.get("captured_at_utc") == current.get("captured_at_utc"),
        "drifted": drifted,
        "changed": changed, "added": added, "removed": removed,
    }


def compute_reality_gap(node_name: str, as_of_iso: str) -> dict:
    """investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md, hueco #5
    (Sammartino & Pasquini's "contextual reality gap"): does the twin's OWN
    reference model of "normal" for this node still match what it really
    was at the time a historical case was built, or has the reference model
    itself silently drifted since then -- a different question from "did
    the fault/attack diverge from the model" (hueco #1), which is what
    every other divergence check in this module already answers.

    Takes a node NAME, not an instance_id, and resolves it against the
    CURRENT live node list: a historical case's own host instance_id is for
    a VM already destroyed and redeployed since (every repetition gets
    fresh VMs) and would never resolve to anything live -- "PLC_Instance",
    unlike any one instance_id, is the stable identity that actually
    persists across redeployments, which is the whole point of this check.

    Deliberately on-demand only, same tier as check_config_integrity/
    check_network_exposure: both require a fresh, real SSH probe of the
    CURRENT node (file hashes + `ss -tulwn`), so this is never folded into
    check_node_state(), the continuous monitor, or the reconstruction
    timeline payload -- a human (or Reconstruction View's own toggle) must
    ask for it explicitly.

    `as_of_iso` is normally a historical case's own real timestamp (e.g. its
    `case_created_utc`), not "now" -- comparing against "now" would be
    comparing the current baseline against itself, trivially always zero
    gap, which is still an honest answer when truly requested that way."""
    node = _resolve_node_by_name(node_name)
    if not node:
        return {"ok": False, "error": f"no live node is currently named '{node_name}' -- the scenario may not be deployed right now"}
    node_id = node.get("id")
    current_files = _collect_config_files(node)
    exposure = _check_network_exposure(node)
    return {
        "ok": True,
        "node_id": node_id,
        "node_name": node.get("name"),
        "as_of": as_of_iso,
        "checked_at": _utc_now(),
        "config": _reality_gap_for_kind("config", node, node_id, as_of_iso, current_files),
        "network": _reality_gap_for_kind("network", node, node_id, as_of_iso, exposure["listening_ports"]),
    }


SCENARIO_SCOPE = "scenario"


_scenario_ref_cache: dict | None = None
_scenario_ref_cache_at: float = 0.0
SCENARIO_REF_CACHE_TTL_SECONDS = 120


def _latest_scenario_snapshot_ref() -> dict | None:
    """Cheap, read-only reference to the most recently captured whole-scenario
    snapshot. scenario_snapshot.list_snapshots() loads and parses EVERY
    stored snapshot manifest to build its summaries (143 real manifests as of
    this development effort, and growing) just so this function can take the
    first one -- real, measurable cost, never SSH but not free either. A
    short in-process cache avoids repeating that full directory scan for
    every node checked in the same tick (5 nodes x 1 scan each, otherwise) --
    this is not for freshness (2 minutes is plenty for a reference field that
    is purely informational; the real check-for-divergence path is
    check_scenario_state(), never cached)."""
    global _scenario_ref_cache, _scenario_ref_cache_at
    now = time.time()
    if _scenario_ref_cache is not None and (now - _scenario_ref_cache_at) < SCENARIO_REF_CACHE_TTL_SECONDS:
        return _scenario_ref_cache
    from app_core.infrastructure.scenario_snapshot.service import list_snapshots
    summaries = _safe(list_snapshots, [])
    ref = None
    if summaries:
        latest = summaries[0]
        ref = {
            "snapshot_id": latest.get("snapshot_id"),
            "captured_at_utc": latest.get("captured_at_utc"),
            "scenario_id": latest.get("scenario_id"),
        }
    _scenario_ref_cache = ref
    _scenario_ref_cache_at = now
    return ref


def check_scenario_state() -> dict:
    """Reads the two most recently captured whole-scenario snapshots
    (scenario_snapshot.service: list_snapshots/get_snapshot -- the same hash
    already used for Level C reproducibility comparisons, never recomputed
    here) and, if their hash differs, reuses diff_snapshots() (already
    built) for a real, structured, informational diff.

    The formal divergence event is deliberately NOT "the hash changed" --
    verified against 143 real snapshots from this development effort's own
    Level C campaign that the hash (and fields like attack_execution_count/
    campaign_count) changes between essentially every pair of snapshots,
    since those are platform-wide monotonic counters, not scenario health
    indicators. The real, honest signal already computed by scenario_snapshot
    itself is `validation.overall_reproduction_ready` -- that is what fires
    an event here, mirroring the same readiness gate Level C already uses
    before allowing a campaign to proceed."""
    from app_core.infrastructure.scenario_snapshot.service import diff_snapshots, get_snapshot, list_snapshots
    summaries = _safe(list_snapshots, [])
    if not summaries:
        return {"ok": False, "error": "no scenario snapshots captured yet -- capture one via scenario_snapshot first"}

    _register_scope(SCENARIO_SCOPE, "scenario", "Whole-scenario snapshot")

    latest = summaries[0]
    latest_full = _safe(lambda: get_snapshot(latest["snapshot_id"])) or {}
    latest_hash = (latest_full.get("hashes") or {}).get("snapshot_hash")
    latest_validation = latest_full.get("validation") or {}

    diff = None
    hash_changed = False
    if len(summaries) >= 2:
        previous = summaries[1]
        previous_full = _safe(lambda: get_snapshot(previous["snapshot_id"])) or {}
        previous_hash = (previous_full.get("hashes") or {}).get("snapshot_hash")
        if previous_hash and latest_hash and previous_hash != latest_hash:
            hash_changed = True
            diff = _safe(lambda: diff_snapshots(previous["snapshot_id"], latest["snapshot_id"]))

    events: list[dict] = []
    if latest_validation.get("overall_reproduction_ready") is False:
        events.append(_record_event(
            SCENARIO_SCOPE, "scenario_validation_degraded",
            snapshot_id=latest.get("snapshot_id"),
            validation=latest_validation,
            evidence=f"snapshot {latest.get('snapshot_id')}: validation.overall_reproduction_ready=False",
        ))

    state = {
        "checked_at": _utc_now(),
        "latest_snapshot_id": latest.get("snapshot_id"),
        "latest_snapshot_hash": latest_hash,
        "latest_captured_at": latest.get("captured_at_utc"),
        "total_snapshots": len(summaries),
        "hash_changed_vs_previous": hash_changed,
        "diff_vs_previous": diff,
        "overall_reproduction_ready": latest_validation.get("overall_reproduction_ready"),
        "new_events": events,
    }
    _append_state_history(SCENARIO_SCOPE, state)
    return {"ok": True, "state": state}


def get_scenario_state() -> dict:
    last = _last_state(SCENARIO_SCOPE)
    if not last:
        return {"ok": False, "error": "no scenario check recorded yet -- call check-scenario first"}
    events = get_events(SCENARIO_SCOPE, limit=50)
    return {"ok": True, "state": last, "recent_events": events}


def check_node_state(node_id: str, *, include_clock: bool = True, include_plc: bool = True, source: str = "on_demand") -> dict:
    """Main entrypoint: pulls fresh tool inventory + real service-liveness
    (+ PLC control-law state for role=plc, unless include_plc=False) (+ a
    LIVE clock reading, unless include_clock=False), compares against the
    last state THIS module recorded for this node, and records a formal
    divergence event only for a real regression (something that used to be
    installed and no longer is, or a service that was active and now isn't)
    or a currently-measured problem (clock degraded, PLC control law
    violated) -- never a false positive from a node still mid-deployment on
    its very first check, since there is nothing yet to regress against.

    `include_clock=False`/`include_plc=False` are used by the continuous
    background monitor (start_continuous_monitor) to skip the two most
    expensive real signals -- a full time_sync_preflight.sh SSH round-trip,
    and a batch of real mbpoll reads against the PLC -- on every periodic
    tick. Both stay available on demand via the API/dashboard, at full cost,
    whenever a human explicitly asks for them. This keeps the automatic
    background tick to cheap, local-file reads plus a couple of fast
    `systemctl is-active` calls -- deliberately minimal given this host also
    runs the rest of the platform and has hit real memory pressure before."""
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}

    scope_id = _node_scope_id(node_id)
    _register_scope(scope_id, "node", node.get("name") or node_id)

    tools = _check_tools(node)
    services = _check_services(node)
    clock = _check_clock(node) if include_clock else None
    plc = _check_plc_state(node) if include_plc else None
    scenario_snapshot = _latest_scenario_snapshot_ref()

    state = {
        "node_id": node_id,
        "node_name": node.get("name"),
        "role": node.get("role"),
        "checked_at": _utc_now(),
        "source": source,
        "tools": tools,
        "services": services,
        "clock": clock,
        "plc": plc,
        "scenario_snapshot": scenario_snapshot,
    }

    events: list[dict] = []
    previous = _last_state(node_id)
    if previous:
        prev_installed = set((previous.get("tools") or {}).get("installed_tools") or [])
        now_installed = set(tools["installed_tools"])
        regressed = sorted(prev_installed - now_installed)
        if regressed:
            events.append(_record_event(
                scope_id, "tool_regression",
                node_id=node_id, node_name=node.get("name"),
                tools_no_longer_installed=regressed,
                evidence=f"Installed as of {previous.get('checked_at')}, missing as of {state['checked_at']}",
            ))

    if services["down"]:
        events.append(_record_event(
            scope_id, "service_down",
            node_id=node_id, node_name=node.get("name"),
            services_down=services["down"], services_checked=services["checked"],
            evidence=f"systemctl is-active reports {', '.join(services['down'])} not active on {node.get('name')}",
        ))

    if clock is not None and clock["degraded"]:
        events.append(_record_event(
            scope_id, "clock_offset_degraded",
            node_id=node_id, node_name=node.get("name"),
            offset_ms=clock["offset_ms"], threshold_ms=CLOCK_OFFSET_DEGRADED_MS,
            evidence=f"Live clock offset {clock['offset_ms']}ms exceeds the {CLOCK_OFFSET_DEGRADED_MS}ms threshold",
        ))

    if plc and plc.get("control_law") and plc["control_law"].get("diverged") is True:
        events.append(_record_event(
            scope_id, "plc_control_law_violation",
            node_id=node_id, node_name=node.get("name"),
            control_law=plc["control_law"],
            evidence="evaluate_control_law_consistency() found the PLC doing something its own program would never produce on its own",
        ))
    if plc and plc.get("comparison") and plc["comparison"].get("diverged") is True:
        events.append(_record_event(
            scope_id, "plc_baseline_divergence",
            node_id=node_id, node_name=node.get("name"),
            comparison=plc["comparison"],
            evidence="compare_against_baseline() found a static-variable mismatch against the captured baseline",
        ))

    state["new_events"] = events
    _append_state_history(node_id, state)
    return {"ok": True, "state": state}


def get_twin_state(node_id: str) -> dict:
    last = _last_state(node_id)
    if not last:
        return {"ok": False, "error": f"no state recorded yet for node {node_id} -- call check first"}
    events = get_events(_node_scope_id(node_id), limit=50)
    # config_integrity/network_exposure are deliberately never computed as
    # part of check_node_state (see check_config_integrity/check_network_exposure
    # docstrings -- both are heavy, on-demand-only SSH probes, excluded from
    # the continuous monitor for cost reasons). Merging in whatever each one
    # last found is a cheap local-file read (_last_state is just a JSONL
    # tail), never a new SSH round-trip, so this adds zero cost to every
    # Digital Twin View poll -- it only makes the persistent state the 3D
    # view already fetches actually carry these two sensors' last real
    # result, instead of silently dropping them (previously: a node could
    # have a config_integrity_changed/listening_port_added divergence on
    # record, visible only as a ~12s event flash, with the persistent lamp
    # color never reflecting it at all).
    state = dict(last)
    state["config_integrity"] = _last_state(f"{node_id}:config")
    state["network_exposure"] = _last_state(f"{node_id}:network")
    state["resource_usage"] = _last_state(f"{node_id}:resources")
    state["network_latency"] = _last_state(f"{node_id}:network_rtt")
    return {"ok": True, "state": state, "recent_events": events}


# ---------------------------------------------------------------------------
# Resource-exhaustion sensor (CPU/RAM/disk) -- built after a real gap was
# found live: cpu_ram_stress had no forensic_twin sensor at all, so applying
# it never produced anything stronger than the neutral "fault_injection_applied"
# marker, and the node's own health lamp stayed "healthy" throughout a real,
# measurable CPU spike. On-demand only (a real SSH probe, same tier as
# check_config_integrity/check_network_exposure, excluded from the
# continuous monitor), reusing node_health's OWN already-computed severity
# thresholds (_node_metrics_row: ok<85%, warning 85-95%, critical >=95% for
# cpu/memory/disk usage) rather than inventing a second set of numbers --
# the exact same real signal the fault catalog already names as
# cpu_ram_stress/disk_fill's effectiveness_signal, and the exact same live
# (never stale-cache) read fault_injection.service._snapshot_resources
# already performs for its own before/after comparison.
# ---------------------------------------------------------------------------


def _check_resource_usage(node: dict) -> dict:
    from app_core.infrastructure.node_health import node_health_api
    row = _safe(lambda: node_health_api._probe_cached_or_refresh(node, refresh=True, max_age_seconds=0)) or {}
    return {
        "cpu_usage_pct": row.get("cpu_usage_pct"), "cpu_severity": row.get("cpu_severity", "unknown"),
        "memory_usage_pct": row.get("memory_usage_pct"), "memory_severity": row.get("memory_severity", "unknown"),
        "disk_root_use_pct": row.get("disk_root_use_pct"), "disk_severity": row.get("disk_severity", "unknown"),
    }


def check_resource_usage(node_id: str) -> dict:
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}
    scope_id = _node_scope_id(node_id)
    _register_scope(scope_id, "node", node.get("name") or node_id)
    usage = _check_resource_usage(node)
    diverged = any(usage.get(k) in ("warning", "critical") for k in ("cpu_severity", "memory_severity", "disk_severity"))
    state = {"node_id": node_id, "node_name": node.get("name"), "checked_at": _utc_now(), "diverged": diverged, **usage}
    events: list[dict] = []
    if diverged:
        events.append(_record_event(
            scope_id, "resource_exhaustion_degraded",
            node_id=node_id, node_name=node.get("name"), **usage,
            evidence=(
                f"cpu={usage.get('cpu_usage_pct')}% ({usage.get('cpu_severity')}), "
                f"memory={usage.get('memory_usage_pct')}% ({usage.get('memory_severity')}), "
                f"disk={usage.get('disk_root_use_pct')}% ({usage.get('disk_severity')})"
            ),
        ))
    state["new_events"] = events
    _append_state_history(f"{node_id}:resources", state)
    return {"ok": True, "state": state}


def get_resource_usage_state(node_id: str) -> dict:
    last = _last_state(f"{node_id}:resources")
    if not last:
        return {"ok": False, "error": f"no resource usage check recorded yet for {node_id} -- run a check first"}
    events = get_events(_node_scope_id(node_id), limit=50)
    return {"ok": True, "state": last, "recent_events": events}


# ---------------------------------------------------------------------------
# Network-latency sensor -- closes another real gap: network_fault (tc qdisc
# netem delay/loss) had no forensic_twin sensor at all, only its own
# before/after ping shown in the Fault Injection dashboard's effectiveness
# column, never fed into the twin views. Reuses fault_injection's own
# _snapshot_network_rtt (ping -c 4 to 8.8.8.8 from the node -- the exact
# traffic path network_fault's own tc rule affects) and the SAME real
# threshold measure_effectiveness already uses for this fault's own
# effectiveness verdict (a >50ms increase), never an invented second number.
#
# Deliberately NOT a fixed absolute threshold (e.g. "RTT > 50ms = bad"):
# background internet RTT to an external host varies by real network
# conditions far more than a local SSH/Modbus round trip does, so a fixed
# floor would be noisy. Instead this keeps a persisted per-node "floor" --
# the lowest RTT ever observed for that node while NOT diverged -- and
# compares each new reading against that floor. The floor is only ever
# updated by a healthy reading, never by a degraded one, so a SECOND check
# taken while the fault is still active (e.g. this view's own 60s
# bootstrap-recheck cooldown) still correctly compares against the real
# pre-fault floor instead of against its own already-degraded previous
# reading -- a real bug that comparing against "the last reading" instead of
# a stable floor would have caused (the lamp would have incorrectly cleared
# on the second check even with the fault still applied, since two
# already-degraded readings rarely differ from each other by >50ms).
# ---------------------------------------------------------------------------

NETWORK_RTT_FLOOR_DIR = RUNTIME_DIR / "network_rtt_floor"
NETWORK_RTT_FLOOR_DIR.mkdir(parents=True, exist_ok=True)
NETWORK_RTT_DEGRADED_DELTA_MS = 50


def _network_rtt_floor_path(node_id: str) -> Path:
    return NETWORK_RTT_FLOOR_DIR / f"{node_id}.json"


def _get_network_rtt_floor(node_id: str) -> float | None:
    data = _safe(lambda: json.loads(_network_rtt_floor_path(node_id).read_text(encoding="utf-8")))
    return (data or {}).get("floor_ms")


def _update_network_rtt_floor(node_id: str, ping_avg_ms: float) -> None:
    current = _get_network_rtt_floor(node_id)
    new_floor = ping_avg_ms if current is None else min(current, ping_avg_ms)
    _network_rtt_floor_path(node_id).write_text(
        json.dumps({"floor_ms": new_floor, "updated_at_utc": _utc_now()}), encoding="utf-8"
    )


def check_network_latency(node_id: str) -> dict:
    node = _resolve_node(node_id)
    if not node:
        return {"ok": False, "error": f"node not found or not live: {node_id}"}
    from app_core.infrastructure.fault_injection.service import _snapshot_network_rtt
    scope_id = _node_scope_id(node_id)
    _register_scope(scope_id, "node", node.get("name") or node_id)
    reading = _safe(lambda: _snapshot_network_rtt(node)) or {}
    ping_avg_ms = reading.get("ping_avg_ms")
    floor_ms = _get_network_rtt_floor(node_id)
    diverged = ping_avg_ms is not None and floor_ms is not None and (ping_avg_ms - floor_ms) > NETWORK_RTT_DEGRADED_DELTA_MS
    if ping_avg_ms is not None and not diverged:
        _update_network_rtt_floor(node_id, ping_avg_ms)
    state = {
        "node_id": node_id, "node_name": node.get("name"), "checked_at": _utc_now(),
        "ping_avg_ms": ping_avg_ms, "floor_ms": floor_ms, "diverged": diverged,
    }
    events: list[dict] = []
    if diverged:
        events.append(_record_event(
            scope_id, "network_latency_degraded",
            node_id=node_id, node_name=node.get("name"),
            ping_avg_ms=ping_avg_ms, floor_ms=floor_ms,
            evidence=f"ping RTT {ping_avg_ms}ms vs. this node's own established floor {floor_ms}ms (+{ping_avg_ms - floor_ms:.1f}ms)",
        ))
    state["new_events"] = events
    _append_state_history(f"{node_id}:network_rtt", state)
    return {"ok": True, "state": state}


def get_network_latency_state(node_id: str) -> dict:
    last = _last_state(f"{node_id}:network_rtt")
    if not last:
        return {"ok": False, "error": f"no network latency check recorded yet for {node_id} -- run a check first"}
    events = get_events(_node_scope_id(node_id), limit=50)
    return {"ok": True, "state": last, "recent_events": events}


# ---------------------------------------------------------------------------
# Fault-injection lifecycle visibility: makes EVERY real fault_injection
# apply/revert (app_core/infrastructure/fault_injection/service.py) show up
# in the 3D twin views, not only the 3-4 fault types that happen to also
# trip one of the divergence rules above. Deliberately a SEPARATE event
# family (event_type prefixed "fault_injection_", never "divergence" --
# applying a fault on purpose during an experiment is not itself forensic
# evidence of an anomaly) so the frontend can render it with a neutral/info
# treatment instead of painting the node red the way a real divergence does.
# Called by fault_injection.apply_fault/revert_fault on a REAL success only
# (never on a failed apply/revert -- nothing actually happened to show).
# ---------------------------------------------------------------------------

FAULT_RELEVANT_CHECKS = {
    # fault_id -> (which on-demand sensor this fault's effect would actually
    # show up in, seconds to wait before checking) so a node's persistent
    # state (not just the transient event) picks up the change -- without
    # adding a single new SSH probe for fault types that have no matching
    # sensor at all (credential_session -- deliberately never auto-flagged,
    # see check_network_exposure's own docstring).
    #
    # "full" means check_node_state() itself -- the SAME function the
    # continuous monitor and the dashboard's own "Check a node" button call,
    # covering clock + PLC control-law/baseline together. This was a REAL
    # gap found live: clock_skew and plc_io_manipulation both change
    # something check_node_state measures (clock offset / PLC static
    # variables), but neither ever triggered a fresh check_node_state() run
    # on their own -- the persistent state shown in Digital Twin View stayed
    # stale until the continuous monitor's next (up to 30min-away, and
    # clock/PLC are only read on its much rarer "heavy" tier) tick, or until
    # a human manually clicked "Check a node". A prior version of this
    # comment incorrectly assumed plc_io_manipulation's effect appeared
    # automatically; it did, in an earlier verification, but only because
    # that check was triggered manually as a separate step, not by anything
    # automatic. cpu_ram_stress gets a real delay too: inject_cpu_stress.sh
    # launches stress-ng in the background and returns almost instantly
    # (nohup ... & disown), so checking with zero delay would measure CPU
    # usage from BEFORE stress-ng has actually ramped up -- confirmed live:
    # the node's health lamp stayed "healthy" through a real stress run
    # because of exactly this race. disk_fill/clock_skew/plc_io_manipulation's
    # own inject scripts all run synchronously (the file write / clock set /
    # Modbus write all complete before the script returns), so no delay is
    # needed for the FAULT to be real by then -- the delay given to those is
    # purely to keep check_node_state's own ~20-30s SSH+Modbus cost off the
    # apply/revert HTTP response, never to wait for the fault itself.
    # network_fault's own inject script (tc qdisc add ... netem) applies
    # synchronously -- no delay needed for the fault itself -- but check_network_latency's
    # own ping takes a few seconds, kept off the HTTP response like everything else here.
    # detection_outage stops a service check_node_state ALWAYS reads (services
    # is never gated behind include_clock/include_plc) -- "full" here simply
    # means "run the check now" instead of waiting for the next bootstrap/
    # continuous cycle to notice it.
    "config_tamper": ("config", 0),
    "rogue_port": ("network", 0),
    "cpu_ram_stress": ("resources", 5),
    "disk_fill": ("resources", 0),
    "clock_skew": ("full", 1),
    "plc_io_manipulation": ("full", 1),
    "network_fault": ("latency", 0),
    "detection_outage": ("full", 1),
}


def _run_relevant_check(node_id: str, sensor: str) -> None:
    if sensor == "config" and get_config_baseline(node_id):
        check_config_integrity(node_id)
    elif sensor == "network" and get_network_baseline(node_id):
        check_network_exposure(node_id)
    elif sensor == "resources":
        check_resource_usage(node_id)
    elif sensor == "latency":
        check_network_latency(node_id)
    elif sensor == "full":
        check_node_state(node_id, source="fault_injection_followup")


def record_fault_injection_lifecycle(node_id: str, fault_id: str, phase: str, injection_id: str, **extra) -> dict:
    """phase is "applied" or "reverted". Never raises -- a visualization hook
    must never be able to break a real fault injection; callers wrap this in
    their own best-effort call regardless, but this is defensive on its own
    too."""
    try:
        node = _resolve_node(node_id)
        if not node:
            return {"ok": False}
        scope_id = _node_scope_id(node_id)
        _register_scope(scope_id, "node", node.get("name") or node_id)
        event = _record_event(
            scope_id, f"fault_injection_{phase}",
            node_id=node_id, node_name=node.get("name"),
            fault_id=fault_id, injection_id=injection_id,
            evidence=f"fault_injection.{fault_id} {phase} on {node.get('name')}",
            **extra,
        )
        spec = FAULT_RELEVANT_CHECKS.get(fault_id)
        if spec:
            sensor, delay_seconds = spec
            # ALWAYS via a background Timer, even for delay_seconds=0 --
            # every one of these sensors does a real SSH (or SSH+Modbus,
            # for "full") round trip, and this whole function runs
            # synchronously inside apply_fault/revert_fault, right before
            # they return their HTTP response. A direct inline call here
            # would make every Apply/Revert click in the dashboard hang for
            # however long that probe takes -- Timer(0, ...) still starts a
            # new thread and returns immediately, it just runs with no
            # artificial delay added on top.
            threading.Timer(delay_seconds, lambda: _safe(lambda: _run_relevant_check(node_id, sensor))).start()
        return {"ok": True, "event": event}
    except Exception:
        return {"ok": False}


def check_campaign_reproducibility(job_id: str) -> dict:
    """Reuses level_c_orchestrator.get_comparison_report() -- never
    recomputes CPR/WCPR itself."""
    from app_core.infrastructure.level_c_orchestrator.service import get_comparison_report
    report = _safe(lambda: get_comparison_report(job_id))
    if not report:
        return {"ok": False, "error": f"no comparison report available yet for job {job_id}"}
    scope_id = job_id
    _register_scope(scope_id, "campaign", job_id)
    events: list[dict] = []
    if report.get("all_delta_wcpr_acceptable") is False:
        events.append(_record_event(
            scope_id, "reproducibility_degraded",
            job_id=job_id, comparison_report=report,
            evidence=f"all_delta_wcpr_acceptable=False, max_delta_wcpr={report.get('max_delta_wcpr')}",
        ))
    return {"ok": True, "report": report, "new_events": events}


def list_known_scopes() -> dict:
    return _safe(lambda: json.loads(KNOWN_SCOPES_PATH.read_text(encoding="utf-8")), {}) or {}


def list_recent_events(limit: int = 50) -> list[dict]:
    scopes = list_known_scopes()
    all_events: list[dict] = []
    for scope_id in scopes:
        all_events.extend(get_events(scope_id, limit=limit))
    all_events.sort(key=lambda e: e.get("generated_at_utc") or "", reverse=True)
    return all_events[:limit]


# ---------------------------------------------------------------------------
# CASE/UCO export.
#
# CASE (Cyber-investigation Analysis Standard Expression, caseontology.org)
# and UCO (Unified Cyber Ontology, unifiedcyberontology.org) are the real
# published ontologies for exchanging forensic/cyber-investigation data as
# JSON-LD. The @context below uses the REAL, verified namespace URIs
# (checked live against a real CASE example at caseontology.org/examples --
# not guessed), and each event is serialized as a real
# `case-investigation:InvestigativeAction` using its real property names
# (uco-core:name/description, uco-action:startTime/endTime/instrument/object)
# exactly as CASE's own published example structures one.
#
# This is deliberately a MINIMAL, HONEST pilot, not a claim of full CASE/UCO
# compliance: it does not model uco-observable facets for the underlying
# tool-inventory/clock/PLC data, and the raw event payload (fields specific
# to forensic_twin's own divergence rules, which have no equivalent core
# UCO/CASE class) is kept under a clearly separate, explicitly-labeled
# extension property (forensic-twin:rawEvent) rather than invented as a fake
# core UCO/CASE term -- CASE's own design explicitly supports extension
# ontologies for exactly this situation.
# ---------------------------------------------------------------------------

CASE_UCO_CONTEXT = {
    "kb": "https://forge-vi.local/kb/",
    "forensic-twin": "https://forge-vi.local/ontology/forensic-twin#",
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-tool": "https://ontology.unifiedcyberontology.org/uco/tool/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}

_TOOL_KB_ID = "kb:configuredtool-forensic-twin"


def _xsd_datetime(value: str | None) -> dict | None:
    if not value:
        return None
    return {"@type": "xsd:dateTime", "@value": value}


def _event_to_investigative_action(event: dict) -> dict:
    event_id = f"kb:investigativeaction-{event.get('scope_id', 'unknown')}-{event.get('generated_at_utc', '')}".replace(":", "-").replace(" ", "")
    ts = _xsd_datetime(event.get("generated_at_utc"))
    action: dict = {
        "@id": event_id,
        "@type": "case-investigation:InvestigativeAction",
        "uco-core:name": event.get("event_type"),
        "uco-core:description": event.get("evidence") or "",
        "uco-action:instrument": {"@id": _TOOL_KB_ID},
        "uco-action:object": [{"@id": f"kb:scope-{event.get('scope_id')}"}],
    }
    if ts:
        action["uco-action:startTime"] = ts
        action["uco-action:endTime"] = ts
    # Extension property, explicitly namespaced as our own -- never presented
    # as a core UCO/CASE term. Keeps the full original event (every field
    # already real and already verified elsewhere in this module) accessible
    # without losing information in the translation to JSON-LD.
    action["forensic-twin:rawEvent"] = event
    return action


def export_case_uco(scope_id: str | None = None, limit: int = 100) -> dict:
    """Real JSON-LD export of forensic_twin's own divergence events -- never
    recomputes anything, just reformats what get_events()/list_recent_events()
    already return into the real CASE/UCO structure above."""
    events = get_events(scope_id, limit=limit) if scope_id else list_recent_events(limit=limit)
    graph = [
        {
            "@id": _TOOL_KB_ID,
            "@type": "uco-tool:ConfiguredTool",
            "uco-core:name": "FORGE-VI Forensic Twin",
            "uco-core:description": "Read-only expected-vs-real state aggregator; see app_core/infrastructure/forensic_twin/README.md",
        },
    ]
    graph.extend(_event_to_investigative_action(e) for e in events)
    return {"@context": CASE_UCO_CONTEXT, "@graph": graph}


# ---------------------------------------------------------------------------
# Continuous background monitor.
#
# gunicorn runs this app as several worker processes (4 in this deployment,
# same as memory_watchdog's own documented limitation), each importing this
# module independently. memory_watchdog accepts one independent thread per
# worker because its checks are free (a local /proc/meminfo read). This
# module's checks are NOT free -- a real SSH command per node, and a real
# Modbus read for the PLC -- so running the same periodic loop 4x in
# parallel against the same live infrastructure would be exactly the kind of
# "cargar el sistema" this whole session has deliberately avoided.
#
# Fixed with a real cross-process primitive already used elsewhere in this
# codebase for the same kind of problem (forensics_api.py uses fcntl.flock
# for custody-log write safety): whichever worker's thread wins a
# non-blocking exclusive flock on its own lock file becomes the sole leader
# and runs the loop; the other workers' threads fail to acquire the lock and
# exit immediately, doing nothing. The lock is released automatically by the
# OS if the leader worker process dies or is recycled, so gunicorn replacing
# a worker naturally lets a different one take over on next start.
# ---------------------------------------------------------------------------

# Heavy signals (clock time-sync script, PLC batch of mbpoll reads) are real
# but expensive -- excluded from EVERY tick, but not from the continuous
# monitor altogether: they run every Nth tick instead, so the "3am test"
# (does anything notice a real problem with nobody watching) still applies
# to them, just at a slower cadence than tools/services. 4 ticks * 1800s =
# every 2 hours -- still far cheaper than running them every 30 min.
HEAVY_CHECK_EVERY_N_TICKS = 4

_continuous_lock = threading.Lock()
_continuous_started = False
_leader_lock_fh = None  # kept open for the process lifetime -- closing it would release the flock
_last_tick_at: str | None = None
_last_tick_summary: dict | None = None
_tick_count = 0


def _try_become_leader() -> bool:
    global _leader_lock_fh
    fh = open(LEADER_LOCK_PATH, "w")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return False
    fh.write(f"pid={os.getpid()} started_at={_utc_now()}\n")
    fh.flush()
    _leader_lock_fh = fh
    return True


def _continuous_tick(include_heavy: bool) -> dict:
    """One real round. Every known node always gets tools + real
    service-liveness (local file reads plus a handful of fast
    `systemctl is-active` calls). `include_heavy=True` additionally runs the
    two expensive real signals (the full clock time-sync script, the PLC's
    batch of mbpoll reads) that every other tick skips -- see
    HEAVY_CHECK_EVERY_N_TICKS. Plus a scenario-wide check (cheap, no new
    capture, cached snapshot reference)."""
    from app_core.infrastructure.node_health.node_health_api import _list_nodes
    nodes = _safe(_list_nodes, [])
    results = []
    for node in nodes:
        node_id = node.get("id")
        if not node_id:
            continue
        result = _safe(lambda nid=node_id: check_node_state(
            nid, include_clock=include_heavy, include_plc=include_heavy, source="continuous",
        ))
        results.append({"node_id": node_id, "ok": bool(result and result.get("ok"))})
    scenario_result = _safe(check_scenario_state)
    # Intervention Ledger checkpoint (investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md
    # gap #3): reuses this ALREADY-SCHEDULED tick instead of a new thread --
    # a hash chain alone can't detect truncate-then-forge, this gives
    # verify_chain_against_checkpoints() something real to compare against.
    from app_core.infrastructure.intervention_ledger.service import write_checkpoint
    _safe(write_checkpoint)
    # Attestation-pipeline retention safety valve (foc_reconstruction/attestation_retention.py,
    # investigacion_y_novedad, user question 2026-10-10 re: alert_correlation.json's real
    # past 6.4GB size) -- reuses this already-scheduled tick, real no-op unless the real
    # combined size of attack/outputs + alerts_store actually exceeds the real cap.
    from app_core.infrastructure.foc_reconstruction.attestation_retention import maybe_cleanup_attestation_sources
    _safe(maybe_cleanup_attestation_sources)
    return {
        "nodes_checked": len(results),
        "nodes": results,
        "scenario_ok": bool(scenario_result and scenario_result.get("ok")),
        "included_heavy_checks": include_heavy,
    }


def _continuous_loop() -> None:
    global _last_tick_at, _last_tick_summary, _tick_count
    logger = logging.getLogger("app_logger")
    while True:
        try:
            _tick_count += 1
            include_heavy = (_tick_count % HEAVY_CHECK_EVERY_N_TICKS == 0)
            summary = _continuous_tick(include_heavy)
            _last_tick_at = _utc_now()
            _last_tick_summary = summary
            logger.info(
                f"[forensic_twin] continuous tick #{_tick_count}: {summary['nodes_checked']} node(s) checked"
                f"{' (incl. clock+PLC)' if include_heavy else ''}"
            )
        except Exception as exc:
            logger.warning(f"[forensic_twin] continuous tick failed: {exc}")
        time.sleep(CONTINUOUS_CHECK_INTERVAL_SECONDS)


def start_continuous_monitor() -> bool:
    """Starts the continuous monitor thread -- but only actually does
    anything in the single gunicorn worker that wins the flock race (see
    module docstring above). Returns True if THIS call started the loop in
    THIS process, False otherwise (already running in this process, or
    another worker already holds the lock)."""
    global _continuous_started
    with _continuous_lock:
        if _continuous_started:
            return False
        if not _try_become_leader():
            return False
        _continuous_started = True
    t = threading.Thread(target=_continuous_loop, daemon=True, name="forensic-twin-continuous-monitor")
    t.start()
    return True


def get_continuous_monitor_status() -> dict:
    return {
        "leader_in_this_worker": _continuous_started,
        "interval_seconds": CONTINUOUS_CHECK_INTERVAL_SECONDS,
        "heavy_check_interval_seconds": CONTINUOUS_CHECK_INTERVAL_SECONDS * HEAVY_CHECK_EVERY_N_TICKS,
        "tick_count_in_this_worker": _tick_count,
        "last_tick_at": _last_tick_at,
        "last_tick_summary": _last_tick_summary,
    }
