"""
Level C Campaign Orchestrator
==============================
Manages a full scenario redeployment cycle:
  Destroy → Clean → Deploy IT → Deploy OT → Wait Nodes →
  Install Tools → Run Level B → Capture Snapshot
  (repeat N times, then compare snapshots)

Scientific tool installation order — 4 phases, strictly sequential:

  Phase 1 – IT SERVERS (monitor, then attack)
      Wazuh Manager and Caldera Server must be fully running before any
      agent anywhere tries to connect.
        monitor: wazuh (Manager), nmap
        attack:  caldera (Server), caldera_ot_plugins, mbpoll, nmap

  Phase 2 – IT VICTIM
      All victim tools installed after servers are up.
      Suricata runs before agents (IDS ready first).
        victim: suricata, nmap, wazuh_agent, caldera_agent

  Phase 3 – OT BASE TOOLS (plc, then fuxa, then scada)
      Suricata sensor installed before wazuh_agent on each OT node.
        plc/fuxa/scada: suricata, wazuh_agent

  Phase 4 – OT CONFIGS
      ALL phase-3 tools (suricata + wazuh_agent) must be present.
      rollback_wazuh_suricata_integration requires BOTH.
      wazuh_fim_realtime requires wazuh_agent to be enrolled.
        plc/fuxa/scada: rollback_suricata_ping_detection,
                        rollback_suricata_modbus_register_detection,
                        rollback_wazuh_suricata_integration,
                        wazuh_fim_realtime

  Within each phase, nodes are processed in order:
      monitor → attack → victim → plc → fuxa → scada
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve()
PROJECT_ROOT = _HERE.parents[3]

JOBS_DIR = PROJECT_ROOT / "runtime" / "level_c_jobs"
TOOLS_INSTALLED_DIR = PROJECT_ROOT / "tools-installer" / "installed"
TOOLS_TMP_DIR = PROJECT_ROOT / "tools-installer-tmp"
TOOLS_SCRIPTS_DIR = PROJECT_ROOT / "tools-installer" / "scripts"
SNAPSHOTS_DIR = PROJECT_ROOT / "runtime" / "scenario_snapshots"
SCENARIO_FILE = PROJECT_ROOT / "scenario" / "scenario_file.json"
SCENARIO_FILE_BACKUP = PROJECT_ROOT / "app_core" / "infrastructure" / "redeployment_module" / "scenario_file.json"
INDUSTRIAL_FILE = PROJECT_ROOT / "industrial-scenario" / "scenarios" / "industrial_industrial_file.json"
DEPLOY_IT_SCRIPT = PROJECT_ROOT / "app_core" / "infrastructure" / "redeployment_module" / "deploy_scenario_from_json.sh"
DEPLOY_PLC_SCRIPT = PROJECT_ROOT / "industrial-scenario" / "PLC" / "deploy_plc_scenario.sh"
DEPLOY_FUXA_SCRIPT = PROJECT_ROOT / "industrial-scenario" / "FUXA" / "deploy_fuxa_vm.sh"
ADMIN_OPENRC = PROJECT_ROOT / "admin-openrc.sh"
DEPLOY_STATUS_FILE = PROJECT_ROOT / "scenario" / "deployment_status.json"

# ---------------------------------------------------------------------------
# Sentinel values
# ---------------------------------------------------------------------------
CONFIRMATION_TOKEN = "LAUNCH_LEVEL_C"

PHASES = [
    "IDLE",
    "VALIDATING",
    "DESTROYING",
    "CLEANING",
    "DEPLOYING_IT",
    "DEPLOYING_OT",
    "WAITING_NODES",
    "INSTALLING_TOOLS",
    "VERIFYING_MONITORING",
    "RUNNING_LEVEL_B",
    "WAITING_LEVEL_B",
    "CAPTURING_SNAPSHOT",
    "COMPARING",
    "COMPLETED",
    "FAILED",
    "ABORTED",
]

# Scientific tool dependency order: (instance_role_pattern, tool_name, phase)
# role_pattern is matched as a substring of the instance name (case-insensitive).
# Installation rule: monitor COMPLETE → attack COMPLETE → victim COMPLETE → PLC+FUXA tools → PLC+FUXA configs
# Each node group must finish entirely before moving to the next.
_TOOL_SCIENTIFIC_ORDER: list[tuple[str, str, int]] = [
    # ── Phase 1: MONITOR ─────────────────────────────────────────────────────
    # Wazuh Manager and all monitor tools MUST be done before any agent installs.
    ("monitor",  "wazuh",                1),
    ("monitor",  "nmap",                 1),

    # ── Phase 2: ATTACK ──────────────────────────────────────────────────────
    # Caldera Server + OT plugins ready before caldera_agent on victim/OT.
    ("attack",   "caldera",              2),
    ("attack",   "caldera_ot_plugins",   2),
    ("attack",   "mbpoll",               2),
    ("attack",   "nmap",                 2),

    # ── Phase 3: VICTIM ──────────────────────────────────────────────────────
    # Suricata (IDS) before agents — sensor running before agents enrol.
    ("victim",   "suricata",             3),
    ("victim",   "nmap",                 3),
    ("victim",   "wazuh_agent",          3),   # connects to Wazuh Manager (phase 1 done)
    ("victim",   "caldera_agent",        3),   # connects to Caldera Server (phase 2 done)

    # ── Phase 4: OT BASE TOOLS ───────────────────────────────────────────────
    # All IT nodes done → now OT. suricata before wazuh_agent on each OT node.
    ("plc",      "suricata",             4),
    ("fuxa",     "suricata",             4),
    ("scada",    "suricata",             4),
    ("plc",      "wazuh_agent",          4),
    ("fuxa",     "wazuh_agent",          4),
    ("scada",    "wazuh_agent",          4),

    # ── Phase 5: OT CONFIGS ──────────────────────────────────────────────────
    # All OT base tools (suricata + wazuh_agent) installed and enrolled.
    # rollback_wazuh_suricata_integration needs BOTH active on the node.
    ("plc",      "rollback_suricata_ping_detection",            5),
    ("plc",      "rollback_suricata_modbus_register_detection", 5),
    ("plc",      "rollback_wazuh_suricata_integration",         5),
    ("plc",      "wazuh_fim_realtime",                          5),
    ("fuxa",     "rollback_suricata_ping_detection",            5),
    ("fuxa",     "rollback_suricata_modbus_register_detection", 5),
    ("fuxa",     "rollback_wazuh_suricata_integration",         5),
    ("fuxa",     "wazuh_fim_realtime",                          5),
    ("scada",    "rollback_suricata_ping_detection",            5),
    ("scada",    "rollback_suricata_modbus_register_detection", 5),
    ("scada",    "rollback_wazuh_suricata_integration",         5),
    ("scada",    "wazuh_fim_realtime",                          5),
]

# Node installation priority — enforces the within-phase order.
# Lower value = installed first.  Nodes not listed sort last.
_NODE_INSTALL_ORDER = ["monitor", "attack", "victim", "plc", "fuxa", "scada"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _log(state: dict, level: str, msg: str, extra: dict | None = None) -> None:
    entry = {"ts": _utc_now(), "level": level, "msg": msg}
    if extra:
        entry["extra"] = extra
    state.setdefault("log", []).append(entry)


def _host_resource_snapshot() -> dict:
    """Cheap, pure-Python snapshot of load/memory/swap/disk on this host.

    2026-09-03: added after a real incident (PLC deploy timing out at 1800s)
    whose root cause -- this host being simultaneously the user's desktop and
    the OpenStack compute node, under load average 8.14 / 8 vCPUs and 68%
    swap at the time -- could only be found by manually running `free`/
    `uptime` after the fact. Reads /proc and statvfs directly instead of
    shelling out to free/uptime/df -- no subprocess spawn, no risk of this
    call itself hanging the orchestrator thread. Failure of any individual
    read is swallowed (returns None for that field) rather than raising --
    a diagnostic snapshot must never be able to break the campaign it is
    trying to help diagnose.
    """
    snap: dict = {}
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        snap["load_1m"], snap["load_5m"], snap["load_15m"] = (float(parts[0]), float(parts[1]), float(parts[2]))
    except Exception:
        pass
    try:
        snap["cpu_count"] = os.cpu_count()
    except Exception:
        pass
    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                meminfo[key] = int(rest.strip().split()[0])  # kB
        total_kb = meminfo.get("MemTotal", 0)
        avail_kb = meminfo.get("MemAvailable", 0)
        swap_total_kb = meminfo.get("SwapTotal", 0)
        swap_free_kb = meminfo.get("SwapFree", 0)
        snap["mem_total_gb"] = round(total_kb / 1024 / 1024, 1)
        snap["mem_available_gb"] = round(avail_kb / 1024 / 1024, 1)
        snap["mem_used_pct"] = round(100 * (1 - avail_kb / total_kb), 1) if total_kb else None
        snap["swap_total_gb"] = round(swap_total_kb / 1024 / 1024, 1)
        snap["swap_used_pct"] = round(100 * (1 - swap_free_kb / swap_total_kb), 1) if swap_total_kb else 0.0
    except Exception:
        pass
    try:
        st = os.statvfs(str(PROJECT_ROOT))
        free_gb = (st.f_bavail * st.f_frsize) / 1024 / 1024 / 1024
        snap["disk_free_gb"] = round(free_gb, 1)
    except Exception:
        pass
    return snap


_ACTIVE_CASE_PTR_PATH = PROJECT_ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store" / "_active_case.txt"


def _process_case_pointer_snapshot() -> dict:
    """Diagnostic sensor: PID of the process executing THIS phase transition,
    plus the raw current value of the global active-case pointer.

    Added 2026-09-14 after two SYNCING_CLOCKS blocks on a live campaign that
    could not be conclusively root-caused after the fact — we could not tell
    whether the process running this job's background thread had changed
    (proving a worker/process restart interrupted and something else resumed
    it) or whether some unrelated, legitimate case was simply active at that
    exact moment. Logging the PID on every phase transition makes a process
    change directly visible by comparing consecutive log lines; logging the
    raw pointer value (not just whether it blocked something) means the
    _active_case_history.jsonl trail (forensics_api.py) can be cross-checked
    against the exact phase timeline. Pure /proc + file read, cannot hang or
    raise in a way that affects the campaign.
    """
    snap: dict = {"pid": os.getpid()}
    try:
        if _ACTIVE_CASE_PTR_PATH.is_file():
            raw = _ACTIVE_CASE_PTR_PATH.read_text(encoding="utf-8").strip()
            snap["active_case_ptr_raw"] = raw or None
            snap["active_case_ptr_exists_as_dir"] = bool(raw) and Path(raw).is_dir()
        else:
            snap["active_case_ptr_raw"] = None
            snap["active_case_ptr_exists_as_dir"] = False
    except Exception:
        pass
    return snap


def _host_snapshot_summary(snap: dict) -> str:
    """One-line human-readable summary of _host_resource_snapshot(), for
    inline log messages (the full dict is still attached as `extra` on the
    log entry for anything that wants the raw numbers)."""
    if not snap:
        return "host snapshot unavailable"
    load = snap.get("load_1m")
    cpus = snap.get("cpu_count")
    load_part = f"load={load}/{cpus}cpu" if load is not None and cpus else "load=?"
    mem_part = f"mem={snap.get('mem_used_pct', '?')}%"
    swap_part = f"swap={snap.get('swap_used_pct', '?')}%"
    disk_part = f"disk_free={snap.get('disk_free_gb', '?')}GB"
    return f"{load_part} {mem_part} {swap_part} {disk_part}"


def _save_state(job_dir: Path, state: dict) -> None:
    # Heartbeat: every save marks the job as "still being worked on" — this is
    # what _recover_orphaned_lc_job compares against, so every call site gets
    # it for free (mirrors job_runner.update_job's same fix, applied here
    # 2026-07-17 after a job from days earlier was found still reporting
    # status=running with no watchdog to catch it).
    state["updated_at"] = _utc_now()
    _write_json(job_dir / "job_state.json", state)


_ORPHAN_LC_JOB_GRACE_SECONDS = 180


def _parse_ts(raw) -> float | None:
    if not raw:
        return None
    try:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def _seconds_between(start_iso, end_iso) -> float | None:
    a = _parse_ts(start_iso)
    b = _parse_ts(end_iso)
    if a is None or b is None:
        return None
    return round(b - a, 3)


def _stage_timeline_total_elapsed(timeline: list[dict] | None, live_anchor_iso: str | None) -> float | None:
    """Total elapsed for a running repetition, computed from its real
    per-stage timeline: first stage's start to either the last stage's
    finish (if everything is done) or a live anchor (the parent job's own
    updated_at heartbeat) if something is still running -- same
    grows-while-alive/freezes-if-dead reasoning as
    campaign_repetitions.service._total_elapsed_seconds() (duplicated here,
    not imported, to avoid a backwards dependency -- campaign_repetitions
    already imports FROM this module). 2026-07-19: user asked for a real
    repetition total in this panel too, not just the repetitions center.
    """
    if not timeline:
        return None
    started = [s.get("started_at") for s in timeline if s.get("started_at")]
    if not started:
        return None
    start = min((_parse_ts(s) for s in started), default=None)
    if start is None:
        return None
    still_running = any(s.get("status") == "running" for s in timeline)
    if still_running:
        end = _parse_ts(live_anchor_iso)
    else:
        finished = [s.get("finished_at") for s in timeline if s.get("finished_at")]
        end = max((_parse_ts(f) for f in finished), default=None) if finished else None
    if end is None:
        return None
    return round(end - start, 3)


def _recover_orphaned_lc_job(state: dict, job_dir: Path) -> dict:
    """Lazy watchdog for Level C jobs, mirroring job_runner._recover_orphaned_job
    (foc_experimentation) and foc_case_analysis._recover_orphaned_analysis_status
    — Level C keeps its own separate file-based job state, so it needed its own
    copy of the same check. If status is still 'running' but nothing has
    touched job_state.json (updated_at, now stamped on every _save_state call)
    in _ORPHAN_LC_JOB_GRACE_SECONDS, seal it as failed with an honest reason
    instead of leaving it reporting as the 'active' campaign forever. Deletes
    nothing, retries nothing.
    """
    status = str(state.get("status") or "").lower()
    if status != "running":
        return state
    last_activity = _parse_ts(state.get("updated_at")) or _parse_ts(state.get("started_at")) or _parse_ts(state.get("created_at"))
    if last_activity is None or (time.time() - last_activity) <= _ORPHAN_LC_JOB_GRACE_SECONDS:
        return state
    phase = state.get("phase") or "unknown"
    reason = (
        f"Level C job state was left in 'running' mode at phase '{phase}', but no update in over "
        f"{_ORPHAN_LC_JOB_GRACE_SECONDS}s. It was likely interrupted by a process/worker restart before "
        "it could finish. Nothing already produced was deleted — review and relaunch manually if needed."
    )
    # Real gap found 2026-10-11 investigating why Reconstruction View showed
    # NO hosts/machines at all for an orphan-killed campaign: the graceful
    # failure path (level_b_ok == False, still inside the live thread) always
    # captures a final scenario snapshot before sealing the job (see the
    # CAPTURING_SNAPSHOT phase above) -- but THIS path runs only after that
    # thread has already died, so it never had the chance. `level_c_snapshot_ids`
    # stayed permanently empty for every orphan-recovered job, and
    # monitor3d._frozen_hosts_for_repetition() depends on exactly that field
    # to draw any host box at all. Fixed the same way: a best-effort snapshot
    # of whatever scenario is STILL live right now (scenario_snapshot.
    # capture_snapshot() is explicitly documented "safe to call from any
    # thread" and has its own internal lock against concurrent captures) --
    # wrapped so a capture failure (e.g. the scenario was already torn down)
    # never blocks sealing the job as failed, the one thing this function
    # must always do.
    if not state.get("level_c_snapshot_ids"):
        try:
            from app_core.infrastructure.scenario_snapshot.service import capture_snapshot
            result = capture_snapshot()
            snap_id = (result or {}).get("snapshot_id")
            if snap_id:
                state["level_c_snapshot_ids"] = [snap_id]
                _log(state, "INFO", f"Orphan recovery: captured a best-effort final scenario snapshot ({snap_id}) so Reconstruction View still has real host data for this campaign.")
        except Exception as exc:
            _log(state, "WARNING", f"Orphan recovery: best-effort snapshot capture failed ({exc}) -- Reconstruction View will have no host/machine data for this campaign.")
    state["status"] = "failed"
    state["error"] = reason
    state["completed_at"] = state.get("completed_at") or _utc_now()
    _log(state, "ERROR", reason)
    _save_state(job_dir, state)
    return state


_heartbeat_touch_lock = threading.Lock()


def _touch_heartbeat(job_dir: Path) -> None:
    """Cheap heartbeat used inside long blocking subprocess waits (see
    _run_cmd's interruptible poll loop below) so a phase that legitimately
    runs longer than _ORPHAN_LC_JOB_GRACE_SECONDS without an explicit
    _save_state/_log call (e.g. _phase_deploy_ot: PLC compiles from source,
    up to 30 min, blocked on subprocess.Popen + thread.join with nothing
    else happening) doesn't get wrongly declared orphaned.

    Root-caused live 2026-07-17: a brand-new campaign was killed ~8 minutes
    in, right as OT deployment started, by exactly this path. The campaign's
    OWN worker (_active_jobs has the live thread) would never do this to
    itself -- get_job_status()/list_jobs() skip the orphan check entirely
    when this worker's thread registry confirms the thread is alive. The
    kill came from a DIFFERENT gunicorn worker (e.g. the Live Campaign
    Status panel's 3s poll landing on a different `-w` process), which has
    no entry for this job_id in ITS OWN _active_jobs and can't verify true
    liveness that way, so it fell back to updated_at staleness -- which had
    gone stale simply because nothing called _save_state during the blocking
    deploy, not because the campaign was actually dead.

    Only touches updated_at on disk via an atomic write, independent of the
    calling thread's own in-memory `state` dict -- can't race with or lose
    that thread's pending log entries, which still flush normally on its own
    next _save_state() call once the blocking phase returns.
    """
    try:
        path = job_dir / "job_state.json"
        with _heartbeat_touch_lock:
            state = _load_json(path)
            if not isinstance(state, dict):
                return
            state["updated_at"] = _utc_now()
            tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False, default=str))
            tmp.replace(path)
    except Exception:
        pass


def _run_cmd(
    cmd: list[str],
    cwd: Path,
    timeout: int = 600,
    job_dir: Path | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr).

    When job_dir is provided the process is launched with Popen and the stop
    flag is polled every 2 s.  If the flag is set the subprocess is terminated
    immediately (returncode -2) so the background thread can exit without
    waiting for the full Terraform/script timeout.
    When job_dir is None the call blocks until completion (legacy behaviour).
    """
    try:
        env = {**os.environ}
        if job_dir is None:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                env=env,
            )
            return proc.returncode, proc.stdout, proc.stderr

        # Interruptible path — poll stop flag every 2 s.
        # setsid: new session so killpg() kills the entire process tree
        # (prevents orphaned SSH children from keeping stdout pipes open).
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            preexec_fn=os.setsid,
        )

        def _kill_group():
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                try:
                    proc.kill()
                except Exception:
                    pass

        def _drain(timeout_s: int = 10) -> tuple[str, str]:
            try:
                return proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                _kill_group()
                return "", ""

        deadline = time.time() + timeout
        last_heartbeat = time.time()
        while proc.poll() is None:
            if time.time() >= deadline:
                _kill_group()
                stdout, stderr = _drain()
                return -1, stdout or "", f"Command timed out after {timeout}s\n{stderr or ''}"
            if _is_stop_requested(job_dir):
                # 2026-09-03: found live -- a tool install (ansible-playbook)
                # that finished successfully at almost the exact same instant
                # a stop was requested got its real rc=0/full clean output
                # discarded here and reported as "failed/skipped", because
                # this branch always returned -2 unconditionally. Re-check
                # proc.poll() right here: if the process already exited on
                # its own between the top-of-loop check and this line,
                # _kill_group() is a no-op on a dead pid and its real
                # returncode/output is what should be honoured, not a
                # synthetic "stopped" result that throws away a genuine
                # success (or a genuine, differently-diagnosable failure).
                if proc.poll() is not None:
                    stdout, stderr = _drain(timeout_s=30)
                    return proc.returncode, stdout or "", stderr or ""
                _kill_group()
                stdout, stderr = _drain()
                return -2, stdout or "", "Process killed: stop requested by user."
            if time.time() - last_heartbeat >= 30:
                _touch_heartbeat(job_dir)
                last_heartbeat = time.time()
            time.sleep(2)

        stdout, stderr = _drain(timeout_s=30)
        return proc.returncode, stdout or "", stderr or ""

    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        return -1, "", str(exc)


def _source_openrc_env() -> dict:
    """Source admin-openrc.sh and return the resulting env vars."""
    if not ADMIN_OPENRC.is_file():
        return dict(os.environ)
    cmd = ["bash", "-c", f"source {ADMIN_OPENRC} >/dev/null 2>&1 && env"]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=10)
        env = dict(os.environ)
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                env[k] = v
        return env
    except Exception:
        return dict(os.environ)


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------

def _phase_validate(state: dict, job_dir: Path, config: dict) -> bool:
    """Check prerequisites before starting any destructive action."""
    _log(state, "INFO", "Validating prerequisites for Level C campaign...")
    errors = []

    # Snapshot must exist
    snaps = sorted(SNAPSHOTS_DIR.glob("SS-*/snapshot_manifest.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not snaps:
        errors.append("No scenario snapshot found. Capture a snapshot first.")
    else:
        snap = _load_json(snaps[0])
        state["source_snapshot_id"] = snap.get("snapshot_id")
        _log(state, "INFO", f"Using source snapshot: {snap.get('snapshot_id')}")

    # IT scenario deploy script must exist
    if not DEPLOY_IT_SCRIPT.is_file():
        errors.append(f"IT deploy script missing: {DEPLOY_IT_SCRIPT.relative_to(PROJECT_ROOT)}")

    # IT scenario file must exist (or restorable from backup)
    if not SCENARIO_FILE.is_file() and not SCENARIO_FILE_BACKUP.is_file():
        errors.append(f"IT scenario file missing: {SCENARIO_FILE.relative_to(PROJECT_ROOT)} (and no backup in redeployment_module)")

    # Campaign must exist and be Level B
    campaign_id = config.get("campaign_id")
    if not campaign_id:
        errors.append("campaign_id is required.")
    else:
        from app_core.infrastructure.foc_experimentation.campaign_service import get_campaign
        camp = get_campaign(campaign_id)
        if not camp:
            errors.append(f"Campaign not found: {campaign_id}")
        elif str(camp.get("level") or camp.get("config", {}).get("level") or "").upper() != "B":
            errors.append(f"Campaign {campaign_id} is not Level B.")
        else:
            attack_id = (camp.get("config") or {}).get("attack_id")
            if not attack_id:
                errors.append(f"Campaign {campaign_id} has no attack_id configured.")
            else:
                _log(state, "INFO", f"Level B campaign OK: {campaign_id} | attack: {attack_id}")

    # Destruction / reconstruction readiness check.
    # Level C destroys the scenario itself in each cycle, so it is valid to start
    # even if the scenario is ALREADY destroyed from a previous failed cycle — as
    # long as the reconstruction blueprint exists so we can redeploy.
    try:
        from app_core.infrastructure.foc_experimentation.scenario_destruction_service import validate_scenario_destruction
        from app_core.infrastructure.foc_experimentation.scientific_memory_sync import get_active_scenario_memory_hint
        val = validate_scenario_destruction()
        if val.get("error") == "scenario_not_found":
            # No scenario card at all — genuinely blocked
            errors.append(f"Scenario card not found. Deploy and snapshot a scenario first.")
        elif val.get("error"):
            errors.append(f"Scenario destruction validation: {val.get('message')}")
        elif not val.get("ready"):
            blocking = val.get("missing_blocking", [])
            # If the only blocker is active_scenario_exists, it means the scenario
            # was already destroyed by a previous Level C cycle. This is fine — we
            # skip destruction and go straight to redeployment.
            only_missing_active = blocking == ["active_scenario_exists"] or (
                len(blocking) == 1 and "active_scenario" in blocking[0]
            )
            if only_missing_active:
                _log(state, "INFO", "Scenario already destroyed from previous cycle. Redeployment will proceed directly.")
            else:
                errors.append(f"Scenario not ready for Level C: missing {blocking}. Capture a snapshot first.")
        else:
            _log(state, "INFO", "Scenario destruction validation: READY")
    except Exception as exc:
        errors.append(f"Scenario destruction validation failed: {exc}")

    if errors:
        for e in errors:
            _log(state, "ERROR", e)
        state["validation_errors"] = errors
        return False

    state["validation_errors"] = []
    _log(state, "INFO", "Validation passed.")
    return True


def _all_openstack_servers(env: dict | None = None) -> list[dict]:
    """Return all OpenStack servers as list of {id, name, status} dicts."""
    try:
        rc, stdout, _ = _run_cmd(
            ["openstack", "server", "list", "--format", "json"],
            cwd=PROJECT_ROOT, timeout=45,
        )
        if rc != 0 or not stdout.strip():
            return []
        import json as _json
        return [{"id": s.get("ID", ""), "name": s.get("Name", ""), "status": s.get("Status", "")}
                for s in _json.loads(stdout)]
    except Exception:
        return []


def _scenario_node_names() -> set[str]:
    """Collect all known IT node names from scenario files (current + backup)."""
    names: set[str] = set()
    for src in (SCENARIO_FILE, SCENARIO_FILE_BACKUP):
        if src.is_file():
            try:
                import json as _json
                sc = _json.loads(src.read_text())
                for n in sc.get("nodes", []):
                    if n.get("name"):
                        names.add(n["name"].strip())
            except Exception:
                pass
    return names


def _openstack_sweep_delete(state: dict, rep_num: int, env: dict) -> None:
    """After the main destroy, delete any surviving scenario instances directly.

    Targets: known OT names + all IT node names from scenario files.
    This catches nodes from previous deployments that are no longer tracked
    by Terraform and would otherwise survive the standard destroy script.
    """
    ot_fixed = {"PLC_Instance", "FUXA_Instance", "SCADA_Instance"}
    it_names = _scenario_node_names()
    target_names = ot_fixed | it_names

    servers = _all_openstack_servers(env)
    remaining = [s for s in servers if s["name"] in target_names and s["status"] not in ("DELETED", "SOFT_DELETED")]

    if not remaining:
        _log(state, "INFO", f"  [Sweep] No surviving scenario instances found.")
        return

    _log(state, "WARN", f"  [Sweep] {len(remaining)} instance(s) survived standard destroy: {[s['name'] for s in remaining]}")
    for srv in remaining:
        _log(state, "INFO", f"  [Sweep] Deleting {srv['name']} ({srv['id']})...")
        rc, _, stderr = _run_cmd(
            ["openstack", "server", "delete", srv["id"]],
            cwd=PROJECT_ROOT, timeout=60,
        )
        if rc == 0:
            _log(state, "INFO", f"  [Sweep] Deleted {srv['name']} OK.")
        elif "No Server found" in (stderr or ""):
            # 2026-09-03: this is not a real failure -- it means the instance
            # was already gone (deleted by the standard destroy step itself,
            # or by a concurrent cleanup) by the time this forced-delete ran;
            # the "survived standard destroy" listing above is a snapshot
            # that can race with reality by a few seconds. Logged as INFO,
            # not WARN, so this stops reading as an error when nothing was
            # actually left over to clean up.
            _log(state, "INFO", f"  [Sweep] {srv['name']} was already gone by the time of the forced delete — nothing to do.")
        else:
            _log(state, "WARN", f"  [Sweep] Delete {srv['name']} returned rc={rc}: {stderr[:120]}")


def _wait_openstack_clean(state: dict, job_dir: Path, rep_num: int, env: dict, timeout_s: int = 240) -> bool:
    """Poll OpenStack until all known scenario instances are fully gone."""
    ot_fixed = {"PLC_Instance", "FUXA_Instance", "SCADA_Instance"}
    target_names = ot_fixed | _scenario_node_names()
    deadline = time.time() + timeout_s
    poll = 10

    _log(state, "INFO", f"  [Wait] Polling OpenStack until all scenario instances are gone (up to {timeout_s}s)...")
    while time.time() < deadline:
        if _is_stop_requested(job_dir):
            _log(state, "WARN", "  [Wait] Stop requested — aborting OpenStack clean wait.")
            return False
        servers = _all_openstack_servers(env)
        alive = [s for s in servers if s["name"] in target_names and s["status"] not in ("DELETED", "SOFT_DELETED")]
        if not alive:
            _log(state, "INFO", "  [Wait] OpenStack is clean — no scenario instances remaining.")
            return True
        _log(state, "INFO", f"  [Wait] Still waiting: {[s['name']+'/'+s['status'] for s in alive]}")
        state["updated_at"] = _utc_now()
        _save_state(job_dir, state)
        time.sleep(poll)

    # One last check
    servers = _all_openstack_servers(env)
    alive = [s for s in servers if s["name"] in target_names and s["status"] not in ("DELETED", "SOFT_DELETED")]
    if alive:
        _log(state, "ERROR", f"  [Wait] Timeout: instances still present after {timeout_s}s: {[s['name'] for s in alive]}")
        return False
    return True


def _phase_destroy(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Destroy IT + OT scenario.

    Strategy:
    1. Run destroy_full_scenario() (Terraform + OT named deletes).
    2. Do a sweep-delete of any surviving scenario instances (catches stale
       nodes from older deployments not tracked by current Terraform state).
    3. Poll OpenStack until zero scenario instances remain.

    Never skip based on scientific memory alone — always verify via OpenStack.
    """
    _log(state, "INFO", f"[Rep {rep_num}] Destroying active scenario (IT + OT)...")

    env = _source_openrc_env()

    # Step 1: run the standard destroy service
    try:
        from app_core.infrastructure.foc_experimentation.scenario_destruction_service import destroy_full_scenario
        result = destroy_full_scenario(
            confirmation="OK",
            operator=f"level_c_orchestrator_rep_{rep_num}",
        )
        if result.get("error") and result["error"] != "scenario_not_found":
            _log(state, "WARN", f"Destroy service: {result.get('message')} — continuing with sweep.")
        elif not result.get("error"):
            destroyed = result.get("resources_destroyed", [])
            failed = result.get("resources_failed", [])
            _log(state, "INFO", f"Destroy service: {len(destroyed)} destroyed, {len(failed)} failed.")
            for f in failed:
                _log(state, "WARN", f"  Destroy warning: {f}")
    except Exception as exc:
        _log(state, "WARN", f"Destroy service exception (continuing with sweep): {exc}")

    # Step 2: sweep any survivors (stale nodes from previous deployments)
    _openstack_sweep_delete(state, rep_num, env)

    # Step 3: wait for OpenStack to confirm all instances are gone
    clean = _wait_openstack_clean(state, job_dir, rep_num, env)
    if not clean:
        _log(state, "ERROR", "OpenStack still has scenario instances after destroy+sweep (or stop requested). Aborting.")
        return False

    _log(state, "INFO", f"[Rep {rep_num}] Destroy complete — OpenStack confirmed clean.")

    # Step 4: release orphaned floating IPs (port=None) to prevent quota exhaustion.
    # Each deploy cycle consumes floating IPs; without this cleanup they accumulate
    # and block PLC/FUXA from getting floating IPs on the next deploy.
    try:
        _rc, fips_raw, _ = _run_cmd(
            ["openstack", "floating", "ip", "list", "--format", "json"],
            cwd=PROJECT_ROOT, timeout=30,
        )
        import json as _json
        fips = _json.loads(fips_raw) if fips_raw else []
        orphaned = [f for f in fips if not f.get("Port")]
        released = 0
        for fip in orphaned:
            rc2, _, _ = _run_cmd(
                ["openstack", "floating", "ip", "delete", fip["ID"]],
                cwd=PROJECT_ROOT, timeout=15,
            )
            if rc2 == 0:
                released += 1
        if orphaned:
            _log(state, "INFO",
                 f"[Rep {rep_num}] Released {released}/{len(orphaned)} orphaned floating IPs → quota freed.")
        else:
            _log(state, "INFO", f"[Rep {rep_num}] No orphaned floating IPs found.")
    except Exception as exc:
        _log(state, "WARN", f"Could not release orphaned floating IPs: {exc}")

    # Step 5: release orphaned Neutron ports (no device attached) to prevent
    # the private subnet's IP pool from silently filling up.
    # 2026-07-26: confirmed live -- when an instance is destroyed, its Neutron
    # port does not always get cleaned up automatically. These leftover ports
    # keep holding a private-subnet address forever (device_id="" and
    # device_owner="" -- never a DHCP/router/floating-ip-gateway port, those
    # always have a device_owner starting with "network:"). Found the private
    # subnet (192.168.100.0/24, 253 usable addresses) at 254/253 ports --
    # completely full, with `openstack server list` showing ZERO real
    # instances -- meaning every single occupied address was a zombie. This
    # silently blocked ANY new instance from getting a private IP at all
    # (confirmed and fixed live with the user's explicit authorization: "si
    # ves que son mi puesro... borralos... y pon mecanismo de limpieza").
    # Only ever targets ports with BOTH device_id and device_owner empty --
    # never touches a port that's actually in use or a special network port.
    try:
        _rc2, ports_raw, _ = _run_cmd(
            ["openstack", "port", "list", "--format", "json"],
            cwd=PROJECT_ROOT, timeout=30,
        )
        ports = _json.loads(ports_raw) if ports_raw else []
        orphaned_ports = [
            p for p in ports
            if not p.get("Device ID") and not p.get("Device Owner")
        ]
        released_ports = 0
        for p in orphaned_ports:
            rc3, _, _ = _run_cmd(
                ["openstack", "port", "delete", p["ID"]],
                cwd=PROJECT_ROOT, timeout=15,
            )
            if rc3 == 0:
                released_ports += 1
        if orphaned_ports:
            _log(state, "INFO",
                 f"[Rep {rep_num}] Released {released_ports}/{len(orphaned_ports)} orphaned network ports → private IP pool freed.")
        else:
            _log(state, "INFO", f"[Rep {rep_num}] No orphaned network ports found.")
    except Exception as exc:
        _log(state, "WARN", f"Could not release orphaned network ports: {exc}")

    # Reset tool deployment state so the dashboard shows a clean slate.
    # tools-installer-tmp/ holds per-run pending/error entries; stale files
    # from previous runs cause the index to display phantom "pending" counts.
    try:
        tmp_dir = PROJECT_ROOT / "tools-installer-tmp"
        removed = []
        for f in tmp_dir.glob("*.json"):
            f.unlink()
            removed.append(f.name)
        if removed:
            _log(state, "INFO", f"[Rep {rep_num}] Cleared {len(removed)} stale tool-status files from tools-installer-tmp/.")
    except Exception as exc:
        _log(state, "WARN", f"Could not clear tools-installer-tmp/: {exc}")

    # After each redeploy, VMs get new SSH host keys at the same floating IPs.
    # known_hosts uses hashed format (|1|...) — must use ssh-keygen -R per IP,
    # NOT a plaintext grep, or the cleanup silently does nothing.
    try:
        import subprocess as _sp
        removed_count = 0
        for last_octet in range(1, 255):
            ip = f"10.0.2.{last_octet}"
            result = _sp.run(
                ["ssh-keygen", "-R", ip],
                capture_output=True, text=True, timeout=5
            )
            if "found" in result.stdout.lower() or "updated" in result.stdout.lower():
                removed_count += 1
        if removed_count:
            _log(state, "INFO",
                 f"[Rep {rep_num}] Cleared {removed_count} stale 10.0.2.x known_hosts entries (hashed).")
    except Exception as exc:
        _log(state, "WARN", f"Could not clear known_hosts: {exc}")

    return True


def _phase_clean_cases(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Clean disabled/archived cases and old campaign data to start fresh."""
    _log(state, "INFO", f"[Rep {rep_num}] Cleaning old cases and validation reports...")
    try:
        from app_core.infrastructure.foc_experimentation.global_cleanup_service import (
            list_cleanup_inventory,
            execute_cleanup,
        )
        inventory = list_cleanup_inventory()
        items = inventory.get("items", [])
        # Select: disabled cases and validation reports only (NOT campaigns, NOT snapshots)
        eligible_ids = [
            item["item_id"]
            for item in items
            if item.get("deletable") and item.get("item_type") in (
                "forensic_case", "validation_report", "scientific_report"
            )
        ]
        if not eligible_ids:
            _log(state, "INFO", "No eligible items to clean.")
            return True
        result = execute_cleanup(
            selected_item_ids=eligible_ids,
            confirmation="OK",
            operator=f"level_c_orchestrator_rep_{rep_num}",
        )
        deleted = result.get("deleted_count", 0)
        _log(state, "INFO", f"Cleanup completed: {deleted} items deleted.")
        return True
    except Exception as exc:
        _log(state, "WARN", f"Cleanup warning (non-fatal): {exc}")
        return True  # Non-fatal


def _phase_clean_installed_records(state: dict, job_dir: Path, rep_num: int) -> None:
    """Reset 'installed' tool statuses in tools-installer-tmp/*.json to 'pending'
    after destruction, so fresh instances always get all tools re-installed.

    Does NOT touch tools-installer/installed/*.json: those are historical,
    display-only records read by dashboards (keyed by instance_id). Destroyed
    instances get a brand new instance_id on redeploy, so old records simply
    stop matching anything — they never cause a tool to be skipped, so wiping
    them here only destroys legitimate history for instances that were not
    even part of this destroy operation.
    """
    _log(state, "INFO", f"[Rep {rep_num}] Resetting stale tool-install status...")

    # Reset 'installed' → 'pending' in all tools-installer-tmp/*.json so that
    # fresh instances always get all tools re-installed after each redeploy.
    reset_count = 0
    try:
        if TOOLS_TMP_DIR.is_dir():
            for f in TOOLS_TMP_DIR.glob("*.json"):
                try:
                    data = _load_json(f)
                    if not isinstance(data, dict):
                        continue
                    tools = data.get("tools")
                    if not isinstance(tools, dict):
                        continue
                    changed = False
                    for tool, status in tools.items():
                        if status == "installed":
                            tools[tool] = "pending"
                            changed = True
                    if changed:
                        _write_json(f, data)
                        reset_count += 1
                except Exception as exc:
                    _log(state, "WARN", f"  Could not reset statuses in {f.name}: {exc}")
        _log(state, "INFO", f"  Reset 'installed'→'pending' in {reset_count} tmp file(s).")
    except Exception as exc:
        _log(state, "WARN", f"  Tmp file status reset warning: {exc}")


def _phase_deploy_it(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Run the IT scenario deployment script."""
    _log(state, "INFO", f"[Rep {rep_num}] Deploying IT scenario from {SCENARIO_FILE.relative_to(PROJECT_ROOT)}...")
    if not DEPLOY_IT_SCRIPT.is_file():
        _log(state, "ERROR", "IT deploy script not found.")
        return False

    # After each destruction cycle, scenario/scenario_file.json is deleted by the
    # destroy service. Restore it from the redeployment module backup copy.
    if not SCENARIO_FILE.is_file():
        if SCENARIO_FILE_BACKUP.is_file():
            import shutil
            try:
                SCENARIO_FILE.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(SCENARIO_FILE_BACKUP), str(SCENARIO_FILE))
                _log(state, "INFO", f"  Restored scenario_file.json from redeployment module backup.")
            except Exception as exc:
                _log(state, "ERROR", f"  Could not restore scenario_file.json: {exc}")
                return False
        else:
            _log(state, "ERROR", "IT scenario file not found and no backup available.")
            return False

    rc, stdout, stderr = _run_cmd(
        ["bash", str(DEPLOY_IT_SCRIPT), str(SCENARIO_FILE)],
        cwd=PROJECT_ROOT,
        timeout=900,  # 15 min — OpenStack VM creation can be slow
        job_dir=job_dir,  # allow stop to kill the subprocess
    )
    _log(state, "INFO", f"IT deploy exit code: {rc}")
    if stdout:
        for line in stdout.strip().splitlines()[-20:]:
            _log(state, "STDOUT", line)
    if stderr:
        for line in stderr.strip().splitlines()[-10:]:
            _log(state, "STDERR", line)
    if rc != 0:
        _log(state, "ERROR", f"IT deployment failed (rc={rc})")
        return False
    _log(state, "INFO", "IT scenario deployed successfully.")
    return True


def _phase_deploy_ot(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Deploy OT nodes (PLC + FUXA) in parallel to cut total deploy time."""
    _log(state, "INFO", f"[Rep {rep_num}] Deploying OT nodes (PLC + FUXA) in parallel...")
    results: dict = {}
    lock = threading.Lock()

    def _deploy_component(component: str, script: Path) -> None:
        if not script.is_file():
            _log(state, "WARN", f"OT deploy script not found for {component}: {script}")
            with lock:
                results[component] = "script_missing"
            return
        _log(state, "INFO", f"Deploying {component.upper()} via {script.name}...")
        # 2026-09-03: PLC compiles OpenPLC from source (CPU-heavy) while FUXA
        # only pulls a Docker image (~3min) -- both shared one 1800s timeout.
        # Root-caused a real Level B attack failure to this: PLC deploy hit
        # 1800s and was killed mid-script, *after* the VM existed and was
        # SSH-reachable (later tool installs on it succeeded) but *before*
        # the actual OpenPLC ladder-logic program got loaded -- leaving a PLC
        # with no Modbus registers to read/write, so every attack attempt
        # failed with "Could not read pre-state level_max". Host was measured
        # at load average 8.14 / 8 vCPUs and 68% swap at the time -- this
        # host doubles as the user's desktop, so its available compute for
        # compiling PLC varies. Widened PLC's own timeout to give it real
        # margin under current host conditions; left FUXA's short so a
        # genuine FUXA hang is still caught quickly.
        deploy_timeout = 3600 if component == "plc" else 1800
        rc, stdout, stderr = _run_cmd(
            ["bash", str(script)],
            cwd=PROJECT_ROOT,
            timeout=deploy_timeout,
            job_dir=job_dir,
        )
        with lock:
            if rc == 0:
                _log(state, "INFO", f"{component.upper()} deployed OK.")
                results[component] = "ok"
            else:
                # 2026-07-26: this only ever logged stderr -- a real PLC+FUXA
                # simultaneous deploy failure (LC-20260725-223404-85DF, rep 3)
                # showed up as "FUXA deploy failed (rc=1): " with literally
                # nothing after the colon, because these deploy scripts (like
                # deploy_it_scenario above) print their real error text to
                # STDOUT, not stderr -- it was captured in `stdout` here but
                # never logged anywhere, so it was permanently unrecoverable
                # after the fact. Now logs the stdout tail too, same pattern
                # _phase_deploy_it already uses above.
                if stdout:
                    for line in stdout.strip().splitlines()[-20:]:
                        _log(state, "STDOUT", line)
                if stderr:
                    for line in stderr.strip().splitlines()[-10:]:
                        _log(state, "STDERR", line)
                # 2026-09-03: attach a host resource snapshot to this exact
                # failure (extra field only, message text untouched -- other
                # code scans WARN message strings for specific substrings,
                # e.g. campaign_repetitions.service's stage_warnings, so
                # nothing is appended to the text itself). This is the exact
                # failure class root-caused today to host load/swap
                # (LC-20260902-202836-5170: PLC deploy timed out at load
                # 8.14/8cpu, 68% swap) -- next time this happens the
                # correlation is right there instead of needing a manual
                # `free`/`uptime` check after the fact.
                snap = _host_resource_snapshot()
                _log(state, "WARN", f"{component.upper()} deploy failed (rc={rc}): {stderr[:200]}", extra={"host_snapshot": snap})
                _log(state, "INFO", f"  [Host] at failure: {_host_snapshot_summary(snap)}")
                results[component] = f"failed_rc_{rc}"

    components = [("plc", DEPLOY_PLC_SCRIPT), ("fuxa", DEPLOY_FUXA_SCRIPT)]
    threads = [
        threading.Thread(target=_deploy_component, args=(comp, script), daemon=True)
        for comp, script in components
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    state.setdefault("rep_results", {}).setdefault(str(rep_num), {})["ot_deploy"] = results

    # Write industrial scenario + state files so the dashboard shows PLC/FUXA.
    _phase_update_industrial_files(state, rep_num, results)

    # Non-fatal: OT nodes can be missing in some configurations
    return True


INDUSTRIAL_STATE_FILE = PROJECT_ROOT / "industrial-scenario" / "state" / "industrial_state.json"


def _phase_update_industrial_files(state: dict, rep_num: int, ot_results: dict) -> None:
    """After OT deploy, write the two files the dashboard reads:
      - industrial-scenario/scenarios/industrial_industrial_file.json
      - industrial-scenario/state/industrial_state.json

    industrial_industrial_file.json = IT nodes (from scenario_file.json) +
                                      OT nodes (PLC_Instance, FUXA_Instance)
    industrial_state.json            = per-component status + floating IPs
    """
    plc_ok  = ot_results.get("plc")  == "ok"
    fuxa_ok = ot_results.get("fuxa") == "ok"

    plc_info  = _resolve_instance_info("PLC_Instance")  if plc_ok  else {}
    fuxa_info = _resolve_instance_info("FUXA_Instance") if fuxa_ok else {}

    # ── 1. industrial_state.json ─────────────────────────────────────────────
    industrial_state: dict = {}

    if plc_ok and plc_info:
        industrial_state["plc"] = {
            "instance": {
                "status":      "created",
                "instance_id": plc_info.get("id"),
                "name":        "PLC_Instance",
                "ip_floating": plc_info.get("ip_floating"),
                "ip_private":  plc_info.get("ip_private"),
                "last_error":  None,
            },
            "tool": {
                "name":        "openplc",
                "status":      "installed",
                "last_error":  None,
            },
        }

    if fuxa_ok and fuxa_info:
        industrial_state["scada"] = {
            "instance": {
                "status":      "created",
                "instance_id": fuxa_info.get("id"),
                "name":        "FUXA_Instance",
                "ip_floating": fuxa_info.get("ip_floating"),
                "ip_private":  fuxa_info.get("ip_private"),
                "last_error":  None,
            },
            "tool": {
                "name":        "fuxa",
                "status":      "installed",
                "last_error":  None,
            },
        }

    try:
        INDUSTRIAL_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write_json(INDUSTRIAL_STATE_FILE, industrial_state)
        _log(state, "INFO", f"  [OT] industrial_state.json written: plc={plc_ok} fuxa={fuxa_ok}")
    except Exception as exc:
        _log(state, "WARN", f"  [OT] Could not write industrial_state.json: {exc}")

    # ── 2. industrial_industrial_file.json ───────────────────────────────────
    # Base: IT nodes from scenario_file.json (already restored for this rep).
    base = _load_json(SCENARIO_FILE) or {}
    it_nodes: list[dict] = [n for n in (base.get("nodes") or []) if isinstance(n, dict)]
    it_edges: list[dict] = [e for e in (base.get("edges") or []) if isinstance(e, dict)]

    # Collect IT node IDs to build edges towards OT
    it_node_ids = [n["id"] for n in it_nodes if n.get("id")]

    ot_nodes: list[dict] = []
    ot_edges: list[dict] = []

    if plc_ok and plc_info:
        ot_nodes.append({
            "id":         "plc1",
            "name":       "PLC_Instance",
            "type":       "industrial_plc",
            "position":   {"x": 1200, "y": 280},
            "ip_floating": plc_info.get("ip_floating"),
            "ip_private":  plc_info.get("ip_private"),
        })
        for nid in it_node_ids:
            ot_edges.append({"id": f"edge_{nid}_plc1", "source": nid, "target": "plc1"})

    if fuxa_ok and fuxa_info:
        ot_nodes.append({
            "id":         "scada1",
            "name":       "FUXA_Instance",
            "type":       "industrial_scada",
            "position":   {"x": 1200, "y": 160},
            "ip_floating": fuxa_info.get("ip_floating"),
            "ip_private":  fuxa_info.get("ip_private"),
        })
        for nid in it_node_ids:
            ot_edges.append({"id": f"edge_{nid}_scada1", "source": nid, "target": "scada1"})
        # PLC ↔ FUXA edge
        if plc_ok:
            ot_edges.append({"id": "edge_plc1_scada1", "source": "plc1", "target": "scada1"})

    industrial_scenario = {
        "scenario_name": "industrial_file",
        "nodes":         it_nodes + ot_nodes,
        "edges":         it_edges + ot_edges,
        "deployment": {
            "plc_instance": {
                "state":       "created" if plc_ok  else "not_deployed",
                "instance_id": plc_info.get("id"),
                "name":        "PLC_Instance",
                "ip_floating": plc_info.get("ip_floating"),
                "ip_private":  plc_info.get("ip_private"),
            } if plc_ok else {"state": "not_deployed"},
            "scada_instance": {
                "state":       "created" if fuxa_ok else "not_deployed",
                "instance_id": fuxa_info.get("id"),
                "name":        "FUXA_Instance",
                "ip_floating": fuxa_info.get("ip_floating"),
                "ip_private":  fuxa_info.get("ip_private"),
            } if fuxa_ok else {"state": "not_deployed"},
        },
    }

    try:
        INDUSTRIAL_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write_json(INDUSTRIAL_FILE, industrial_scenario)
        _log(state, "INFO",
             f"  [OT] industrial_industrial_file.json written: "
             f"{len(it_nodes)} IT + {len(ot_nodes)} OT nodes, "
             f"plc_ip={plc_info.get('ip_floating')} fuxa_ip={fuxa_info.get('ip_floating')}")
    except Exception as exc:
        _log(state, "WARN", f"  [OT] Could not write industrial_industrial_file.json: {exc}")

    # ── 3. Upload FUXA project rendered with real PLC IP ────────────────────
    plc_ip_val  = plc_info.get("ip_floating")  if plc_ok  else None
    fuxa_ip_val = fuxa_info.get("ip_floating") if fuxa_ok else None
    if plc_ip_val and fuxa_ip_val:
        _phase_deploy_fuxa_project(state, plc_ip_val, fuxa_ip_val)


def _phase_deploy_fuxa_project(state: dict, plc_ip: str, fuxa_ip: str) -> None:
    """Render the FUXA project template with the real PLC floating IP and
    push it to the FUXA VM via its REST API (POST /api/project).

    FUXA stores the project in SQLite databases (_appdata/*.fuxap.db), so
    file-copy approaches don't work — the API is the only correct path.

    Template marker: __PLC_IP__  (replaced in both the Modbus address field
    and the SVG status label inside fuxa_mi_proyecto_simple.json).
    """
    fuxa_dir      = PROJECT_ROOT / "industrial-scenario" / "FUXA"
    template_path = fuxa_dir / "fuxa_mi_proyecto_simple.template.json"
    rendered_path = fuxa_dir / "fuxa_mi_proyecto_simple.json"

    if not template_path.exists():
        _log(state, "WARN", f"  [OT] FUXA template not found: {template_path}")
        return

    try:
        rendered = template_path.read_text().replace("__PLC_IP__", plc_ip)

        # Persist rendered version (real IP) so it can be manually imported into FUXA.
        try:
            rendered_path.write_text(rendered)
        except Exception as exc:
            _log(state, "WARN", f"  [OT] Could not save rendered FUXA project: {exc}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write(rendered)
            tmp_path = f.name

        try:
            # Wait for FUXA HTTP server to be ready (it starts async inside Docker).
            # deploy_fuxa_vm.sh only waits for the FUXA_READY flag, which is set
            # right after 'docker compose up -d' — before FUXA finishes booting.
            _log(state, "INFO", f"  [OT] Waiting for FUXA HTTP server at {fuxa_ip}:1881...")
            fuxa_ready = False
            for attempt in range(24):  # up to 120 s (24 × 5 s)
                rc_check, out_check, _ = _run_cmd(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", "5", f"http://{fuxa_ip}:1881/"],
                    cwd=PROJECT_ROOT, timeout=10,
                )
                if rc_check == 0 and (out_check or "").strip().startswith(("2", "3")):
                    fuxa_ready = True
                    break
                time.sleep(5)

            if not fuxa_ready:
                _log(state, "WARN",
                     f"  [OT] FUXA HTTP server not ready after 120s — skipping project deploy")
            else:
                # POST the rendered project to FUXA's REST API.
                # secureEnabled=false means no auth token required.
                rc, stdout, stderr = _run_cmd(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "-d", f"@{tmp_path}",
                     f"http://{fuxa_ip}:1881/api/project"],
                    cwd=PROJECT_ROOT, timeout=30,
                )
                http_code = (stdout or "").strip()
                if rc == 0 and http_code == "200":
                    _log(state, "INFO",
                         f"  [OT] FUXA project deployed via API → {fuxa_ip}:1881 (PLC_IP={plc_ip})")
                else:
                    _log(state, "WARN",
                         f"  [OT] FUXA API returned HTTP {http_code} (rc={rc}): {stderr}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    except Exception as exc:
        _log(state, "WARN", f"  [OT] Could not deploy FUXA project: {exc}")


def _phase_wait_nodes(state: dict, job_dir: Path, rep_num: int, timeout_seconds: int = 300) -> bool:
    """Poll until nodes are ACTIVE in OpenStack, then poll until each is actually
    SSH-reachable.

    'ACTIVE' in Nova only means the VM is running — it says nothing about
    cloud-init/networking/sshd being up. OT nodes (PLC/FUXA) in particular can
    take noticeably longer to become reachable than IT nodes. Installing tools
    against a node that is ACTIVE but not yet SSH-reachable was producing
    'Connection timed out' failures for Suricata/Wazuh-agent on PLC/FUXA.
    """
    _log(state, "INFO", f"[Rep {rep_num}] Waiting for nodes to be ACTIVE in OpenStack (up to {timeout_seconds}s)...")
    deadline = time.time() + timeout_seconds
    poll_interval = 15
    servers: list[dict] = []

    while time.time() < deadline:
        if _is_stop_requested(job_dir):
            _log(state, "WARN", "Stop requested — aborting node wait.")
            return False
        rc, stdout, _ = _run_cmd(
            ["openstack", "server", "list", "--format", "json", "--status", "ACTIVE"],
            cwd=PROJECT_ROOT,
            timeout=30,
        )
        if rc == 0:
            try:
                found = json.loads(stdout) if stdout.strip() else []
                if len(found) >= 3:  # At least IT nodes up
                    servers = found
                    _log(state, "INFO", f"Nodes active: {[s.get('Name') for s in servers]}")
                    break
            except Exception:
                pass
        remaining = int(deadline - time.time())
        _log(state, "INFO", f"Waiting for nodes... ({remaining}s remaining)")
        state["updated_at"] = _utc_now()
        _save_state(job_dir, state)
        time.sleep(poll_interval)
    else:
        _log(state, "WARN", "Node wait timeout — proceeding anyway.")
        return True  # Non-fatal: tool installer will report per-node errors

    # Nodes are ACTIVE in Nova — now confirm each one actually answers SSH.
    SSH_KEY = str(Path.home() / ".ssh" / "my_key")
    ssh_deadline = time.time() + timeout_seconds
    pending = {s.get("Name"): True for s in servers if s.get("Name")}

    while pending and time.time() < ssh_deadline:
        if _is_stop_requested(job_dir):
            _log(state, "WARN", "Stop requested — aborting SSH wait.")
            return False
        for name in list(pending.keys()):
            info = _resolve_instance_info(name)
            ip = info.get("ip_floating") or info.get("ip_private")
            user = info.get("ssh_user") or "debian"
            if not ip:
                continue
            rc, _, _ = _run_cmd(
                ["ssh", "-i", SSH_KEY, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
                 f"{user}@{ip}", "echo ok"],
                cwd=PROJECT_ROOT,
                timeout=15,
            )
            if rc == 0:
                _log(state, "OK", f"  {name} ({ip}): SSH reachable.")
                del pending[name]
        if pending:
            remaining = int(ssh_deadline - time.time())
            _log(state, "INFO", f"  Waiting for SSH on: {list(pending.keys())} ({remaining}s remaining)")
            state["updated_at"] = _utc_now()
            _save_state(job_dir, state)
            if remaining > 0:
                time.sleep(poll_interval)

    if pending:
        _log(state, "WARN",
             f"  SSH wait timeout — still unreachable: {list(pending.keys())}. Proceeding anyway.")
        # A still-unreachable node with no floating IP at all is the exact
        # signature of floating-IP quota exhaustion -- confirmed against a
        # real historical incident (Level C job LC-20260722-180010-9D3A,
        # repetition 6, 2026-07-22): PLC_Instance/FUXA_Instance both deployed
        # with float=None after "Quota exceeded for resources:
        # ['floatingip']", this exact SSH wait then timed out on both, tools
        # (incl. Suricata/Wazuh) never installed on either, and detection
        # went completely silent for the rest of that repetition. The
        # cleanup this needs already exists
        # (node_health_api.trigger_floating_ip_cleanup, releases unattached
        # floating IPs) but is only ever auto-triggered by someone polling
        # the Node Health page, AND that auto-trigger deliberately REFUSES to
        # run while a Level C deployment is in flight (see
        # _floating_ip_deployment_in_progress -- a different, legitimate
        # guard against deleting an IP another live deployment is about to
        # use) -- so during an unattended campaign run, nothing ever freed
        # quota at the moment it was actually needed. Triggered directly
        # here instead, NOT through that guard: this deployment is the one
        # already stuck, so freeing unattached IPs right now can only help
        # it (or at worst the next repetition), never race a different one.
        missing_ip_nodes = [name for name in pending if not _resolve_instance_info(name).get("ip_floating")]
        if missing_ip_nodes:
            _log(state, "WARN",
                 f"  {len(missing_ip_nodes)} unreachable node(s) also have no floating IP "
                 f"({missing_ip_nodes}) -- likely floating-IP quota exhaustion. Triggering cleanup "
                 f"of unattached floating IPs now to free headroom.")
            try:
                from app_core.infrastructure.node_health.node_health_api import trigger_floating_ip_cleanup
                cleanup_status = trigger_floating_ip_cleanup(triggered_by="level_c_node_unreachable")
                _log(state, "INFO", f"  Floating-IP cleanup triggered: {cleanup_status.get('status', 'unknown')}.")
            except Exception as exc:
                _log(state, "WARN", f"  Could not trigger floating-IP cleanup: {exc}")
    else:
        _log(state, "INFO", "  All nodes SSH-reachable.")
    return True  # Non-fatal: tool installer will report per-node errors


def _phase_sync_node_clocks(state: dict, job_dir: Path, rep_num: int) -> None:
    """Force a chrony clock sync (measure + makestep) on every live lab VM,
    right after the scenario is up and before any tool gets installed.

    Level B's alert matcher (level_b_orchestrator._alert_is_within_attack_window)
    compares an attack-window timestamp computed on THIS host against alert
    timestamps generated on the VMs, with only a ~300s grace period. A drifted
    VM clock makes every real detection alert look like it happened outside
    the attack window, so DFIR case creation silently never triggers. This
    reuses the existing node-health time-sync mechanism (same one behind the
    per-node "fix" button on the Node Health dashboard) instead of duplicating
    it.

    Also resyncs THIS host's own clock first (2026-07-17), via
    tools-installer/scripts-host/host_clock_sync.sh — root-caused live: this
    host is a VMware guest whose virtualized TSC clocksource was wildly
    unstable (~200000 ppm frequency error), made worse by VMware Tools' own
    time sync fighting chrony over the same clock. Fixed structurally
    (clocksource switched to hpet, VMware Tools time sync disabled, both
    persisted across reboots) — this call is the ongoing safety net: forces
    one immediate `chronyc makestep` right before every campaign run starts,
    on top of chrony's own continuous discipline, so a rep never begins with
    a stale host clock. See level_c_orchestrator/README.md and
    forensics/README.md for the full incident (this was the root cause of
    the ~625s clock-offset causal-reconstruction ambiguity warnings).

    Non-fatal: failures/blocks are logged with their real reason per node.
    """
    _log(state, "INFO", f"[Rep {rep_num}] Resyncing host clock...")
    try:
        host_sync = subprocess.run(
            ["sudo", "-n", "/usr/bin/bash",
             str(PROJECT_ROOT / "tools-installer" / "scripts-host" / "host_clock_sync.sh")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60,
        )
        for line in (host_sync.stdout or "").strip().splitlines():
            _log(state, "INFO", f"  [host-clock] {line}")
        if host_sync.returncode != 0:
            _log(state, "WARN", f"  Host clock sync script exited {host_sync.returncode} — continuing anyway (non-fatal).")
    except Exception as exc:
        _log(state, "WARN", f"  Could not run host clock sync: {exc}")

    _log(state, "INFO", f"[Rep {rep_num}] Synchronizing VM clocks before tool installation...")
    try:
        from app_core.infrastructure.node_health.node_health_api import (
            _list_nodes as _nh_list_nodes,
            run_node_time_sync as _nh_run_time_sync,
            load_node_time_sync_status as _nh_load_time_sync_status,
        )
    except Exception as exc:
        _log(state, "WARN", f"  Could not load node-health time-sync module: {exc}")
        return

    try:
        nodes = [n for n in (_nh_list_nodes() or []) if n.get("id") and str(n.get("status")).upper() == "ACTIVE"]
    except Exception as exc:
        _log(state, "WARN", f"  Could not list nodes for clock sync: {exc}")
        return

    pending: dict[str, str] = {}
    for node in nodes:
        inst_id, name = node["id"], node.get("name") or node["id"]
        try:
            result = _nh_run_time_sync(inst_id, fix_time=True)
        except Exception as exc:
            _log(state, "WARN", f"  {name}: could not start clock sync: {exc}")
            continue
        if result.get("status") == "blocked_policy":
            blocking_case = (result.get("policy") or {}).get("active_case_id") or "unknown"
            _log(state, "WARN", f"  {name}: clock sync blocked (active_case={blocking_case}, pid={os.getpid()}) — {result.get('error')}")
            continue
        pending[inst_id] = name

    deadline = time.time() + 120
    while pending and time.time() < deadline:
        for inst_id in list(pending.keys()):
            status = _nh_load_time_sync_status(inst_id)
            st = status.get("status")
            if st in ("completed", "failed", "blocked_policy"):
                name = pending.pop(inst_id)
                if st == "completed":
                    hint = status.get("result_hint") or {}
                    _log(state, "OK",
                         f"  {name}: clock sync {hint.get('temporal_sync_status', 'done')} "
                         f"(offset={hint.get('selected_node_abs_offset_ms')}ms, "
                         f"corrected={hint.get('correction_applied')})")
                else:
                    _log(state, "WARN", f"  {name}: clock sync {st} — {status.get('error') or 'no reason recorded'}")
        if pending:
            time.sleep(3)
    for inst_id, name in pending.items():
        _log(state, "WARN", f"  {name}: clock sync still running after 120s — proceeding without waiting further.")


def _resolve_instance_info(instance_name: str) -> dict:
    """Query OpenStack for the ID, private IP, and floating IP of an instance by name."""
    rc, stdout, _ = _run_cmd(
        ["openstack", "server", "show", instance_name, "--format", "json"],
        cwd=PROJECT_ROOT,
        timeout=20,
    )
    if rc != 0:
        return {}
    try:
        data = json.loads(stdout)
        instance_id = data.get("id") or data.get("ID")
        nets = data.get("addresses") or {}
        ip_private = None
        ip_floating = None
        for _net, addrs in nets.items():
            for addr in addrs:
                if isinstance(addr, dict):
                    # Detailed format: {"addr": "x.x.x.x", "OS-EXT-IPS:type": "fixed"/"floating"}
                    t = addr.get("OS-EXT-IPS:type", "")
                    a = addr.get("addr") or addr.get("ip") or ""
                    if t == "fixed" and not ip_private:
                        ip_private = a
                    elif t == "floating" and not ip_floating:
                        ip_floating = a
                    elif not t and a and not ip_private:
                        ip_private = a
                elif isinstance(addr, str):
                    # Compact format: plain IP strings; classify by subnet prefix
                    # 192.168.x.x = internal private; anything else = floating/routable
                    if addr.startswith("192.168.") and not ip_private:
                        ip_private = addr
                    elif not ip_floating and not addr.startswith("192.168."):
                        ip_floating = addr
            if not ip_private and not ip_floating:
                for addr in addrs:
                    raw = addr.get("addr") if isinstance(addr, dict) else addr
                    if raw:
                        ip_private = raw
                        break
        # Detect SSH user: Ubuntu images → "ubuntu", all others → "debian"
        image_raw = data.get("image") or data.get("image_name") or ""
        if isinstance(image_raw, dict):
            image_raw = image_raw.get("name") or image_raw.get("id") or ""
        ssh_user = "ubuntu" if "ubuntu" in str(image_raw).lower() else "debian"
        return {
            "id": instance_id,
            "ip_private": ip_private,
            "ip_floating": ip_floating,
            "ssh_user": ssh_user,
        }
    except Exception:
        return {}


def _build_instance_tool_map() -> list[dict]:
    """
    Build the list of instances + their tools to install.

    Uses _TOOL_SCIENTIFIC_ORDER as the authoritative definition of what goes
    on each node role. tools-installer-tmp/ is a STATUS directory (wiped each
    redeploy), NOT a source of tool definitions — never read from it here.

    Resolves current OpenStack instance names (which change after each
    redeploy — e.g. 'monitor 1' becomes 'monitor 11').
    Returns list of {instance_id, instance_name, tools: [str]}.
    """
    # Build role → ordered tool list from the static order table
    role_tools: dict[str, list[str]] = {}
    for role_pattern, tool, _phase in _TOOL_SCIENTIFIC_ORDER:
        role_tools.setdefault(role_pattern, [])
        if tool not in role_tools[role_pattern]:
            role_tools[role_pattern].append(tool)

    # Query live OpenStack to get current instance names (change each redeploy)
    try:
        rc, stdout, _ = _run_cmd(
            ["openstack", "server", "list", "--format", "json"],
            cwd=PROJECT_ROOT, timeout=30,
        )
        servers = json.loads(stdout) if rc == 0 and stdout.strip() else []
    except Exception:
        servers = []

    role_to_server: dict[str, dict] = {}
    for srv in servers:
        srv_name = (srv.get("Name") or srv.get("name") or "").lower()
        for r in _NODE_INSTALL_ORDER:
            if r in srv_name and r not in role_to_server:
                role_to_server[r] = {
                    "instance_id":   srv.get("ID")   or srv.get("id")   or "",
                    "instance_name": srv.get("Name") or srv.get("name") or "",
                }
                break

    result = []
    for role, tools in role_tools.items():
        srv_info = role_to_server.get(role)
        if not srv_info:
            continue  # no live instance for this role — skip silently
        result.append({
            "instance_id":   srv_info["instance_id"],
            "instance_name": srv_info["instance_name"],
            "tools":         tools,
        })
    return result


def _scientific_tool_phases(instance_tool_map: list[dict]) -> list[list[dict]]:
    """
    Assign each (instance, tool) to one of 5 phases and sort within each phase.

    Installation rule: monitor COMPLETE → attack COMPLETE → victim COMPLETE
                       → OT base tools → OT configs.

    Sort key: (phase, node_priority, tool_position_in_order)
      - node_priority follows _NODE_INSTALL_ORDER: monitor→attack→victim→plc→fuxa→scada
      - tool_position is the index in _TOOL_SCIENTIFIC_ORDER, preserving declared order
      - Unknown tools (not in the table) go to phase 5, node last, position last.
    """
    phases: list[list[dict]] = [[], [], [], [], []]  # phases 1–5

    def _node_priority(inst_name: str) -> int:
        n = inst_name.lower()
        for i, pattern in enumerate(_NODE_INSTALL_ORDER):
            if pattern in n:
                return i
        return len(_NODE_INSTALL_ORDER)

    def _phase_and_pos(inst_name: str, tool: str) -> tuple[int, int]:
        n = inst_name.lower()
        t = tool.lower()
        for pos, (role_pattern, t2, ph) in enumerate(_TOOL_SCIENTIFIC_ORDER):
            if role_pattern.lower() in n and t2.lower() == t:
                return ph, pos
        return 5, len(_TOOL_SCIENTIFIC_ORDER)  # unknown → last phase, last position

    all_items: list[tuple[int, int, int, dict]] = []
    for inst in instance_tool_map:
        node_pri = _node_priority(inst["instance_name"])
        for tool in inst["tools"]:
            ph, tool_pos = _phase_and_pos(inst["instance_name"], tool)
            all_items.append((ph, node_pri, tool_pos, {
                "instance_name": inst["instance_name"],
                "instance_id":   inst["instance_id"],
                "tool": tool,
            }))

    all_items.sort(key=lambda x: (x[0], x[1], x[2]))

    for ph, _node_pri, _tool_pos, item in all_items:
        phases[ph - 1].append(item)

    return phases


def _set_tmp_tool_status(tmp_path: Path, tool: str, status: str) -> None:
    """Update a single tool's status in its tools-installer-tmp JSON file."""
    try:
        fdata = _load_json(tmp_path) or {}
        tools_dict = dict(fdata.get("tools") or {})
        tools_dict[tool] = status
        fdata["tools"] = tools_dict
        _write_json(tmp_path, fdata)
    except Exception:
        pass


def _install_tool_on_instance(instance_name: str, tool: str, log: list,
                               instance_info: dict | None = None,
                               job_dir: Path | None = None) -> bool:
    """Install a single tool on an instance by calling its install script directly.

    Bypasses tools_install_master.sh (which processes ALL files and ignores phase
    ordering). Instead, calls tools-installer/scripts/install_{tool}.sh directly
    with the target IP and SSH user, respecting the phase ordering enforced by
    _phase_install_tools.
    """
    import re as _re

    # Resolve OpenStack instance info if not provided
    info = instance_info or _resolve_instance_info(instance_name)
    instance_id = info.get("id") or instance_name
    ip_private  = info.get("ip_private")
    ip_floating = info.get("ip_floating")
    ip          = ip_floating or ip_private
    ssh_user    = info.get("ssh_user") or "debian"

    if not ip:
        log.append(f"  [ERROR] {instance_name}/{tool}: no IP available")
        return False

    # Locate the install script for this tool
    script = TOOLS_SCRIPTS_DIR / f"install_{tool}.sh"
    if not script.is_file():
        log.append(f"  [ERROR] {instance_name}/{tool}: script not found: {script}")
        return False

    safe = _re.sub(r"[^a-zA-Z0-9_-]", "_", instance_name.lower())
    tmp_path = TOOLS_TMP_DIR / f"{safe}_tools.json"

    # Mark as pending in the tmp JSON so dashboard shows active install
    _set_tmp_tool_status(tmp_path, tool, "pending")

    # Run the install script via _run_cmd so stop requests are honoured
    # and the process group is killed on timeout.
    TOOLS_LOGS_DIR = PROJECT_ROOT / "tools-installer" / "logs"
    TOOLS_LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Recorded so campaign_repetitions/service.py can show real per-tool
    # install duration (previously only the completion timestamp existed).
    # Forward-only: installs recorded before this change have no start time
    # on disk and will show as "pending" for duration in that view — accepted,
    # not backfilled, since the real start moment is genuinely unrecoverable
    # for past runs.
    install_started_utc = _utc_now()

    rc, stdout, stderr = _run_cmd(
        ["bash", str(script), ip, ssh_user],
        cwd=PROJECT_ROOT,
        timeout=900,
        job_dir=job_dir,
    )
    # Write log file for debugging
    try:
        log_file = TOOLS_LOGS_DIR / f"{safe}_{tool}.log"
        log_file.write_text((stdout or "") + (stderr or ""))
    except Exception:
        pass

    combined = ((stdout or "") + "\n" + (stderr or "")).strip()
    log.append(combined[-500:] if len(combined) > 500 else combined)

    if rc == -2:
        # Stop requested
        _set_tmp_tool_status(tmp_path, tool, "pending")  # leave as pending, not error
        return False

    success = rc == 0
    new_status = "installed" if success else "error"
    _set_tmp_tool_status(tmp_path, tool, new_status)

    if success:
        # Save permanent record to tools-installer/installed/{instance_id}.json
        try:
            TOOLS_INSTALLED_DIR.mkdir(parents=True, exist_ok=True)
            inst_file = TOOLS_INSTALLED_DIR / f"{instance_id}.json"
            inst_data = _load_json(inst_file) or {
                "instance_id":   instance_id,
                "instance_name": instance_name,
                "installed_tools": {},
            }
            inst_data.setdefault("installed_tools", {})[tool] = _utc_now()
            inst_data.setdefault("install_started_utc", {})[tool] = install_started_utc
            _write_json(inst_file, inst_data)
        except Exception as exc:
            log.append(f"  [WARN] Could not write installed record: {exc}")

    return success


def _phase_install_tools(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Install tools in 4-phase scientific dependency order."""
    _log(state, "INFO", f"[Rep {rep_num}] Installing tools in scientific order (4 phases)...")

    instance_tool_map = _build_instance_tool_map()
    if not instance_tool_map:
        _log(state, "WARN", "No live instances found matching known roles — skipping tool install.")
        return True

    # Resolve fresh OpenStack info for each instance ONCE (IPs change after redeploy)
    _log(state, "INFO", "  Resolving current OpenStack instance info...")
    instance_info_cache: dict[str, dict] = {}
    for inst in instance_tool_map:
        name = inst["instance_name"]
        info = _resolve_instance_info(name)
        instance_info_cache[name] = info
        _log(state, "INFO",
             f"  {name}: id={info.get('id') or 'not_found'} "
             f"ip={info.get('ip_private') or info.get('ip_floating') or 'not_found'}")

    # Initialise tools-installer-tmp files with fresh metadata (name, id, IPs,
    # all tools as "pending") so _phase_verify_monitoring can read node IPs
    # and the UI shows accurate status from the start of each install phase.
    import re as _re
    TOOLS_TMP_DIR.mkdir(parents=True, exist_ok=True)
    for inst in instance_tool_map:
        name = inst["instance_name"]
        info = instance_info_cache.get(name, {})
        safe = _re.sub(r"[^a-zA-Z0-9_-]", "_", name.lower())
        tmp_path = TOOLS_TMP_DIR / f"{safe}_tools.json"
        try:
            tools_pending = {t: "pending" for t in inst["tools"]}
            fdata = {
                "name":        name,
                "instance":    name,
                "id":          info.get("id") or inst.get("instance_id") or "",
                "instance_id": info.get("id") or inst.get("instance_id") or "",
                "ip_private":  info.get("ip_private") or "",
                "ip_floating": info.get("ip_floating") or "",
                "tools":       tools_pending,
            }
            _write_json(tmp_path, fdata)
            _log(state, "INFO",
                 f"  Initialised {tmp_path.name}: float={info.get('ip_floating')}")
        except Exception as exc:
            _log(state, "WARN", f"  Could not initialise {tmp_path.name}: {exc}")

    phases = _scientific_tool_phases(instance_tool_map)
    phase_labels = [
        "Phase 1 — MONITOR     (Wazuh Manager, nmap) — completo antes de atacante",
        "Phase 2 — ATTACK      (Caldera, OT plugins, mbpoll, nmap) — completo antes de víctima",
        "Phase 3 — VICTIM      (suricata, wazuh_agent, caldera_agent) — completo antes de OT",
        "Phase 4 — OT TOOLS    (PLC + FUXA: suricata → wazuh_agent)",
        "Phase 5 — OT CONFIGS  (rollback rules, Wazuh-Suricata integration, FIM)",
    ]
    # Phase 1 (monitor): 90s — Wazuh Manager must be fully UP before any agent enrols.
    # Phase 2 (attack): 30s — Caldera Server stable before caldera_agent connects.
    # Phase 3 (victim): 30s — agents enrolled before OT nodes try to connect.
    # Phase 4 (OT tools): 30s — OT agents enrolled and active before configs run.
    phase_waits = [90, 30, 30, 30]

    for ph_idx, phase_items in enumerate(phases):
        label = phase_labels[ph_idx]
        if not phase_items:
            _log(state, "INFO", f"  {label}: nothing to install, skipping.")
            continue
        _log(state, "INFO", f"  {label} — {len(phase_items)} install(s)")
        ph_log: list[str] = []
        stopped_mid_phase = False
        for item in phase_items:
            if _is_stop_requested(job_dir):
                _log(state, "WARN", f"  Stop requested — halting tool installation mid-phase.")
                stopped_mid_phase = True
                break
            info = instance_info_cache.get(item["instance_name"], {})
            ok = _install_tool_on_instance(item["instance_name"], item["tool"], ph_log,
                                            instance_info=info, job_dir=job_dir)
            status = "OK" if ok else "WARN"
            _log(state, status,
                 f"    {item['instance_name']} ← {item['tool']}: {'installed' if ok else 'failed/skipped'}")
            # Heartbeat: each tool install can take minutes; keep updated_at fresh.
            state["updated_at"] = _utc_now()
            _save_state(job_dir, state)
        for line in ph_log:
            _log(state, "STDOUT", line)
        # Heartbeat after each phase so stop_job() never sees a stale updated_at.
        state["updated_at"] = _utc_now()
        _save_state(job_dir, state)
        if stopped_mid_phase:
            return False  # caller will pick up stop flag via _check_stop()
        if ph_idx < len(phase_waits) and phase_items:
            wait_s = phase_waits[ph_idx]
            _log(state, "INFO", f"  Waiting {wait_s}s before next phase...")
            # Sleep in 10 s chunks so updated_at stays fresh during long waits.
            slept = 0
            while slept < wait_s:
                time.sleep(min(10, wait_s - slept))
                slept += 10
                state["updated_at"] = _utc_now()
                _save_state(job_dir, state)

    _log(state, "INFO", "Tool installation phases completed.")
    return True  # Non-fatal: individual tool failures don't abort Level C


def _phase_verify_monitoring(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Verify the monitoring stack is fully operational before Level B attacks begin.

    Reads node IPs from tools-installer-tmp/*.json (which always have the current
    floating IPs after each redeploy). Detects the SSH user via OpenStack.

    Checks per node role:
      monitor  → wazuh-manager active
      victim, plc, fuxa, scada → wazuh-agent active + connected + suricata active

    Polls every 30 s for up to 10 min (600 s). Non-fatal: logs WARN and proceeds.
    """
    import re as _re
    _log(state, "INFO", f"[Rep {rep_num}] Verifying live monitoring stack (Wazuh + Suricata)...")

    SSH_KEY  = str(Path.home() / ".ssh" / "my_key")
    MAX_WAIT = 600
    POLL     = 30

    # ── Build node list from tools-installer-tmp/*.json ──────────────────────
    # These files always have fresh floating IPs (updated in _phase_install_tools).
    monitor_nodes: list[dict] = []    # need wazuh-manager
    agent_nodes:   list[dict] = []    # need wazuh-agent + suricata

    if TOOLS_TMP_DIR.is_dir():
        for f in sorted(TOOLS_TMP_DIR.glob("*.json")):
            try:
                d    = _load_json(f) or {}
                name = (d.get("name") or d.get("instance") or f.stem).lower()
                ip   = d.get("ip_floating") or d.get("ip_private") or ""
                if not ip or ip.startswith("192.168.1."):
                    # 192.168.1.x = design-time placeholder, not real; skip
                    continue
                # Detect SSH user via OpenStack (cached in instance_info)
                real_name = d.get("name") or d.get("instance") or ""
                info  = _resolve_instance_info(real_name) if real_name else {}
                user  = info.get("ssh_user") or "debian"
                entry = {"name": real_name or name, "ip": ip, "user": user}
                if "monitor" in name:
                    monitor_nodes.append(entry)
                elif any(r in name for r in ("victim", "plc", "fuxa", "scada")):
                    agent_nodes.append(entry)
            except Exception:
                continue

    if not monitor_nodes and not agent_nodes:
        _log(state, "WARN", "  No nodes resolved for monitoring verification — skipping.")
        return True

    _log(state, "INFO",
         f"  Monitor nodes: {[n['ip'] for n in monitor_nodes]} | "
         f"Agent nodes: {[n['ip'] for n in agent_nodes]}")

    elapsed = 0
    while elapsed < MAX_WAIT:
        if _is_stop_requested(job_dir):
            return False

        all_ready = True
        lines: list[str] = []

        # ── Wazuh Manager check ────────────────────────────────────────────
        for node in monitor_nodes:
            ip, user, name = node["ip"], node["user"], node["name"]
            _, out, _ = _run_cmd(
                ["ssh", "-i", SSH_KEY, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=5", f"{user}@{ip}",
                 "systemctl is-active wazuh-manager 2>/dev/null"],
                cwd=PROJECT_ROOT, timeout=15,
            )
            ok = "active" in (out or "")
            if not ok:
                all_ready = False
            lines.append(
                f"  {name} ({ip}): wazuh-manager={'OK' if ok else 'DOWN'}"
                f"{' [READY]' if ok else ' [WAIT]'}"
            )

        # ── Wazuh-agent + Suricata check ───────────────────────────────────
        for node in agent_nodes:
            ip, user, name = node["ip"], node["user"], node["name"]

            # ossec.log is owned root:wazuh (mode 660) — unreadable by ssh user.
            # Use sudo grep; all lab nodes have NOPASSWD sudo configured.
            _, out_w, _ = _run_cmd(
                ["ssh", "-i", SSH_KEY, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=5", f"{user}@{ip}",
                 "bash -c 'systemctl is-active wazuh-agent 2>/dev/null && "
                 "sudo grep -qEi \"Connected to the server|Agent connected\" "
                 "/var/ossec/logs/ossec.log 2>/dev/null && echo CONN_OK || echo CONN_MISS'"],
                cwd=PROJECT_ROOT, timeout=15,
            )
            wazuh_active = (out_w or "").split('\n')[0].strip() == "active"
            wazuh_conn   = "CONN_OK" in (out_w or "")

            _, out_s, _ = _run_cmd(
                ["ssh", "-i", SSH_KEY, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=5", f"{user}@{ip}",
                 "systemctl is-active suricata 2>/dev/null"],
                cwd=PROJECT_ROOT, timeout=15,
            )
            sur_ok = "active" in (out_s or "")

            node_ok = wazuh_active and wazuh_conn and sur_ok
            if not node_ok:
                all_ready = False
            lines.append(
                f"  {name} ({ip}): wazuh-agent={'OK' if wazuh_active else 'DOWN'} "
                f"conn={'OK' if wazuh_conn else 'MISS'} "
                f"suricata={'OK' if sur_ok else 'DOWN'}"
                f"{' [READY]' if node_ok else ' [WAIT]'}"
            )

        lvl = "INFO" if all_ready else "WARN"
        for line in lines:
            _log(state, lvl, line)

        if all_ready:
            _log(state, "INFO",
                 f"  Live monitoring READY after {elapsed}s — proceeding to Level B.")
            return True

        _log(state, "INFO",
             f"  Not fully ready ({elapsed}s/{MAX_WAIT}s). Next check in {POLL}s...")
        slept = 0
        while slept < POLL:
            time.sleep(min(5, POLL - slept))
            slept += 5
            state["updated_at"] = _utc_now()
            _save_state(job_dir, state)
        elapsed += POLL

    _log(state, "WARN",
         f"  Monitoring NOT fully ready after {MAX_WAIT}s — proceeding to Level B anyway.")
    return False


def _phase_run_level_b(state: dict, job_dir: Path, rep_num: int, config: dict) -> str | None:
    """Launch Level B repetitions. Returns job_id or None on failure."""
    campaign_id = config["campaign_id"]
    requested_reps = int(config.get("level_b_repetitions") or 10)
    nested_a_reps = int(config.get("level_a_repetitions") or requested_reps)
    # 2026-09-01: only the case from the campaign's true final repetition should
    # ever be kept intact as a full result sample -- not every Level C repetition's
    # own (usually single) inner Level B batch, which would otherwise each look
    # like "the last one" from level_b_repetition_runner's own local point of view.
    level_c_total_reps = int(config.get("level_c_repetitions") or 1)
    is_final_level_c_rep = rep_num >= level_c_total_reps

    try:
        from app_core.infrastructure.foc_experimentation.level_b_repetition_runner import (
            start_level_b_repetitions_job,
            find_active_level_b_job,
        )

        # _phase_wait_level_b's own timeout is now scaled to how many
        # repetitions were actually requested (see LEVEL_B_WAIT_* constants),
        # so it should rarely time out on genuinely-alive work anymore. This
        # is just a short closing buffer for the edge case where the previous
        # batch finishes moments after that wait gave up — the real "is it
        # actually dead" detection is job_runner._recover_orphaned_job (fires
        # within ~180s of a real death), not a long blind wait here. If this
        # short wait also expires, launch anyway and let the concurrent-job
        # guard's own clear error explain what's still running, if anything.
        wait_deadline = time.time() + 300  # 5 min closing buffer, not a second full wait
        while time.time() < wait_deadline:
            if _is_stop_requested(job_dir):
                return None
            active = find_active_level_b_job()
            if not active or active.get("campaign_id") != campaign_id:
                break
            _log(state, "WARN",
                 f"[Rep {rep_num}] A previous Level B batch ({active.get('job_id')}) for this campaign is still "
                 f"genuinely running (phase '{active.get('current_phase_label') or active.get('current_phase')}', "
                 f"started {active.get('started_at')}) — waiting for it to finish before launching this repetition "
                 "instead of failing immediately.")
            state["updated_at"] = _utc_now()
            _save_state(job_dir, state)
            time.sleep(30)

        _log(state, "INFO",
             f"[Rep {rep_num}] Launching Level B: campaign={campaign_id} reps={requested_reps} nested_A={nested_a_reps}"
             + (f" — final repetition ({rep_num}/{level_c_total_reps}): its case will be preserved fully intact as a result sample." if is_final_level_c_rep else ""))
        result = start_level_b_repetitions_job(
            campaign_id=campaign_id,
            confirmation="OK",
            requested_repetitions=requested_reps,
            requested_nested_level_a_repetitions=nested_a_reps,
            cleanup_old_cases=True,
            dfir_mode_before="on",
            dfir_mode_after="on",
            preserve_final_case=is_final_level_c_rep,
        )
        if result.get("error"):
            _log(state, "ERROR", f"Level B launch error: {result.get('message')}")
            return None
        job_id = result.get("job_id")
        _log(state, "INFO", f"Level B job started: {job_id}")
        return job_id
    except Exception as exc:
        _log(state, "ERROR", f"Level B launch exception: {exc}")
        return None


def _summarize_level_b_result(job: dict) -> list[str]:
    """Pull the REAL per-repetition reasons out of a Level B job result instead
    of the coarse top-level status string.

    Level B already computes truthful diagnostics per case (dfir_mode_blocker,
    analysis_status, reconstruction_status, case_sealed_status, nested Level A
    report status/errors, blockers, warnings) — this just surfaces them into
    the Level C log so 'nothing happened and nobody said why' stops happening.
    """
    lines: list[str] = []
    job = job or {}
    reps = job.get("per_repetition_results") or []
    for i, rep in enumerate(reps, 1):
        case = rep.get("case_id") or rep.get("attack") or f"rep {i}"
        parts = []
        dfir_blocker = rep.get("dfir_mode_blocker")
        if dfir_blocker:
            parts.append(f"DFIR=BLOCKED ({dfir_blocker})")
        elif rep.get("dfir_mode_enabled_successfully"):
            parts.append("DFIR=armed")
        for field, label in (
            ("analysis_status", "analysis"),
            ("reconstruction_status", "reconstruction"),
            ("case_sealed_status", "case_sealed"),
        ):
            val = rep.get(field)
            if val:
                parts.append(f"{label}={val}")
        nested = rep.get("nested_level_a") or {}
        nested_status = nested.get("status")
        if nested_status:
            tag = f"report(nested_A)={nested_status}"
            if nested_status not in ("completed", "completed_with_degradation"):
                nested_errs = nested.get("errors") or []
                err_msg = nested_errs[0].get("message") if nested_errs and isinstance(nested_errs[0], dict) else None
                if err_msg:
                    tag += f" [{err_msg}]"
            parts.append(tag)
        blockers = rep.get("blockers") or []
        if blockers:
            parts.append(f"blockers={blockers}")
        lines.append(f"  [{case}] " + (" | ".join(parts) if parts else "no diagnostic fields present"))

    for w in job.get("warnings") or []:
        lines.append(f"  [WARN] {w}")
    for e in job.get("errors") or []:
        msg = e.get("message") if isinstance(e, dict) else str(e)
        lines.append(f"  [ERROR] {msg}")
    return lines


# Timeout philosophy changed 2026-07-17 at the user's explicit request: no
# fixed deadline that, once reached, lets the campaign move on as if nothing
# happened. As long as a stage shows real activity, it keeps running no
# matter how long. Only two things end the wait now:
#   (a) the Level B job reaches a genuine terminal status on its own — this
#       relies on job_runner._recover_orphaned_job already self-healing a
#       truly dead job to 'failed' within ~180s of its heartbeat going stale
#       (get_job() triggers this on every poll here, for free);
#   (b) BOTH the job's own heartbeat AND its linked case's real file activity
#       (pipeline_events.jsonl / acquisition_profile.json / analysis_status.json
#       mtimes — forensics_api._latest_case_activity_ts, the same proxy
#       already used for the preservation-lock watchdog) have been stale for
#       LEVEL_B_STALL_GRACE_SECONDS at once. This is the blind spot a
#       heartbeat-only check misses: a job stuck in an inner polling loop
#       that keeps calling update_job() while the actual work underneath it
#       has stopped moving. Checking both independently catches that.
# A stage running past its own historical median (stage_timing_service's
# existing 'delayed' flag) raises a visible, non-fatal, system-wide alert
# (see node_health_api._build_health_alerts) — it does not stop anything by
# itself; it's purely informational so a human can look if they want to.
LEVEL_B_STALL_GRACE_SECONDS = 300


def _phase_wait_level_b(state: dict, job_dir: Path, rep_num: int, job_id: str) -> bool:
    """Wait for the Level B job to reach a real terminal state — driven by
    activity and progress, not a fixed deadline. See module comment above
    for exactly what ends the wait and why.

    Returns True only for a genuine terminal completion (including
    completed_with_failures — the batch really finished, even if degraded).
    Returns False for any real failure, cancellation, or confirmed stall —
    the caller must treat False as fatal for the whole campaign: no next
    repetition, no scenario destruction, no marking the result valid.
    """
    from app_core.infrastructure.foc_experimentation.job_runner import get_job, request_force_stop, update_job
    _log(state, "INFO", f"[Rep {rep_num}] Waiting for Level B job {job_id} (activity-driven, no fixed deadline)...")

    poll_interval = 15
    status = "unknown"
    last_job: dict | None = None
    stall_since: float | None = None
    alerted_stage_keys: set[str] = set()

    while True:
        if _is_stop_requested(job_dir):
            _log(state, "WARN", f"Stop requested — aborting wait for Level B job {job_id}.")
            return False
        # Real false-positive found live (2026-10-09): a whole campaign got
        # wrongly marked "failed" by the cross-worker orphan watchdog
        # (_recover_orphaned_lc_job) at WAITING_LEVEL_B, 183s after the last
        # _save_state -- while the real Level B job, confirmed independently
        # via its own campaign record, kept running and genuinely completed
        # 7 minutes later. Root cause: this loop only stamps updated_at via
        # _save_state at the END of each iteration (below); if any call in
        # between (get_job, case-directory file scans, stage-timeline reads)
        # happens to run slow for one iteration -- plausible right as Level B
        # transitions into its own heavy nested Level A analysis -- the
        # heartbeat goes stale even though this thread is genuinely still
        # alive and about to log again. Same exact mechanism already
        # documented on _touch_heartbeat's own docstring for _phase_deploy_ot;
        # this loop just never called it. Fixed by touching the heartbeat
        # FIRST, before any of the potentially-slow calls below, so a single
        # slow iteration can no longer look like 180s+ of total silence.
        _touch_heartbeat(job_dir)
        try:
            job = get_job(job_id)
            last_job = job or last_job
            status = (job or {}).get("status", "unknown")
            if status in ("completed", "completed_with_warnings", "completed_with_degradation",
                          "completed_with_failures"):
                _log(state, "INFO", f"Level B job {job_id} completed: {status}")
                for line in _summarize_level_b_result(job):
                    _log(state, "INFO" if status == "completed" else "WARN", line)
                return True
            if status in ("failed", "error", "cancelled", "stopped"):
                _log(state, "ERROR", f"Level B job {job_id} ended with: {status}")
                for line in _summarize_level_b_result(job):
                    _log(state, "ERROR", line)
                return False
        except Exception as exc:
            _log(state, "WARN", f"Polling Level B job {job_id}: {exc}")
            job = last_job

        # --- real-progress check, independent of the job's own heartbeat ---
        case_id = (job or {}).get("current_case_id")
        case_dir_str: str | None = None
        case_stale = False
        if case_id:
            try:
                from app_core.infrastructure.foc_reconstruction.foc_case_analysis import get_case_entry, _case_dir_from_entry
                from app_core.infrastructure.forensics.forensics_api import _latest_case_activity_ts
                entry = get_case_entry(case_id)
                if entry:
                    case_dir_str = str(_case_dir_from_entry(entry))
                    latest_ts = _latest_case_activity_ts(case_dir_str)
                    case_stale = bool(latest_ts) and (time.time() - latest_ts) > LEVEL_B_STALL_GRACE_SECONDS
            except Exception:
                pass

        job_updated_ts = _parse_ts((job or {}).get("updated_at"))
        job_stale = bool(job_updated_ts and (time.time() - job_updated_ts) > LEVEL_B_STALL_GRACE_SECONDS)

        # Only treat it as stalled if we actually have a case to check AND
        # both signals agree nothing real is happening. No case yet (early
        # attack/trigger phase) falls back to trusting the job heartbeat
        # alone, same as before.
        genuinely_stalled = job_stale and (case_stale if case_id else job_stale)
        if genuinely_stalled:
            if stall_since is None:
                stall_since = time.time()
                _log(state, "WARN",
                     f"[Rep {rep_num}] Level B job {job_id} (case {case_id or 'not_available'}) shows no real "
                     f"activity — heartbeat and case files both stale for over {LEVEL_B_STALL_GRACE_SECONDS}s. "
                     f"Watching for {LEVEL_B_STALL_GRACE_SECONDS}s more before stopping it in a controlled way.")
            elif time.time() - stall_since > LEVEL_B_STALL_GRACE_SECONDS:
                reason = (
                    f"Level B job {job_id} (case {case_id or 'not_available'}) had no real activity for over "
                    f"{2 * LEVEL_B_STALL_GRACE_SECONDS}s — neither its own heartbeat nor the case's pipeline files "
                    "changed. Stopped in a controlled way; nothing already produced (logs, states, analysis, "
                    "partial results) was deleted."
                )
                _log(state, "ERROR", reason)
                try:
                    existing_errors = list((job or {}).get("errors") or [])
                    update_job(job_id, Path(str((job or {}).get("job_path") or "")),
                               errors=[{"message": reason}] + existing_errors)
                    request_force_stop(job_id)
                except Exception as exc:
                    _log(state, "WARN", f"Could not cleanly force-stop {job_id}: {exc}")
                return False
        else:
            stall_since = None

        # --- delayed-but-progressing: visible system-wide alert, keep waiting ---
        if case_id:
            try:
                from app_core.infrastructure.forensics.stage_timing_service import get_case_stage_timeline_by_case_id
                for stg in get_case_stage_timeline_by_case_id(case_id):
                    if stg.get("delayed") and stg.get("stage_key") not in alerted_stage_keys:
                        alerted_stage_keys.add(stg["stage_key"])
                        _log(state, "WARN",
                             f"[Rep {rep_num}] Stage '{stg.get('label')}' (target={stg.get('target') or 'n/a'}) is "
                             f"taking longer than usual: {stg.get('elapsed_seconds')}s vs ~{stg.get('expected_seconds')}s "
                             "historical — still progressing, not stopping it. Visible in the system alert bell too.")
            except Exception:
                pass

        _log(state, "INFO", f"Level B running... (status={status}, case={case_id or 'not_yet_created'})")
        state["updated_at"] = _utc_now()
        _save_state(job_dir, state)
        time.sleep(poll_interval)


def _phase_capture_snapshot(state: dict, job_dir: Path, rep_num: int) -> str | None:
    """Capture a snapshot and return its ID."""
    _log(state, "INFO", f"[Rep {rep_num}] Capturing scenario snapshot...")
    try:
        from app_core.infrastructure.scenario_snapshot.service import capture_snapshot
        result = capture_snapshot()
        snap_id = result.get("snapshot_id")
        _log(state, "INFO", f"Snapshot captured: {snap_id}")
        return snap_id
    except Exception as exc:
        _log(state, "ERROR", f"Snapshot capture failed: {exc}")
        return None


def _fault_schedule_condition(fault_schedule: dict | None, rep: int) -> str:
    """Strict alternating-treatments design (Barlow & Hayes, 1979, Journal of
    Applied Behavior Analysis 12:199-210, DOI 10.1901/jaba.1979.12-199):
    control and treatment repetitions alternate within the SAME campaign so
    the comparison phase can measure a fault's real effect directly (control
    mean vs. treatment mean), instead of needing two separate campaigns run
    at different times. The original paper's own preferred variant alternates
    randomly/semi-randomly to rule out order effects; this implements the
    simpler strict-alternation variant the user explicitly asked for --
    documented here, not silently substituted, so the difference is honest
    rather than hidden."""
    if not fault_schedule or not fault_schedule.get("fault_ids"):
        return "none"
    start_with = fault_schedule.get("start_with") or "control"
    is_odd = (rep % 2) == 1
    if start_with == "control":
        return "control" if is_odd else "treatment"
    return "treatment" if is_odd else "control"


def _resolve_node_by_role(role: str) -> dict | None:
    try:
        from app_core.infrastructure.node_health.node_health_api import _list_nodes
        nodes = _list_nodes()
        return next((n for n in nodes if str(n.get("role") or "").lower() == str(role or "").lower()), None)
    except Exception:
        return None


def _apply_fault_schedule_for_rep(state: dict, job_dir: Path, fault_schedule: dict | None, rep: int) -> list[dict]:
    """Applies every fault_id in the schedule against the configured
    target_role, ONLY on a "treatment" repetition -- reuses
    fault_injection.apply_fault() exactly as the Fault Injection dashboard's
    own on-demand buttons do, zero new injection logic. Returns the list of
    {fault_id, injection_id, node_id} applied, so the caller can revert
    exactly these later regardless of how the repetition turns out."""
    condition = _fault_schedule_condition(fault_schedule, rep)
    if condition != "treatment":
        return []
    target_role = (fault_schedule or {}).get("target_role") or "plc"
    node = _resolve_node_by_role(target_role)
    if not node:
        _log(state, "WARN", f"[Rep {rep}] Fault schedule: no live node found for role='{target_role}' -- skipping injection this repetition.")
        return []
    applied: list[dict] = []
    try:
        from app_core.infrastructure.fault_injection.service import apply_fault
        for fault_id in (fault_schedule or {}).get("fault_ids") or []:
            params = ((fault_schedule or {}).get("params") or {}).get(fault_id) or {}
            result = apply_fault(fault_id, node["id"], params, campaign_id=(state.get("config") or {}).get("campaign_id"))
            if result.get("ok"):
                injection_id = (result.get("record") or {}).get("injection_id")
                applied.append({"fault_id": fault_id, "injection_id": injection_id, "node_id": node["id"]})
                _log(state, "INFO", f"[Rep {rep}] Fault schedule: applied '{fault_id}' on {node.get('name')} (injection_id={injection_id}).")
            else:
                _log(state, "WARN", f"[Rep {rep}] Fault schedule: '{fault_id}' failed to apply: {result.get('error') or (result.get('record') or {}).get('errors')}")
    except Exception as exc:
        _log(state, "WARN", f"[Rep {rep}] Fault schedule: exception applying faults: {exc}")
    return applied


def _revert_fault_schedule_injections(state: dict, rep: int, injections: list[dict]) -> None:
    if not injections:
        return
    try:
        from app_core.infrastructure.fault_injection.service import revert_fault
        for item in injections:
            if not item.get("injection_id"):
                continue
            result = revert_fault(item["injection_id"])
            _log(state, "INFO", f"[Rep {rep}] Fault schedule: reverted '{item['fault_id']}' (injection_id={item['injection_id']}) -> ok={result.get('ok')}.")
    except Exception as exc:
        _log(state, "WARN", f"[Rep {rep}] Fault schedule: exception reverting faults: {exc}")


def _phase_compare_snapshots(state: dict, job_dir: Path, snapshot_ids: list[str], fault_schedule_log: list[dict] | None = None) -> dict:
    """
    Compare all Level C snapshots scientifically.
    Returns a comparison report with ΔWCPR, ΔCPR, reproducibility index.
    """
    _log(state, "INFO", f"Comparing {len(snapshot_ids)} Level C snapshots...")
    if len(snapshot_ids) < 2:
        return {"status": "single_repetition", "message": "Only one Level C repetition — no cross-deployment comparison."}

    try:
        from app_core.infrastructure.scenario_snapshot.service import (
            get_snapshot,
            diff_snapshots,
        )
        comparisons = []
        for i in range(len(snapshot_ids) - 1):
            a_id = snapshot_ids[i]
            b_id = snapshot_ids[i + 1]
            diff = diff_snapshots(a_id, b_id)
            cpr_a = _extract_cpr_from_snapshot(get_snapshot(a_id))
            cpr_b = _extract_cpr_from_snapshot(get_snapshot(b_id))
            wcpr_a = _extract_wcpr_from_snapshot(get_snapshot(a_id))
            wcpr_b = _extract_wcpr_from_snapshot(get_snapshot(b_id))
            # Honest-missing-data handling (2026-07-20 fix): a delta can only be computed
            # when BOTH sides have a real CPR/WCPR value. Silently treating a missing value
            # as 0 (the old behavior) made an absent measurement indistinguishable from a
            # genuinely perfect 0.0000 delta -- i.e. it could report "REPRODUCIBLE" from no
            # data at all, not from evidence of reproducibility.
            cpr_available = cpr_a is not None and cpr_b is not None
            wcpr_available = wcpr_a is not None and wcpr_b is not None
            delta_cpr = round(abs(cpr_b - cpr_a), 4) if cpr_available else None
            delta_wcpr = round(abs(wcpr_b - wcpr_a), 4) if wcpr_available else None
            comparisons.append({
                "rep_a": i + 1,
                "rep_b": i + 2,
                "snapshot_a": a_id,
                "snapshot_b": b_id,
                "cpr_a": cpr_a,
                "cpr_b": cpr_b,
                "wcpr_a": wcpr_a,
                "wcpr_b": wcpr_b,
                "delta_cpr": delta_cpr,
                "delta_wcpr": delta_wcpr,
                "delta_wcpr_acceptable": (delta_wcpr <= 0.05) if wcpr_available else None,
                "diff_summary": diff.get("diff") or {},
            })
            _log(state, "INFO",
                 f"  Rep {i+1} vs Rep {i+2}: ΔCPR={delta_cpr if delta_cpr is not None else 'not_available'} "
                 f"ΔWCPR={delta_wcpr if delta_wcpr is not None else 'not_available'} "
                 f"{'✓ ACCEPTABLE' if wcpr_available and delta_wcpr <= 0.05 else ('⚠ EXCEEDS 5% THRESHOLD' if wcpr_available else '— WCPR not available for one or both repetitions')}")

        wcpr_deltas = [c["delta_wcpr"] for c in comparisons if c["delta_wcpr"] is not None]
        missing_wcpr_pairs = [f"rep{c['rep_a']}-rep{c['rep_b']}" for c in comparisons if c["delta_wcpr"] is None]
        all_acceptable = bool(wcpr_deltas) and all(d <= 0.05 for d in wcpr_deltas) and not missing_wcpr_pairs
        max_delta_wcpr = max(wcpr_deltas, default=None)
        reproducibility_index = round(max(0.0, 1.0 - max_delta_wcpr * 10), 4) if max_delta_wcpr is not None else None

        if missing_wcpr_pairs:
            verdict = (
                f"INDETERMINATE — WCPR was not available for {len(missing_wcpr_pairs)} of {len(comparisons)} "
                f"repetition pair(s) ({', '.join(missing_wcpr_pairs)}); reproducibility cannot be honestly assessed "
                "for those pairs. Review why the nested Level B run(s) did not produce WCPR."
            )
        elif all_acceptable:
            verdict = "REPRODUCIBLE — All Level C deployments yield consistent forensic evidence chains."
        else:
            verdict = "NON-REPRODUCIBLE — ΔWCPR exceeds 5% threshold. Review environment stability."

        report = {
            "status": "ok",
            "level_c_repetitions": len(snapshot_ids),
            "comparisons": comparisons,
            "all_delta_wcpr_acceptable": all_acceptable,
            "max_delta_wcpr": max_delta_wcpr,
            "reproducibility_index": reproducibility_index,
            "verdict": verdict,
        }
        alternating = _alternating_design_analysis(comparisons, fault_schedule_log)
        if alternating:
            report["alternating_design_analysis"] = alternating
        _write_json(job_dir / "comparison_report.json", report)
        return report
    except Exception as exc:
        _log(state, "ERROR", f"Comparison failed: {exc}")
        return {"status": "error", "error": str(exc)}


def _alternating_design_analysis(comparisons: list[dict], fault_schedule_log: list[dict] | None) -> dict | None:
    """Groups the per-repetition CPR/WCPR already computed above by
    control/treatment condition (Barlow & Hayes, 1979, alternating treatments
    design -- see _fault_schedule_condition's docstring) instead of only
    comparing consecutive pairs. `comparisons` already carries every
    repetition's own cpr/wcpr twice (as rep_a of one pair and rep_b of the
    next); reconstructed here into one value per repetition, deliberately
    NOT recomputed, so this can never disagree with the pairwise comparisons
    already in the same report."""
    if not fault_schedule_log or not any((item.get("condition") in ("control", "treatment")) for item in fault_schedule_log):
        return None
    per_rep: dict[int, dict] = {}
    if comparisons:
        per_rep[comparisons[0]["rep_a"]] = {"cpr": comparisons[0]["cpr_a"], "wcpr": comparisons[0]["wcpr_a"]}
        for c in comparisons:
            per_rep[c["rep_b"]] = {"cpr": c["cpr_b"], "wcpr": c["wcpr_b"]}

    def _group(condition: str) -> dict:
        reps = [item["rep"] for item in fault_schedule_log if item.get("condition") == condition]
        cprs = [per_rep[r]["cpr"] for r in reps if r in per_rep and per_rep[r]["cpr"] is not None]
        wcprs = [per_rep[r]["wcpr"] for r in reps if r in per_rep and per_rep[r]["wcpr"] is not None]
        return {
            "repetitions": reps,
            "cpr_mean": round(sum(cprs) / len(cprs), 4) if cprs else None,
            "wcpr_mean": round(sum(wcprs) / len(wcprs), 4) if wcprs else None,
        }

    control = _group("control")
    treatment = _group("treatment")
    delta_cpr = (
        round(abs(control["cpr_mean"] - treatment["cpr_mean"]), 4)
        if control["cpr_mean"] is not None and treatment["cpr_mean"] is not None else None
    )
    delta_wcpr = (
        round(abs(control["wcpr_mean"] - treatment["wcpr_mean"]), 4)
        if control["wcpr_mean"] is not None and treatment["wcpr_mean"] is not None else None
    )
    fault_ids = sorted({fault_id for item in fault_schedule_log for fault_id in (inj.get("fault_id") for inj in (item.get("injections") or []))})
    return {
        "methodology": "alternating_treatments_design",
        "reference": "Barlow & Hayes (1979), Journal of Applied Behavior Analysis 12:199-210, DOI 10.1901/jaba.1979.12-199",
        "fault_ids": fault_ids,
        "control": control,
        "treatment": treatment,
        "delta_cpr_control_vs_treatment": delta_cpr,
        "delta_wcpr_control_vs_treatment": delta_wcpr,
        "interpretation": (
            "delta measures the fault's real, measured effect on reproducibility -- a value near 0 means "
            "this fault had no detectable effect in this scenario (a genuine, honest null result), not an error."
        ),
    }


def _extract_cpr_from_snapshot(snap: dict | None) -> float | None:
    if not snap:
        return None
    camps = snap.get("campaigns") or {}
    # 2026-07-20: was reading "level_b_stats" -- the real key scenario_snapshot.service
    # writes is "level_b_statistics". The typo meant this always returned None, silently
    # treated as 0 by the old delta computation, making every Level C comparison report
    # "REPRODUCIBLE" from a complete absence of data rather than real evidence.
    stats = camps.get("level_b_statistics") or {}
    return stats.get("cpr_mean")


def _extract_wcpr_from_snapshot(snap: dict | None) -> float | None:
    if not snap:
        return None
    camps = snap.get("campaigns") or {}
    # 2026-07-20: was reading "level_b_stats" -- the real key scenario_snapshot.service
    # writes is "level_b_statistics". The typo meant this always returned None, silently
    # treated as 0 by the old delta computation, making every Level C comparison report
    # "REPRODUCIBLE" from a complete absence of data rather than real evidence.
    stats = camps.get("level_b_statistics") or {}
    return stats.get("wcpr_mean")


# ---------------------------------------------------------------------------
# Main orchestration loop
# ---------------------------------------------------------------------------

def _is_stop_requested(job_dir: Path) -> bool:
    return (job_dir / "stop.flag").exists()


def _run_level_c_job(job_id: str, job_dir: Path, config: dict) -> None:
    """Background thread: runs the full Level C state machine."""
    state_path = job_dir / "job_state.json"
    state = _load_json(state_path) or {}

    def _save():
        state["updated_at"] = _utc_now()
        _save_state(job_dir, state)

    def _set_phase(phase: str):
        # Set started_at once, on the very first phase transition.
        if not state.get("started_at"):
            state["started_at"] = _utc_now()
        state["phase"] = phase
        # Clean key without "(rep N/N)" suffix — used by the JS progress monitor.
        state["phase_key"] = re.sub(r"\s*\(rep\s+\d+/\d+\)\s*$", "", phase).strip()
        state["phase_started_at"] = _utc_now()
        _log(state, "PHASE", f"→ {phase}")
        # 2026-09-03: host resource snapshot on every phase transition (see
        # _host_resource_snapshot's own docstring for why) — gives a full,
        # free timeline of host load/mem/swap/disk across a repetition
        # without anyone needing to SSH in and run free/uptime by hand after
        # the fact, which is how every host-load-caused failure this session
        # was actually root-caused. Cheap (pure /proc reads), never blocks.
        # Logged as its own INFO entry, deliberately NOT appended to the
        # "→ {phase}" message above — campaign_repetitions.service parses
        # that exact string with an anchored regex ($ at the end); anything
        # trailing it would silently break the whole repetitions tree/table
        # view (caught before shipping by re-checking every consumer of
        # level=="PHASE" log entries, not just eyeballing the format).
        snap = _host_resource_snapshot()
        _log(state, "INFO", f"  [Host] {_host_snapshot_summary(snap)}", extra={"host_snapshot": snap})
        proc_snap = _process_case_pointer_snapshot()
        _log(
            state, "INFO",
            f"  [Proc] pid={proc_snap.get('pid')} active_case_ptr={proc_snap.get('active_case_ptr_raw') or '(empty)'} "
            f"exists_as_dir={proc_snap.get('active_case_ptr_exists_as_dir')}",
            extra={"process_snapshot": proc_snap},
        )
        _save()

    def _check_stop() -> bool:
        """Return True and set STOPPED state if stop was requested."""
        if _is_stop_requested(job_dir):
            _log(state, "INFO", "Stop requested — halting campaign.")
            _set_phase("STOPPED")
            state["status"] = "stopped"
            state["completed_at"] = _utc_now()
            state["error"] = "Campaign stopped by user request."
            _save()
            return True
        return False

    level_c_reps = int(config.get("level_c_repetitions") or 1)
    snapshot_ids: list[str] = []
    fault_schedule = config.get("fault_schedule")
    fault_schedule_log: list[dict] = []

    # ── VALIDATE ─────────────────────────────────────────────────────────────
    _set_phase("VALIDATING")
    if _check_stop(): return
    if not _phase_validate(state, job_dir, config):
        _set_phase("FAILED")
        state["status"] = "failed"
        state["completed_at"] = _utc_now()
        state["error"] = "Validation failed. See log for details."
        _save()
        return

    # ── REPETITION LOOP ──────────────────────────────────────────────────────
    for rep in range(1, level_c_reps + 1):
        if _check_stop(): return
        state["current_repetition"] = rep
        _log(state, "INFO", f"━━━ Starting Level C repetition {rep}/{level_c_reps} ━━━")

        # DESTROY
        _set_phase(f"DESTROYING (rep {rep}/{level_c_reps})")
        if _check_stop(): return
        if not _phase_destroy(state, job_dir, rep):
            if _check_stop(): return  # stop was requested inside destroy
            _set_phase("FAILED")
            state["status"] = "failed"
            state["completed_at"] = _utc_now()
            state["error"] = f"Destruction failed at rep {rep}."
            _save()
            return
        _save()
        time.sleep(10)

        # CLEAN
        if _check_stop(): return
        _set_phase(f"CLEANING (rep {rep}/{level_c_reps})")
        _phase_clean_cases(state, job_dir, rep)
        _phase_clean_installed_records(state, job_dir, rep)
        _save()

        # DEPLOY IT
        if _check_stop(): return
        _set_phase(f"DEPLOYING_IT (rep {rep}/{level_c_reps})")
        if not _phase_deploy_it(state, job_dir, rep):
            if _check_stop(): return  # stop was requested inside deploy
            _set_phase("FAILED")
            state["status"] = "failed"
            state["completed_at"] = _utc_now()
            state["error"] = f"IT deployment failed at rep {rep}."
            _save()
            return
        _save()

        # DEPLOY OT
        if _check_stop(): return
        _set_phase(f"DEPLOYING_OT (rep {rep}/{level_c_reps})")
        _phase_deploy_ot(state, job_dir, rep)
        _save()

        # WAIT NODES
        if _check_stop(): return
        _set_phase(f"WAITING_NODES (rep {rep}/{level_c_reps})")
        if not _phase_wait_nodes(state, job_dir, rep):
            if _check_stop(): return  # stop was requested during wait
            # timeout is non-fatal — continue to tool install
        _save()

        # SYNC CLOCKS — before any tool install, so Level B's alert-window
        # matching later doesn't get poisoned by a drifted VM clock.
        if _check_stop(): return
        _set_phase(f"SYNCING_CLOCKS (rep {rep}/{level_c_reps})")
        _phase_sync_node_clocks(state, job_dir, rep)
        _save()

        # INSTALL TOOLS
        if _check_stop(): return
        _set_phase(f"INSTALLING_TOOLS (rep {rep}/{level_c_reps})")
        if not _phase_install_tools(state, job_dir, rep):
            if _check_stop(): return  # stop was requested mid-install
        _save()

        # VERIFY MONITORING — ensure Wazuh + Suricata are live before attacks
        if _check_stop(): return
        _set_phase(f"VERIFYING_MONITORING (rep {rep}/{level_c_reps})")
        _phase_verify_monitoring(state, job_dir, rep)
        _save()

        # FAULT SCHEDULE -- apply (treatment reps only; see _fault_schedule_condition)
        if _check_stop(): return
        rep_condition = _fault_schedule_condition(fault_schedule, rep)
        active_injections = _apply_fault_schedule_for_rep(state, job_dir, fault_schedule, rep)
        fault_schedule_log.append({"rep": rep, "condition": rep_condition, "injections": active_injections})
        state["fault_schedule_log"] = fault_schedule_log
        _save()

        # RUN LEVEL B
        if _check_stop(): return
        _set_phase(f"RUNNING_LEVEL_B (rep {rep}/{level_c_reps})")
        b_job_id = _phase_run_level_b(state, job_dir, rep, config)
        state["current_level_b_job_id"] = b_job_id
        _save()
        if not b_job_id:
            _revert_fault_schedule_injections(state, rep, active_injections)
            if _check_stop(): return  # stop was requested
            _set_phase("FAILED")
            state["status"] = "failed"
            state["completed_at"] = _utc_now()
            state["error"] = f"Level B launch failed at rep {rep}."
            _save()
            return

        # WAIT LEVEL B
        if _check_stop(): return
        _set_phase(f"WAITING_LEVEL_B (rep {rep}/{level_c_reps})")
        level_b_ok = _phase_wait_level_b(state, job_dir, rep, b_job_id)
        _save()
        if not level_b_ok:
            _revert_fault_schedule_injections(state, rep, active_injections)
            if _check_stop(): return  # stop was requested during wait
            # A real failure/stall (not a give-up-after-N-hours guess, see
            # _phase_wait_level_b) is fatal for the WHOLE campaign, per the
            # 2026-07-17 timeout-philosophy change: still capture a final
            # snapshot so nothing observable is lost, but do not launch the
            # next repetition (which would destroy this scenario) and do not
            # mark the campaign as completed/valid.
            _set_phase(f"CAPTURING_SNAPSHOT (rep {rep}/{level_c_reps})")
            snap_id = _phase_capture_snapshot(state, job_dir, rep)
            if snap_id:
                snapshot_ids.append(snap_id)
            state["level_c_snapshot_ids"] = snapshot_ids
            _set_phase("FAILED")
            state["status"] = "failed"
            state["completed_at"] = _utc_now()
            state["error"] = f"Level B repetition {rep}/{level_c_reps} failed or stalled — see log for the exact cause. Campaign stopped; scenario left intact, nothing already produced was deleted."
            _log(state, "ERROR", state["error"])
            _save()
            return

        # SNAPSHOT -- fault reverted BEFORE the snapshot, never captured mid-fault
        _revert_fault_schedule_injections(state, rep, active_injections)
        if _check_stop(): return
        _set_phase(f"CAPTURING_SNAPSHOT (rep {rep}/{level_c_reps})")
        snap_id = _phase_capture_snapshot(state, job_dir, rep)
        if snap_id:
            snapshot_ids.append(snap_id)
        _save()

    state["level_c_snapshot_ids"] = snapshot_ids

    # ── COMPARE ───────────────────────────────────────────────────────────────
    if _check_stop(): return
    _set_phase("COMPARING")
    comparison = _phase_compare_snapshots(state, job_dir, snapshot_ids, fault_schedule_log)
    state["comparison_report"] = comparison
    _save()

    # ── DONE ──────────────────────────────────────────────────────────────────
    _set_phase("COMPLETED")
    state["status"] = "completed"
    state["completed_at"] = _utc_now()
    state["level_c_snapshot_ids"] = snapshot_ids
    _log(state, "INFO", f"Level C campaign completed. {len(snapshot_ids)} snapshots captured.")
    _save()

    # Auto-generate the FORGE-VI paper_exports reports now that this run is fully done --
    # 2026-07-21: user asked for these to be created automatically at the end of every
    # Level C run, no manual click required. Previously required manually clicking two
    # separate buttons in the Paper Evidence dashboard, and had gone unclicked for 13 days
    # (confirmed live: paper_exports/FORGE-VI/*.json timestamps frozen since 2026-07-07).
    # Both exporter scripts were fixed the same day to recover cleaned-up cases via their
    # preserved lightweight bundles and to default to the latest campaign dynamically
    # instead of a hardcoded one (see tools/forge_vi_paper_metrics_exporter.py and
    # tools/forge_vi_cpr_edge_matrix_exporter.py's own change notes) -- safe to call
    # unconditionally here now. Runs synchronously (job already shows "completed" to the
    # operator by this point, so the ~10-30s this takes doesn't block anything visible);
    # best-effort, any failure is logged into this job's own log but never affects the
    # job's own completed status, which was already saved above.
    _generate_paper_exports(state, job_dir)


def _generate_paper_exports(state: dict, job_dir: Path) -> None:
    """Runs both FORGE-VI paper_exports scripts (workflow metrics + CPR edge matrix),
    the same two scripts the "Generate Level C Workflow Metrics" / "Generate CPR Edge
    Matrix" buttons in the Paper Evidence dashboard trigger manually. Logs into this
    Level C job's own log for visibility; never raises, since this is a best-effort
    enrichment step running after the job's own completed status is already saved.
    """
    import sys
    out_dir = PROJECT_ROOT / "paper_exports" / "FORGE-VI"
    scripts = [
        ("FORGE-VI workflow metrics", PROJECT_ROOT / "tools" / "forge_vi_paper_metrics_exporter.py"),
        ("FORGE-VI CPR edge matrix", PROJECT_ROOT / "tools" / "forge_vi_cpr_edge_matrix_exporter.py"),
    ]
    for label, script in scripts:
        try:
            if not script.is_file():
                _log(state, "WARN", f"{label} export skipped: script not found ({script}).")
                continue
            result = subprocess.run(
                [sys.executable, str(script), "--out-dir", str(out_dir)],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode == 0:
                _log(state, "INFO", f"{label} export completed automatically → {out_dir}")
            else:
                tail = (result.stderr or result.stdout or "").strip()[-500:]
                _log(state, "WARN", f"{label} export failed (exit {result.returncode}): {tail or 'no output'}")
        except Exception as exc:
            _log(state, "WARN", f"{label} export raised an exception: {exc}")
    _save_state(job_dir, state)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_active_jobs: dict[str, threading.Thread] = {}


def launch_level_c(
    *,
    campaign_id: str,
    level_c_repetitions: int = 1,
    level_b_repetitions: int = 10,
    level_a_repetitions: int | None = None,
    confirmation: str = "",
    fault_schedule: dict | None = None,
) -> dict:
    """Launch a Level C campaign orchestration job. Returns job info immediately."""
    if confirmation.strip() != CONFIRMATION_TOKEN:
        return {
            "error": "confirmation_required",
            "message": f'Type exactly "{CONFIRMATION_TOKEN}" to confirm. This will DESTROY the active scenario and redeploy from scratch.',
            "confirmation_token": CONFIRMATION_TOKEN,
        }

    job_id = f"LC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    # 2026-07-22: removed the previous silent upper clamps (min(5, ...) / min(50, ...)) --
    # neither had a comment or any discoverable justification anywhere in this codebase,
    # and they were silently overriding whatever the operator actually requested with zero
    # feedback (confirmed live: a request for 10 Level C repetitions was clamped to 5 with
    # no warning anywhere in the UI, only discovered when the live status panel didn't
    # match what was launched). User: "el número que pongo es el número que tiene que dar
    # de vueltas" -- whatever is typed is now exactly what runs. Only floor (at least 1) is
    # kept, since 0 or negative repetitions has no meaning.
    config = {
        "campaign_id": campaign_id,
        "level_c_repetitions": max(1, level_c_repetitions),
        "level_b_repetitions": max(1, level_b_repetitions),
        "level_a_repetitions": level_a_repetitions or level_b_repetitions,
        # Optional alternating-treatments design (Barlow & Hayes, 1979) --
        # see _fault_schedule_condition/_apply_fault_schedule_for_rep. None
        # (the default, every pre-existing caller) means zero change in
        # behavior: _fault_schedule_condition(None, rep) always returns
        # "none" and no fault is ever applied.
        "fault_schedule": fault_schedule,
    }

    initial_state = {
        "job_id": job_id,
        "job_type": "level_c_campaign",
        "phase": "QUEUED",
        "phase_key": "QUEUED",
        "status": "running",
        "config": config,
        "created_at": _utc_now(),
        "started_at": None,
        "updated_at": _utc_now(),
        "current_repetition": 0,
        "level_c_snapshot_ids": [],
        "comparison_report": None,
        "validation_errors": [],
        "log": [],
    }
    _save_state(job_dir, initial_state)

    thread = threading.Thread(
        target=_run_level_c_job,
        args=(job_id, job_dir, config),
        daemon=True,
    )
    _active_jobs[job_id] = thread
    thread.start()

    return {
        "job_id": job_id,
        "status": "started",
        "config": config,
        "message": f"Level C campaign launched (job {job_id}).",
    }


def get_job_status(job_id: str) -> dict | None:
    path = JOBS_DIR / job_id / "job_state.json"
    state = _load_json(path)
    if not isinstance(state, dict):
        return state
    thread = _active_jobs.get(job_id)
    if thread and thread.is_alive():
        return state  # genuinely alive in this worker — never mark orphaned
    return _recover_orphaned_lc_job(state, JOBS_DIR / job_id)


def stop_job(job_id: str) -> dict:
    """Request graceful stop of a running Level C job.

    Two strategies depending on whether the background thread is still alive:

    • Thread alive (updated_at recent): write stop.flag — the thread picks it up
      within 2 s (Popen poll) or 15 s (status poll) and transitions to STOPPED.

    • Thread dead (Flask restart / crash, updated_at > 60 s old): write STOPPED
      directly to job_state.json so the UI exits "Stopping…" immediately instead
      of being stuck forever.
    """
    job_dir = JOBS_DIR / job_id
    if not job_dir.is_dir():
        return {"error": "job_not_found", "message": f"Job {job_id} does not exist."}

    flag = job_dir / "stop.flag"
    flag.touch()

    state_path = job_dir / "job_state.json"
    state = _load_json(state_path) or {}
    phase = state.get("phase", "unknown")

    if state.get("status") in ("stopped", "completed", "failed"):
        return {"status": "ok", "job_id": job_id, "current_phase": phase,
                "message": "Job is already in a terminal state."}

    # Detect whether the background thread is still alive by checking when the
    # state was last written.  If >60 s old, the thread is gone and nobody will
    # ever process the stop.flag — write STOPPED directly.
    thread_alive = False
    updated_at_str = state.get("updated_at", "")
    if updated_at_str:
        try:
            updated_at = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
            age_s = (datetime.now(timezone.utc) - updated_at).total_seconds()
            thread_alive = age_s < 60
        except Exception:
            pass

    if not thread_alive:
        # Thread is dead — set STOPPED directly so the UI clears immediately
        state["phase"] = "STOPPED"
        state["status"] = "stopped"
        state["stop_requested"] = False
        state["error"] = "Campaign stopped (background thread was no longer active)."
        state["updated_at"] = _utc_now()
        state["completed_at"] = state.get("completed_at") or _utc_now()
        _write_json(state_path, state)
        return {
            "status": "ok",
            "job_id": job_id,
            "current_phase": "STOPPED",
            "message": "Thread was no longer running — state set to STOPPED immediately.",
        }

    # Thread is alive — mark stop_requested so UI shows "Stopping…" right away,
    # the thread will pick up stop.flag within 2–15 s and write STOPPED itself.
    state["stop_requested"] = True
    state["stop_requested_at"] = _utc_now()
    _write_json(state_path, state)
    return {
        "status": "ok",
        "job_id": job_id,
        "current_phase": phase,
        "message": f"Stop requested. Job will halt within ~2–15 s. Current phase: {phase}.",
    }


def list_jobs() -> list[dict]:
    if not JOBS_DIR.is_dir():
        return []
    result = []
    for job_dir in sorted(JOBS_DIR.iterdir(), reverse=True):
        state_file = job_dir / "job_state.json"
        if not state_file.is_file():
            continue
        state = _load_json(state_file) or {}
        thread = _active_jobs.get(state.get("job_id") or job_dir.name)
        if not (thread and thread.is_alive()):
            state = _recover_orphaned_lc_job(state, job_dir)
        result.append({
            "job_id": state.get("job_id", job_dir.name),
            "phase": state.get("phase"),
            "status": state.get("status", "unknown"),
            "current_repetition": state.get("current_repetition", 0),
            "level_c_repetitions": (state.get("config") or {}).get("level_c_repetitions", 1),
            "level_c_snapshot_ids": state.get("level_c_snapshot_ids", []),
            "created_at": state.get("created_at"),
            "completed_at": state.get("completed_at"),
            "error": state.get("error"),
        })
    return result


def get_last_campaign_summary() -> dict | None:
    """Real recap of the most recently touched Level C job, whether or not
    anything is currently running — "what actually happened last time",
    built entirely from persisted state (job log tail, snapshot ids) and,
    where traceable, the linked Level B job's real stage timeline and
    analysis-layer outcomes (reusing get_case_stage_timeline_by_case_id /
    summarize_case_analysis_layers_by_case_id — no new computation, no
    fabricated fields). Returns None only if no Level C job has ever run.

    This is what backs the "what happened" recap any user can open from the
    Live Campaign Status panel, including right after a campaign finishes.
    """
    all_jobs = list_jobs()  # already newest-first; each entry self-heals via _recover_orphaned_lc_job
    if not all_jobs:
        return None
    lc_state = get_job_status(all_jobs[0]["job_id"]) or {}
    log_tail = [
        {"ts": item.get("ts"), "level": item.get("level"), "msg": item.get("msg")}
        for item in (lc_state.get("log") or [])[-12:]
    ]
    result: dict = {
        "job_id": lc_state.get("job_id"),
        "campaign_id": (lc_state.get("config") or {}).get("campaign_id"),
        "status": lc_state.get("status"),
        "phase": lc_state.get("phase"),
        "error": lc_state.get("error"),
        "started_at": lc_state.get("started_at") or lc_state.get("created_at"),
        "completed_at": lc_state.get("completed_at"),
        "snapshot_ids": lc_state.get("level_c_snapshot_ids") or [],
        "log_tail": log_tail,
        # Which repetition of Level C this was, out of how many requested —
        # added 2026-07-17 after the user couldn't tell from the recap alone
        # whether this was e.g. rep 1/2 or rep 2/2 that failed.
        "current_repetition": lc_state.get("current_repetition"),
        "total_repetitions": (lc_state.get("config") or {}).get("level_c_repetitions"),
        "level_b": None,
    }

    b_job_id = lc_state.get("current_level_b_job_id")
    if not b_job_id:
        return result
    try:
        from app_core.infrastructure.foc_experimentation.level_b_repetition_runner import get_level_b_repetition_status
        b_state = get_level_b_repetition_status(b_job_id) or {}
    except Exception:
        b_state = {}
    if not b_state:
        return result

    case_id = b_state.get("current_case_id")
    stage_timeline: list = []
    analysis_layers: list = []
    if case_id:
        try:
            from app_core.infrastructure.forensics.stage_timing_service import (
                get_case_stage_timeline_by_case_id,
                summarize_case_analysis_layers_by_case_id,
            )
            stage_timeline = get_case_stage_timeline_by_case_id(case_id)
            analysis_layers = summarize_case_analysis_layers_by_case_id(case_id)
        except Exception:
            pass

    # Was the nested Level A scientific report ever launched for this
    # repetition? level_b_repetition_runner sets nested_level_a_campaign_id
    # only once it actually calls start_level_a_scientific_report_job — if
    # the Level B job was stopped before reaching that step (e.g. by the
    # stall detector), this stays null even though the case's OWN analysis
    # (14-layer pipeline, see analysis_layers above) may have completed
    # fine. Added 2026-07-17 after the user asked "did it stop at Level B
    # without ever launching Level A, or something else?" and the recap had
    # no way to answer that.
    nested_a_campaign_id = b_state.get("nested_level_a_campaign_id")
    nested_a: dict = {"launched": bool(nested_a_campaign_id), "campaign_id": nested_a_campaign_id}
    child_job_id = b_state.get("current_child_job_id")
    if nested_a_campaign_id and child_job_id:
        try:
            from app_core.infrastructure.foc_experimentation.job_runner import get_job as _get_exp_job
            child_job = _get_exp_job(child_job_id) or {}
            nested_a["job_id"] = child_job_id
            nested_a["status"] = child_job.get("status")
            nested_a["current_phase_label"] = child_job.get("current_phase_label")
        except Exception:
            pass

    result["level_b"] = {
        "job_id": b_state.get("job_id"),
        "status": b_state.get("status"),
        "current_repetition": b_state.get("current_repetition"),
        "requested_repetitions": b_state.get("requested_repetitions") or (b_state.get("meta") or {}).get("requested_repetitions"),
        "current_phase_label": b_state.get("current_phase_label"),
        "completed_repetitions": b_state.get("completed_repetitions"),
        "partial_repetitions": b_state.get("partial_repetitions"),
        "failed_repetitions": b_state.get("failed_repetitions"),
        "current_case_id": case_id,
        "nested_level_a": nested_a,
        "warnings": b_state.get("warnings") or [],
        "errors": b_state.get("errors") or [],
        "stage_timeline": stage_timeline,
        "analysis_layers": analysis_layers,
    }
    return result


_CAMPAIGN_HIERARCHY_CACHE: dict[str, Any] = {"computed_at": 0.0, "value": None}
_CAMPAIGN_HIERARCHY_CACHE_TTL_SECONDS = 30


def _duration_stats(durations: list[float]) -> dict:
    if not durations:
        return {"count_with_duration": 0, "total_seconds": None, "mean_seconds": None, "min_seconds": None, "max_seconds": None}
    return {
        "count_with_duration": len(durations),
        "total_seconds": round(sum(durations), 1),
        "mean_seconds": round(sum(durations) / len(durations), 1),
        "min_seconds": round(min(durations), 1),
        "max_seconds": round(max(durations), 1),
    }


def _compute_campaign_hierarchy_stats() -> dict:
    """How many runs have actually happened at each level (A/B/C) and how
    long they really took — built from the same persisted job files already
    used everywhere else in this module, nothing counted twice or invented.
    A 'run' at each level is one job file: one Level C job = one full
    multi-repetition campaign drive; one Level B job = one repetitions batch
    (whether launched by Level C or standalone); one Level A job = one
    scientific report generation (nested inside a Level B repetition, or
    standalone). Duration is real started/created -> finished timestamps;
    still-running jobs are counted but excluded from duration stats (no
    guessed end time).
    """
    from app_core.infrastructure.foc_experimentation.config import CAMPAIGNS_ROOT

    def _level_stats(job_type_names: set[str], start_field: str, end_field: str) -> dict:
        total = 0
        by_status: dict[str, int] = {}
        durations: list[float] = []
        for job_path in CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
            try:
                payload = json.loads(job_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict) or payload.get("job_type") not in job_type_names:
                continue
            total += 1
            status = str(payload.get("status") or "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            start_ts = _parse_ts(payload.get(start_field))
            end_ts = _parse_ts(payload.get(end_field))
            if start_ts and end_ts and end_ts >= start_ts:
                durations.append(end_ts - start_ts)
        return {"total": total, "by_status": by_status, **_duration_stats(durations)}

    level_b = _level_stats({"level_b_repetitions", "level_b_real_execution"}, "started_at", "finished_at")
    level_a = _level_stats({"level_a_scientific_report"}, "started_at", "finished_at")

    level_c_total = 0
    level_c_by_status: dict[str, int] = {}
    level_c_durations: list[float] = []
    for entry in list_jobs():
        level_c_total += 1
        status = str(entry.get("status") or "unknown")
        level_c_by_status[status] = level_c_by_status.get(status, 0) + 1
        start_ts = _parse_ts(entry.get("created_at"))
        end_ts = _parse_ts(entry.get("completed_at"))
        if start_ts and end_ts and end_ts >= start_ts:
            level_c_durations.append(end_ts - start_ts)
    level_c = {"total": level_c_total, "by_status": level_c_by_status, **_duration_stats(level_c_durations)}

    return {
        "level_a": level_a,
        "level_b": level_b,
        "level_c": level_c,
        "note": (
            "Durations are real created/started -> completed/finished timestamps from each job's own state "
            "file. For a job that was later found orphaned (dead worker, no watchdog yet at the time — see "
            "README), 'completed' is when the watchdog sealed it, not when real work stopped, so its duration "
            "can look inflated. That is a known, already-explained data point, not a bug in this aggregation."
        ),
    }


def get_campaign_hierarchy_stats() -> dict:
    now = time.time()
    if _CAMPAIGN_HIERARCHY_CACHE["value"] is not None and (now - _CAMPAIGN_HIERARCHY_CACHE["computed_at"]) < _CAMPAIGN_HIERARCHY_CACHE_TTL_SECONDS:
        return _CAMPAIGN_HIERARCHY_CACHE["value"]
    value = _compute_campaign_hierarchy_stats()
    _CAMPAIGN_HIERARCHY_CACHE["value"] = value
    _CAMPAIGN_HIERARCHY_CACHE["computed_at"] = now
    return value


def _current_phase_started_at(lc_state: dict) -> str | None:
    """Timestamp of the most recent PHASE transition in the job's own log —
    i.e. when the CURRENT phase actually began, not when the whole campaign
    started. Added 2026-07-18: the panel only ever showed campaign-wide
    elapsed time, which made every phase look like it had been running for
    the full campaign duration so far -- confirmed live against a real job:
    WAITING_NODES showed "13m 11s" elapsed and looked stuck, but the log
    showed it actually started at 14:09:41 and finished by 14:10:25 (44s) —
    the other ~12min was destroy/redeploy phases before it. Pure read of the
    log this module already writes on every _set_phase() call — no new
    tracking, no invented timestamp.
    """
    for entry in reversed(lc_state.get("log") or []):
        if entry.get("level") == "PHASE":
            return entry.get("ts")
    return lc_state.get("started_at") or lc_state.get("created_at")


def get_live_campaign_summary() -> dict:
    """Aggregate the real, currently-persisted status of the running Level C
    job (if any) and its currently active nested Level B repetitions job into
    one truthful readout for the UI's live-status panel.

    Every field here is read directly from persisted job state (job_state.json
    for Level C, the level-b-repetitions job JSON for Level B) — nothing is
    estimated, inferred, or hardcoded. Where a fact genuinely isn't known yet
    (e.g. cleanup for the current repetition hasn't been reached), that is
    reported explicitly as such rather than guessed.
    """
    try:
        campaign_hierarchy = get_campaign_hierarchy_stats()
    except Exception:
        campaign_hierarchy = None

    running = [j for j in list_jobs() if j.get("status") == "running"]
    if not running:
        try:
            last_run = get_last_campaign_summary()
        except Exception:
            last_run = None
        # This panel was originally built to track Level C-orchestrated
        # campaigns only -- "active" meant "a Level C job is running". Once a
        # Level B batch got launched directly (not via Level C), the panel
        # correctly reported active=False but gave no visibility at all into
        # that standalone run, even though it was genuinely in progress.
        # Confirmed live 2026-07-19: user reported "no detecta la nueva
        # repetición de nivel B" right after launching Level B standalone.
        # Fix: check for one, real, on-disk (not the caching-vulnerable
        # job_runner.list_jobs()) via the existing find_active_level_b_job()
        # already used for the concurrent-Level-B guard. Deliberately kept
        # OUT of the active=True/level_c shape (which the whole rest of this
        # function and every frontend reader assumes means "Level C is
        # running") -- a new, additive standalone_level_b field instead, so
        # nothing that depends on the existing contract can break.
        standalone_b = None
        nested_child_job_id = None
        try:
            from app_core.infrastructure.foc_experimentation.level_b_repetition_runner import find_active_level_b_job
            from app_core.infrastructure.foc_experimentation.job_runner import get_job as _get_exp_job
            candidate = find_active_level_b_job()
            if candidate and str(candidate.get("status") or "").lower() == "running":
                stage_timeline = None
                case_id = candidate.get("current_case_id")
                if case_id:
                    try:
                        from app_core.infrastructure.forensics import stage_timing_service
                        stage_timeline = stage_timing_service.get_case_stage_timeline_by_case_id(case_id)
                    except Exception:
                        pass
                # Needed both for de-dupe against standalone_level_a below
                # AND for a real total-elapsed anchor (live if still running,
                # frozen at its last heartbeat if not).
                lb_raw = None
                try:
                    lb_raw = _get_exp_job(candidate.get("job_id"))
                except Exception:
                    lb_raw = None
                nested_child_job_id = (lb_raw or {}).get("current_child_job_id")
                # "estoy en rep 1 o 2?" -- current_phase_label alone (e.g.
                # "Store repetition result") never says WHICH repetition.
                # current_phase itself is "repetition_<N>_<suffix>" -- the
                # same shape campaign_repetitions._LB_CURRENT_PHASE_REP_RE
                # already parses, duplicated here for the same
                # can't-import-forward reason as _stage_timeline_total_elapsed.
                current_repetition = None
                rep_match = re.match(r"^repetition_(\d+)_", str((lb_raw or {}).get("current_phase") or ""))
                if rep_match:
                    current_repetition = int(rep_match.group(1))
                requested_repetitions = ((lb_raw or {}).get("meta") or {}).get("requested_repetitions")
                # Same gap one level deeper: the nested Level A launch (once
                # this repetition reaches "store") only said which dry-run
                # index it's on inside a prose sentence
                # ("Run Dry-Run Execution 2/2: ..."), never as a clean field.
                current_dry_run = None
                dr_match = re.search(r"Run Dry-Run Execution (\d+)/(\d+)", str((lb_raw or {}).get("current_phase_detail") or ""))
                if dr_match:
                    current_dry_run = {"index": int(dr_match.group(1)), "total": int(dr_match.group(2))}
                standalone_b = {
                    "job_id": candidate.get("job_id"),
                    "campaign_id": candidate.get("campaign_id"),
                    "status": candidate.get("status"),
                    "current_repetition": current_repetition,
                    "requested_repetitions": requested_repetitions,
                    "current_phase_label": candidate.get("current_phase_label"),
                    "current_phase_detail": candidate.get("current_phase_detail"),
                    "current_dry_run": current_dry_run,
                    "started_at": candidate.get("started_at"),
                    "current_case_id": case_id,
                    "stage_timeline": stage_timeline,
                    # 2026-07-19: user asked for a real repetition total here
                    # too, not just in the campaign_repetitions detail center.
                    "total_elapsed_seconds": _stage_timeline_total_elapsed(stage_timeline, (lb_raw or {}).get("updated_at")),
                }
        except Exception:
            standalone_b = None

        # Same fix, one level over: a Level A report launched standalone
        # (not nested inside an active Level B repetition, which is already
        # covered above) was equally invisible to this panel. Reported live
        # 2026-07-19 right after the Level B fix above shipped -- the user
        # asked for Level A standalone detection the same way.
        standalone_a = None
        try:
            from app_core.infrastructure.foc_experimentation.level_a_scientific_report_service import find_active_level_a_job
            a_candidate = find_active_level_a_job()
            if (
                a_candidate
                and str(a_candidate.get("status") or "").lower() == "running"
                and a_candidate.get("job_id") != nested_child_job_id
            ):
                a_analysis_layers = None
                a_case_id = a_candidate.get("current_case_id")
                if a_case_id:
                    try:
                        from app_core.infrastructure.forensics import stage_timing_service
                        a_analysis_layers = stage_timing_service.summarize_case_analysis_layers_by_case_id(a_case_id)
                    except Exception:
                        pass
                a_updated_at = None
                try:
                    a_raw = _get_exp_job(a_candidate.get("job_id"))
                    a_updated_at = (a_raw or {}).get("updated_at")
                except Exception:
                    a_updated_at = None
                a_dry_run = None
                a_dr_match = re.search(r"Run Dry-Run Execution (\d+)/(\d+)", str(a_candidate.get("current_phase_detail") or ""))
                if a_dr_match:
                    a_dry_run = {"index": int(a_dr_match.group(1)), "total": int(a_dr_match.group(2))}
                standalone_a = {
                    "job_id": a_candidate.get("job_id"),
                    "campaign_id": a_candidate.get("campaign_id"),
                    "status": a_candidate.get("status"),
                    "current_phase_label": a_candidate.get("current_phase_label"),
                    "current_phase_detail": a_candidate.get("current_phase_detail"),
                    "current_dry_run": a_dry_run,
                    "started_at": a_candidate.get("started_at"),
                    "current_case_id": a_case_id,
                    "analysis_layers": a_analysis_layers,
                    "total_elapsed_seconds": _seconds_between(a_candidate.get("started_at"), a_updated_at),
                }
        except Exception:
            standalone_a = None

        return {
            "active": False,
            "last_run": last_run,
            "campaign_hierarchy": campaign_hierarchy,
            "standalone_level_b": standalone_b,
            "standalone_level_a": standalone_a,
        }

    lc_state = get_job_status(running[0]["job_id"]) or {}
    result: dict = {
        "active": True,
        "level_c": {
            "job_id": lc_state.get("job_id"),
            "status": lc_state.get("status"),
            "phase": lc_state.get("phase"),
            "current_repetition": lc_state.get("current_repetition"),
            "total_repetitions": (lc_state.get("config") or {}).get("level_c_repetitions"),
            "campaign_id": (lc_state.get("config") or {}).get("campaign_id"),
            "started_at": lc_state.get("started_at") or lc_state.get("created_at"),
            "phase_started_at": _current_phase_started_at(lc_state),
        },
        "level_b": None,
        "campaign_hierarchy": campaign_hierarchy,
    }

    b_job_id = lc_state.get("current_level_b_job_id")
    campaign_id = (lc_state.get("config") or {}).get("campaign_id")
    try:
        from app_core.infrastructure.foc_experimentation.level_b_repetition_runner import (
            find_active_level_b_job,
            get_level_b_repetition_status,
        )
        if not b_job_id:
            # Older Level C job threads (started before current_level_b_job_id
            # was persisted) never wrote this field. Fall back to the same
            # disk-scan used for the concurrent-launch guard, restricted to
            # this campaign — still real, on-disk job state, not a guess.
            active = find_active_level_b_job()
            if active and active.get("campaign_id") == campaign_id:
                b_job_id = active.get("job_id")
        b_state = get_level_b_repetition_status(b_job_id) if b_job_id else {}
        b_state = b_state or {}
    except Exception:
        b_state = {}
    if not b_state:
        return result

    current_rep = b_state.get("current_repetition")
    phase_statuses = b_state.get("phase_statuses") or []
    cleanup_key = f"repetition_{current_rep}_cleanup" if current_rep else None
    cleanup_entry = None
    if cleanup_key:
        for item in reversed(phase_statuses):
            if item.get("phase_key") == cleanup_key:
                cleanup_entry = item
                break

    # Same "when did the CURRENT phase actually start" fix as level_c above
    # — b_state.started_at is when the whole Level B batch began, which
    # made every phase look like it had been running for the full batch
    # duration so far. phase_statuses already records a "running" entry per
    # phase transition (append_phase, existing behavior) — just reading the
    # latest one here, nothing new tracked.
    phase_started_at = b_state.get("started_at") or b_state.get("requested_at")
    for item in reversed(phase_statuses):
        if item.get("status") == "running":
            phase_started_at = item.get("updated_at") or phase_started_at
            break

    result["level_b"] = {
        "job_id": b_state.get("job_id"),
        "status": b_state.get("status"),
        "current_repetition": current_rep,
        "requested_repetitions": b_state.get("requested_repetitions") or (b_state.get("meta") or {}).get("requested_repetitions"),
        "current_case_id": b_state.get("current_case_id"),
        "current_phase_label": b_state.get("current_phase_label"),
        "current_phase_detail": b_state.get("current_phase_detail"),
        "progress_percent": b_state.get("progress_percent"),
        "started_at": b_state.get("started_at") or b_state.get("requested_at"),
        "phase_started_at": phase_started_at,
        "heavy_artifact_cleanup_for_current_repetition": {
            "status": cleanup_entry.get("status") if cleanup_entry else "not_yet_reached",
            "detail": cleanup_entry.get("detail") if cleanup_entry else "The automatic cleanup phase for this repetition has not run yet — it fires after nested Level A analysis finishes for this repetition.",
        },
    }

    case_id = b_state.get("current_case_id")
    if case_id:
        try:
            from app_core.infrastructure.forensics.stage_timing_service import get_case_stage_timeline_by_case_id
            result["level_b"]["stage_timeline"] = get_case_stage_timeline_by_case_id(case_id)
        except Exception:
            result["level_b"]["stage_timeline"] = []

    return result


def get_comparison_report(job_id: str) -> dict | None:
    path = JOBS_DIR / job_id / "comparison_report.json"
    return _load_json(path)
