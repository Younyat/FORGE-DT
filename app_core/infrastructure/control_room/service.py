from __future__ import annotations

"""Read-only aggregator for the "Control Room" dashboard. See
investigacion_y_novedad/08_dashboard_sala_control.md for the full design,
the research sources, and the implementation phases.

Guiding principle (section 3.1 of the document): measure nothing new, just
aggregate into a single payload what existing modules already expose. This
file opens no SSH connection, calls no OpenStack API, creates no new
thread -- all it does is read state already computed by other modules
(memory_watchdog, job_runner, campaign_repetitions, this same job_chain) and
combine it with hash-based cutoff, same as monitor3d.get_snapshot().
"""

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .job_chain import walk_job_chain

_ACQ_CORE_STAGE_KEYS = {"memory_acquisition", "disk_acquisition", "ot_export", "network_context_import"}


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


def _parse_iso(value: str | None):
    if not value:
        return None
    try:
        v = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

# Was 3.0 -- found 2026-10-13 to be shorter than useful in practice: this
# cache is a plain process-global, so each of gunicorn's worker processes
# keeps its OWN independent copy (never shared across workers). The
# dashboard polls this endpoint every 5s, and gunicorn distributes requests
# across all 4 workers -- with a 3s TTL, a request landing back on the same
# worker within its own cache's lifetime was the exception, not the rule,
# so nearly every poll forced a full recompute. Measured real cost of that
# recompute: ~4.7s combined across _attack_lab_section (2.6s, dominated by
# a one-time cold import of monitor3d.service on a worker's first call --
# ~20ms on every call after that in the same worker), _active_campaigns_section
# (0.9s), _scenario_nodes_section (0.6s), _evidence_store_section (0.57s).
# 10s keeps the dashboard's own data far fresher than a human notices for
# campaign/node status, while giving every worker's cache a real chance to
# be reused across its own next 1-2 polls instead of recomputing every time.
_CACHE_TTL_SECONDS = 10.0
_cache: dict | None = None
_cache_ts = 0.0
_cache_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_worker_thread_census() -> dict:
    """The only genuinely new signal in the whole dashboard (section 3.4):
    ~0 cost, purely in-memory. Since gunicorn runs several sync workers
    without --worker-class, this only sees the threads OF THIS particular
    worker -- the payload states that explicitly instead of pretending to a
    global view that doesn't exist."""
    try:
        threads = threading.enumerate()
        return {
            "pid": os.getpid(),
            "thread_count": threading.active_count(),
            "threads": [
                {"name": t.name, "alive": t.is_alive(), "daemon": t.daemon}
                for t in threads
            ],
            "note": "Only the threads of THIS gunicorn worker (PID above) -- with several sync "
                    "workers, each request can land on a different one; calling repeatedly "
                    "samples the different workers.",
        }
    except Exception as exc:
        return {"pid": os.getpid(), "error": str(exc)}


def _host_memory_section() -> dict:
    try:
        from app_core.infrastructure.memory_watchdog.service import (
            get_memory_pressure_snapshot,
            get_recent_watchdog_events,
        )
        snapshot = get_memory_pressure_snapshot()
        snapshot["recent_watchdog_events"] = get_recent_watchdog_events(limit=5)
        return snapshot
    except Exception as exc:
        return {"error": str(exc), "source": "not_available"}


def _host_basic_section() -> dict:
    """Hostname/loadavg -- the same cheap local commands already used by
    node_health_api._local_host_summary(), without needing the OpenStack node
    list that function normally requires as an argument."""
    import subprocess

    def _run(cmd: list[str]) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            return ""

    return {
        "hostname": _run(["hostname"]) or "not_available",
        "loadavg": _run(["bash", "-lc", "cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}'"]) or "not_available",
    }


def _host_processes_section() -> dict:
    """Real HOST processes (not a VM's, over SSH) -- the same `ps` command
    already used over SSH against each VM by probe_node_health_inside_node.sh,
    here run locally against the host that serves the dashboard itself. It is
    read-only: it never sends signals, never kills anything -- that is left
    for explicit actions confirmed by the user (see README)."""
    import subprocess

    def _ps(sort_key: str) -> list[dict]:
        try:
            out = subprocess.run(
                ["ps", "-eo", "pid,ppid,comm,%cpu,%mem,etimes", f"--sort=-{sort_key}"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            rows = []
            for line in out.splitlines()[1:11]:
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                pid, ppid, comm, cpu, mem, etimes = parts
                rows.append({
                    "pid": int(pid), "ppid": int(ppid), "command": comm,
                    "cpu_pct": float(cpu), "mem_pct": float(mem), "elapsed_seconds": int(etimes),
                })
            return rows
        except Exception:
            return []

    top_cpu = _ps("%cpu")
    top_mem = _ps("%mem")
    if not top_cpu and not top_mem:
        return {"source": "not_available"}
    return {"top_cpu": top_cpu, "top_mem": top_mem, "source": "real_sensor"}


def _active_campaigns_section(limit: int) -> list[dict]:
    """Discovers recent campaigns by reading disk (doesn't depend on THIS
    worker being the one that launched them -- campaign_repetitions.
    list_recent_repetitions already reads the state files directly), and for
    the ones still "running" walks their real nesting chain with job_chain."""
    try:
        from app_core.infrastructure.campaign_repetitions.service import list_recent_repetitions
    except Exception as exc:
        return [{"error": str(exc)}]

    try:
        rows = list_recent_repetitions(limit=limit)
    except Exception as exc:
        return [{"error": str(exc)}]

    out = []
    for row in rows:
        entry = {
            "campaign_id": row.get("campaign_id"),
            "job_id": row.get("job_id"),
            "level": row.get("level"),
            "repetition_status": row.get("repetition_status"),
            "execution_label": row.get("execution_label"),
        }
        if str(row.get("repetition_status") or "").lower() == "running" and row.get("job_id"):
            store = "level_c" if row.get("level") == "C" else "job_runner"
            try:
                entry["job_chain"] = walk_job_chain(row["job_id"], root_store=store)
            except Exception as exc:
                entry["job_chain"] = {"error": str(exc)}
        out.append(entry)
    return out


def _scenario_nodes_section() -> dict:
    """Real inventory of the scenario's nodes (5 known VMs) reusing
    node_health._list_nodes() -- NEVER triggers a new SSH probe (that remains
    on-demand, an explicit button, as everywhere else in the platform).
    Splits IT (victim/attacker/monitor) from OT (plc/scada) for the "IT
    Scenario" / "OT Scenario" boxes, exactly as the user requested in the
    reference image.

    Per-node CPU/RAM/disk is added via build_node_health_summary(
    refresh_node_metrics=False) -- confirmed by reading
    _probe_cached_or_refresh: with refresh=False it NEVER calls
    _probe_node_live (SSH), it only reads the disk cache already written by
    the last manual probe from Node Health; if a node has never been probed,
    it honestly reports "not_available" instead of inventing a value. This is
    the same cache-only call already used by monitor3d.get_host_vitals()."""
    try:
        from app_core.infrastructure.node_health.node_health_api import _list_nodes
        nodes = _list_nodes()
    except Exception as exc:
        return {"error": str(exc), "nodes": [], "total": 0, "active": 0, "it_count": 0, "ot_count": 0}

    metrics_by_id: dict[str, dict] = {}
    try:
        from app_core.infrastructure.node_health.node_health_api import build_node_health_summary
        summary = build_node_health_summary(refresh_node_metrics=False)
        metrics_by_id = {row.get("id"): row for row in (summary.get("nodes") or []) if row.get("id")}
    except Exception:
        pass

    it_roles = {"victim", "attacker", "monitor"}
    ot_roles = {"plc", "scada"}
    out_nodes = []
    for n in nodes:
        metrics = metrics_by_id.get(n.get("id")) or {}
        out_nodes.append({
            "id": n.get("id"),
            "name": n.get("name"),
            "role": n.get("role"),
            "status": n.get("status"),
            "ip": n.get("ssh_target_ip") or n.get("ip_floating") or n.get("ip_private"),
            "cpu_usage_pct": metrics.get("cpu_usage_pct"),
            "memory_usage_pct": metrics.get("memory_usage_pct"),
            "disk_root_use_pct": metrics.get("disk_root_use_pct"),
            "overall_severity": metrics.get("overall_severity", "unknown"),
            "metrics_source": metrics.get("source", "not_available"),
            "metrics_stale": metrics.get("stale", True),
            "metrics_age_seconds": metrics.get("cache_age_seconds"),
        })
    return {
        "nodes": out_nodes,
        "instance_ids": sorted({n.get("id") for n in nodes if n.get("id")}),
        "total": len(nodes),
        "active": sum(1 for n in nodes if str(n.get("status") or "").upper() == "ACTIVE"),
        "it_count": sum(1 for n in nodes if n.get("role") in it_roles),
        "ot_count": sum(1 for n in nodes if n.get("role") in ot_roles),
        "metrics_note": "cpu/ram/disk are cache-ONLY (never trigger a new SSH probe) -- "
                        "they may be stale if nobody has refreshed Node Health recently; "
                        "see metrics_source/metrics_stale/metrics_age_seconds per node",
    }


def _ot_asset_section() -> dict:
    """Reads directly the real Modbus/PLC register map already resolved by
    parse_fuxa_project() (see investigacion_y_novedad/05_nombre_y_evolucion.md)
    -- a file already generated on disk, nothing is recomputed here."""
    try:
        from app_core.infrastructure.attack.industrial_resolver import RUNTIME_ASSETS_PATH
        base_dir = RUNTIME_ASSETS_PATH.parent
    except Exception:
        base_dir = None

    try:
        path = (base_dir / "industrial_asset_register_map.json") if base_dir else None
        if not path or not path.is_file():
            return {"source": "not_available"}
        data = json.loads(path.read_text(encoding="utf-8"))
        registers = data.get("registers") or []
        hmi_views = {ref.get("view_id") for reg in registers for ref in (reg.get("hmi_refs") or []) if ref.get("view_id")}
        return {
            "plc_count": 1 if data.get("plc") else 0,
            "register_count": len(registers),
            "hmi_view_count": len(hmi_views),
            "source": "real_sensor",
        }
    except Exception as exc:
        return {"source": "not_available", "error": str(exc)}


def _tools_section(current_instance_ids: set[str]) -> dict:
    """Counts tools installed ONLY on the real VMs that exist right now
    (current_instance_ids, from _scenario_nodes_section). The
    tools-installer/installed/ directory accumulates one file per
    instance_id that has ever existed (618 historical files seen this
    session, from months of deployments) -- exactly the same "unbounded
    accumulation" pattern as the alert_correlation.json finding this session;
    summing the whole directory would give a meaningless number (thousands of
    "installed" tools on VMs that no longer exist). If the list of current
    VMs can't be resolved (e.g. no OpenStack credentials), honestly returns
    not_available instead of falling back to the historical total."""
    try:
        from app_core.infrastructure.node_health.node_health_api import TOOLS_INSTALLED_DIR
    except Exception:
        return {"tools_installed": None, "source": "not_available"}
    if not current_instance_ids:
        return {"tools_installed": None, "source": "not_available", "reason": "no_current_instance_ids"}
    try:
        total = 0
        for instance_id in current_instance_ids:
            f = TOOLS_INSTALLED_DIR / f"{instance_id}.json"
            if not f.is_file():
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                total += len(data.get("installed_tools") or {})
            except Exception:
                continue
        return {"tools_installed": total, "source": "real_sensor"}
    except Exception as exc:
        return {"tools_installed": None, "source": "not_available", "error": str(exc)}


def _evidence_store_section() -> dict:
    """Real forensic case count -- simple directory listing (cheap, no content
    walk) for `case_count`. Also sums real artifacts/bytes by reading the
    `size`/`artifacts` fields ALREADY persisted in each `manifest.json` in the
    store (measured live: 175 manifests, 0.41s total read time) -- never a
    recursive `du -sh` of the whole store (already confirmed expensive this
    same session: 122GB+, minutes of CPU)."""
    try:
        from app_core.infrastructure.foc_experimentation.config import EVIDENCE_STORE_ROOT
    except Exception:
        return {"case_count": None, "source": "not_available"}
    try:
        cases = [p for p in EVIDENCE_STORE_ROOT.iterdir() if p.is_dir() and (p.name.startswith("CASE-") or p.name.startswith("case-"))]
        # `campaign_packages/` is an EXPORTED package that literally duplicates the same
        # case-*/CASE-* directories that already exist under `repetition_campaigns/`
        # (verified: same leaf directory name, same total size, same artifact count) --
        # summing both trees would double-count. Deduplicated by leaf directory name
        # (case-xxxxxxxx / CASE-YYYYMMDD-HHMMSS), the only stable key observed on disk.
        seen_case_dirs: dict[str, tuple[int, int]] = {}
        for manifest_path in EVIDENCE_STORE_ROOT.rglob("manifest.json"):
            data = _safe(lambda: json.loads(manifest_path.read_text(encoding="utf-8")))
            if not isinstance(data, dict):
                continue
            artifacts = data.get("artifacts") or []
            case_key = manifest_path.parent.name
            seen_case_dirs[case_key] = (
                len(artifacts),
                sum(int(a.get("size") or 0) for a in artifacts),
            )
        artifact_count = sum(c for c, _ in seen_case_dirs.values())
        total_size_bytes = sum(b for _, b in seen_case_dirs.values())
        return {
            "case_count": len(cases),
            "manifest_count": len(seen_case_dirs),
            "artifact_count": artifact_count,
            "total_size_bytes": total_size_bytes,
            # One real cell per distinct case ever registered (for the
            # "wall of lights" in All in One mode) -- capped at 300, not a
            # made-up figure.
            "case_keys": sorted(seen_case_dirs.keys())[:300],
            "note": "case_count = top-level acquisition cases; manifest_count/artifact_count/"
                    "total_size_bytes are the deduplicated HISTORICAL TOTAL of every case ever "
                    "registered in the evidence_store (including repetition/campaign bundles) -- not "
                    "current disk usage nor the size of the running campaign",
            "source": "real_sensor",
        }
    except Exception as exc:
        return {"case_count": None, "source": "not_available", "error": str(exc)}


def _attack_lab_section() -> dict:
    """Real attack-catalog templates + attacks genuinely active right now
    (window started_at<=now<=completed_at in attack_attestation.json).
    `attacks_recorded_total` is a HISTORICAL counter for the whole lab
    (653 records measured this session) -- explicitly labeled as such so as
    not to repeat the alert_correlation.json mistake (confusing an
    accumulated total with current state)."""
    templates_count = None
    try:
        from app_core.infrastructure.attack.catalog import ATTACK_CATALOG
        templates_count = len(ATTACK_CATALOG)
    except Exception:
        pass

    try:
        from app_core.infrastructure.monitor3d.service import ATTACK_ATTESTATION_PATH
        if not ATTACK_ATTESTATION_PATH.is_file():
            return {"templates_count": templates_count, "active_now": 0, "attacks_recorded_total": 0, "source": "not_available"}
        data = json.loads(ATTACK_ATTESTATION_PATH.read_text(encoding="utf-8"))
        attacks = data.get("attacks") or []
        now = datetime.now(timezone.utc)
        active_now = 0
        active_attacks: list[dict] = []
        last_attack = None
        last_started = None
        # Verified against real data: of 653 attacks, only 2 have a null
        # completed_at, and both have gone MONTHS without completing
        # (started_at back in June) -- while the remaining 651 DO have a
        # completed_at and last between 0.5s and 80s (95th percentile: 45s).
        # Treating "null completed_at" as "still running" with no time limit
        # flagged these 2 abandoned/broken records as "attack active now",
        # which is misleading -- started_at is additionally required to be
        # recent (<=30 min, well above the real observed maximum) to count as
        # genuinely active.
        _STILL_RUNNING_MAX_AGE_SECONDS = 1800
        for record in attacks:
            execution = (record or {}).get("execution") or {}
            started = _parse_iso(execution.get("started_at"))
            completed = _parse_iso(execution.get("completed_at"))
            if completed is not None:
                is_active = bool(started and started <= now <= completed)
            else:
                is_active = bool(started and started <= now and (now - started).total_seconds() <= _STILL_RUNNING_MAX_AGE_SECONDS)
            if is_active:
                active_now += 1
                if len(active_attacks) < 30:
                    active_attacks.append({
                        "attack_id": record.get("attack_id"),
                        "attack_name": record.get("attack_name") or record.get("display_name"),
                        "mitre_technique": ((record.get("mitre") or {}).get("technique_id")),
                        "attacker_ip": ((record or {}).get("attacker") or {}).get("ip"),
                        "target_ip": ((record or {}).get("target") or {}).get("target_ip"),
                        "started_at": execution.get("started_at"),
                        "completed_at": execution.get("completed_at"),
                    })
            if started and (last_started is None or started > last_started):
                last_started = started
                last_attack = {
                    "attack_name": record.get("attack_name") or record.get("display_name"),
                    "target_ip": ((record or {}).get("target") or {}).get("target_ip"),
                    "started_at": execution.get("started_at"),
                    "completed_at": execution.get("completed_at"),
                    "execution_status": record.get("execution_status"),
                }
        return {
            "templates_count": templates_count,
            "active_now": active_now,
            "active_attacks": active_attacks,
            "attacks_recorded_total": len(attacks),
            "last_attack": last_attack,
            # A real, minimal signal (status only) for each of the last N
            # recorded attacks -- used ONLY for the "wall of lights" in All in
            # One mode (one cell == one real attack_attestation.json record,
            # never a decorative/random light).
            "history_signals": [
                {"status": r.get("execution_status") or "unknown"}
                for r in attacks[-500:]
            ],
            "note": "attacks_recorded_total es historico acumulado de todo el laboratorio, no del proceso actual",
            "source": "real_sensor",
        }
    except Exception as exc:
        return {"templates_count": templates_count, "active_now": None, "source": "not_available", "error": str(exc)}


def _forensic_acquisition_section() -> dict:
    """Real per-artifact state of the currently ACTIVE case (if any), via the
    same pointer (`_read_active_case_dir`) and the same timeline service
    (`stage_timing_service`) already used by node_health and monitor3d. There
    is no real "Live Response" stage in the platform's event vocabulary -- it
    is honestly reported as unavailable instead of inventing a fourth
    state."""
    try:
        from app_core.infrastructure.node_health.node_health_api import _read_active_case_dir
        case_dir = _read_active_case_dir()
    except Exception as exc:
        return {"active": False, "source": "not_available", "error": str(exc)}
    if not case_dir:
        return {"active": False, "source": "no_active_case"}

    case_path = Path(case_dir)
    try:
        from app_core.infrastructure.forensics.stage_timing_service import get_case_stage_timeline_by_case_id
        timeline = get_case_stage_timeline_by_case_id(case_path.name) or []
    except Exception as exc:
        return {"active": True, "case_id": case_path.name, "source": "not_available", "error": str(exc)}

    stage_status = {str(s.get("stage_key") or ""): s.get("status") for s in timeline}
    network_status = stage_status.get("network_context_import") or stage_status.get("ot_export")
    core_stages = [s for s in timeline if str(s.get("stage_key") or "") in _ACQ_CORE_STAGE_KEYS]
    completed = sum(1 for s in core_stages if s.get("status") == "completed")
    total = len(core_stages)
    return {
        "active": True,
        "case_id": case_path.name,
        "stages": {
            "memory": stage_status.get("memory_acquisition") or "pending",
            "disk": stage_status.get("disk_acquisition") or "pending",
            "network": network_status or "pending",
            "live_response": None,
        },
        "progress_pct": round(100 * completed / total) if total else None,
        "note": "live_response has no real stage instrumented in the platform",
        "source": "real_sensor",
    }


def _resolve_recent_case_dir() -> Path | None:
    """The active case if there is one; otherwise the latest case per
    foc-reconstruction/indexes/cases_index.json (the same index already used
    by the FOC module) -- never recomputes or regenerates anything."""
    try:
        from app_core.infrastructure.node_health.node_health_api import _read_active_case_dir
        active = _read_active_case_dir()
        if active:
            return Path(active)
    except Exception:
        pass
    try:
        from app_core.infrastructure.monitor3d.service import PROJECT_ROOT
        idx_path = PROJECT_ROOT / "foc-reconstruction" / "indexes" / "cases_index.json"
        if not idx_path.is_file():
            return None
        data = json.loads(idx_path.read_text(encoding="utf-8"))
        cases = data.get("cases") or []
        if not cases:
            return None
        # The index's "path" field can go stale if the case was archived later
        # (seen live: a case pointed to a top-level path that no longer
        # exists, because it moved to repetition_campaigns/.../final_sample_case/)
        # -- walked from most recent to oldest, using the first one whose
        # directory REALLY STILL exists on disk, never trusting the "path"
        # field blindly.
        cases_sorted = sorted(cases, key=lambda c: c.get("source_case_name") or "", reverse=True)
        for entry in cases_sorted:
            candidate = PROJECT_ROOT / entry["path"]
            if candidate.is_dir():
                return candidate
        return None
    except Exception:
        return None


def _foc_reconstruction_section() -> dict:
    """Real CPR/WCPR + real causal graph size of the most recently resolvable
    case -- both files are already written by foc_causal_reconstruction when
    sealing the case; here they are only read."""
    case_dir = _safe(_resolve_recent_case_dir)
    if not case_dir:
        return {"source": "not_available", "reason": "no_case_resolved"}
    out = {"case_id": case_dir.name, "source": "not_available"}
    try:
        metrics_path = case_dir / "derived" / "reconstruction" / "reconstruction_metrics.json"
        graph_path = case_dir / "derived" / "reconstruction" / "causal_graph.json"
        if metrics_path.is_file():
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            out["cpr"] = metrics.get("causal_path_recoverability")
            out["weighted_cpr"] = metrics.get("weighted_cpr")
            out["recoverability_label"] = metrics.get("recoverability_label")
            out["source"] = "real_sensor"
        if graph_path.is_file():
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            nodes = graph.get("nodes") or []
            edges = graph.get("edges") or []
            out["node_count"] = len(nodes)
            out["edge_count"] = len(edges)
            out["source"] = "real_sensor"
            node_labels = {n.get("node_id"): n.get("label") or n.get("node_id") for n in nodes}
            out["graph_edges_preview"] = [
                {
                    "source": node_labels.get(e.get("source"), e.get("source")),
                    "target": node_labels.get(e.get("target"), e.get("target")),
                    "support_status": e.get("support_status"),
                }
                for e in edges[:25]
            ]
        return out
    except Exception as exc:
        out["error"] = str(exc)
        return out


def _forensic_analysis_section() -> dict:
    """Analysis phases for the most recently resolvable case
    (analysis/analysis_status.json, already written by the forensic
    pipeline) -- scoped to ONE case, never a global counter (none exists)."""
    case_dir = _safe(_resolve_recent_case_dir)
    if not case_dir:
        return {"source": "not_available", "reason": "no_case_resolved"}
    status_path = case_dir / "analysis" / "analysis_status.json"
    if not status_path.is_file():
        return {"case_id": case_dir.name, "source": "not_available"}
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
        phases = data.get("phases") or {}
        completed = sum(1 for p in phases.values() if str((p or {}).get("status") or "").lower() == "completed")
        return {
            "case_id": case_dir.name,
            "phases_total": len(phases),
            "phases_completed": completed,
            "progress_percent": data.get("progress_percent"),
            # Real name + status for each phase (analysis_status.json already
            # tags them with a readable "label") -- so bars are drawn with
            # real names (Pre-flight validation, Evidence inventory, ...)
            # instead of made-up generic names (Ingest/Parse/Correlate...).
            "phases_list": [
                {"label": (v or {}).get("label") or k, "status": (v or {}).get("status")}
                for k, v in phases.items()
            ],
            "source": "real_sensor",
        }
    except Exception as exc:
        return {"case_id": case_dir.name, "source": "not_available", "error": str(exc)}


def _campaign_comparisons_section(campaign_rows: list[dict]) -> dict:
    """Real comparison report already persisted by level_c_orchestrator
    (comparison_report.json) for the most recent Level C campaign that has
    one -- only exists after >=2 completed repetitions with the comparison
    step already run; otherwise declared not available."""
    level_c_jobs = [r for r in campaign_rows if r.get("level") == "C" and r.get("job_id")]
    if not level_c_jobs:
        return {"source": "not_available", "reason": "no_level_c_campaign_found"}
    try:
        from app_core.infrastructure.level_c_orchestrator.service import get_comparison_report
    except Exception as exc:
        return {"source": "not_available", "error": str(exc)}
    for row in level_c_jobs:
        report = _safe(lambda job_id=row["job_id"]: get_comparison_report(job_id))
        if report:
            comparisons = report.get("comparisons") or []
            repro = report.get("reproducibility_index")
            return {
                "job_id": row["job_id"],
                "comparisons_count": len(comparisons),
                "reproducibility_index_pct": round(repro * 100, 1) if repro is not None else None,
                "verdict": report.get("verdict"),
                "all_delta_wcpr_acceptable": report.get("all_delta_wcpr_acceptable"),
                "source": "real_sensor",
            }
    return {"source": "not_available", "reason": "no_comparison_report_persisted_yet"}


def _alerts_section() -> dict:
    """Reads the cache already persisted by node_health.build_node_health_summary()
    (HEALTH_SUMMARY_CACHE_PATH) -- the same topbar alert bell (see
    node_health/README.md). Recomputes nothing, triggers no new
    OpenStack/SSH query: it's a read of a JSON that another module already
    writes on each of its own runs."""
    try:
        from app_core.infrastructure.node_health.node_health_api import HEALTH_SUMMARY_CACHE_PATH
        if not HEALTH_SUMMARY_CACHE_PATH.is_file():
            return {"count": None, "source": "not_available"}
        data = json.loads(HEALTH_SUMMARY_CACHE_PATH.read_text(encoding="utf-8"))
        alerts = data.get("alerts") or []
        return {
            "count": data.get("alert_count", len(alerts)),
            "critical": sum(1 for a in alerts if str(a.get("severity", "")).lower() == "critical"),
            "warning": sum(1 for a in alerts if str(a.get("severity", "")).lower() == "warning"),
            "generated_at": data.get("generated_at"),
            "items": [
                {
                    "alert_id": a.get("alert_id"),
                    "severity": a.get("severity"),
                    "scope": a.get("scope"),
                    "target": a.get("target"),
                    "title": a.get("title"),
                    "detail": a.get("detail"),
                    "generated_at": a.get("generated_at"),
                }
                for a in alerts[:30]
            ],
            "source": "real_sensor_cached",
        }
    except Exception as exc:
        return {"count": None, "source": "not_available", "error": str(exc)}


def _campaigns_summary_section(rows: list[dict]) -> dict:
    """Aggregated summary of the campaigns already discovered by
    _active_campaigns_section -- reads nothing again, just counts what was
    already read to avoid a second disk walk."""
    total = len(rows)
    running = sum(1 for r in rows if str(r.get("repetition_status", "")).lower() == "running")
    completed = sum(1 for r in rows if str(r.get("repetition_status", "")).lower() == "completed")
    failed = sum(1 for r in rows if str(r.get("repetition_status", "")).lower() in {"failed", "partial"})
    return {"total": total, "running": running, "completed": completed, "failed": failed}


def _current_process_section(campaign_rows: list[dict], attack_lab: dict | None = None) -> dict | None:
    """The first genuinely "running" job among the already-discovered
    campaigns, with its honest nesting chain (job_chain) if it has one
    (`mode: "running"`). If no campaign is running, instead of leaving the
    panel blank it honestly falls back to the LAST known real campaign
    (`campaign_rows[0]`, already sorted by date desc by
    list_recent_repetitions) with its last real status (`mode:
    "idle_last_campaign"`), and adds the real count of currently active
    attacks if there are any -- a "current process" that doesn't exist is
    never invented, this only avoids showing a blank panel when there is real
    history to show."""
    for row in campaign_rows:
        if str(row.get("repetition_status", "")).lower() == "running":
            chain = row.get("job_chain") or {}
            leaf = (chain.get("chain") or [{}])[-1]
            return {
                "mode": "running",
                "campaign_id": row.get("campaign_id"),
                "job_id": row.get("job_id"),
                "level": row.get("level"),
                "execution_label": row.get("execution_label"),
                "current_phase": leaf.get("current_phase"),
                "current_phase_detail": leaf.get("current_phase_detail"),
                "liveness": leaf.get("liveness"),
                "depth": chain.get("depth"),
            }
    active_attacks_now = (attack_lab or {}).get("active_now")
    last_attack = (attack_lab or {}).get("last_attack")
    if campaign_rows:
        last = campaign_rows[0]
        return {
            "mode": "idle_last_campaign",
            "campaign_id": last.get("campaign_id"),
            "job_id": last.get("job_id"),
            "level": last.get("level"),
            "execution_label": last.get("execution_label"),
            "last_status": last.get("repetition_status"),
            "active_attacks_now": active_attacks_now,
            "last_attack": last_attack,
        }
    if active_attacks_now:
        return {"mode": "attack_only", "active_attacks_now": active_attacks_now, "last_attack": last_attack}
    return {"mode": "no_data"}


def _hash_payload(payload: dict) -> str:
    try:
        blob = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        blob = str(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def get_snapshot(since_hash: str | None = None, *, campaigns_limit: int = 10) -> dict:
    """Single entry point: the same data for the human (Three.js view) and
    for Claude Code (direct curl). Short cache (3s) + hash-based cutoff, the
    same pattern as monitor3d.get_snapshot() already validated in production
    -- if nothing changed since `since_hash`, returns {"unchanged": true}
    without recomputing anything expensive."""
    global _cache, _cache_ts

    with _cache_lock:
        now = time.time()
        if _cache is not None and (now - _cache_ts) < _CACHE_TTL_SECONDS:
            payload = _cache
        else:
            campaign_rows = _active_campaigns_section(campaigns_limit)
            scenario_nodes = _scenario_nodes_section()
            attack_lab = _attack_lab_section()
            payload = {
                "generated_at": _utc_now(),
                "host": {**_host_basic_section(), "memory": _host_memory_section(), "processes": _host_processes_section()},
                "worker": get_worker_thread_census(),
                "active_campaigns": campaign_rows,
                "campaigns_summary": _campaigns_summary_section(campaign_rows),
                "current_process": _current_process_section(campaign_rows, attack_lab),
                "scenario_nodes": scenario_nodes,
                "ot_assets": _ot_asset_section(),
                "tools": _tools_section(set(scenario_nodes.get("instance_ids") or [])),
                "evidence_store": _evidence_store_section(),
                "alerts": _alerts_section(),
                "attack_lab": attack_lab,
                "forensic_acquisition": _forensic_acquisition_section(),
                "forensic_analysis": _forensic_analysis_section(),
                "foc_reconstruction": _foc_reconstruction_section(),
                "campaign_comparisons": _campaign_comparisons_section(campaign_rows),
            }
            payload["hash"] = _hash_payload(payload)
            _cache = payload
            _cache_ts = now

    if since_hash and since_hash == payload.get("hash"):
        return {"unchanged": True, "hash": payload["hash"]}
    return payload
