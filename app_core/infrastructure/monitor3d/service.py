"""
Monitor3D aggregator
=====================
Read-only, additive aggregator for the "3D Live Monitor" dashboard. Focuses
on exactly ONE campaign at a time -- the currently-running Level C job if
one exists, otherwise the most recently touched job (any status) -- and
returns its FULL real detail (not summarized): every stage, the live/last
case with its real integrity state and recent events, and every host with
its real tool inventory, clock offset, and derived current activity.

Built by calling `campaign_repetitions.service`'s already-existing
per-repetition functions in-process, plus `node_health_api` for live host
identity/tool inventory/vitals, plus small, honest, read-only derivations
(case integrity, case recent events, per-host activity) cross-referencing
already-durable files. Never duplicates acquisition/attack/tools logic.

Hard rules (mirrors campaign_repetitions/service.py's own rules):
  - Never invent a stage/state that doesn't exist. Every derived field
    carries a `*_source` string describing exactly which files it was
    cross-referenced from.
  - A value that genuinely does not exist anywhere is reported as `None`
    with an explanatory sensor_status, never fabricated (see
    get_sensor_coverage()). No placeholder text like a fake "location" or
    fake NTP source is ever emitted.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from ..campaign_repetitions import service as rep_service
from ..level_c_orchestrator import service as level_c_service
from ..node_health import node_health_api
from ..forensics import stage_timing_service
from ..foc_reconstruction.foc_config import PROJECT_ROOT

ATTACK_ATTESTATION_PATH = PROJECT_ROOT / "foc-reconstruction" / "attestations" / "attack_attestation.json"
TOOLS_TMP_DIR = PROJECT_ROOT / "tools-installer-tmp"
EVIDENCE_STORE_ROOT = PROJECT_ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store"

# Building a fresh payload (live manifest-hash re-verification, per-host tool
# inventory reads, etc.) costs ~1.5-2s. Must stay above the frontend's poll
# interval (api.js POLL_INTERVAL_MS) or every single poll misses the cache
# and pays that cost again, which is what made the dashboard feel stuck.
_CACHE_TTL_SECONDS = 4.0
_cache_lock = threading.Lock()
_cache: dict = {"built_at": 0.0, "payload": None, "hash": None}

# Rolling, in-memory, per-host metrics history -- built ONLY from real samples
# actually observed since this worker process started (never backfilled or
# fabricated). Per-worker, not shared across gunicorn's 4 sync workers -- see
# the plan doc's caching caveat. Capped so it can't grow unbounded.
_METRICS_HISTORY_MAXLEN = 60
_metrics_history: dict[str, deque] = {}
_metrics_history_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _now().isoformat()


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _parse_ts(value) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _safe_tool_status_slug(instance_name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", (instance_name or "").lower())


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Host "current activity" derivation (unchanged from the first iteration).
# ---------------------------------------------------------------------------

def _tool_installing_now(instance_name: str, job_phase: str | None) -> bool:
    if not job_phase or "INSTALLING_TOOLS" not in job_phase:
        return False
    tmp_path = TOOLS_TMP_DIR / f"{_safe_tool_status_slug(instance_name)}_tools.json"
    payload = _load_json(tmp_path)
    if not isinstance(payload, dict):
        return False
    tools = payload.get("tools") or {}
    return any(str(v) == "pending" for v in tools.values())


def _attack_target_match(ip_candidates: set[str]) -> dict | None:
    ip_candidates = {ip for ip in ip_candidates if ip}
    if not ip_candidates:
        return None
    data = _load_json(ATTACK_ATTESTATION_PATH) or {}
    attacks = data.get("attacks") or []
    now = _now()
    for record in attacks:
        target_ip = ((record or {}).get("target") or {}).get("target_ip")
        if target_ip not in ip_candidates:
            continue
        execution = (record or {}).get("execution") or {}
        started = _parse_ts(execution.get("started_at"))
        completed = _parse_ts(execution.get("completed_at"))
        if started is None:
            continue
        if started <= now and (completed is None or now <= completed):
            return {
                "attack_id": record.get("attack_id"),
                "attack_name": record.get("attack_name") or record.get("display_name"),
                "started_at": execution.get("started_at"),
                "completed_at": execution.get("completed_at"),
            }
    return None


def _acquiring_evidence_match(active_case_dir: Path | None, ip_candidates: set[str], instance_id: str | None) -> bool:
    if active_case_dir is None:
        return False
    try:
        from ..forensics.forensics_api import _read_jsonl_events
        events = _read_jsonl_events(str(active_case_dir))
    except Exception:
        return False
    open_steps: dict[str, bool] = {}
    for item in events:
        event = str((item or {}).get("event") or "")
        meta = (item or {}).get("meta") or {}
        vm_id = meta.get("vm_id")
        vm_matches = vm_id and (vm_id == instance_id)
        if event == "dfir_step_start" and vm_matches:
            open_steps[meta.get("step") or "?"] = True
        elif event in ("dfir_step_done", "dfir_step_failed") and vm_matches:
            open_steps[meta.get("step") or "?"] = False
    return any(open_steps.values())


def _derive_host_activity(*, node: dict, job_phase: str | None, active_case_dir: Path | None) -> dict:
    ip_candidates = {node.get("ip_private"), node.get("ip_floating"), node.get("ssh_target_ip")}
    instance_name = node.get("name") or ""
    instance_id = node.get("id")

    if str(node.get("status") or "").upper() == "BUILD":
        return {"state": "provisioning", "activity_source": "openstack_instance_status"}
    if _tool_installing_now(instance_name, job_phase):
        return {"state": "installing_tools", "activity_source": "derived_from_job_phase+tools_installer_tmp"}
    attack_match = _safe(lambda: _attack_target_match(ip_candidates))
    if attack_match:
        return {"state": "under_attack", "activity_source": "derived_from_attack_attestation", "detail": attack_match}
    if _safe(lambda: _acquiring_evidence_match(active_case_dir, ip_candidates, instance_id)):
        return {"state": "acquiring_evidence", "activity_source": "derived_from_pipeline_events"}
    return {"state": "idle", "activity_source": "absence_of_other_signals"}


def _active_case_dir() -> Path | None:
    try:
        return node_health_api._read_active_case_dir()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Resolve a Level B job_id for a Level C repetition when campaign_repetitions'
# own level_b_job_id lookup comes back empty (confirmed gap on older jobs:
# the log line is there, but the window-scoped parser in that module doesn't
# always find it). Read-only fallback: the Nth "Level B job started: X" line
# in the raw job log belongs to the Nth repetition, since Level C repetitions
# run strictly sequentially -- verified against real job logs this session.
# ---------------------------------------------------------------------------

_LEVEL_B_STARTED_RE = re.compile(r"Level B job started:\s*(\S+)")


def _resolve_level_b_job_id(job_id: str, rep_num: int) -> str | None:
    state = _load_json(level_c_service.JOBS_DIR / job_id / "job_state.json")
    if not isinstance(state, dict):
        return None
    matches = []
    for entry in state.get("log") or []:
        m = _LEVEL_B_STARTED_RE.search(str(entry.get("msg") or ""))
        if m:
            matches.append(m.group(1))
    if 1 <= rep_num <= len(matches):
        return matches[rep_num - 1]
    return None


# ---------------------------------------------------------------------------
# Resolve where a case's bytes actually live NOW. `case_path` returned by
# campaign_repetitions is the case's ORIGINAL evidence_store path, which is
# stale once retention_service.py has reduced it to a lightweight bundle
# (moved under the campaign's own execution folder) or archived it as the
# campaign's final sample. Read-only: tries the original path first, then
# the two known real relocation patterns.
# ---------------------------------------------------------------------------

def _resolve_case_dir(*, case_path_hint: str | None, case_id: str | None, campaign_id: str | None, execution_id: str | None) -> Path | None:
    if case_path_hint:
        candidate = PROJECT_ROOT / case_path_hint if not str(case_path_hint).startswith("/") else Path(case_path_hint)
        if candidate.is_dir() and (candidate / "manifest.json").is_file():
            return candidate
    if not (case_id and campaign_id and execution_id):
        return None
    base = EVIDENCE_STORE_ROOT / "repetition_campaigns" / campaign_id / "level_B" / execution_id
    lightweight = base / "retained_case_lightweight_bundle" / case_id
    if lightweight.is_dir():
        return lightweight
    final_sample = base.parent.parent / "final_sample_case"
    if final_sample.is_dir():
        for child in final_sample.iterdir():
            if case_id in child.name or child.name == case_id:
                return child
    return None


def _case_integrity(case_dir: Path | None) -> dict:
    if case_dir is None:
        return {"available": False}
    manifest_path = case_dir / "manifest.json"
    custody_path = case_dir / "chain_of_custody.log"
    digest_path = case_dir / "metadata" / "case_digest.json"
    manifest = _load_json(manifest_path)
    digest = _load_json(digest_path)

    custody_entries = 0
    last_custody_action = None
    if custody_path.is_file():
        try:
            with custody_path.open(encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        custody_entries += 1
                        try:
                            last_custody_action = json.loads(line).get("action")
                        except Exception:
                            pass
        except Exception:
            pass

    artifacts = (manifest or {}).get("artifacts") or []
    artifacts_with_hash = sum(1 for a in artifacts if a.get("sha256"))

    recorded_manifest_hash = ((digest or {}).get("digests") or {}).get("manifest_json_sha256")
    live_manifest_hash = _sha256_file(manifest_path) if manifest_path.is_file() else None
    integrity_verified = bool(recorded_manifest_hash) and recorded_manifest_hash == live_manifest_hash

    return {
        "available": True,
        "manifest_present": manifest_path.is_file(),
        "custody_present": custody_path.is_file(),
        "custody_entries": custody_entries,
        "last_custody_action": last_custody_action,
        "artifacts_total": len(artifacts),
        "artifacts_with_hash": artifacts_with_hash,
        "manifest_hash": recorded_manifest_hash,
        "manifest_hash_verified_live": integrity_verified,
        "case_sealed": digest_path.is_file(),
    }


def _case_recent_events(case_dir: Path | None, limit: int = 15) -> list[dict]:
    if case_dir is None:
        return []
    path = case_dir / "metadata" / "pipeline_events.jsonl"
    if not path.is_file():
        return []
    lines = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    lines.append(line)
    except Exception:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
        except Exception:
            continue
        out.append({"ts_utc": item.get("ts_utc"), "event": item.get("event"), "meta": item.get("meta") or {}})
    out.reverse()  # most recent first, matches the reference dashboard's feed
    return out


def _case_evidence_pipeline(level_b_detail: dict | None, case_integrity: dict) -> list[dict]:
    """Honest evidence-preservation pipeline for the case, built from real
    acquisition/reconstruction fields already returned by campaign_repetitions
    -- not a re-implementation of acquisition logic, just a re-labeling of
    already-computed statuses into the Memory/Disk/Network/Manifest/
    Reconstruction/Seal steps the reference UI shows."""
    acquisition = (level_b_detail or {}).get("acquisition") or {}
    reconstruction = (level_b_detail or {}).get("reconstruction") or {}
    steps = [
        {"label": "Memory", "status": acquisition.get("memory_status") or "pending", "detail": f"{acquisition.get('memory_size_bytes')} bytes" if acquisition.get("memory_size_bytes") else None},
        {"label": "Disk", "status": acquisition.get("disk_status") or "pending", "detail": f"{acquisition.get('disk_size_bytes')} bytes" if acquisition.get("disk_size_bytes") else None},
        {"label": "Network", "status": acquisition.get("network_status") or "pending", "detail": f"{acquisition.get('pcap_segments_imported')} segment(s)" if acquisition.get("pcap_segments_imported") else None},
        {"label": "OT / Industrial", "status": acquisition.get("ot_status") or "pending", "detail": None},
        {"label": "Manifest", "status": "completed" if case_integrity.get("manifest_present") else "pending", "detail": f"{case_integrity.get('artifacts_total')} artifact(s)" if case_integrity.get("available") else None},
        {
            "label": "Reconstruction",
            "status": "completed" if reconstruction.get("recoverability_score") is not None else ("blocked" if reconstruction.get("warnings") else "pending"),
            # Real, already-computed reasons (foc_causal_reconstruction warns per
            # blocking condition) -- surfaced here instead of discarded, so a
            # "blocked" badge in the 3D monitor isn't just a color with no cause.
            "detail": " ".join(dict.fromkeys(reconstruction.get("warnings") or [])) or None,
        },
        {"label": "Seal", "status": "completed" if case_integrity.get("case_sealed") else "pending", "detail": None},
    ]
    return steps


# ---------------------------------------------------------------------------
# Live host block
# ---------------------------------------------------------------------------

def _record_metrics_sample(instance_id: str, probe_row: dict) -> None:
    if not instance_id or not probe_row:
        return
    with _metrics_history_lock:
        buf = _metrics_history.setdefault(instance_id, deque(maxlen=_METRICS_HISTORY_MAXLEN))
        buf.append({
            "ts": _utc_now_iso(),
            "cpu": probe_row.get("cpu_usage_pct"),
            "memory": probe_row.get("memory_usage_pct"),
            "disk": probe_row.get("disk_root_use_pct"),
        })


def _metrics_history_for(instance_id: str) -> list[dict]:
    with _metrics_history_lock:
        return list(_metrics_history.get(instance_id) or [])


def _build_live_hosts(job_phase: str | None) -> list[dict]:
    try:
        nodes = node_health_api._list_nodes()
    except Exception:
        return []
    active_case = _active_case_dir()
    hosts = []
    for node in nodes:
        activity = _derive_host_activity(node=node, job_phase=job_phase, active_case_dir=active_case)
        tool_inventory = _safe(lambda: node_health_api._tool_inventory_for_instance(node.get("id"), node.get("name")), {})
        time_sync = _safe(lambda: node_health_api._node_time_sync_summary(node.get("id"), node), {})
        # Cheap, cache-only vitals read (never triggers a fresh SSH probe from
        # the main 2-3s poll loop -- only the separate, slower vitals poll
        # does that). Also feeds the rolling in-memory history.
        cached_vitals = None
        try:
            summary_row = node_health_api._probe_cached_or_refresh(node, refresh=False, max_age_seconds=9999)
            cached_vitals = summary_row
            if summary_row and summary_row.get("source") in ("cache", "live_probe"):
                _record_metrics_sample(node.get("id"), summary_row)
        except Exception:
            pass
        hosts.append({
            "instance_id": node.get("id"),
            "name": node.get("name"),
            "role": node.get("role"),
            "os": node.get("os"),
            "status": node.get("status"),
            "ip_private": node.get("ip_private"),
            "ip_floating": node.get("ip_floating"),
            "networks": node.get("networks"),
            "tools": [
                {
                    "id": t.get("id"),
                    "display_name": t.get("display_name"),
                    "category": t.get("category"),
                    "inventory_status": t.get("inventory_status"),
                    "installed_at": t.get("installed_at"),
                }
                for t in (tool_inventory.get("tools") or [])
            ] if isinstance(tool_inventory, dict) else [],
            "clock_offset_ms": time_sync.get("max_clock_offset_ms") if isinstance(time_sync, dict) else None,
            "clock_synchronized": time_sync.get("synchronized") if isinstance(time_sync, dict) else None,
            "current_activity": activity,
            "vitals": cached_vitals,
            "metrics_history": _metrics_history_for(node.get("id")),
            "source": "live",
        })
    return hosts


def get_live_attack_feed(since_iso: str | None) -> dict:
    """NEW events since `since_iso` for the "Live Attack View" mode: only
    just-started attacks, new node_health alerts, and new forensic cases --
    meant for drawing a transient arrow/notification, not for reconstructing
    the full state. Each event is resolved against the nodes LIVE right now
    (by IP) so the arrow can be drawn at that host's real 3D box position; if
    an attack can't be mapped to a live host (a historical IP that no longer
    exists), it is still returned with `attacker_host`/`target_host` as null
    instead of being hidden, honestly."""
    now = _now()
    # With no `since`, "starting from now" is assumed -- the full historical
    # backlog (653 historical attacks seen this session) is never dumped all
    # at once the first time this mode is entered.
    since = _parse_ts(since_iso) if since_iso else now

    try:
        nodes = node_health_api._list_nodes()
    except Exception:
        nodes = []
    ip_to_host = {}
    for n in nodes:
        for ip in (n.get("ip_private"), n.get("ip_floating")):
            if ip:
                ip_to_host[ip] = {"instance_id": n.get("id"), "name": n.get("name"), "role": n.get("role")}

    attacks: list[dict] = []
    try:
        data = _load_json(ATTACK_ATTESTATION_PATH) or {}
        for record in data.get("attacks") or []:
            execution = (record or {}).get("execution") or {}
            started = _parse_ts(execution.get("started_at"))
            if not started or (since and started <= since) or started > now:
                continue
            attacker_ip = ((record or {}).get("attacker") or {}).get("ip")
            target_ip = ((record or {}).get("target") or {}).get("target_ip")
            attacks.append({
                "kind": "attack",
                "attack_id": record.get("attack_id"),
                "attack_name": record.get("attack_name") or record.get("display_name"),
                "mitre_technique": ((record.get("mitre") or {}).get("technique_id")),
                "attacker_ip": attacker_ip,
                "target_ip": target_ip,
                "attacker_host": ip_to_host.get(attacker_ip),
                "target_host": ip_to_host.get(target_ip),
                "started_at": execution.get("started_at"),
                "completed_at": execution.get("completed_at"),
                "execution_status": record.get("execution_status"),
            })
    except Exception:
        pass

    alerts: list[dict] = []
    try:
        cache_path = node_health_api.HEALTH_SUMMARY_CACHE_PATH
        if cache_path.is_file():
            health = json.loads(cache_path.read_text(encoding="utf-8"))
            for a in health.get("alerts") or []:
                gen = _parse_ts(a.get("generated_at"))
                if not gen or (since and gen <= since):
                    continue
                alerts.append({
                    "kind": "alert",
                    "alert_id": a.get("alert_id"),
                    "severity": a.get("severity"),
                    "scope": a.get("scope"),
                    "target": a.get("target"),
                    "title": a.get("title"),
                    "detail": a.get("detail"),
                    "generated_at": a.get("generated_at"),
                    "target_host": ip_to_host.get(a.get("target")) or next(
                        (h for h in ip_to_host.values() if h.get("name") == a.get("target")), None
                    ),
                })
    except Exception:
        pass

    faults: list[dict] = []
    try:
        from ..forensic_twin.service import list_recent_events
        id_to_host = {n.get("id"): {"instance_id": n.get("id"), "name": n.get("name"), "role": n.get("role")} for n in nodes}
        for ev in list_recent_events(limit=100):
            event_type = str(ev.get("event_type") or "")
            if not event_type.startswith("fault_injection_"):
                continue
            gen = _parse_ts(ev.get("generated_at_utc"))
            if not gen or (since and gen <= since) or gen > now:
                continue
            scope_id = ev.get("scope_id") or ""
            node_id = scope_id[len("node:"):] if scope_id.startswith("node:") else None
            faults.append({
                "kind": "fault_injection",
                "event_type": event_type,
                "phase": "reverted" if event_type.endswith("_reverted") else "applied",
                "fault_id": ev.get("fault_id"),
                "injection_id": ev.get("injection_id"),
                "node_id": node_id,
                "target_host": id_to_host.get(node_id),
                "evidence": ev.get("evidence"),
                "generated_at": ev.get("generated_at_utc"),
            })
    except Exception:
        pass

    new_cases: list[dict] = []
    try:
        from ..foc_experimentation.config import EVIDENCE_STORE_ROOT
        for p in EVIDENCE_STORE_ROOT.iterdir():
            if not p.is_dir() or not p.name.startswith("CASE-"):
                continue
            try:
                ts_part = p.name[len("CASE-"):]
                created = datetime.strptime(ts_part, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
            except Exception:
                continue
            if (since and created <= since) or created > now:
                continue
            new_cases.append({"kind": "case_created", "case_id": p.name, "created_at": created.isoformat()})
    except Exception:
        pass

    return {
        "generated_at": _utc_now_iso(),
        "attacks": attacks,
        "alerts": alerts,
        "faults": faults,
        "new_cases": new_cases,
    }


# ---------------------------------------------------------------------------
# Single-campaign focus assembly.
# ---------------------------------------------------------------------------

def _pick_campaign_job(job_id: str | None = None) -> dict | None:
    jobs = level_c_service.list_jobs()
    if not jobs:
        return None
    if job_id:
        # Explicit target (reconstruction mode picking a historical campaign
        # by id) -- bypasses the "running, else newest" heuristic below,
        # which only makes sense for "whatever campaign is currently live".
        return next((j for j in jobs if j.get("job_id") == job_id), None)
    live = next((j for j in jobs if j.get("status") == "running"), None)
    return live or jobs[0]  # list_jobs() is already newest-first


def _build_case_and_level_b_for_repetition(job_id: str, rep_num: int, *, lc_detail: dict | None = None) -> dict:
    """Resolves the real Level B detail + case bundle for ONE specific Level C
    repetition -- parametrized by rep_num rather than assuming "the campaign's
    current repetition", since each Level C repetition launches its own,
    distinct Level B job/case (verified against real job data: 10 different
    level_b_job_id values across a 10-repetition campaign). Shared by the
    campaign-focus snapshot (for the focus repetition) and the on-demand
    per-repetition endpoint (for whichever repetition the user actually
    clicked) so the two never compute this differently.
    """
    if lc_detail is None:
        lc_detail = _safe(lambda: rep_service.get_level_c_repetition_detail(job_id, rep_num)) or {}
    campaign_id = lc_detail.get("campaign_id")

    level_b_job_id = lc_detail.get("level_b_job_id") or _resolve_level_b_job_id(job_id, rep_num)
    level_b_detail = None
    if level_b_job_id:
        level_b_detail = _safe(lambda: rep_service.get_level_b_repetition_detail(level_b_job_id, 1))

    case_summary = (level_b_detail or {}).get("case")
    execution_id = f"EXEC-{rep_num:04d}"
    case_dir = None
    if case_summary:
        case_dir = _resolve_case_dir(
            case_path_hint=case_summary.get("case_path"),
            case_id=case_summary.get("case_id"),
            campaign_id=campaign_id,
            execution_id=execution_id,
        )
    integrity = _case_integrity(case_dir)
    recent_events = _case_recent_events(case_dir)
    evidence_pipeline = _case_evidence_pipeline(level_b_detail, integrity)

    case = {
        "case_id": (case_summary or {}).get("case_id"),
        "case_real_name": (case_summary or {}).get("case_real_name"),
        "resolved_case_dir": str(case_dir) if case_dir else None,
        "integrity": integrity,
        "recent_events": recent_events,
        "evidence_pipeline": evidence_pipeline,
    } if case_summary else None

    return {"level_b": level_b_detail, "case": case}


def _build_campaign_focus(job: dict) -> dict:
    job_id = job.get("job_id")
    total_reps = int(job.get("level_c_repetitions") or 1)
    status = str(job.get("status") or "unknown")
    current_rep = int(job.get("current_repetition") or 0)
    is_live = status == "running"
    focus_rep = max(current_rep, 1)

    lc_detail = _safe(lambda: rep_service.get_level_c_repetition_detail(job_id, focus_rep)) or {}
    campaign_id = lc_detail.get("campaign_id")

    case_and_level_b = _build_case_and_level_b_for_repetition(job_id, focus_rep, lc_detail=lc_detail)
    level_b_detail = case_and_level_b["level_b"]

    hosts = _build_live_hosts(job.get("phase"))
    repetitions = _safe(lambda: rep_service.list_level_c_repetition_statuses(job)) or []

    return {
        "job_id": job_id,
        "campaign_id": campaign_id,
        "label": f"Level C · repetition {focus_rep}/{total_reps}",
        "status": status,
        "phase": job.get("phase"),
        "total_repetitions": total_reps,
        "current_repetition": current_rep,
        "focus_repetition": focus_rep,
        "is_live": is_live,
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "total_elapsed_seconds": lc_detail.get("total_elapsed_seconds"),
        "repetitions": repetitions,
        "stages": lc_detail.get("stages") or [],
        "tool_installs": lc_detail.get("tool_installs") or [],
        "time_sync_checks": lc_detail.get("time_sync_checks") or [],
        "level_b": level_b_detail,
        "case": case_and_level_b["case"],
        "hosts": hosts,
    }


def _build_snapshot_payload() -> dict:
    job = _pick_campaign_job()
    campaign = _safe(lambda: _build_campaign_focus(job)) if job else None
    return {
        "generated_at_utc": _utc_now_iso(),
        "campaign": campaign,
    }


def _hash_payload(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def get_snapshot(since_hash: str | None = None) -> dict:
    with _cache_lock:
        stale = (time.time() - _cache["built_at"]) > _CACHE_TTL_SECONDS
        if stale or _cache["payload"] is None:
            payload = _build_snapshot_payload()
            payload_hash = _hash_payload(payload)
            _cache["payload"] = payload
            _cache["hash"] = payload_hash
            _cache["built_at"] = time.time()
        payload = _cache["payload"]
        payload_hash = _cache["hash"]

    if since_hash and since_hash == payload_hash:
        return {"unchanged": True, "hash": payload_hash}
    return {"unchanged": False, "hash": payload_hash, **payload}


# ---------------------------------------------------------------------------
# Per-host vitals -- thin pass-through to node_health's own cached-or-refresh
# probing, enriched with the real "network" sensor and the rolling history.
# ---------------------------------------------------------------------------

def get_repetition_detail(rep_num: int) -> dict | None:
    """Full per-phase stage detail for ONE Level C repetition of the
    currently-focused campaign, fetched on demand (only when a user clicks
    that repetition) rather than for all repetitions on every poll -- this
    is the same rep_service.get_level_c_repetition_detail already used for
    the focused repetition, just made callable for any repetition number.

    Also resolves THAT repetition's own case/level_b bundle (attack,
    detection, acquisition, evidence pipeline, seal status) via the same
    helper _build_campaign_focus() uses for the campaign's focus repetition
    -- each Level C repetition launches its own distinct Level B job/case
    (verified: 10 different level_b_job_id values across a real 10-rep
    campaign), so without this a clicked repetition's case data was
    previously unreachable and the UI's Case box stayed frozen on whichever
    repetition happened to be the campaign's current/last one.
    """
    job = _pick_campaign_job()
    if not job:
        return None
    job_id = job.get("job_id")
    lc_detail = _safe(lambda: rep_service.get_level_c_repetition_detail(job_id, rep_num))
    if not lc_detail:
        return None
    case_and_level_b = _build_case_and_level_b_for_repetition(job_id, rep_num, lc_detail=lc_detail)
    return {**lc_detail, **case_and_level_b}


# ---------------------------------------------------------------------------
# Post-campaign reconstruction: a purely read-only, chronologically-ordered
# "beat" timeline covering a WHOLE already-completed campaign (every
# repetition, full artifact-by-artifact/phase-by-phase detail), built
# entirely from files that already exist on disk. This function NEVER
# writes, generates, or triggers generation of anything -- every read below
# is either an already-existing accessor (rep_service.*, level_c_service.*)
# or a direct `_load_json` of a file that some OTHER, already-run pipeline
# step produced earlier. A repetition/case missing a given artifact simply
# gets `available: False` on that beat, never a fabricated value.
# ---------------------------------------------------------------------------

def _iso_diff_seconds(start, end) -> float | None:
    try:
        s = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        e = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        return max(0.0, (e - s).total_seconds())
    except Exception:
        return None


def _role_lookup_by_name() -> dict:
    """Host role (attacker/victim/plc/scada/monitor) is stable scenario
    topology, not something snapshot_infrastructure records per repetition --
    reusing the live node list (by name) is legitimate here (role doesn't
    change between repetitions of the same scenario), not fabrication. A
    host whose name isn't currently live gets role=None, never a guess.
    """
    hosts = _safe(lambda: _build_live_hosts(None), []) or []
    return {h.get("name"): h.get("role") for h in hosts if h.get("name")}


def _tool_install_timing(instance_id: str | None, tool_name: str | None) -> tuple[str | None, str | None]:
    """Real per-tool install start+end, from tools-installer/installed/<id>.json
    (level_c_orchestrator/service.py already records install_started_utc
    alongside installed_tools[tool] specifically so this could be read one
    day -- confirmed nothing reads it yet). Read-only; never writes here.
    Missing file or missing pairing for this tool -> (None, None), never a
    guessed duration.
    """
    if not instance_id or not tool_name:
        return None, None
    data = _load_json(level_c_service.TOOLS_INSTALLED_DIR / f"{instance_id}.json")
    if not isinstance(data, dict):
        return None, None
    finished_at = (data.get("installed_tools") or {}).get(tool_name)
    started_at = (data.get("install_started_utc") or {}).get(tool_name)
    if not finished_at or not started_at:
        return None, None
    return started_at, finished_at


def _beat(kind: str, rep_num: int | None, *, seq: int, available: bool = True, started_at=None, finished_at=None,
          real_duration_seconds=None, title: str = "", detail_lines=None, nav_level: str = "overview",
          focus_ids=None, payload=None) -> dict:
    return {
        "beat_id": f"{'rep' + str(rep_num) if rep_num else 'campaign'}.{kind}.{seq}",
        "kind": kind,
        "repetition_number": rep_num,
        "available": available,
        "started_at": started_at,
        "finished_at": finished_at,
        "real_duration_seconds": real_duration_seconds if real_duration_seconds is not None else _iso_diff_seconds(started_at, finished_at),
        "title": title,
        "detail_lines": detail_lines or [],
        "nav": {"level": nav_level, "focus_ids": focus_ids or []},
        "payload": payload or {},
    }


_PHASE_TOTAL_STAGE_KEYS = ("memory_acquisition", "disk_acquisition", "ot_export", "network_context_import")


def _stage_phase_totals(stage_timeline: list[dict]) -> list[dict]:
    """Real combined duration per acquisition phase, summed across every
    host that went through it -- each `preservation_step` beat already
    shows one host's own real elapsed time (e.g. "Memory acquisition: 3m
    3s"), which is accurate but reads as misleadingly short when a case
    actually has 3+ hosts going through the same phase one after another.
    Built from the same already-computed `stage_timeline` entries, zero new
    I/O, zero new timestamps -- purely a group-and-sum over real
    `elapsed_seconds`/`started_at`/`finished_at` fields that already exist.
    User explicitly asked (2026-10-11) to re-verify these durations; this is
    the real total that was missing, not a correction of a wrong number."""
    groups: dict[str, dict] = {}
    for entry in stage_timeline or []:
        key = entry.get("stage_key")
        if key not in _PHASE_TOTAL_STAGE_KEYS:
            continue
        g = groups.setdefault(key, {
            "stage_key": key, "label": entry.get("label"), "host_count": 0,
            "total_elapsed_seconds": 0.0, "span_started_at": None, "span_finished_at": None,
        })
        g["host_count"] += 1
        g["total_elapsed_seconds"] += entry.get("elapsed_seconds") or 0.0
        started = entry.get("started_at")
        finished = entry.get("finished_at")
        if started and (g["span_started_at"] is None or started < g["span_started_at"]):
            g["span_started_at"] = started
        if finished and (g["span_finished_at"] is None or finished > g["span_finished_at"]):
            g["span_finished_at"] = finished
    for g in groups.values():
        g["total_elapsed_seconds"] = round(g["total_elapsed_seconds"], 1)
        # The real wall-clock span this phase occupied (first host's start to
        # last host's finish) -- can exceed the summed per-host time if hosts
        # ran sequentially with gaps, or be close to it if they overlapped;
        # both are real, honest numbers, never reconciled into one guess.
        g["span_seconds"] = _iso_diff_seconds(g["span_started_at"], g["span_finished_at"])
    # Stable order matching the chronological pipeline, not dict insertion order.
    return [groups[k] for k in _PHASE_TOTAL_STAGE_KEYS if k in groups]


def _frozen_hosts_for_repetition(lc_detail: dict, role_lookup: dict) -> list[dict]:
    """A snapshot.hosts-shaped list built from THIS repetition's own real
    snapshot_infrastructure (real per-repetition IP/status/tools) instead of
    the live/current node list, since the real VMs from a past repetition
    were already destroyed and redeployed since. Role is looked up by name
    (see _role_lookup_by_name) since it isn't part of the infra snapshot.
    """
    infra = (lc_detail or {}).get("snapshot_infrastructure") or {}
    out = []
    for inst in infra.get("instances") or []:
        out.append({
            "instance_id": inst.get("instance_id"),
            "name": inst.get("name"),
            "role": role_lookup.get(inst.get("name")),
            "os": None,
            "status": inst.get("status"),
            "ip_private": inst.get("ip_private"),
            "ip_floating": inst.get("ip_floating"),
            "networks": None,
            "tools": [
                {"id": t.get("tool_name"), "display_name": t.get("tool_name"), "category": None,
                 "inventory_status": str(t.get("status") or "").lower(), "installed_at": t.get("installed_at")}
                for t in (inst.get("tools") or [])
            ],
            "clock_offset_ms": None,
            "clock_synchronized": None,
            "current_activity": None,
            "vitals": None,
        })
    return out


def _repetition_beats(job: dict, rep_num: int, role_lookup: dict, base_repetitions: list) -> dict:
    """Builds one repetition's full bundle: the frozen case/level_b/hosts
    state a reconstruction beat needs to re-render this repetition (same
    shape app.js's repFocusOverride already expects), a full snapshot-shaped
    object (same shape _build_campaign_focus() returns, so the frontend's
    existing renderOverview()/renderDrilledCase() work completely unchanged),
    plus its ordered list of real, timestamped story beats.
    """
    job_id = job.get("job_id")
    lc_detail = _safe(lambda: rep_service.get_level_c_repetition_detail(job_id, rep_num)) or {}
    case_and_level_b = _build_case_and_level_b_for_repetition(job_id, rep_num, lc_detail=lc_detail)
    level_b = case_and_level_b.get("level_b") or {}
    case = case_and_level_b.get("case")
    hosts = _frozen_hosts_for_repetition(lc_detail, role_lookup)

    case_dir = Path(case["resolved_case_dir"]) if case and case.get("resolved_case_dir") else None
    stage_timeline = _safe(lambda: stage_timing_service.get_case_stage_timeline(case_dir)) if case_dir else []
    causal_status = _load_json(case_dir / "derived" / "reconstruction" / "causal_status.json") if case_dir else None
    causal_graph = _load_json(case_dir / "derived" / "reconstruction" / "causal_graph.json") if case_dir else None
    narrative = _load_json(case_dir / "derived" / "executive" / "execution_narrative_report.json") if case_dir else None

    campaign_focus_ids = [f"rep:{rep_num}"]
    beats: list[dict] = []
    seq = 0

    def next_seq():
        nonlocal seq
        seq += 1
        return seq

    # 1) Deployment -- one beat per host, real per-host creation timestamp,
    # immediately followed by that host's own tool-install beats (so the
    # story stays "build this machine, then configure it" before moving to
    # the next machine, instead of grouping all deployments then all tools).
    # Real deployment order, not whatever order snapshot_infrastructure happens
    # to list instances in -- confirmed those two can differ (e.g. a real
    # repetition had monitor created first at 09:21:15Z, then attacker,
    # victim, fuxa, plc last at 09:25:26Z, while the instances list itself
    # was ordered plc/fuxa/victim/attack/monitor). ISO 8601 zulu timestamps
    # sort correctly as plain strings; instances missing created_at (should
    # not happen for a real deployed instance) sort last rather than
    # fabricating a position for them.
    infra_instances = sorted(
        (lc_detail.get("snapshot_infrastructure") or {}).get("instances") or [],
        key=lambda inst: inst.get("created_at") or "9999",
    )
    for inst in infra_instances:
        beats.append(_beat(
            "deployment", rep_num, seq=next_seq(), available=bool(inst.get("created_at")),
            started_at=inst.get("created_at"), title=f"Instance created: {inst.get('name')}",
            detail_lines=[inst.get("ip_floating") or inst.get("ip_private") or "no IP recorded"],
            nav_level="overview", focus_ids=campaign_focus_ids + [f"host:{inst.get('instance_id')}"],
            payload={"instance": inst},
        ))
        for tool in inst.get("tools") or []:
            if str(tool.get("status") or "").lower() != "installed":
                continue
            started_at, finished_at = _tool_install_timing(inst.get("instance_id"), tool.get("tool_name"))
            beats.append(_beat(
                "tool_install", rep_num, seq=next_seq(), available=bool(started_at and finished_at),
                started_at=started_at, finished_at=finished_at,
                title=f"Installing {tool.get('tool_name')} — {inst.get('name')}",
                detail_lines=[inst.get("name")],
                nav_level="overview", focus_ids=campaign_focus_ids + [f"host:{inst.get('instance_id')}"],
                payload={"instance": inst, "tool": tool},
            ))

    # 1.5) Real interventions (Intervention Ledger, M1) recorded against any
    # of this repetition's own real hosts -- reuses the exact same
    # phase-timeline build already verified live in Digital Twin View
    # (intervention_ledger/timeline.py::build_phase_timeline), so the
    # frontend renders this beat with the SAME phase_timeline.js widget,
    # not a second one. Scoped by instance_id, which is correct here
    # specifically because each repetition redeploys fresh VMs with their
    # own real instance_ids -- an intervention only matches the repetition
    # whose live host it was really applied against. Zero or more per
    # repetition, honestly: most repetitions run before this session's
    # Ledger existed have none, and this never invents one.
    from ..intervention_ledger.service import get_ledger_entries
    from ..intervention_ledger.timeline import build_phase_timeline

    intervention_attempts = []
    for h in hosts:
        if not h.get("instance_id"):
            continue
        for entry in get_ledger_entries(node_id=h["instance_id"], limit=5000):
            if entry.get("phase") in ("applied", "executed"):
                intervention_attempts.append(entry)
    intervention_attempts.sort(key=lambda e: e.get("applied_at") or e.get("recorded_at_utc") or "")
    for entry in intervention_attempts:
        timeline = _safe(lambda e=entry: build_phase_timeline(e["intervention_id"]))
        if not timeline or not timeline.get("ok"):
            continue
        done_phases = [p for p in timeline["phases"] if p.get("status") == "done"]
        beats.append(_beat(
            "intervention", rep_num, seq=next_seq(), available=True,
            started_at=entry.get("applied_at") or entry.get("requested_at"),
            finished_at=entry.get("rollback_at"),
            title=f"Intervention: {entry.get('type')} on {entry.get('target_node_name') or entry.get('target_node_id')}",
            detail_lines=[f"{len(done_phases)}/{len(timeline['phases'])} phases completed (real)"],
            nav_level="overview", focus_ids=campaign_focus_ids + [f"host:{entry.get('target_node_id')}"],
            payload={"phase_timeline": timeline},
        ))

    # 2) Attack
    # `detection` is computed here (not after, as step "3" below used to
    # read) purely so its real `trigger_alert_severity` can already ride
    # along on the attack beat's own payload -- reconstruction mode replays
    # ALREADY-KNOWN history, so showing the real outcome severity right on
    # the attack arc itself (not just two beats later) is honest, not a
    # spoiler invented for effect. `detection` itself is unchanged below.
    attack = level_b.get("attack") or {}
    detection = level_b.get("detection") or {}

    # This repetition genuinely never started -- no real attack was ever
    # launched and no real case was ever created. True for every repetition
    # after the one where a FAILED campaign actually died (e.g. reps 4-10
    # of a 10-rep campaign that failed in rep 3). Previously this still
    # built 6 more "(no data)"/"not available" placeholder beats per such
    # repetition -- each one individually honest, but together a real UX
    # bug the user flagged (2026-10-12): after the real "campaign failed
    # here" moment (see build_reconstruction_timeline), the replay kept
    # going through dozens of beats for repetitions that never happened.
    # Skipping them here means the replay correctly ends where the real
    # story actually ends; the repetition's own box in the 3D foundation
    # still exists and correctly shows "pending" -- that comes from
    # base_repetitions/marked_repetitions below, a separate, real, honest
    # data source unaffected by this early return.
    if not attack.get("attack_name") and not case:
        return {
            "repetition_number": rep_num, "case": case, "level_b": level_b, "hosts": hosts,
            "snapshot_infrastructure": lc_detail.get("snapshot_infrastructure"),
            "snapshot": None, "beats": beats,
        }

    beats.append(_beat(
        "attack", rep_num, seq=next_seq(), available=bool(attack.get("attack_name")),
        started_at=attack.get("started_at"), finished_at=attack.get("completed_at"),
        title=attack.get("attack_name") or "Attack (no data)",
        detail_lines=[x for x in [attack.get("protocol"), attack.get("function_code"),
                                   f"register {attack.get('register')}" if attack.get("register") else None,
                                   f"value {attack.get('value')}" if attack.get("value") else None] if x],
        nav_level="overview", focus_ids=campaign_focus_ids + ([f"host:{h['instance_id']}" for h in hosts if h.get("name") == attack.get("target_node")]),
        payload={"attack": attack, "known_severity": detection.get("trigger_alert_severity")},
    ))

    # 3) Detection
    beats.append(_beat(
        "detection", rep_num, seq=next_seq(), available=bool(detection.get("outcome")),
        started_at=detection.get("trigger_alert_timestamp"),
        title=f"Detection: {detection.get('outcome') or 'unknown'}",
        detail_lines=[x for x in [
            f"rule {detection.get('trigger_alert_rule')}" if detection.get("trigger_alert_rule") else None,
            detection.get("trigger_alert_severity"),
        ] if x],
        nav_level="overview", focus_ids=campaign_focus_ids,
        payload={"detection": detection},
    ))

    # 4) Case created
    beats.append(_beat(
        "case_created", rep_num, seq=next_seq(), available=bool(case),
        started_at=(case or {}).get("case_created_utc"),
        title=f"Case created: {(case or {}).get('case_id') or 'not available'}",
        detail_lines=[(case or {}).get("case_real_name")] if case else ["No case was created for this repetition."],
        # `hosts` (already built above for the attack beat) lets the frontend
        # request a Reality Gap check for this case's own real nodes BY NAME
        # (stable across redeployments) -- see forensic_twin.compute_reality_gap's
        # own docstring for why name, not instance_id.
        nav_level="overview", focus_ids=campaign_focus_ids + ([f"case:{case['case_id']}"] if case else []),
        payload={"case": case, "phase_totals": _stage_phase_totals(stage_timeline), "hosts": hosts},
    ))

    case_focus = [f"case:{case['case_id']}"] if case else campaign_focus_ids

    # 5) Preservation, per real artifact (stage_timeline: memory/disk/ot/network)
    for entry in stage_timeline or []:
        if entry.get("stage_key") not in {"memory_acquisition", "disk_acquisition", "ot_export", "network_context_import"}:
            continue
        size = entry.get("size_bytes")
        beats.append(_beat(
            "preservation_step", rep_num, seq=next_seq(), available=True,
            started_at=entry.get("started_at"), finished_at=entry.get("finished_at"),
            real_duration_seconds=entry.get("elapsed_seconds"),
            title=entry.get("label") or entry.get("stage_key"),
            detail_lines=[x for x in [f"{size} bytes" if size else None, entry.get("target"), entry.get("status")] if x],
            nav_level="drilled_case", focus_ids=case_focus,
            payload={"stage_timeline_entry": entry},
        ))

    # 6) Analysis, per real sub-phase (stage_timeline: analysis_*)
    for entry in stage_timeline or []:
        if not str(entry.get("stage_key") or "").startswith("analysis_"):
            continue
        beats.append(_beat(
            "analysis_phase", rep_num, seq=next_seq(), available=True,
            started_at=entry.get("started_at"), finished_at=entry.get("finished_at"),
            real_duration_seconds=entry.get("elapsed_seconds"),
            title=entry.get("label") or entry.get("stage_key"),
            detail_lines=[entry.get("status")] if entry.get("status") else [],
            nav_level="drilled_case", focus_ids=case_focus,
            payload={"stage_timeline_entry": entry},
        ))

    # 7) Causal reconstruction
    metrics = (causal_status or {}).get("metrics_preview") or {}
    edges = (causal_graph or {}).get("edges") or []
    # C3 CPR (forge_dt_metrics, M6/2026-10-10): re-scores the SAME two
    # upstream edges using independent corroboration from the Intervention
    # Ledger + post-hoc Linker + Evidence Bridge, never touching C0's own
    # fields above -- reused here unchanged so Reconstruction View shows the
    # same number already verified live in forge_dt_metrics.html, instead of
    # requiring a separate dashboard visit to see it.
    c3 = None
    if case and case.get("case_id") and case_dir:
        from ..forge_dt_metrics.service import compute_c3_cpr_for_case
        c3 = _safe(lambda: compute_c3_cpr_for_case(case["case_id"], case_dir))
    beats.append(_beat(
        "reconstruction", rep_num, seq=next_seq(), available=bool(causal_status),
        title="Causal reconstruction" + (f" — CPR {metrics.get('causal_path_recoverability')}" if metrics.get("causal_path_recoverability") is not None else ""),
        detail_lines=[f"{len(edges)} edges evaluated"] if edges else ["Reconstruction not available for this repetition."],
        nav_level="drilled_case", focus_ids=case_focus,
        payload={"causal_status": causal_status, "edges": edges, "c3": c3},
    ))

    # 8) Seal
    integ = (case or {}).get("integrity") or {}
    beats.append(_beat(
        "seal", rep_num, seq=next_seq(), available=bool(integ.get("case_sealed")),
        title="Case sealed" if integ.get("case_sealed") else "Case not sealed",
        detail_lines=[integ.get("manifest_hash")[:16] + "…"] if integ.get("manifest_hash") else [],
        nav_level="drilled_case", focus_ids=case_focus,
        payload={"integrity": integ},
    ))

    # 9) Repetition summary / conclusions
    beats.append(_beat(
        "repetition_summary", rep_num, seq=next_seq(), available=bool(narrative),
        title=f"Repetition {rep_num} conclusions" if narrative else f"Repetition {rep_num}: no narrative report available",
        detail_lines=[f"CPR {narrative.get('cpr')}"] + [f"{k}: {v}" for k, v in (narrative.get("edge_counts") or {}).items()] if narrative else [],
        nav_level="drilled_case", focus_ids=case_focus,
        payload={"narrative": narrative},
    ))

    total_reps = int(job.get("level_c_repetitions") or 1)
    marked_repetitions = [
        {**r, "is_focus": r.get("repetition_number") == rep_num} for r in (base_repetitions or [])
    ]
    snapshot = {
        "job_id": job_id,
        "campaign_id": lc_detail.get("campaign_id"),
        "label": f"Level C · repetition {rep_num}/{total_reps}",
        "status": job.get("status"),
        "phase": job.get("phase"),
        "total_repetitions": total_reps,
        "current_repetition": rep_num,
        "focus_repetition": rep_num,
        "is_live": False,  # reconstruction is always a replay of already-finished history
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "total_elapsed_seconds": lc_detail.get("total_elapsed_seconds"),
        "repetitions": marked_repetitions,
        "stages": lc_detail.get("stages") or [],
        "tool_installs": lc_detail.get("tool_installs") or [],
        "time_sync_checks": lc_detail.get("time_sync_checks") or [],
        "level_b": level_b,
        "case": case,
        "hosts": hosts,
    }

    # 2026-10-15: a global chronological sort was tried here and reverted
    # the same day -- user-reported regression, confirmed real: this
    # repetition's own beats are built in deliberate STRUCTURAL blocks
    # (per-host deployment+tools grouped together, so the replay finishes
    # one machine before moving to the next -- see the per-host loop above,
    # "keeps the construction story... before moving to the next machine"),
    # and a blanket sort-by-`started_at` also reshuffled THAT intentional
    # grouping, interleaving different hosts' tool_install beats by raw
    # time. Worse, `intervention_attempts` here is scoped by `instance_id`
    # across ALL time (get_ledger_entries has no campaign/job scope), so a
    # real instance reused weeks later by an unrelated later campaign (e.g.
    # a gap_validation run) pulls in THAT campaign's own interventions too,
    # with real timestamps far outside this repetition's actual window --
    # sorting globally let those foreign, unrelated interventions scramble
    # into the middle of this repetition's real narrative. A correct fix
    # needs to either scope interventions to this repetition's own real time
    # window or keep them as their own block while only reordering block
    # 1.5 itself in time relative to the surrounding blocks -- not attempted
    # here again without the user's go-ahead, given the first attempt's
    # blast radius was wider than intended.

    return {
        "repetition_number": rep_num,
        "case": case,
        "level_b": level_b,
        "hosts": hosts,
        "snapshot_infrastructure": lc_detail.get("snapshot_infrastructure"),
        "snapshot": snapshot,
        "beats": beats,
    }


def build_reconstruction_timeline(job_id: str) -> dict | None:
    """Full, chronologically-ordered replay timeline for ONE already-completed
    (or in-progress) campaign, covering every repetition in full artifact/
    phase detail, purely from files that already exist -- see module-level
    docstring above this section for the hard read-only rule.
    """
    job = _pick_campaign_job(job_id)
    if not job:
        return None
    total_reps = int(job.get("level_c_repetitions") or 1)
    role_lookup = _role_lookup_by_name()
    base_repetitions = _safe(lambda: rep_service.list_level_c_repetition_statuses(job)) or []

    repetitions = []
    for rep_num in range(1, total_reps + 1):
        repetitions.append(_safe(lambda rn=rep_num: _repetition_beats(job, rn, role_lookup, base_repetitions)) or {
            "repetition_number": rep_num, "case": None, "level_b": None, "hosts": [], "beats": [], "snapshot": None,
        })

    # A failed campaign gets one more real beat, chronologically last,
    # exactly where it actually died -- not shown up front disconnected from
    # the replay (the user's own correction, 2026-10-12: watching the replay
    # should build up normally, phase by phase, and ONLY when playback
    # genuinely reaches the failure moment should the "here it stopped, and
    # here is why" account appear, like a video reaching the exact frame of
    # the incident rather than a spoiler shown before pressing play).
    # Reuses campaign_failure_forensics.reconstruct_failure() unchanged --
    # same real evidence, same real explanation, just placed at its correct
    # point in time instead of in an always-visible side panel.
    if job.get("status") == "failed":
        failed_rep_num = job.get("current_repetition") or total_reps
        target_rep = next((r for r in repetitions if r.get("repetition_number") == failed_rep_num), None)
        if target_rep is not None:
            from ..campaign_failure_forensics.service import reconstruct_failure as _reconstruct_failure
            failure_report = _safe(lambda: _reconstruct_failure(job_id))
            if failure_report and failure_report.get("ok"):
                fail_ts = failure_report.get("last_real_activity", {}).get("ts") or failure_report.get("declared_failed_at")
                target_rep["beats"].append(_beat(
                    "campaign_failed", failed_rep_num, seq=10_000, available=True,
                    started_at=fail_ts, finished_at=failure_report.get("declared_failed_at"),
                    title=f"Campaign failed here — {(failure_report.get('probable_cause') or 'undetermined').replace('_', ' ')}",
                    detail_lines=[failure_report.get("declared_error") or ""],
                    nav_level="overview", focus_ids=[f"rep:{failed_rep_num}"],
                    payload={"failure_report": failure_report},
                ))

    comparison_report = _safe(lambda: level_c_service.get_comparison_report(job_id))
    # A failed campaign never has a real comparison report (that needs every
    # repetition to actually finish) -- rather than end the replay on an
    # empty, honest-but-pointless "No comparison report available" anticlimax
    # right after the real "campaign failed here" moment, this beat is
    # skipped entirely for a failed job. The campaign_failed beat is already
    # the real, correct ending for that story.
    finale_beat = None if (job.get("status") == "failed" and not comparison_report) else _beat(
        "campaign_finale", None, seq=0, available=bool(comparison_report),
        title=(comparison_report or {}).get("verdict") or "No comparison report available",
        detail_lines=[
            f"reproducibility index {comparison_report.get('reproducibility_index')}",
            f"max Δwcpr {comparison_report.get('max_delta_wcpr')}",
        ] if comparison_report else [],
        nav_level="drilled_campaign", focus_ids=[f"campaign:{job_id}"],
        payload={"comparison_report": comparison_report},
    )

    return {
        "job_id": job_id,
        "campaign_id": job.get("campaign_id"),
        "total_repetitions": total_reps,
        "generated_at_utc": _utc_now_iso(),
        "repetitions": repetitions,
        "comparison_report": comparison_report,
        "finale_beat": finale_beat,
    }


def get_host_vitals(instance_id: str, *, refresh: bool = False) -> dict | None:
    summary = node_health_api.build_node_health_summary(refresh_node_metrics=refresh, max_probe_age_seconds=20)
    row = None
    for candidate in summary.get("nodes") or []:
        if candidate.get("id") == instance_id:
            row = dict(candidate)
            break
    if row is None:
        return None
    cached = _load_json(node_health_api._probe_cache_path(instance_id))
    network = ((cached or {}).get("probe") or {}).get("network") if isinstance(cached, dict) else None
    row["network"] = network or {"rx_bytes": None, "tx_bytes": None}
    if row.get("source") in ("cache", "live_probe"):
        _record_metrics_sample(instance_id, row)
    row["metrics_history"] = _metrics_history_for(instance_id)
    return row


# ---------------------------------------------------------------------------
# Sensor coverage
# ---------------------------------------------------------------------------

def get_sensor_coverage() -> dict:
    return {
        "generated_at_utc": _utc_now_iso(),
        "fields": [
            {"field": "host.cpu_usage_pct / memory / disk", "kind": "real_sensor", "source": "SSH probe (probe_node_health_inside_node.sh)"},
            {"field": "host.network_rx_bytes/tx_bytes", "kind": "real_sensor", "source": "SSH probe, added 2026-09-14"},
            {"field": "host.metrics_history (sparkline)", "kind": "real_sensor_accumulating", "source": "in-memory rolling buffer of real samples observed since this process started -- not backfilled, starts empty"},
            {"field": "host.clock_offset_ms", "kind": "real_sensor", "source": "node_health_api time-sync summary"},
            {"field": "host.tools[].inventory_status", "kind": "real_sensor", "source": "tools-installer/installed + tools-installer-tmp"},
            {"field": "host.tools[].version", "kind": "not_available_by_default", "source": "only via a separate, slow SSH tooling probe; not fetched on the main poll"},
            {"field": "host.tools[].install_progress_pct", "kind": "not_available", "source": "only a 4-value enum exists; no percentage is ever recorded"},
            {"field": "host.current_activity", "kind": "derived", "source": "cross-reference of job phase, tools-installer-tmp, attack_attestation.json, pipeline_events.jsonl"},
            {"field": "host.location / ntp_source / asset_type", "kind": "not_available", "source": "not tracked anywhere in this platform -- deliberately omitted rather than shown as placeholder text"},
            {"field": "campaign.repetitions[].status", "kind": "real_sensor", "source": "level_c_orchestrator job status/current_repetition, added 2026-09-15"},
            {"field": "case.integrity.manifest_hash", "kind": "real_sensor", "source": "metadata/case_digest.json, live-reverified against the current manifest.json on every read"},
            {"field": "case.recent_events", "kind": "real_sensor", "source": "metadata/pipeline_events.jsonl"},
            {"field": "case.*, repetition.stages[]", "kind": "real_sensor", "source": "campaign_repetitions.service (durable job/case state)"},
        ],
    }
