from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import openstack
from flask import Blueprint, Response, jsonify, request, send_from_directory, stream_with_context


node_health_bp = Blueprint("node_health", __name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
STATIC_DIR = REPO_ROOT / "app_core" / "static"
SSH_KEY_PATH = os.path.expanduser("~/.ssh/my_key")
PROBE_SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "probe_node_health_inside_node.sh"
TOOLING_PROBE_SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "probe_node_tooling_inside_node.sh"
CLEANUP_SCRIPT_PATH = REPO_ROOT / "pre_memory_cleanup_inside_node.sh"
TIME_SYNC_SCRIPT_PATH = REPO_ROOT / "app_core" / "infrastructure" / "forensics" / "scripts" / "time_sync_preflight.sh"
OPENSTACK_HEALTH_DIR = Path(__file__).resolve().parent / "openstack_health"
OPENSTACK_RESTART_SCRIPT_PATH = OPENSTACK_HEALTH_DIR / "restart_openstack_services.sh"
FREE_HOST_MEMORY_SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "free_host_memory.sh"
TOOLS_INSTALLED_DIR = REPO_ROOT / "tools-installer" / "installed"
TOOLS_TMP_DIR = REPO_ROOT / "tools-installer-tmp"
NODE_HEALTH_TIME_SYNC_DIR = REPO_ROOT / "runtime" / "time_sync" / "node_health"
NODE_HEALTH_RUNTIME_DIR = REPO_ROOT / "runtime" / "node_health"
OPENSTACK_HEALTH_RUNTIME_DIR = NODE_HEALTH_RUNTIME_DIR / "openstack_health"
OPENSTACK_RESTART_JOBS_DIR = OPENSTACK_HEALTH_RUNTIME_DIR / "restart_jobs"
PROBE_CACHE_DIR = NODE_HEALTH_RUNTIME_DIR / "probe_cache"
HEALTH_SUMMARY_CACHE_PATH = OPENSTACK_HEALTH_RUNTIME_DIR / "health_summary.json"
EVIDENCE_ROOT = REPO_ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store"
ACTIVE_CASE_PTR = EVIDENCE_ROOT / "_active_case.txt"
_TIME_SYNC_STATE_LOCK = threading.Lock()
_RUNNING_TIME_SYNC: dict[str, threading.Thread] = {}

# Floating IP quota monitor + cleanup -- added 2026-07-20 after a real incident: the lab
# silently ran out of floating IPs (nothing detected or reported it until a Level C launch
# failed because OpenStack could not allocate one). The invariant the user wants enforced:
# at least 50% of the project's floating IP quota must stay available at all times. Below
# that, unattached (orphan) floating IPs are released automatically and the action is
# reported with how long it took -- mirrors the existing safe-disk-cleanup precedent
# (cleanup_node_free_space() above) but for a quota-level OpenStack resource instead of a
# per-node filesystem.
FLOATING_IP_RUNTIME_DIR = NODE_HEALTH_RUNTIME_DIR / "floating_ips"
FLOATING_IP_JOB_STATUS_PATH = FLOATING_IP_RUNTIME_DIR / "job_status.json"
FLOATING_IP_HISTORY_PATH = FLOATING_IP_RUNTIME_DIR / "cleanup_history.jsonl"
FLOATING_IP_MIN_AVAILABLE_PCT = 50.0
FLOATING_IP_CLEANUP_TARGET_PCT = 65.0  # auto-cleanup stops once back above this, not just past the 50% floor -- avoids re-triggering on every single health-summary poll
_FLOATING_IP_LOCK = threading.Lock()
_FLOATING_IP_CLEANUP_RUNNING = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _safe_slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", str(value or "")).strip("_") or "unknown"


def _cache_age_seconds(path: Path) -> float | None:
    try:
        if not path.is_file():
            return None
        return max(time.time() - path.stat().st_mtime, 0.0)
    except Exception:
        return None


def _probe_cache_path(instance_id: str) -> Path:
    return PROBE_CACHE_DIR / f"{_safe_slug(instance_id)}.json"


def _severity_rank(value: str | None) -> int:
    normalized = str(value or "unknown").lower()
    if normalized == "critical":
        return 3
    if normalized == "warning":
        return 2
    if normalized == "ok":
        return 1
    return 0


def _max_severity(*values: str | None) -> str:
    ranked = sorted(values, key=_severity_rank, reverse=True)
    return ranked[0] if ranked else "unknown"


def _host_pct_severity(pct: float | int | None) -> str:
    if pct is None:
        return "unknown"
    if pct >= 95:
        return "critical"
    if pct >= 85:
        return "warning"
    return "ok"


def _host_load_severity(loadavg: str | None) -> tuple[str, float | None]:
    try:
        one_min = float(str(loadavg or "").split()[0])
        cores = max(os.cpu_count() or 1, 1)
        ratio = one_min / cores
        if ratio >= 1.5:
            return "critical", ratio
        if ratio >= 1.0:
            return "warning", ratio
        return "ok", ratio
    except Exception:
        return "unknown", None


def _read_probe_cache(instance_id: str) -> dict | None:
    return _read_json(_probe_cache_path(instance_id))


def _write_probe_cache(instance_id: str, payload: dict) -> None:
    _write_json(_probe_cache_path(instance_id), payload)


def _read_active_case_dir() -> Path | None:
    try:
        if not ACTIVE_CASE_PTR.is_file():
            return None
        raw = (ACTIVE_CASE_PTR.read_text(encoding="utf-8").splitlines() or [""])[0].strip()
        if not raw:
            # Pointer present but empty (no active case) -- Path("").resolve()
            # would return the process's cwd, whose "is_dir()" is always True,
            # falsely reporting the project's root directory as "active case".
            return None
        candidate = Path(raw).expanduser().resolve()
        return candidate if candidate.is_dir() else None
    except Exception:
        return None


def _connect():
    return openstack.connection.Connection(
        auth_url=os.environ.get("OS_AUTH_URL"),
        project_name=os.environ.get("OS_PROJECT_NAME"),
        username=os.environ.get("OS_USERNAME"),
        password=os.environ.get("OS_PASSWORD"),
        region_name=os.environ.get("OS_REGION_NAME"),
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
        compute_api_version="2",
        identity_interface="public",
    )


def _classify_role(server_name: str) -> str:
    name = (server_name or "").lower()
    if "fuxa" in name or "scada" in name:
        return "scada"
    if "plc" in name:
        return "plc"
    if "attack" in name:
        return "attacker"
    if "monitor" in name:
        return "monitor"
    if "victim" in name:
        return "victim"
    return "unknown"


def _map_user(image_name: str) -> str:
    n = (image_name or "").lower()
    if "ubuntu" in n:
        return "ubuntu"
    if "kali" in n:
        return "kali"
    return "debian"


def _detect_os(conn, server) -> tuple[str, str]:
    image_name = ""
    try:
        image_id = None
        img_prop = getattr(server, "image", None)
        if img_prop:
            if isinstance(img_prop, dict):
                image_id = img_prop.get("id")
            else:
                image_id = getattr(img_prop, "id", None)
        if image_id:
            image = conn.get_image(image_id)
            if image:
                image_name = image.get("os_distro") or image.get("display_name") or image.name or ""
        if not image_name:
            image_name = (getattr(server, "metadata", {}) or {}).get("os_distro", "Linux")
    except Exception:
        image_name = (getattr(server, "metadata", {}) or {}).get("os_distro", "Linux")

    low = (image_name or "").lower()
    if "ubuntu" in low:
        return "Ubuntu Linux", image_name
    if "debian" in low:
        return "Debian Linux", image_name
    if "kali" in low:
        return "Kali Linux", image_name
    if "windows" in low:
        return "Windows", image_name
    return image_name or "Linux", image_name or "Linux"


def _extract_ips_and_networks(server) -> tuple[str | None, str | None, list[dict]]:
    ip_private = None
    ip_floating = None
    networks: list[dict] = []
    addresses = getattr(server, "addresses", {}) or {}
    for net_name, addrs in addresses.items():
        for addr in addrs or []:
            ip = addr.get("addr")
            ip_type = addr.get("OS-EXT-IPS:type")
            mac = addr.get("OS-EXT-IPS-MAC:mac_addr") or addr.get("mac_addr")
            networks.append(
                {
                    "network": net_name,
                    "ip": ip,
                    "type": ip_type or "fixed",
                    "mac": mac,
                }
            )
            if ip_type == "floating":
                ip_floating = ip
            elif not ip_private:
                ip_private = ip
    return ip_private, ip_floating, networks


def _normalize_node(conn, server) -> dict:
    ip_private, ip_floating, networks = _extract_ips_and_networks(server)
    os_label, image_name = _detect_os(conn, server)
    ssh_user = _map_user(image_name or os_label)
    preferred_ip = ip_floating or ip_private or ""
    tool_inventory = _tool_inventory_for_instance(server.id, server.name)
    return {
        "id": server.id,
        "name": server.name,
        "status": getattr(server, "status", "UNKNOWN"),
        "role": _classify_role(server.name),
        "os": os_label,
        "image_name": image_name,
        "ssh_user": ssh_user,
        "ip_private": ip_private,
        "ip_floating": ip_floating,
        "ssh_target_ip": preferred_ip,
        "networks": networks,
        "availability_zone": getattr(server, "availability_zone", None),
        "flavor": getattr(getattr(server, "flavor", None), "get", lambda *_: None)("original_name") if getattr(server, "flavor", None) else None,
        "tool_inventory": tool_inventory,
    }


def _list_nodes() -> list[dict]:
    conn = _connect()
    try:
        servers = list(conn.compute.servers(details=True))
        return [_normalize_node(conn, server) for server in servers]
    finally:
        try:
            conn.close()
        except Exception:
            pass


def power_on_stopped_nodes() -> dict:
    """Starts every real, currently-SHUTOFF instance (Nova's own 'start'
    action, openstacksdk's start_server) -- one click to recover from
    everything that only comes back once the lab VMs themselves are running
    again (network state that only settles once a VM's own interface is up,
    etc.). Safe by construction, not just by convention: Nova itself rejects
    starting an instance that is already ACTIVE (real per-server exception,
    caught below and reported as a no-op) -- an already-running machine is
    never touched, never rebooted, by this call.
    """
    conn = _connect()
    results: list[dict] = []
    try:
        servers = list(conn.compute.servers(details=True))
        for server in servers:
            status = getattr(server, "status", "")
            if status != "SHUTOFF":
                continue
            try:
                conn.compute.start_server(server.id)
                results.append({"instance_id": server.id, "name": server.name, "result": "start_requested"})
            except Exception as exc:
                results.append({"instance_id": server.id, "name": server.name, "result": "error", "detail": str(exc)})
        return {"attempted": len(results), "results": results}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def free_host_memory() -> dict:
    """Frees reclaimable OS memory on THIS host -- the OpenStack
    controller/gunicorn server itself, never the scenario's SSH-probed VMs
    (fuxa/plc/victim/attacker/monitor), which are an entirely separate,
    unrelated code path in this module.

    Motivated directly by a real incident this session: `regenerate_foc()`
    during Level B/C analysis drove real system free memory from 33GB down
    to 423MB with swap 100% full, which is what killed gunicorn workers.
    This gives the operator an on-demand way to reclaim what CAN be safely
    reclaimed, without deleting or breaking anything:
      - `gc.collect()` inside THIS worker process (Python-level garbage --
        note: gunicorn runs 4 sync workers, each with its own memory, so
        this only affects whichever worker happens to serve this request,
        not the other 3).
      - `sync` + `echo 1 > /proc/sys/vm/drop_caches` on the host (kernel
        page cache/dentries/inodes -- documented by the kernel as always
        safe: rebuilt on demand, no user data ever deleted). Requires the
        NOPASSWD sudoers rule installed by start_dashboard.sh's
        "[2.9/6]" step; if that rule is missing, `sudo -n` fails fast
        (no password prompt) and this reports it explicitly instead of
        silently doing nothing.
    Deliberately does NOT touch swap (swapoff/swapon) -- that needs enough
    free RAM to hold everything currently swapped out, and an automatic
    button doing it blindly could itself trigger the exact OOM this is
    meant to prevent. That stays a manual, confirmed action (see
    node_health/README.md for the exact commands used this session).
    """
    import gc

    before = _parse_free_m(_run_local_text(["free", "-m"]).splitlines())
    collected_objects = gc.collect()

    script_attempted = FREE_HOST_MEMORY_SCRIPT_PATH.exists()
    script_ok = False
    script_output = ""
    script_error = None
    if script_attempted:
        try:
            proc = subprocess.run(
                ["bash", str(FREE_HOST_MEMORY_SCRIPT_PATH)],
                capture_output=True,
                text=True,
                timeout=20,
            )
            script_output = ((proc.stdout or "") + (proc.stderr or "")).strip()
            script_ok = proc.returncode == 0
            if not script_ok:
                script_error = f"exit_code={proc.returncode}"
        except Exception as exc:
            script_error = str(exc)
    else:
        script_error = "script_not_found"

    after = _parse_free_m(_run_local_text(["free", "-m"]).splitlines())

    mem_avail_delta = None
    if before.get("mem_avail_mb") is not None and after.get("mem_avail_mb") is not None:
        mem_avail_delta = after["mem_avail_mb"] - before["mem_avail_mb"]

    return {
        "generated_at": _utc_now(),
        "gc_collected_objects": collected_objects,
        "drop_caches": {
            "attempted": script_attempted,
            "ok": script_ok,
            "error": script_error,
            "output": script_output,
        },
        "before": before,
        "after": after,
        "mem_avail_mb_delta": mem_avail_delta,
        "note": (
            "gc.collect() only frees memory in this one gunicorn worker process, not all 4. "
            "Swap is intentionally left untouched -- see node_health/README.md for the manual "
            "swapoff/swapon procedure if swap itself needs reducing."
        ),
    }


def _find_node(instance_id: str) -> dict | None:
    for node in _list_nodes():
        if node["id"] == instance_id:
            return node
    return None


def resolve_node_for_remote_ops(*, instance_id: str | None = None, vm_ip: str | None = None) -> dict | None:
    instance_id = str(instance_id or "").strip()
    vm_ip = str(vm_ip or "").strip()
    nodes = _list_nodes()
    if instance_id:
        for node in nodes:
            if str(node.get("id") or "") == instance_id:
                return node
    if vm_ip:
        for node in nodes:
            candidates = {
                str(node.get("ssh_target_ip") or "").strip(),
                str(node.get("ip_private") or "").strip(),
                str(node.get("ip_floating") or "").strip(),
            }
            candidates.update(
                str(item.get("ip") or "").strip()
                for item in (node.get("networks") or [])
                if str(item.get("ip") or "").strip()
            )
            if vm_ip in candidates:
                return node
    return None


def _run_local_text(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _parse_free_m(mem_lines: list[str]) -> dict:
    """Parses `free -m` output into MB ints. Shared by `_local_host_summary`
    (fleet table row) and `free_host_memory` (before/after snapshot), so the
    two never disagree on how they read the same command's output."""
    result: dict[str, int | None] = {
        "mem_total_mb": None,
        "mem_used_mb": None,
        "mem_avail_mb": None,
        "swap_total_mb": None,
        "swap_used_mb": None,
        "swap_free_mb": None,
    }
    for line in mem_lines:
        if line.startswith("Mem:"):
            cols = line.split()
            if len(cols) >= 7:
                try:
                    result["mem_total_mb"] = int(cols[1])
                    result["mem_used_mb"] = int(cols[2])
                    result["mem_avail_mb"] = int(cols[6])
                except Exception:
                    pass
        elif line.startswith("Swap:"):
            cols = line.split()
            if len(cols) >= 4:
                try:
                    result["swap_total_mb"] = int(cols[1])
                    result["swap_used_mb"] = int(cols[2])
                    result["swap_free_mb"] = int(cols[3])
                except Exception:
                    pass
    return result


def _local_host_summary(nodes: list[dict]) -> dict:
    root_df = _run_local_text(["df", "-P", "-B1", "/"]).splitlines()
    mem_lines = _run_local_text(["free", "-m"]).splitlines()

    root_total = root_used = root_avail = None
    root_use_pct = None
    if len(root_df) >= 2:
        cols = root_df[1].split()
        if len(cols) >= 6:
            try:
                root_total = int(cols[1])
                root_used = int(cols[2])
                root_avail = int(cols[3])
                root_use_pct = cols[4]
            except Exception:
                pass

    mem_swap = _parse_free_m(mem_lines)

    role_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for node in nodes:
        role = node.get("role", "unknown")
        status = node.get("status", "UNKNOWN")
        role_counts[role] = role_counts.get(role, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "host": {
            "hostname": _run_local_text(["hostname"]) or "not_available",
            "date_utc": _run_local_text(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]) or "not_available",
            "loadavg": _run_local_text(["bash", "-lc", "cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}'"]) or "not_available",
            "root_total_bytes": root_total,
            "root_used_bytes": root_used,
            "root_avail_bytes": root_avail,
            "root_use_pct": root_use_pct,
            "mem_total_mb": mem_swap["mem_total_mb"],
            "mem_used_mb": mem_swap["mem_used_mb"],
            "mem_avail_mb": mem_swap["mem_avail_mb"],
            "swap_total_mb": mem_swap["swap_total_mb"],
            "swap_used_mb": mem_swap["swap_used_mb"],
            "swap_free_mb": mem_swap["swap_free_mb"],
        },
        "scenario": {
            "node_count": len(nodes),
            "role_counts": role_counts,
            "status_counts": status_counts,
            "network_count": len({net.get("network") for node in nodes for net in node.get("networks", []) if net.get("network")}),
        },
    }


def _network_graph(nodes: list[dict]) -> dict:
    graph_nodes = []
    graph_edges = []
    seen_networks: dict[str, dict] = {}
    for node in nodes:
        graph_nodes.append(
            {
                "data": {
                    "id": node["id"],
                    "label": node["name"],
                    "kind": "instance",
                    "role": node["role"],
                    "status": node["status"],
                    "os": node["os"],
                }
            }
        )
        for net in node.get("networks", []):
            if net.get("type") == "floating":
                continue
            net_name = net.get("network") or "unknown_net"
            net_id = f"net::{net_name}"
            if net_id not in seen_networks:
                seen_networks[net_id] = {
                    "data": {
                        "id": net_id,
                        "label": net_name,
                        "kind": "network",
                        "network": net_name,
                    }
                }
            graph_edges.append(
                {
                    "data": {
                        "id": f"edge::{node['id']}::{net_id}",
                        "source": node["id"],
                        "target": net_id,
                        "label": net_name,
                    }
                }
            )
    graph_nodes.extend(seen_networks.values())
    return {"nodes": graph_nodes, "edges": graph_edges}


def _run_remote_script_capture(node: dict, script_path: Path, *, remote_dump: str = "", timeout: int = 90) -> subprocess.CompletedProcess[str]:
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")
    ssh_ip = node.get("ssh_target_ip") or node.get("ip_floating") or node.get("ip_private")
    if not ssh_ip:
        raise RuntimeError("No SSH target IP available for node")
    ssh_user = node.get("ssh_user") or "debian"
    remote_cmd = f"REMOTE_DUMP={shlex.quote(remote_dump)} bash -s"
    script_text = script_path.read_text(encoding="utf-8")
    return subprocess.run(
        [
            "ssh",
            "-i",
            SSH_KEY_PATH,
            "-o",
            "StrictHostKeyChecking=no",
            f"{ssh_user}@{ssh_ip}",
            remote_cmd,
        ],
        input=script_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_remote_text_capture(node: dict, command: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    ssh_ip = node.get("ssh_target_ip") or node.get("ip_floating") or node.get("ip_private")
    if not ssh_ip:
        raise RuntimeError("No SSH target IP available for node")
    ssh_user = node.get("ssh_user") or "debian"
    return subprocess.run(
        [
            "ssh",
            "-i",
            SSH_KEY_PATH,
            "-o",
            "StrictHostKeyChecking=no",
            f"{ssh_user}@{ssh_ip}",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _node_root_free_mb(node: dict) -> int | None:
    try:
        proc = _run_remote_text_capture(node, "df -Pm / | awk 'NR==2 {print $4}'", timeout=20)
        raw = str(proc.stdout or "").strip()
        return int(raw) if raw else None
    except Exception:
        return None


def cleanup_node_free_space(
    *,
    instance_id: str | None = None,
    vm_ip: str | None = None,
    remote_dump: str = "",
    timeout: int = 120,
    minimum_free_mb: int | None = None,
    max_attempts: int = 2,
) -> dict:
    node = resolve_node_for_remote_ops(instance_id=instance_id, vm_ip=vm_ip)
    if not node:
        return {
            "status": "failed",
            "reason": "node_not_found",
            "instance_id": instance_id,
            "vm_ip": vm_ip,
            "attempts": [],
        }
    if not CLEANUP_SCRIPT_PATH.exists():
        return {
            "status": "failed",
            "reason": "cleanup_script_not_found",
            "instance_id": instance_id,
            "vm_ip": vm_ip,
            "script_path": str(CLEANUP_SCRIPT_PATH),
            "attempts": [],
        }

    before_free_mb = _node_root_free_mb(node)
    attempts: list[dict] = []
    final_after_free_mb = before_free_mb
    for attempt_no in range(1, max(int(max_attempts or 1), 1) + 1):
        proc = _run_remote_script_capture(node, CLEANUP_SCRIPT_PATH, remote_dump=remote_dump, timeout=timeout)
        after_free_mb = _node_root_free_mb(node)
        final_after_free_mb = after_free_mb
        stdout_excerpt = [line.rstrip() for line in str(proc.stdout or "").splitlines()[-40:] if line.strip()]
        stderr_excerpt = [line.rstrip() for line in str(proc.stderr or "").splitlines()[-40:] if line.strip()]
        attempts.append(
            {
                "attempt": attempt_no,
                "returncode": proc.returncode,
                "stdout_excerpt": stdout_excerpt,
                "stderr_excerpt": stderr_excerpt,
                "free_mb_before": before_free_mb if attempt_no == 1 else attempts[-1].get("free_mb_after"),
                "free_mb_after": after_free_mb,
            }
        )
        if proc.returncode == 0 and (
            minimum_free_mb is None or (after_free_mb is not None and after_free_mb >= int(minimum_free_mb))
        ):
            return {
                "status": "completed",
                "reason": "cleanup_completed",
                "instance_id": node.get("id"),
                "vm_ip": node.get("ssh_target_ip") or node.get("ip_private") or node.get("ip_floating"),
                "node_name": node.get("name"),
                "ssh_user": node.get("ssh_user"),
                "free_mb_before": before_free_mb,
                "free_mb_after": after_free_mb,
                "minimum_free_mb": minimum_free_mb,
                "attempts": attempts,
            }

    reason = "cleanup_script_failed"
    if minimum_free_mb is not None and final_after_free_mb is not None and final_after_free_mb < int(minimum_free_mb):
        reason = "insufficient_free_space_after_cleanup"
    return {
        "status": "failed",
        "reason": reason,
        "instance_id": node.get("id"),
        "vm_ip": node.get("ssh_target_ip") or node.get("ip_private") or node.get("ip_floating"),
        "node_name": node.get("name"),
        "ssh_user": node.get("ssh_user"),
        "free_mb_before": before_free_mb,
        "free_mb_after": final_after_free_mb,
        "minimum_free_mb": minimum_free_mb,
        "attempts": attempts,
    }


def _floating_ip_severity(available_pct: float | None) -> str:
    if available_pct is None:
        return "unknown"
    if available_pct < 25.0:
        return "critical"
    if available_pct < FLOATING_IP_MIN_AVAILABLE_PCT:
        return "warning"
    return "ok"


def _floating_ip_status(conn=None) -> dict:
    """Real, live floating IP quota usage for the current OpenStack project.

    `available_pct` is what the 50% invariant is checked against: (quota_limit -
    allocated_total) / quota_limit. If the quota itself can't be read (some OpenStack
    deployments report -1/unlimited, or the quota API call fails), available/available_pct
    are left None and severity is "unknown" rather than guessing -- there is nothing honest
    to compare against without a real limit.
    """
    owns_conn = conn is None
    if owns_conn:
        conn = _connect()
    try:
        project_id = conn.current_project_id
        floating_ips = list(conn.network.ips())
        ip_rows = [
            {
                "id": ip.id,
                "floating_ip_address": getattr(ip, "floating_ip_address", None),
                "fixed_ip_address": getattr(ip, "fixed_ip_address", None),
                "status": getattr(ip, "status", "UNKNOWN"),
                "port_id": getattr(ip, "port_id", None),
                "attached": bool(getattr(ip, "port_id", None)),
                "description": getattr(ip, "description", None) or None,
            }
            for ip in floating_ips
        ]
        allocated_total = len(ip_rows)
        attached_count = sum(1 for row in ip_rows if row["attached"])
        unattached_count = allocated_total - attached_count

        quota_limit = None
        quota_error = None
        try:
            quota = conn.network.get_quota(project_id)
            raw_limit = getattr(quota, "floating_ips", None)
            if raw_limit is None:
                raw_limit = getattr(quota, "floating_ip", None)
            if raw_limit is None:
                raw_limit = getattr(quota, "floatingip", None)
            if raw_limit is not None and int(raw_limit) >= 0:
                quota_limit = int(raw_limit)
        except Exception as exc:
            quota_error = str(exc)

        available = None
        available_pct = None
        if quota_limit:
            available = max(quota_limit - allocated_total, 0)
            available_pct = round((available / quota_limit) * 100.0, 1)

        severity = _floating_ip_severity(available_pct)
        return {
            "generated_at": _utc_now(),
            "quota_limit": quota_limit,
            "quota_error": quota_error,
            "allocated_total": allocated_total,
            "attached_count": attached_count,
            "unattached_count": unattached_count,
            "available": available,
            "available_pct": available_pct,
            "severity": severity,
            "threshold_pct": FLOATING_IP_MIN_AVAILABLE_PCT,
            "below_threshold": available_pct is not None and available_pct < FLOATING_IP_MIN_AVAILABLE_PCT,
            "ips": ip_rows,
        }
    finally:
        if owns_conn:
            try:
                conn.close()
            except Exception:
                pass


def _floating_ip_deployment_in_progress() -> bool:
    """True while a Level C job is actively (re)deploying instances.

    Guards ONLY the automatic threshold-triggered cleanup (never the manual button, which
    is an explicit operator action) against a real race: a floating IP can briefly exist
    allocated-but-not-yet-associated to a port while a scenario is being stood back up
    during DEPLOYING_IT/DEPLOYING_OT/WAITING_NODES. Deleting it in that exact window would
    break the deployment it was about to be used by. If this can't be determined, err
    towards NOT auto-cleaning rather than risking a live deployment.
    """
    try:
        from ..level_c_orchestrator.service import list_jobs
        risky_phases = {"DEPLOYING_IT", "DEPLOYING_OT", "WAITING_NODES"}
        for job in list_jobs():
            if str(job.get("status") or "").lower() != "running":
                continue
            phase = str(job.get("phase") or "")
            if any(phase.startswith(p) for p in risky_phases):
                return True
        return False
    except Exception:
        return True


def _write_floating_ip_job_status(payload: dict) -> None:
    _write_json(FLOATING_IP_JOB_STATUS_PATH, payload)


def _floating_ip_cleanup_worker(*, triggered_by: str, target_pct: float = FLOATING_IP_CLEANUP_TARGET_PCT) -> None:
    global _FLOATING_IP_CLEANUP_RUNNING
    job_id = f"fip-cleanup-{uuid.uuid4().hex[:12]}"
    started_at = _utc_now()
    start_ts = time.time()
    status = {
        "job_id": job_id,
        "status": "running",
        "triggered_by": triggered_by,
        "started_at": started_at,
        "updated_at": started_at,
        "finished_at": None,
        "duration_seconds": None,
        "target_pct": target_pct,
        "before": None,
        "after": None,
        "released": [],
        "released_count": 0,
        "skipped_attached_count": 0,
        "per_ip_errors": [],
        "error": None,
    }
    _write_floating_ip_job_status(status)
    conn = None
    try:
        conn = _connect()
        before = _floating_ip_status(conn)
        status["before"] = {k: before[k] for k in ("quota_limit", "allocated_total", "attached_count", "unattached_count", "available_pct")}
        status["skipped_attached_count"] = before["attached_count"]

        candidates = [row for row in before["ips"] if not row["attached"]]
        released: list[dict] = []
        for row in candidates:
            try:
                conn.network.delete_ip(row["id"])
                released.append(row)
            except Exception as exc:
                status["per_ip_errors"].append({"id": row["id"], "floating_ip_address": row.get("floating_ip_address"), "error": str(exc)})
                continue
            status["released"] = released
            status["released_count"] = len(released)
            status["updated_at"] = _utc_now()
            _write_floating_ip_job_status(status)
            interim = _floating_ip_status(conn)
            if interim.get("available_pct") is not None and interim["available_pct"] >= target_pct:
                break

        after = _floating_ip_status(conn)
        status["after"] = {k: after[k] for k in ("quota_limit", "allocated_total", "attached_count", "unattached_count", "available_pct")}
        status["released"] = released
        status["released_count"] = len(released)
        status["status"] = "completed"
    except Exception as exc:
        status["status"] = "failed"
        status["error"] = str(exc)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        finished_at = _utc_now()
        status["finished_at"] = finished_at
        status["updated_at"] = finished_at
        status["duration_seconds"] = round(time.time() - start_ts, 2)
        _write_floating_ip_job_status(status)
        _append_jsonl(FLOATING_IP_HISTORY_PATH, status)
        with _FLOATING_IP_LOCK:
            _FLOATING_IP_CLEANUP_RUNNING = False


def trigger_floating_ip_cleanup(*, triggered_by: str) -> dict:
    """Starts the cleanup in the background (fire-and-forget, same pattern as
    run_node_time_sync). If one is already running, returns its current status instead of
    starting a second one -- releasing floating IPs is not something to run concurrently
    with itself.
    """
    global _FLOATING_IP_CLEANUP_RUNNING
    with _FLOATING_IP_LOCK:
        if _FLOATING_IP_CLEANUP_RUNNING:
            return _read_json(FLOATING_IP_JOB_STATUS_PATH) or {"status": "running", "triggered_by": triggered_by}
        _FLOATING_IP_CLEANUP_RUNNING = True
    thread = threading.Thread(
        target=_floating_ip_cleanup_worker,
        kwargs={"triggered_by": triggered_by},
        daemon=True,
        name="floating-ip-cleanup",
    )
    thread.start()
    return _read_json(FLOATING_IP_JOB_STATUS_PATH) or {"status": "starting", "triggered_by": triggered_by}


def floating_ip_cleanup_status() -> dict:
    current = _read_json(FLOATING_IP_JOB_STATUS_PATH) or {"status": "not_available"}
    history: list[dict] = []
    if FLOATING_IP_HISTORY_PATH.is_file():
        try:
            lines = FLOATING_IP_HISTORY_PATH.read_text(encoding="utf-8").splitlines()
            for line in lines[-10:]:
                try:
                    history.append(json.loads(line))
                except Exception:
                    continue
        except Exception:
            pass
    history.reverse()
    return {"current": current, "history": history}


def _safe_instance_filename(instance_name: str) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", (instance_name or "").lower())
    return f"{safe_name}_tools.json"


def _read_json_file(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _node_time_sync_dir(instance_id: str) -> Path:
    return NODE_HEALTH_TIME_SYNC_DIR / instance_id


def _node_time_sync_paths(instance_id: str) -> dict[str, Path]:
    base = _node_time_sync_dir(instance_id)
    return {
        "dir": base,
        "json": base / "time_sync.json",
        "before": base / "time_sync_before.json",
        "after": base / "time_sync_after.json",
        "status": base / "job_status.json",
        "stdout": base / "time_sync.stdout.log",
        "stderr": base / "time_sync.stderr.log",
        "interventions": base / "time_sync_interventions.jsonl",
    }


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except Exception:
        return str(path)


def _case_relative_path(path: Path) -> str:
    active_case = _read_active_case_dir()
    if active_case:
        try:
            return str(path.relative_to(active_case))
        except Exception:
            pass
    return str(path)


def _tool_category(tool_name: str) -> str:
    name = (tool_name or "").lower()
    if name == "suricata":
        return "ids"
    if name == "wazuh":
        return "siem"
    if name in {"wazuh_agent", "caldera_agent"}:
        return "agent"
    if "integration" in name:
        return "integration"
    if "fim" in name:
        return "fim"
    if name.startswith("rollback_suricata_"):
        return "rule_pack"
    if name.startswith("rollback_wazuh_"):
        return "integration"
    if name.startswith("caldera"):
        return "orchestrator"
    return "other"


def _tool_display_name(tool_name: str) -> str:
    custom = {
        "suricata": "Suricata IDS",
        "wazuh": "Wazuh Manager",
        "wazuh_agent": "Wazuh Agent",
        "wazuh_fim_realtime": "Wazuh FIM Realtime",
        "rollback_suricata_ping_detection": "Suricata Ping Detection Rules",
        "rollback_suricata_modbus_register_detection": "Suricata Modbus Register Rules",
        "rollback_wazuh_suricata_integration": "Wazuh-Suricata Integration",
        "caldera": "MITRE Caldera",
        "caldera_agent": "Caldera Agent",
        "caldera_ot_plugins": "Caldera OT Plugins",
        "mbpoll": "mbpoll",
        "nmap": "Nmap",
    }
    if tool_name in custom:
        return custom[tool_name]
    return tool_name.replace("_", " ").strip().title()


def _runtime_probe_key(tool_name: str) -> str | None:
    mapping = {
        "suricata": "suricata",
        "wazuh": "wazuh-manager",
        "wazuh_agent": "wazuh-agent",
        "zeek": "zeek",
        "snort": "snort",
        "openplc": "openplc",
        "nmap": "nmap",
        "mbpoll": "mbpoll",
        "caldera": "caldera",
        "caldera_agent": "caldera-agent",
    }
    return mapping.get(tool_name)


def _expected_artifacts(tool_name: str) -> list[str]:
    mapping = {
        "rollback_suricata_ping_detection": ["nics-ping.rules"],
        "rollback_suricata_modbus_register_detection": ["nics-modbus-register-manipulation.rules"],
        "rollback_wazuh_suricata_integration": ["/var/ossec/etc/ossec.conf", "/var/ossec/logs/ossec.log"],
        "wazuh_fim_realtime": ["/var/ossec/etc/ossec.conf"],
    }
    return mapping.get(tool_name, [])


def _tool_inventory_for_instance(instance_id: str, instance_name: str) -> dict:
    records: dict[str, dict] = {}
    source_files: list[str] = []

    installed_path = TOOLS_INSTALLED_DIR / f"{instance_id}.json"
    installed_payload = _read_json_file(installed_path) if installed_path.exists() else None
    tmp_payload = None
    tmp_path = TOOLS_TMP_DIR / _safe_instance_filename(instance_name)
    if tmp_path.exists():
        tmp_payload = _read_json_file(tmp_path)
    if tmp_payload:
        source_files.append(str(tmp_path.relative_to(REPO_ROOT)))
    if installed_payload:
        source_files.append(str(installed_path.relative_to(REPO_ROOT)))

    tmp_tools = (tmp_payload or {}).get("tools") or {}
    installed_tools = (installed_payload or {}).get("installed_tools") or {}

    merged: dict[str, str] = {}
    for tool_name, status in tmp_tools.items():
        merged[tool_name] = status
    for tool_name, installed_at in installed_tools.items():
        if tool_name not in merged:
            merged[tool_name] = installed_at
        elif merged[tool_name] in ("error", "pending", "uninstalling"):
            continue
        else:
            merged[tool_name] = installed_at

    for tool_name, merged_status in merged.items():
        record = records.setdefault(
            tool_name,
            {
                "id": tool_name,
                "display_name": _tool_display_name(tool_name),
                "category": _tool_category(tool_name),
                "inventory_status": "unknown",
                "installed_at": None,
                "expected_artifacts": _expected_artifacts(tool_name),
            },
        )
        if tool_name in installed_tools:
            record["installed_at"] = installed_tools.get(tool_name)
        if tool_name in tmp_tools and tmp_tools.get(tool_name) in ("error", "pending", "uninstalling"):
            record["inventory_status"] = tmp_tools.get(tool_name)
        else:
            record["inventory_status"] = "installed" if tool_name in installed_tools or tmp_tools.get(tool_name) == "installed" else str(merged_status)

    tools = sorted(records.values(), key=lambda item: (item["category"], item["display_name"].lower()))
    counts: dict[str, int] = {}
    for tool in tools:
        counts[tool["category"]] = counts.get(tool["category"], 0) + 1
    return {
        "source_files": source_files,
        "tools": tools,
        "counts": counts,
        "total": len(tools),
    }


def _parse_probe_output(stdout: str) -> dict:
    values: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    current_section = None
    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("KV\t"):
            _, key, value = line.split("\t", 2)
            values[key] = value
            continue
        if line.startswith("SECTION\t"):
            _, name, marker = line.split("\t", 2)
            if marker == "BEGIN":
                current_section = name
                sections[current_section] = []
            elif marker == "END":
                current_section = None
            continue
        if current_section:
            sections[current_section].append(line)

    def as_int(key: str) -> int | None:
        value = values.get(key, "")
        try:
            return int(float(str(value).replace("%", "").strip()))
        except Exception:
            return None

    def as_float(key: str) -> float | None:
        value = values.get(key, "")
        try:
            return float(str(value).replace("%", "").strip())
        except Exception:
            return None

    mem_total = as_int("mem_total_mb") or 0
    mem_used = as_int("mem_used_mb") or 0
    mem_avail = as_int("mem_avail_mb") or 0
    mem_pct = round((mem_used / mem_total) * 100, 2) if mem_total else None
    swap_total = as_int("swap_total_mb") or 0
    swap_used = as_int("swap_used_mb") or 0
    swap_pct = round((swap_used / swap_total) * 100, 2) if swap_total else None
    root_total = as_int("root_total_bytes") or 0
    root_used = as_int("root_used_bytes") or 0
    root_avail = as_int("root_avail_bytes") or 0
    root_pct = as_int("root_use_pct")

    def severity(pct: float | int | None) -> str:
        if pct is None:
            return "unknown"
        if pct >= 95:
            return "critical"
        if pct >= 85:
            return "warning"
        return "ok"

    return {
        "raw_values": values,
        "sections": sections,
        "identity": {
            "hostname": values.get("hostname", "not_available"),
            "os": values.get("os_pretty", "not_available"),
            "kernel": values.get("kernel", "not_available"),
            "machine": values.get("machine", "not_available"),
            "date_utc": values.get("date_utc", "not_available"),
            "uptime": values.get("uptime_pretty", "not_available"),
            "loadavg": values.get("loadavg", "not_available"),
        },
        "cpu": {
            "cores": as_int("cpu_cores"),
            "usage_pct": as_float("cpu_usage_pct"),
            "severity": severity(as_float("cpu_usage_pct")),
        },
        "memory": {
            "total_mb": mem_total,
            "used_mb": mem_used,
            "available_mb": mem_avail,
            "usage_pct": mem_pct,
            "swap_total_mb": swap_total,
            "swap_used_mb": swap_used,
            "swap_free_mb": as_int("swap_free_mb"),
            "swap_usage_pct": swap_pct,
            "severity": severity(mem_pct),
        },
        "disk": {
            "root_total_bytes": root_total,
            "root_used_bytes": root_used,
            "root_avail_bytes": root_avail,
            "root_use_pct": root_pct,
            "root_inodes_use_pct": as_int("root_inodes_use_pct"),
            "var_log_size_bytes": as_int("var_log_size_bytes"),
            "suricata_log_size_bytes": as_int("suricata_log_size_bytes"),
            "tmp_size_bytes": as_int("tmp_size_bytes"),
            "var_tmp_size_bytes": as_int("var_tmp_size_bytes"),
            "apt_cache_size_bytes": as_int("apt_cache_size_bytes"),
            "severity": severity(root_pct),
        },
        "network": {
            # Raw cumulative counters only (sum of every non-loopback interface),
            # never a computed rate -- probing is on-demand/irregular, so a rate
            # derived here would assume a sampling interval that doesn't really
            # exist. Added 2026-09-14 for the 3D Live Monitor; a rate is derived
            # by the caller from two successive real samples, not fabricated here.
            "rx_bytes": as_int("net_rx_bytes"),
            "tx_bytes": as_int("net_tx_bytes"),
        },
        "services": {
            (line.split("=", 1)[0] if "=" in line else line): (line.split("=", 1)[1] if "=" in line else "unknown")
            for line in sections.get("services", [])
        },
        "tables": {
            "filesystems": sections.get("filesystems", []),
            "top_cpu": sections.get("top_cpu", []),
            "top_mem": sections.get("top_mem", []),
            "largest_var": sections.get("largest_var", []),
            # NIST SP 800-86 Section 5.1.2 "Volatile Data" -- "Network
            # Connections" (ports/addresses the system is listening on) and
            # "Login Sessions" (currently logged-in users), collected via the
            # same SSH session as everything else above, never cached.
            "listening_ports": sections.get("listening_ports", []),
            "login_sessions": sections.get("login_sessions", []),
        },
    }


def _probe_node_live(node: dict, *, timeout: int = 120) -> dict:
    result = _run_remote_script_capture(node, PROBE_SCRIPT_PATH, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Remote probe failed with exit code {result.returncode}")
    probe = _parse_probe_output(result.stdout)
    payload = {
        "generated_at": _utc_now(),
        "node": {
            "id": node.get("id"),
            "name": node.get("name"),
            "role": node.get("role"),
            "status": node.get("status"),
            "ssh_target_ip": node.get("ssh_target_ip"),
        },
        "probe": probe,
        "stdout": result.stdout,
    }
    _write_probe_cache(node["id"], payload)
    return payload


def _node_metrics_row(node: dict, probe_payload: dict | None, *, source: str, stale: bool, error: str | None = None) -> dict:
    probe = (probe_payload or {}).get("probe") or {}
    cpu = probe.get("cpu") or {}
    memory = probe.get("memory") or {}
    disk = probe.get("disk") or {}
    cache_path = _probe_cache_path(node["id"])
    age_seconds = _cache_age_seconds(cache_path)
    generated_at = (probe_payload or {}).get("generated_at")
    overall_severity = _max_severity(cpu.get("severity"), memory.get("severity"), disk.get("severity"))
    if error and overall_severity == "unknown":
        overall_severity = "critical"
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "role": node.get("role"),
        "status": node.get("status"),
        "ssh_target_ip": node.get("ssh_target_ip"),
        "source": source,
        "stale": bool(stale),
        "error": error,
        "generated_at": generated_at,
        "cache_age_seconds": round(age_seconds, 2) if age_seconds is not None else None,
        "cpu_usage_pct": cpu.get("usage_pct"),
        "cpu_severity": cpu.get("severity", "unknown"),
        "memory_usage_pct": memory.get("usage_pct"),
        "memory_available_mb": memory.get("available_mb"),
        "memory_severity": memory.get("severity", "unknown"),
        "disk_root_use_pct": disk.get("root_use_pct"),
        "disk_root_avail_bytes": disk.get("root_avail_bytes"),
        "disk_severity": disk.get("severity", "unknown"),
        "overall_severity": overall_severity,
    }


def _probe_cached_or_refresh(node: dict, *, refresh: bool, max_age_seconds: int) -> dict:
    cache = _read_probe_cache(node["id"])
    cache_path = _probe_cache_path(node["id"])
    age_seconds = _cache_age_seconds(cache_path)
    cache_fresh = cache is not None and age_seconds is not None and age_seconds <= max_age_seconds
    if refresh and not cache_fresh:
        try:
            live = _probe_node_live(node)
            return _node_metrics_row(node, live, source="live_probe", stale=False)
        except Exception as exc:
            if cache:
                return _node_metrics_row(node, cache, source="stale_cache", stale=True, error=str(exc))
            return _node_metrics_row(node, None, source="probe_failed", stale=True, error=str(exc))
    if cache:
        return _node_metrics_row(node, cache, source="cache", stale=not cache_fresh)
    return _node_metrics_row(node, None, source="not_available", stale=True, error="No cached node metrics available yet.")


def _parse_tooling_output(stdout: str) -> dict:
    values: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    current_section = None
    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("KV\t"):
            _, key, value = line.split("\t", 2)
            values[key] = value
            continue
        if line.startswith("SECTION\t"):
            _, name, marker = line.split("\t", 2)
            if marker == "BEGIN":
                current_section = name
                sections[current_section] = []
            elif marker == "END":
                current_section = None
            continue
        if current_section:
            sections[current_section].append(line)

    def _parse_pairs(lines: list[str]) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for line in lines:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()
        return parsed

    def _parse_file_sections(lines: list[str]) -> list[dict]:
        files: list[dict] = []
        current: dict | None = None
        for line in lines:
            if line.startswith("FILE\t"):
                if current:
                    files.append(current)
                current = {"path": line.split("\t", 1)[1].strip(), "content_lines": []}
                continue
            if line.startswith("FILE_END\t"):
                if current:
                    files.append(current)
                    current = None
                continue
            if current is not None:
                current["content_lines"].append(line)
        if current:
            files.append(current)
        return files

    def _interpret_suricata_rule(raw_rule: str) -> str:
        text = (raw_rule or "").strip()
        if not text:
            return "Empty rule line."
        proto = "traffic"
        direction = ""
        if text.startswith("alert "):
            parts = text.split("(", 1)[0].split()
            if len(parts) >= 7:
                proto = parts[1]
                direction = f"{parts[2]} {parts[3]} {parts[4]} {parts[5]} {parts[6]}"
        msg = "custom detection"
        sid = None
        if 'msg:"' in text:
            msg = text.split('msg:"', 1)[1].split('"', 1)[0]
        if "sid:" in text:
            sid = text.split("sid:", 1)[1].split(";", 1)[0].strip()
        hints: list[str] = []
        if "itype:8" in text:
            hints.append("ICMP echo request")
        if "byte_test:1,=,0x10,7" in text:
            hints.append("Modbus write multiple registers function 0x10")
        if "byte_test:1,=,0x06,7" in text:
            hints.append("Modbus write single register function 0x06")
        if "byte_test:1,=,0x05,7" in text:
            hints.append("Modbus write single coil function 0x05")
        if "byte_test:1,=,0x0f,7" in text:
            hints.append("Modbus write multiple coils function 0x0f")
        hint_text = "; ".join(hints) if hints else "see raw rule options"
        sid_text = f"sid {sid}" if sid else "no sid parsed"
        direction_text = direction or "custom flow expression"
        return f"{msg} | {sid_text} | alerts on {proto} {direction_text} | detects {hint_text}."

    def _extract_suricata_rules(files: list[dict]) -> list[dict]:
        parsed_rules: list[dict] = []
        for file_entry in files:
            path = file_entry.get("path", "unknown")
            for line in file_entry.get("content_lines", []):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or not stripped.startswith("alert "):
                    continue
                parsed_rules.append(
                    {
                        "path": path,
                        "raw": stripped,
                        "interpretation": _interpret_suricata_rule(stripped),
                    }
                )
        return parsed_rules

    suricata_rule_contents = _parse_file_sections(sections.get("suricata_rule_contents", []))
    wazuh_rule_contents = _parse_file_sections(sections.get("wazuh_rule_contents", []))

    return {
        "generated_at": values.get("date_utc", "not_available"),
        "tool_presence": _parse_pairs(sections.get("tool_presence", [])),
        "tool_status": _parse_pairs(sections.get("tool_status", [])),
        "tool_versions": _parse_pairs(sections.get("tool_versions", [])),
        "suricata": {
            "active_rule_files": sections.get("suricata_rule_files", []),
            "custom_signatures": sections.get("suricata_custom_signatures", []),
            "rule_inventory": sections.get("suricata_rule_inventory", []),
            "rule_contents": suricata_rule_contents,
            "parsed_rules": _extract_suricata_rules(suricata_rule_contents),
            "config_summary": sections.get("suricata_config_summary", []),
        },
        "wazuh": {
            "fim_paths": sections.get("wazuh_fim_paths", []),
            "local_rules": sections.get("wazuh_local_rules", []),
            "local_decoders": sections.get("wazuh_local_decoders", []),
            "rule_inventory": sections.get("wazuh_rule_inventory", []),
            "rule_contents": wazuh_rule_contents,
            "config_summary": sections.get("wazuh_config_summary", []),
        },
        "raw_values": values,
    }


def _build_tooling_payload(node: dict) -> dict:
    inventory = _tool_inventory_for_instance(node["id"], node.get("name", ""))
    runtime = None
    runtime_error = None
    try:
        result = _run_remote_script_capture(node, TOOLING_PROBE_SCRIPT_PATH, timeout=120)
        if result.returncode == 0:
            runtime = _parse_tooling_output(result.stdout)
        else:
            runtime_error = {
                "message": "Remote tooling probe failed",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
    except Exception as exc:
        runtime_error = {"message": str(exc)}

    tools = []
    runtime_presence = (runtime or {}).get("tool_presence", {})
    runtime_status = (runtime or {}).get("tool_status", {})
    runtime_versions = (runtime or {}).get("tool_versions", {})
    for tool in inventory.get("tools", []):
        enriched = dict(tool)
        probe_key = _runtime_probe_key(tool["id"])
        enriched["runtime_probe_key"] = probe_key
        enriched["runtime_presence"] = runtime_presence.get(probe_key) if probe_key else None
        enriched["runtime_status"] = runtime_status.get(probe_key) if probe_key else None
        enriched["runtime_version"] = runtime_versions.get(probe_key) if probe_key else None
        tools.append(enriched)

    return {
        "node": node,
        "inventory": {
            **inventory,
            "tools": tools,
        },
        "runtime": runtime,
        "runtime_error": runtime_error,
    }


def _inventory_nodes_from_health_cache() -> list[dict]:
    cached = _read_json(HEALTH_SUMMARY_CACHE_PATH) or {}
    nodes = cached.get("inventory_nodes")
    return nodes if isinstance(nodes, list) else []


def _openstack_runtime_status(nodes: list[dict], error: str | None = None, *, cache_fallback: bool = False) -> dict:
    if error:
        return {
            "state": "failed",
            "status_label": "OpenStack API unavailable",
            "inventory_loaded": False,
            "cache_fallback": bool(cache_fallback),
            "instance_count": len(nodes or []),
            "message": "OpenStack inventory could not be loaded. Node Health is using the latest cached topology when available.",
            "error": error,
            "recommendation": "Restarting Keystone, Nova, Neutron, Glance or Horizon may recover the control plane if the failure persists.",
        }
    return {
        "state": "completed",
        "status_label": "OpenStack inventory loaded",
        "inventory_loaded": True,
        "cache_fallback": False,
        "instance_count": len(nodes or []),
        "message": "OpenStack control-plane inventory is reachable and the current node list loaded correctly.",
        "error": None,
        "recommendation": None,
    }


def _host_health_row(summary: dict) -> dict:
    host = summary.get("host") or {}
    mem_total = host.get("mem_total_mb")
    mem_used = host.get("mem_used_mb")
    mem_pct = round((float(mem_used) / float(mem_total)) * 100.0, 2) if mem_total and mem_used is not None else None
    cpu_severity, load_ratio = _host_load_severity(host.get("loadavg"))
    memory_severity = _host_pct_severity(mem_pct)
    disk_pct = None
    try:
        disk_pct = float(str(host.get("root_use_pct") or "").replace("%", "").strip())
    except Exception:
        disk_pct = None
    disk_severity = _host_pct_severity(disk_pct)
    return {
        "hostname": host.get("hostname", "not_available"),
        "date_utc": host.get("date_utc", "not_available"),
        "loadavg": host.get("loadavg", "not_available"),
        "cpu_load_ratio": round(load_ratio, 3) if load_ratio is not None else None,
        "cpu_severity": cpu_severity,
        "mem_total_mb": mem_total,
        "mem_used_mb": mem_used,
        "mem_avail_mb": host.get("mem_avail_mb"),
        "memory_usage_pct": mem_pct,
        "memory_severity": memory_severity,
        "root_total_bytes": host.get("root_total_bytes"),
        "root_used_bytes": host.get("root_used_bytes"),
        "root_avail_bytes": host.get("root_avail_bytes"),
        "root_use_pct": host.get("root_use_pct"),
        "disk_severity": disk_severity,
        "overall_severity": _max_severity(cpu_severity, memory_severity, disk_severity),
    }


def _build_health_alerts(openstack_status: dict, host_row: dict, node_rows: list[dict], floating_ip_status: dict | None = None) -> list[dict]:
    alerts: list[dict] = []

    def push(alert_id: str, level: str, title: str, detail: str, scope: str, recommendation: str, target: str | None = None) -> None:
        alerts.append(
            {
                "alert_id": alert_id,
                "severity": level,
                "scope": scope,
                "target": target,
                "title": title,
                "detail": detail,
                "recommendation": recommendation,
                "generated_at": _utc_now(),
            }
        )

    if openstack_status.get("state") != "completed":
        push(
            "health-openstack-api",
            "critical",
            "OpenStack control-plane inventory is unavailable",
            openstack_status.get("error") or openstack_status.get("message") or "OpenStack API request failed.",
            "openstack",
            openstack_status.get("recommendation") or "Review Keystone and Nova service state, then retry inventory loading.",
        )

    if host_row.get("disk_severity") in {"warning", "critical"}:
        push(
            "health-host-disk",
            host_row["disk_severity"],
            "Host root filesystem pressure detected",
            f"Host {host_row.get('hostname')} is using {host_row.get('root_use_pct', 'not_available')} of root storage.",
            "host",
            "Free host storage before launching additional forensic preservation or OpenStack workloads.",
            target=host_row.get("hostname"),
        )
    if host_row.get("memory_severity") in {"warning", "critical"}:
        push(
            "health-host-memory",
            host_row["memory_severity"],
            "Host memory pressure detected",
            f"Host {host_row.get('hostname')} has {host_row.get('mem_avail_mb', 'not_available')} MB available RAM.",
            "host",
            "Release memory-intensive workloads before starting additional heavy DFIR acquisition or scenario work.",
            target=host_row.get("hostname"),
        )
    if host_row.get("cpu_severity") in {"warning", "critical"}:
        push(
            "health-host-cpu",
            host_row["cpu_severity"],
            "Host CPU load is elevated",
            f"Host {host_row.get('hostname')} reports loadavg {host_row.get('loadavg', 'not_available')}.",
            "host",
            "Reduce concurrent load or wait for the host to stabilize before starting new preservation or OpenStack operations.",
            target=host_row.get("hostname"),
        )

    for row in node_rows:
        name = row.get("name") or row.get("id")
        if row.get("error"):
            if row.get("source") == "not_available":
                continue
            push(
                f"health-node-unreachable-{row.get('id')}",
                "critical",
                "Node probe failed or no metrics are available",
                f"Node {name} could not provide current health telemetry. Detail: {row.get('error')}",
                "node",
                "Open Node Health, verify SSH reachability, free space and OpenStack instance state before continuing.",
                target=name,
            )
            continue
        if row.get("disk_severity") in {"warning", "critical"}:
            push(
                f"health-node-disk-{row.get('id')}",
                row["disk_severity"],
                "Node root filesystem pressure detected",
                f"Node {name} reports root usage {row.get('disk_root_use_pct', 'not_available')}%.",
                "node",
                "Free node storage before preserving new heavy artifacts or maintaining long-running security services.",
                target=name,
            )
        if row.get("memory_severity") in {"warning", "critical"}:
            push(
                f"health-node-memory-{row.get('id')}",
                row["memory_severity"],
                "Node memory pressure detected",
                f"Node {name} reports available memory {row.get('memory_available_mb', 'not_available')} MB.",
                "node",
                "Reduce workload pressure or clean long-lived analysis processes before continuing heavy acquisition.",
                target=name,
            )
        if row.get("cpu_severity") in {"warning", "critical"}:
            push(
                f"health-node-cpu-{row.get('id')}",
                row["cpu_severity"],
                "Node CPU usage is elevated",
                f"Node {name} reports CPU usage {row.get('cpu_usage_pct', 'not_available')}%.",
                "node",
                "Review the node process list from Node Health before launching additional tasks.",
                target=name,
            )

    # Campaign stages running longer than their own historical median — added
    # 2026-07-17 per the "no fixed timeout, alert instead while still
    # progressing" philosophy change. Purely informational (the stage is
    # NOT stopped for this alone — see level_c_orchestrator._phase_wait_level_b);
    # reuses the same live summary the "Live Campaign Status" panel already
    # computes, so this is one more consumer of existing data, not a new
    # tracking system.
    try:
        from app_core.infrastructure.level_c_orchestrator.service import get_live_campaign_summary
        live = get_live_campaign_summary()
        if live.get("active"):
            lc = live.get("level_c") or {}
            b = live.get("level_b") or {}
            for stg in (b.get("stage_timeline") or []):
                if stg.get("delayed"):
                    push(
                        f"campaign-stage-delayed-{stg.get('stage_key')}-{b.get('current_case_id') or ''}",
                        "warning",
                        f"Campaign stage running longer than usual: {stg.get('label')}",
                        f"Campaign {lc.get('campaign_id') or 'not_available'} · repetition "
                        f"{lc.get('current_repetition') or '?'}/{lc.get('total_repetitions') or '?'} · "
                        f"case {b.get('current_case_id') or 'not_available'} · target {stg.get('target') or 'not_available'} — "
                        f"{stg.get('elapsed_seconds')}s elapsed vs ~{stg.get('expected_seconds')}s usual.",
                        "campaign",
                        "Still progressing — no action needed unless it stops advancing. Check the Live Campaign Status panel for the full stage timeline.",
                        target=stg.get("target"),
                    )
    except Exception:
        pass

    # Floating IP quota pressure -- added 2026-07-20 after the lab silently exhausted its
    # floating IP quota with nothing detecting or reporting it (see FLOATING_IP_* above and
    # build_node_health_summary()'s auto-cleanup trigger).
    fip = floating_ip_status or {}
    if fip.get("below_threshold"):
        push(
            "health-openstack-floating-ips",
            fip.get("severity", "warning"),
            "OpenStack floating IP pool is running low",
            f"{fip.get('available')} of {fip.get('quota_limit')} floating IPs available "
            f"({fip.get('available_pct')}%), below the required {fip.get('threshold_pct')}% minimum "
            f"({fip.get('unattached_count', 0)} currently unattached, {fip.get('attached_count', 0)} in active use). "
            "Automatic cleanup of unattached floating IPs has been triggered (skipped if a Level C "
            "deployment is currently in progress, to avoid a race with in-flight allocations).",
            "openstack",
            "Check the Fleet Resource Monitor's Floating IPs panel in Node Health for cleanup progress and history. "
            "If usage stays high after cleanup, review scenarios/campaigns that may not be releasing floating IPs on destroy.",
        )
    elif fip.get("quota_error"):
        push(
            "health-openstack-floating-ips-quota-unknown",
            "warning",
            "Floating IP quota could not be read",
            f"Floating IP count is visible ({fip.get('allocated_total', 'not_available')} allocated) but the project quota "
            f"could not be read: {fip.get('quota_error')}. The 50% availability invariant cannot be checked without it.",
            "openstack",
            "Verify Neutron quota API access for this project so floating IP exhaustion can be detected automatically again.",
        )

    alerts.sort(key=lambda item: (_severity_rank(item.get("severity")), item.get("title", "")), reverse=True)
    return alerts


def _health_state_from_alerts(alerts: list[dict], openstack_status: dict) -> str:
    if openstack_status.get("state") != "completed":
        return "failed"
    if any(alert.get("severity") == "critical" for alert in alerts):
        return "failed"
    if alerts:
        return "partial"
    return "completed"


def build_node_health_summary(*, refresh_node_metrics: bool = False, max_probe_age_seconds: int = 180) -> dict:
    inventory_error = None
    cache_fallback = False
    try:
        nodes = _list_nodes()
    except Exception as exc:
        inventory_error = str(exc)
        nodes = _inventory_nodes_from_health_cache()
        cache_fallback = bool(nodes)

    summary = _local_host_summary(nodes)
    host_row = _host_health_row(summary)

    node_rows: list[dict] = []
    if nodes:
        if refresh_node_metrics:
            workers = max(1, min(4, len(nodes)))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="node-health-probe") as pool:
                future_map = {
                    pool.submit(_probe_cached_or_refresh, node, refresh=True, max_age_seconds=max_probe_age_seconds): node
                    for node in nodes
                }
                for future in as_completed(future_map):
                    node = future_map[future]
                    try:
                        node_rows.append(future.result())
                    except Exception as exc:
                        node_rows.append(_node_metrics_row(node, None, source="probe_failed", stale=True, error=str(exc)))
            node_rows.sort(key=lambda row: row.get("name") or "")
        else:
            node_rows = [
                _probe_cached_or_refresh(node, refresh=False, max_age_seconds=max_probe_age_seconds)
                for node in nodes
            ]

    openstack_status = _openstack_runtime_status(nodes, inventory_error, cache_fallback=cache_fallback)

    # Floating IP quota check + auto-cleanup trigger. Runs on every health-summary
    # computation (i.e. every time anyone loads/polls Node Health, or the alert bell
    # refreshes) -- same "no separate cron, triggered by normal traffic" pattern already
    # used everywhere else in this codebase. Only actually starts a cleanup when the 50%
    # floor is breached AND nothing is auto-triggered twice concurrently (see
    # trigger_floating_ip_cleanup's own running-guard) AND no Level C deployment is
    # currently in flight (see _floating_ip_deployment_in_progress).
    try:
        floating_ip_status = _floating_ip_status()
        if floating_ip_status.get("below_threshold") and not _floating_ip_deployment_in_progress():
            trigger_floating_ip_cleanup(triggered_by="auto_threshold_check")
    except Exception as exc:
        floating_ip_status = {"error": str(exc), "severity": "unknown", "below_threshold": False}

    alerts = _build_health_alerts(openstack_status, host_row, node_rows, floating_ip_status)
    payload = {
        "generated_at": _utc_now(),
        "overall_state": _health_state_from_alerts(alerts, openstack_status),
        "openstack": openstack_status,
        "host": host_row,
        "nodes": node_rows,
        "floating_ips": floating_ip_status,
        "alerts": alerts,
        "alert_count": len(alerts),
        "inventory_nodes": nodes,
        "artifacts": {
            "health_summary_cache": _relative_repo_path(HEALTH_SUMMARY_CACHE_PATH),
            "probe_cache_dir": _relative_repo_path(PROBE_CACHE_DIR),
            "openstack_health_dir": _relative_repo_path(OPENSTACK_HEALTH_DIR),
            "openstack_restart_script": _relative_repo_path(OPENSTACK_RESTART_SCRIPT_PATH),
            "openstack_restart_jobs_dir": _relative_repo_path(OPENSTACK_RESTART_JOBS_DIR),
            "floating_ip_cleanup_history": _relative_repo_path(FLOATING_IP_HISTORY_PATH),
        },
    }
    _write_json(HEALTH_SUMMARY_CACHE_PATH, payload)
    return payload


def _openstack_restart_job_dir(job_id: str) -> Path:
    return OPENSTACK_RESTART_JOBS_DIR / _safe_slug(job_id)


def _write_openstack_restart_status(job_dir: Path, payload: dict) -> None:
    _write_json(job_dir / "status.json", payload)


def _node_time_sync_summary(instance_id: str, node: dict | None = None) -> dict:
    paths = _node_time_sync_paths(instance_id)
    result = _read_json(paths["json"]) or {}
    selected_measurement = None
    for entry in (result.get("nodes") or []):
        if node and entry.get("vm_id") == node.get("id"):
            selected_measurement = entry
            break
    if selected_measurement is None:
        for entry in (result.get("nodes") or []):
            if entry.get("vm_id") == instance_id:
                selected_measurement = entry
                break
    return {
        "temporal_sync_status": result.get("temporal_sync_status", "not_measured"),
        "max_clock_offset_ms": result.get("max_clock_offset_ms"),
        "max_clock_offset_seconds": result.get("max_clock_offset_seconds"),
        "synchronized": result.get("synchronized"),
        "correction_applied": result.get("correction_applied", False),
        "nodes_ok": result.get("nodes_ok", 0),
        "nodes_failed": result.get("nodes_failed", 0),
        "worst_node": result.get("worst_node"),
        "selected_node_measurement": selected_measurement,
    }


def _case_actively_acquiring(case_dir: Path) -> bool:
    """Precise, event-based check (reused from forensics_api._case_preservation_in_progress):
    is this case genuinely in the middle of an evidence-acquisition step (memory/
    disk/network/industrial started but not finished, or DFIR preservation
    claimed but not yet released/done) -- as opposed to merely "a case
    directory currently exists".

    Added 2026-09-14: the previous rule blocked corrective time-sync for the
    mere EXISTENCE of any active-case pointer, which produced unexplained
    SYNCING_CLOCKS blocks even when investigation showed the referenced case
    was not necessarily mid-acquisition. Lazy-imported because forensics_api
    already imports FROM this module at top level (a top-level import here
    would be circular). Fails CLOSED: any import/lookup error is treated as
    "still acquiring" (the old, more conservative behavior) -- a broken check
    must never silently make it easier to alter a VM's clock.
    """
    try:
        from ..forensics.forensics_api import _case_preservation_in_progress
        return _case_preservation_in_progress(str(case_dir))
    except Exception:
        return True


def _time_sync_policy(node: dict | None, *, fix_time: bool = False, maintenance_override: bool = False) -> dict:
    active_case = _read_active_case_dir()
    active_case_id = active_case.name if active_case else None
    active_case_acquiring = bool(active_case) and _case_actively_acquiring(active_case)
    if not fix_time:
        return {
            "measure_allowed": True,
            "fix_allowed": True,
            "requires_override": False,
            "active_case_present": bool(active_case),
            "active_case_id": active_case_id,
            "policy_state": "measure_safe",
            "reason": "Clock offset measurement is non-destructive and allowed by default.",
        }
    if active_case_acquiring and not maintenance_override:
        return {
            "measure_allowed": True,
            "fix_allowed": False,
            "requires_override": True,
            "active_case_present": True,
            "active_case_id": active_case_id,
            "policy_state": "blocked_active_case",
            "reason": "Corrective time synchronization is blocked by default while a forensic case is actively acquiring evidence because it can alter timestamps, logs, temporal ordering and volatile evidence.",
        }
    if active_case_acquiring and maintenance_override:
        return {
            "measure_allowed": True,
            "fix_allowed": True,
            "requires_override": True,
            "active_case_present": True,
            "active_case_id": active_case_id,
            "policy_state": "override_active_case",
            "reason": "Corrective time synchronization is proceeding under explicit laboratory or maintenance override while a forensic case is actively acquiring evidence and must be treated as an infrastructure intervention.",
        }
    return {
        "measure_allowed": True,
        "fix_allowed": True,
        "requires_override": False,
        "active_case_present": bool(active_case),
        "active_case_id": active_case_id,
        "policy_state": "fix_allowed_no_active_case" if not active_case else "fix_allowed_case_not_acquiring",
        "reason": (
            "No active forensic case is registered, so corrective time synchronization is allowed."
            if not active_case else
            "A forensic case is registered but is not currently in an active acquisition window (no evidence "
            "acquisition step is in progress), so corrective time synchronization is allowed."
        ),
    }


def _record_time_sync_intervention(instance_id: str, node: dict, *, fix_time: bool, maintenance_override: bool, policy: dict) -> None:
    if not fix_time:
        return
    paths = _node_time_sync_paths(instance_id)
    record = {
        "generated_at_utc": _utc_now(),
        "type": "time_sync_intervention",
        "node_id": node.get("id"),
        "node_name": node.get("name"),
        "node_role": node.get("role"),
        "ssh_target_ip": node.get("ssh_target_ip"),
        "fix_time": True,
        "maintenance_override": bool(maintenance_override),
        "policy_state": policy.get("policy_state"),
        "policy_reason": policy.get("reason"),
        "active_case_id": policy.get("active_case_id"),
    }
    _append_jsonl(paths["interventions"], record)
    active_case = _read_active_case_dir()
    if active_case:
        _append_jsonl(active_case / "metadata" / "time_sync_interventions.jsonl", {**record, "source": "node_health"})


def load_node_time_sync_status(instance_id: str) -> dict:
    node = _find_node(instance_id)
    paths = _node_time_sync_paths(instance_id)
    status_payload = _read_json(paths["status"]) if paths["status"].is_file() else None
    result_payload = _read_json(paths["json"]) if paths["json"].is_file() else None
    summary = _node_time_sync_summary(instance_id, node)
    policy = _time_sync_policy(node, fix_time=False, maintenance_override=False)
    if not status_payload:
        status_payload = {
            "instance_id": instance_id,
            "node": node,
            "job_id": None,
            "status": "not_available",
            "started_at": None,
            "updated_at": _utc_now(),
            "finished_at": None,
            "current_step": None,
            "progress_percent": 0.0,
            "fix_time": False,
            "error": None,
        }
    status_payload["instance_id"] = instance_id
    status_payload["node"] = node
    status_payload["summary"] = summary
    status_payload["result"] = result_payload
    status_payload["policy"] = policy
    status_payload["artifacts"] = {
        "json": _relative_repo_path(paths["json"]),
        "before": _relative_repo_path(paths["before"]),
        "after": _relative_repo_path(paths["after"]),
        "status": _relative_repo_path(paths["status"]),
        "stdout": _relative_repo_path(paths["stdout"]),
        "stderr": _relative_repo_path(paths["stderr"]),
        "interventions": _relative_repo_path(paths["interventions"]),
    }
    return status_payload


def _write_node_time_sync_status(instance_id: str, payload: dict) -> None:
    _write_json(_node_time_sync_paths(instance_id)["status"], payload)


def _node_time_sync_worker(instance_id: str, fix_time: bool, threshold_ms: int | None, maintenance_override: bool) -> None:
    node = _find_node(instance_id)
    policy = _time_sync_policy(node, fix_time=fix_time, maintenance_override=maintenance_override)
    paths = _node_time_sync_paths(instance_id)
    status = {
        "instance_id": instance_id,
        "node": node,
        "job_id": f"node-time-sync-{uuid.uuid4().hex[:12]}",
        "status": "running",
        "started_at": _utc_now(),
        "updated_at": _utc_now(),
        "finished_at": None,
        "current_step": "executing_time_sync_script",
        "progress_percent": 15.0,
        "fix_time": bool(fix_time),
        "maintenance_override": bool(maintenance_override),
        "policy": policy,
        "error": None,
    }
    _write_node_time_sync_status(instance_id, status)

    env = os.environ.copy()
    env["SSH_KEY"] = SSH_KEY_PATH
    env["FILTER_INSTANCE_ID"] = instance_id
    env["TIME_SYNC_OUT"] = str(paths["json"])
    env["TIME_SYNC_BEFORE_OUT"] = str(paths["before"])
    env["TIME_SYNC_AFTER_OUT"] = str(paths["after"])
    if fix_time:
        env["DO_FIX_TIME"] = "1"
    else:
        env["DO_FIX_TIME"] = "0"
    if threshold_ms is not None:
        env["TIME_SYNC_THRESHOLD_MS"] = str(threshold_ms)

    cmd = ["bash", str(TIME_SYNC_SCRIPT_PATH), "--instance-id", instance_id, "--out", str(paths["json"])]
    if fix_time:
        cmd.append("--fix-time")
    if threshold_ms is not None:
        cmd.extend(["--threshold-ms", str(threshold_ms)])

    try:
        _record_time_sync_intervention(instance_id, node or {}, fix_time=fix_time, maintenance_override=maintenance_override, policy=policy)
        paths["dir"].mkdir(parents=True, exist_ok=True)
        with paths["stdout"].open("w", encoding="utf-8") as stdout_fh, paths["stderr"].open("w", encoding="utf-8") as stderr_fh:
            proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), env=env, stdout=stdout_fh, stderr=stderr_fh, text=True)
            while proc.poll() is None:
                status["updated_at"] = _utc_now()
                status["progress_percent"] = 65.0 if not fix_time else 75.0
                _write_node_time_sync_status(instance_id, status)
                time.sleep(1.5)
            rc = proc.wait()
        if rc != 0:
            status["status"] = "failed"
            status["current_step"] = "time_sync_failed"
            status["progress_percent"] = 100.0
            status["finished_at"] = _utc_now()
            status["updated_at"] = status["finished_at"]
            stderr_text = paths["stderr"].read_text(encoding="utf-8", errors="ignore") if paths["stderr"].is_file() else ""
            stdout_text = paths["stdout"].read_text(encoding="utf-8", errors="ignore") if paths["stdout"].is_file() else ""
            status["error"] = stderr_text.strip() or stdout_text.strip() or f"time sync script failed with exit code {rc}"
            _write_node_time_sync_status(instance_id, status)
            return

        result = _read_json(paths["json"]) or {}
        summary = _node_time_sync_summary(instance_id, node)
        status["status"] = "completed"
        status["current_step"] = "time_sync_completed"
        status["progress_percent"] = 100.0
        status["finished_at"] = _utc_now()
        status["updated_at"] = status["finished_at"]
        status["error"] = None
        status["result_hint"] = {
            "temporal_sync_status": result.get("temporal_sync_status"),
            "max_clock_offset_ms": result.get("max_clock_offset_ms"),
            "correction_applied": result.get("correction_applied", False),
            "selected_node_abs_offset_ms": (summary.get("selected_node_measurement") or {}).get("abs_offset_ms"),
        }
        _write_node_time_sync_status(instance_id, status)
    except Exception as exc:
        status["status"] = "failed"
        status["current_step"] = "internal_error"
        status["progress_percent"] = 100.0
        status["finished_at"] = _utc_now()
        status["updated_at"] = status["finished_at"]
        status["error"] = str(exc)
        _write_node_time_sync_status(instance_id, status)
    finally:
        with _TIME_SYNC_STATE_LOCK:
            _RUNNING_TIME_SYNC.pop(instance_id, None)


def run_node_time_sync(instance_id: str, fix_time: bool = False, threshold_ms: int | None = None, maintenance_override: bool = False) -> dict:
    node = _find_node(instance_id)
    if not node:
        raise FileNotFoundError(f"Instance not found: {instance_id}")
    policy = _time_sync_policy(node, fix_time=fix_time, maintenance_override=maintenance_override)
    if fix_time and not policy.get("fix_allowed"):
        blocked_payload = load_node_time_sync_status(instance_id)
        blocked_payload["status"] = "blocked_policy"
        blocked_payload["error"] = policy.get("reason")
        blocked_payload["policy"] = policy
        return blocked_payload
    with _TIME_SYNC_STATE_LOCK:
        existing = _RUNNING_TIME_SYNC.get(instance_id)
        if existing and existing.is_alive():
            payload = load_node_time_sync_status(instance_id)
            payload["status"] = "running"
            payload["current_step"] = payload.get("current_step") or "executing_time_sync_script"
            return payload
        worker = threading.Thread(
            target=_node_time_sync_worker,
            args=(instance_id, fix_time, threshold_ms, maintenance_override),
            daemon=True,
            name=f"node-time-sync-{instance_id}",
        )
        _RUNNING_TIME_SYNC[instance_id] = worker
        worker.start()
    return load_node_time_sync_status(instance_id)


@node_health_bp.route("/node-health")
def node_health_view():
    return send_from_directory(STATIC_DIR, "node_health.html")


@node_health_bp.route("/api/node-health/nodes/power-on-stopped", methods=["POST"])
def node_health_power_on_stopped():
    try:
        result = power_on_stopped_nodes()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(result)


@node_health_bp.route("/api/node-health/host/free-memory", methods=["POST"])
def node_health_free_host_memory():
    try:
        result = free_host_memory()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(result)


@node_health_bp.route("/api/node-health/host/memory-pressure", methods=["GET"])
def node_health_memory_pressure():
    try:
        from app_core.infrastructure.memory_watchdog.service import (
            get_memory_pressure_snapshot,
            get_recent_watchdog_events,
        )
        snapshot = get_memory_pressure_snapshot()
        snapshot["recent_watchdog_events"] = get_recent_watchdog_events(limit=20)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(snapshot)


@node_health_bp.route("/api/node-health/nodes", methods=["GET"])
def node_health_nodes():
    inventory_error = None
    try:
        nodes = _list_nodes()
    except Exception as exc:
        inventory_error = str(exc)
        nodes = _inventory_nodes_from_health_cache()
    graph = _network_graph(nodes)
    summary = _local_host_summary(nodes)
    return jsonify(
        {
            "generated_at": _utc_now(),
            "nodes": nodes,
            "graph": graph,
            "summary": summary,
            "count": len(nodes),
            "inventory_state": "stale_fallback" if inventory_error else "completed",
            "inventory_error": inventory_error,
        }
    )


@node_health_bp.route("/api/node-health/nodes/<instance_id>/probe", methods=["GET"])
def node_health_probe(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return jsonify({"error": f"Instance not found: {instance_id}"}), 404
    try:
        payload = _probe_node_live(node, timeout=120)
    except Exception as exc:
        return jsonify(
            {
                "error": "Remote probe failed",
                "node": node,
                "detail": str(exc),
            }
        ), 500
    return jsonify(
        {
            "node": node,
            "probe": payload["probe"],
            "stdout": payload["stdout"],
            "generated_at": payload["generated_at"],
        }
    )


@node_health_bp.route("/api/node-health/health-summary", methods=["GET"])
def node_health_summary():
    refresh = str(request.args.get("refresh", "0")).lower() in {"1", "true", "yes", "on"}
    if not refresh:
        cached = _read_json(HEALTH_SUMMARY_CACHE_PATH)
        if isinstance(cached, dict) and cached:
            return jsonify(cached)
    try:
        payload = build_node_health_summary(refresh_node_metrics=refresh)
    except Exception as exc:
        cached = _read_json(HEALTH_SUMMARY_CACHE_PATH) or {}
        if cached:
            cached["overall_state"] = "partial"
            cached["generated_at"] = _utc_now()
            cached["summary_error"] = str(exc)
            return jsonify(cached), 200
        return jsonify({"error": str(exc), "overall_state": "failed"}), 500
    return jsonify(payload)


@node_health_bp.route("/api/node-health/openstack/status", methods=["GET"])
def node_health_openstack_status():
    refresh = str(request.args.get("refresh", "0")).lower() in {"1", "true", "yes", "on"}
    if not refresh:
        cached = _read_json(HEALTH_SUMMARY_CACHE_PATH)
        if isinstance(cached, dict) and cached:
            payload = cached
        else:
            payload = build_node_health_summary(refresh_node_metrics=False)
    else:
        payload = build_node_health_summary(refresh_node_metrics=True)
    return jsonify(
        {
            "generated_at": payload.get("generated_at"),
            "overall_state": payload.get("overall_state"),
            "openstack": payload.get("openstack"),
            "alerts": payload.get("alerts", []),
            "alert_count": payload.get("alert_count", 0),
            "artifacts": payload.get("artifacts", {}),
        }
    )


@node_health_bp.route("/api/node-health/openstack/floating-ips", methods=["GET"])
def node_health_floating_ips_status():
    try:
        return jsonify(_floating_ip_status()), 200
    except Exception as exc:
        return jsonify({"error": str(exc), "severity": "unknown"}), 502


@node_health_bp.route("/api/node-health/openstack/floating-ips/cleanup", methods=["POST"])
def node_health_floating_ips_cleanup():
    payload = trigger_floating_ip_cleanup(triggered_by="manual")
    return jsonify(payload), 202


@node_health_bp.route("/api/node-health/openstack/floating-ips/cleanup/status", methods=["GET"])
def node_health_floating_ips_cleanup_status():
    return jsonify(floating_ip_cleanup_status()), 200


@node_health_bp.route("/api/node-health/alerts", methods=["GET"])
def node_health_alerts():
    refresh = str(request.args.get("refresh", "0")).lower() in {"1", "true", "yes", "on"}
    limit_raw = request.args.get("limit")
    try:
        limit = int(limit_raw) if limit_raw is not None else None
    except Exception:
        limit = None
    if not refresh:
        cached = _read_json(HEALTH_SUMMARY_CACHE_PATH)
        if isinstance(cached, dict) and cached:
            payload = cached
        else:
            payload = build_node_health_summary(refresh_node_metrics=False)
    else:
        payload = build_node_health_summary(refresh_node_metrics=True)
    alerts = list(payload.get("alerts") or [])
    if limit and limit > 0:
        alerts = alerts[:limit]
    return jsonify(
        {
            "generated_at": payload.get("generated_at"),
            "overall_state": payload.get("overall_state"),
            "source_backend": "node_health",
            "alerts": alerts,
            "alert_count": len(payload.get("alerts") or []),
            "preview_count": len(alerts),
            "related_view_default": "node_health",
        }
    )


@node_health_bp.route("/api/node-health/alerts/<alert_id>", methods=["GET"])
def node_health_alert_detail(alert_id: str):
    payload = _read_json(HEALTH_SUMMARY_CACHE_PATH)
    if not isinstance(payload, dict) or not payload:
        payload = build_node_health_summary(refresh_node_metrics=False)
    for alert in (payload.get("alerts") or []):
        if alert.get("alert_id") == alert_id:
            return jsonify(
                {
                    "generated_at": payload.get("generated_at"),
                    "source_backend": "node_health",
                    "alert": {
                        **alert,
                        "related_view": "node_health",
                        "related_action_label": "Open Node Health",
                    },
                    "openstack": payload.get("openstack"),
                    "host": payload.get("host"),
                }
            )
    return jsonify({"error": f"Health alert not found: {alert_id}"}), 404


@node_health_bp.route("/api/node-health/openstack/restart/stream", methods=["GET"])
def node_health_openstack_restart_stream():
    job_id = f"openstack-restart-{uuid.uuid4().hex[:12]}"
    job_dir = _openstack_restart_job_dir(job_id)
    stdout_path = job_dir / "stdout.log"
    stderr_path = job_dir / "stderr.log"
    metadata_path = job_dir / "metadata.json"

    def generate():
        job_dir.mkdir(parents=True, exist_ok=True)
        metadata = {
            "job_id": job_id,
            "generated_at": _utc_now(),
            "script_path": _relative_repo_path(OPENSTACK_RESTART_SCRIPT_PATH),
            "job_dir": _relative_repo_path(job_dir),
            "purpose": "Restart OpenStack services from the Node Health dashboard when control-plane health is degraded.",
        }
        _write_json(metadata_path, metadata)
        status = {
            "job_id": job_id,
            "status": "running",
            "started_at": _utc_now(),
            "completed_at": None,
            "script_path": _relative_repo_path(OPENSTACK_RESTART_SCRIPT_PATH),
            "job_dir": _relative_repo_path(job_dir),
            "stdout_path": _relative_repo_path(stdout_path),
            "stderr_path": _relative_repo_path(stderr_path),
            "message": "Restarting OpenStack services from Node Health.",
        }
        _write_openstack_restart_status(job_dir, status)

        if not OPENSTACK_RESTART_SCRIPT_PATH.exists():
            status["status"] = "failed"
            status["completed_at"] = _utc_now()
            status["message"] = "OpenStack restart script not found."
            _write_openstack_restart_status(job_dir, status)
            yield "data: [ERROR] OpenStack restart script not found.\n\n"
            yield "event: done\ndata: restart_failed\n\n"
            return

        yield f"data: [SYSTEM] job_id={job_id}\n\n"
        yield f"data: [SYSTEM] script={_relative_repo_path(OPENSTACK_RESTART_SCRIPT_PATH)}\n\n"
        try:
            with stdout_path.open("w", encoding="utf-8") as stdout_fh, stderr_path.open("w", encoding="utf-8") as stderr_fh:
                proc = subprocess.Popen(
                    ["bash", str(OPENSTACK_RESTART_SCRIPT_PATH)],
                    cwd=str(REPO_ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                assert proc.stdout is not None
                for line in iter(proc.stdout.readline, ""):
                    if not line:
                        continue
                    stdout_fh.write(line)
                    stdout_fh.flush()
                    yield f"data: {line.rstrip()}\n\n"
                rc = proc.wait()
            status["completed_at"] = _utc_now()
            status["returncode"] = rc
            status["status"] = "completed" if rc == 0 else "failed"
            status["message"] = (
                "OpenStack services restart completed."
                if rc == 0
                else "OpenStack services restart failed. Review stdout/stderr logs from the Node Health runtime job."
            )
            _write_openstack_restart_status(job_dir, status)
            yield f"data: [EXIT CODE] {rc}\n\n"
            yield "event: done\ndata: restart_finished\n\n"
        except Exception as exc:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text(str(exc), encoding="utf-8")
            status["status"] = "failed"
            status["completed_at"] = _utc_now()
            status["message"] = str(exc)
            _write_openstack_restart_status(job_dir, status)
            yield f"data: [ERROR] {str(exc)}\n\n"
            yield "event: done\ndata: restart_failed\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@node_health_bp.route("/api/node-health/nodes/<instance_id>/tooling", methods=["GET"])
def node_health_tooling(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return jsonify({"error": f"Instance not found: {instance_id}"}), 404
    return jsonify(_build_tooling_payload(node))


@node_health_bp.route("/api/node-health/nodes/<instance_id>/time-sync/status", methods=["GET"])
def node_health_time_sync_status(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return jsonify({"error": f"Instance not found: {instance_id}"}), 404
    return jsonify(load_node_time_sync_status(instance_id))


@node_health_bp.route("/api/node-health/nodes/<instance_id>/time-sync/run", methods=["POST"])
def node_health_time_sync_run(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return jsonify({"error": f"Instance not found: {instance_id}"}), 404
    payload = request.get_json(silent=True) or {}
    threshold_ms = payload.get("threshold_ms")
    try:
        threshold_value = int(threshold_ms) if threshold_ms is not None else None
    except Exception:
        threshold_value = None
    try:
        result = run_node_time_sync(
            instance_id,
            fix_time=bool(payload.get("fix_time", False)),
            threshold_ms=threshold_value,
            maintenance_override=bool(payload.get("maintenance_override", False)),
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    if result.get("status") == "blocked_policy":
        return jsonify(result), 409
    return jsonify(result)


@node_health_bp.route("/api/node-health/nodes/<instance_id>/cleanup/stream", methods=["GET"])
def node_health_cleanup_stream(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return Response("data: [ERROR] Instance not found\n\n", mimetype="text/event-stream")

    ssh_ip = node.get("ssh_target_ip") or node.get("ip_floating") or node.get("ip_private")
    ssh_user = node.get("ssh_user") or "debian"
    remote_dump = ""

    def generate():
        yield f"data: [SYSTEM] node={node['name']} role={node['role']} os={node['os']}\n\n"
        yield f"data: [SYSTEM] ssh_user={ssh_user} ssh_target_ip={ssh_ip}\n\n"
        if not CLEANUP_SCRIPT_PATH.exists():
            yield "data: [ERROR] cleanup script not found\n\n"
            return
        remote_cmd = f"REMOTE_DUMP={shlex.quote(remote_dump)} bash -s"
        cmd = [
            "ssh",
            "-i",
            SSH_KEY_PATH,
            "-o",
            "StrictHostKeyChecking=no",
            f"{ssh_user}@{ssh_ip}",
            remote_cmd,
        ]
        script_text = CLEANUP_SCRIPT_PATH.read_text(encoding="utf-8")
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if proc.stdin:
                proc.stdin.write(script_text)
                proc.stdin.close()
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, ""):
                if line:
                    yield f"data: {line.rstrip()}\n\n"
            rc = proc.wait()
            yield f"data: [EXIT CODE] {rc}\n\n"
            yield "event: done\ndata: cleanup_finished\n\n"
        except Exception as exc:
            yield f"data: [ERROR] {str(exc)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
