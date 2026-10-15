from __future__ import annotations

import gc
import json
import logging
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
FREE_HOST_MEMORY_SCRIPT_PATH = REPO_ROOT / "app_core" / "infrastructure" / "node_health" / "scripts" / "free_host_memory.sh"
RUNTIME_DIR = REPO_ROOT / "runtime" / "memory_watchdog"
EVENTS_PATH = RUNTIME_DIR / "events.jsonl"

# Threshold-based watchdog, same philosophy as systemd-oomd/nohang/earlyoom
# (userspace tools that watch swap/PSI and react BEFORE the kernel OOM
# killer has to). Unlike those tools, this NEVER kills a process or cancels
# a job -- it only does safe, reversible reclaim (gc.collect + drop_caches)
# and logs what it did. Motivated directly by two real campaign failures
# this session where system swap filled to ~100% during Level B analysis/
# reconstruction and a gunicorn worker died with zero warning beforehand.
SWAP_PRESSURE_THRESHOLD_PCT = 80.0
CHECK_INTERVAL_SECONDS = 20
ACTION_COOLDOWN_SECONDS = 120

_watchdog_lock = threading.Lock()
_watchdog_started = False
_last_action_at = 0.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def read_meminfo() -> dict:
    """Parses /proc/meminfo directly (no psutil dependency, matches the rest
    of this codebase's convention). Never raises -- returns all-None fields
    if the file is unreadable (e.g. non-Linux)."""
    values: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                raw = parts[1].strip().split()
                if raw and raw[0].isdigit():
                    values[key] = int(raw[0])  # kB
    except Exception:
        return {
            "mem_total_kb": None, "mem_available_kb": None,
            "swap_total_kb": None, "swap_free_kb": None,
            "swap_used_pct": None, "mem_available_pct": None,
        }

    mem_total = values.get("MemTotal")
    mem_available = values.get("MemAvailable")
    swap_total = values.get("SwapTotal")
    swap_free = values.get("SwapFree")

    swap_used_pct = None
    if swap_total and swap_total > 0 and swap_free is not None:
        swap_used_pct = round((swap_total - swap_free) / swap_total * 100.0, 1)

    mem_available_pct = None
    if mem_total and mem_total > 0 and mem_available is not None:
        mem_available_pct = round(mem_available / mem_total * 100.0, 1)

    return {
        "mem_total_kb": mem_total,
        "mem_available_kb": mem_available,
        "swap_total_kb": swap_total,
        "swap_free_kb": swap_free,
        "swap_used_pct": swap_used_pct,
        "mem_available_pct": mem_available_pct,
    }


def read_psi_memory() -> dict | None:
    """Parses /proc/pressure/memory (Pressure Stall Information) -- the
    modern signal systemd-oomd/nohang use in preference to raw swap%. Only
    available on Linux kernel >=4.20 with the feature enabled; returns None
    (not an error) when the file doesn't exist, so callers fall back to
    swap% alone, which is what this watchdog's trigger condition does."""
    try:
        with open("/proc/pressure/memory", "r", encoding="utf-8") as fh:
            text = fh.read()
    except Exception:
        return None

    result: dict[str, float] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        kind = parts[0]  # "some" or "full"
        for token in parts[1:]:
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            try:
                result[f"{kind}_{k}"] = float(v)
            except ValueError:
                pass
    return result or None


def get_memory_pressure_snapshot() -> dict:
    """Single real-time snapshot combining swap% (always available on
    Linux) and PSI (when the kernel exposes it) -- used both by the
    watchdog loop and by the Node Health API, so the dashboard always shows
    exactly what the watchdog itself is looking at, never a separately
    computed number."""
    meminfo = read_meminfo()
    psi = read_psi_memory()
    return {
        "generated_at": _utc_now(),
        "swap_used_pct": meminfo["swap_used_pct"],
        "mem_available_pct": meminfo["mem_available_pct"],
        "swap_total_mb": round(meminfo["swap_total_kb"] / 1024.0, 1) if meminfo["swap_total_kb"] else None,
        "swap_used_mb": (
            round((meminfo["swap_total_kb"] - meminfo["swap_free_kb"]) / 1024.0, 1)
            if meminfo["swap_total_kb"] and meminfo["swap_free_kb"] is not None else None
        ),
        "mem_total_mb": round(meminfo["mem_total_kb"] / 1024.0, 1) if meminfo["mem_total_kb"] else None,
        "mem_available_mb": round(meminfo["mem_available_kb"] / 1024.0, 1) if meminfo["mem_available_kb"] else None,
        "psi_supported": psi is not None,
        "psi_some_avg10": (psi or {}).get("some_avg10"),
        "psi_full_avg10": (psi or {}).get("full_avg10"),
        "threshold_swap_pct": SWAP_PRESSURE_THRESHOLD_PCT,
    }


def _append_event(event: dict) -> None:
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        with open(EVENTS_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except Exception:
        pass


def get_recent_watchdog_events(limit: int = 20) -> list[dict]:
    """Read-only tail of the JSONL event log -- never raises, returns []
    if the watchdog has never fired or the file doesn't exist yet."""
    try:
        if not EVENTS_PATH.exists():
            return []
        with open(EVENTS_PATH, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        out.reverse()
        return out
    except Exception:
        return []


def _take_safe_relief_action() -> dict:
    """Everything here is deliberately reversible and non-destructive: this
    NEVER kills a process, cancels a job, or touches gunicorn itself. It
    only does what's considered always-safe reclaim -- the same two actions
    already exposed as the manual "Free Host Memory" button in Node Health:
    gc.collect() in THIS worker's own memory, and (best-effort, silently
    skipped if the sudoers rule isn't installed yet) sync + drop_caches at
    the OS level via free_host_memory.sh."""
    collected = gc.collect()

    drop_caches_ok = False
    drop_caches_error = None
    if FREE_HOST_MEMORY_SCRIPT_PATH.exists():
        try:
            proc = subprocess.run(
                ["bash", str(FREE_HOST_MEMORY_SCRIPT_PATH)],
                capture_output=True, text=True, timeout=15,
            )
            drop_caches_ok = proc.returncode == 0
            if not drop_caches_ok:
                drop_caches_error = f"exit_code={proc.returncode}"
        except Exception as exc:
            drop_caches_error = str(exc)
    else:
        drop_caches_error = "script_not_found"

    return {
        "gc_collected_objects": collected,
        "drop_caches_ok": drop_caches_ok,
        "drop_caches_error": drop_caches_error,
    }


def _watchdog_loop() -> None:
    global _last_action_at
    logger = logging.getLogger("app_logger")
    was_above_threshold = False
    while True:
        try:
            snapshot = get_memory_pressure_snapshot()
            swap_pct = snapshot.get("swap_used_pct")
            if swap_pct is not None and swap_pct >= SWAP_PRESSURE_THRESHOLD_PCT:
                now = time.time()
                # Edge-triggered + cooldown: react once on crossing the
                # threshold, then wait ACTION_COOLDOWN_SECONDS before
                # reacting again even if still above it -- avoids
                # hammering gc.collect()/drop_caches every 20s while
                # pressure stays high, which wastes CPU for no benefit
                # once the easily-reclaimable memory is already reclaimed.
                if not was_above_threshold or (now - _last_action_at) >= ACTION_COOLDOWN_SECONDS:
                    action = _take_safe_relief_action()
                    _last_action_at = now
                    after = get_memory_pressure_snapshot()
                    event = {
                        "ts_utc": snapshot["generated_at"],
                        "trigger": "swap_pressure",
                        "swap_used_pct_before": swap_pct,
                        "swap_used_pct_after": after.get("swap_used_pct"),
                        "psi_some_avg10": snapshot.get("psi_some_avg10"),
                        **action,
                    }
                    _append_event(event)
                    logger.warning(
                        f"[MEMORY_WATCHDOG] swap_pct={swap_pct} >= {SWAP_PRESSURE_THRESHOLD_PCT} -- "
                        f"gc_collected={action['gc_collected_objects']} drop_caches_ok={action['drop_caches_ok']}"
                    )
                was_above_threshold = True
            else:
                was_above_threshold = False
        except Exception:
            pass
        time.sleep(CHECK_INTERVAL_SECONDS)


def start_memory_watchdog() -> bool:
    """Idempotent: safe to call more than once per process (e.g. if two
    blueprints both try to start it during app boot) -- only the first
    call in a given worker actually starts the thread. Returns True if a
    thread was started by THIS call, False if one was already running in
    this same process. Each of gunicorn's worker processes runs its own
    independent instance (same limitation as _heartbeat_during/_THREADS
    elsewhere in this codebase -- there is no single, shared watchdog
    across workers, each worker watches and reacts on its own)."""
    global _watchdog_started
    with _watchdog_lock:
        if _watchdog_started:
            return False
        _watchdog_started = True
    t = threading.Thread(target=_watchdog_loop, daemon=True, name="memory-watchdog")
    t.start()
    return True
