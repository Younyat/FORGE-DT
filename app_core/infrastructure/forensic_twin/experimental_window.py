from __future__ import annotations

"""M3 (Experimental observation mode, investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md)
-- a generic, high(er)-frequency observation window over a bounded duration,
for a given set of nodes/sensors. Deliberately takes NO fault_id/attack_id
parameter anywhere in this module -- that is the whole point. The study's
own "No label leakage" rule (section 8.2: forensic_twin must never consult
"what fault is active" to decide what to measure or emit) already holds
for every individual divergence rule in service.py, each of which reads
real system state directly. The one place a label COULD leak was in the
*scheduling*: FAULT_RELEVANT_CHECKS (service.py) decides *when* to
re-check a sensor based on which fault_id was just applied. This module is
a deliberately SEPARATE, additive capability for real experiments (used by
the CIE protocol / M9's future campaign runner), not a replacement for
FAULT_RELEVANT_CHECKS -- that mechanism keeps serving the 3D twin views'
real-time responsiveness exactly as before ("no romper nada"). A caller
starts a window naming nodes+sensors+duration; nothing inside the window
loop ever receives or uses a fault/attack identifier.

Every sensor this module calls is an already-existing, already-blind
forensic_twin function (check_node_state/check_resource_usage/
check_network_latency) -- zero new detection logic, same principle as the
rest of this module: never recompute a signal another function already
owns.

Cost safety: only 3 sensors are allowed in a repeating window at all --
"services" (check_node_state with clock/PLC excluded, the SAME light-tier
call the continuous monitor's own automatic tick already uses, confirmed
cheap), "resources" and "network_latency" (each a real SSH probe, so a
floor of 10s between runs is enforced regardless of what the caller asks
for). clock/PLC/config_integrity/network_exposure are NOT allowed here at
any cadence -- the study's own section 1.2/1.3 classifies all four as
"Pesado"/"Bajo demanda, pesado" (heavy, on-demand-only), and putting any of
them on a repeating timer would violate that classification. They stay
reachable only via their own existing single on-demand check.
"""

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

MIN_INTERVAL_SECONDS = {
    "services": 2.0,
    "resources": 10.0,
    "network_latency": 10.0,
}
ALLOWED_WINDOW_SENSORS = tuple(MIN_INTERVAL_SECONDS.keys())

_lock = threading.Lock()
_active_windows: dict[str, dict] = {}

# Monitoring overhead (investigacion_y_novedad/14_estado_actual_y_caso_de_uso_forge_dt.md /
# forge_dt_metrics's own unavailable_metrics: "needs per-tick timing instrumentation in
# experimental_window -- not logged yet"). Real, measured wall-clock cost per sensor tick --
# the honest, directly-measurable proxy for "how much extra cost does running an M3 window
# add", logged to a small history file (not just kept in the live window's own dict, which
# gets discarded the moment the window ends) so the metric reflects real history across many
# windows, not just whichever one happens to be running right now.
RUNTIME_DIR = Path(__file__).resolve().parents[3] / "runtime" / "forensic_twin"
OVERHEAD_LOG_PATH = RUNTIME_DIR / "experimental_window_overhead.jsonl"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_sensor(node_id: str, sensor: str) -> float:
    """Returns the real wall-clock seconds this one sensor call took --
    timed around the exact same already-existing, already-blind calls,
    never a second measurement path."""
    from app_core.infrastructure.forensic_twin import service as ft
    started = time.monotonic()
    try:
        if sensor == "services":
            # include_clock=False, include_plc=False -- the exact same
            # light-tier call start_continuous_monitor's own automatic tick
            # already makes (see service.py's own CONCURRENCY/cost doc),
            # reused here rather than a second cheap-check implementation.
            ft.check_node_state(node_id, include_clock=False, include_plc=False, source="experimental_window")
        elif sensor == "resources":
            ft.check_resource_usage(node_id)
        elif sensor == "network_latency":
            ft.check_network_latency(node_id)
    finally:
        pass
    return time.monotonic() - started


def _append_overhead_record(record: dict) -> None:
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        with OVERHEAD_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception:
        pass


def _window_loop(window_id: str, node_ids: list[str], sensors: list[str], interval_seconds: float, stop_event: threading.Event, stop_at_ts: float) -> None:
    tick_count = 0
    total_sensor_seconds = 0.0
    per_sensor_seconds: dict[str, float] = {s: 0.0 for s in sensors}
    per_sensor_ticks: dict[str, int] = {s: 0 for s in sensors}
    window_started_at = _utc_now()
    while not stop_event.is_set() and time.time() < stop_at_ts:
        for node_id in node_ids:
            for sensor in sensors:
                if stop_event.is_set() or time.time() >= stop_at_ts:
                    break
                try:
                    elapsed = _run_sensor(node_id, sensor)
                except Exception:
                    elapsed = 0.0
                tick_count += 1
                total_sensor_seconds += elapsed
                per_sensor_seconds[sensor] = per_sensor_seconds.get(sensor, 0.0) + elapsed
                per_sensor_ticks[sensor] = per_sensor_ticks.get(sensor, 0) + 1
        with _lock:
            entry = _active_windows.get(window_id)
            if entry is not None:
                entry["tick_count"] = tick_count
                entry["total_sensor_seconds"] = round(total_sensor_seconds, 4)
        # Real bug found testing this locally: waiting the full
        # interval_seconds regardless of stop_at_ts meant a window whose
        # interval is longer than its remaining duration (e.g. interval=10s,
        # duration=3s) overshot its own deadline by up to a full interval
        # before the while condition was re-checked. Cap the wait at
        # whatever time is actually left.
        remaining = stop_at_ts - time.time()
        if remaining <= 0:
            break
        stop_event.wait(min(interval_seconds, remaining))
    _append_overhead_record({
        "window_id": window_id,
        "node_count": len(node_ids),
        "sensors": sensors,
        "interval_seconds": interval_seconds,
        "window_started_at": window_started_at,
        "window_ended_at": _utc_now(),
        "tick_count": tick_count,
        "total_sensor_seconds": round(total_sensor_seconds, 4),
        "mean_sensor_seconds": round(total_sensor_seconds / tick_count, 4) if tick_count else None,
        "per_sensor_seconds": {k: round(v, 4) for k, v in per_sensor_seconds.items()},
        "per_sensor_ticks": per_sensor_ticks,
    })
    with _lock:
        _active_windows.pop(window_id, None)


def get_monitoring_overhead_summary(limit: int = 200) -> dict:
    """Real aggregate overhead across the last `limit` completed experimental
    windows -- never estimated, read straight from OVERHEAD_LOG_PATH's own
    per-window records. Returns an honest "no windows run yet" note instead
    of a fabricated 0 when the log is empty."""
    if not OVERHEAD_LOG_PATH.is_file():
        return {"ok": True, "n_windows": 0, "note": "no experimental window has completed yet"}
    records = []
    for line in OVERHEAD_LOG_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            continue
    records = records[-limit:]
    if not records:
        return {"ok": True, "n_windows": 0, "note": "no experimental window has completed yet"}
    total_ticks = sum(r.get("tick_count") or 0 for r in records)
    total_seconds = sum(r.get("total_sensor_seconds") or 0.0 for r in records)
    per_sensor_totals: dict[str, float] = {}
    for r in records:
        for sensor, secs in (r.get("per_sensor_seconds") or {}).items():
            per_sensor_totals[sensor] = per_sensor_totals.get(sensor, 0.0) + secs
    return {
        "ok": True,
        "n_windows": len(records),
        "total_ticks": total_ticks,
        "total_sensor_seconds": round(total_seconds, 4),
        "mean_seconds_per_tick": round(total_seconds / total_ticks, 4) if total_ticks else None,
        "per_sensor_total_seconds": {k: round(v, 4) for k, v in per_sensor_totals.items()},
    }


def start_experimental_window(
    node_ids: list[str],
    sensors: list[str] | None = None,
    interval_seconds: float = 5.0,
    duration_seconds: float = 120.0,
) -> dict:
    """Generic, blind observation window. Returns a window_id to stop it
    early or check its status; it also self-stops after duration_seconds
    regardless. Never raises -- validation failures come back as
    {"ok": False, "error": ...}."""
    sensors = sensors or ["services"]
    unknown = [s for s in sensors if s not in ALLOWED_WINDOW_SENSORS]
    if unknown:
        return {
            "ok": False,
            "error": f"sensor(s) not allowed in a repeating window (too costly, must stay on-demand): {unknown}. Allowed: {list(ALLOWED_WINDOW_SENSORS)}",
        }
    if not node_ids:
        return {"ok": False, "error": "node_ids is required"}
    if duration_seconds <= 0 or duration_seconds > 3600:
        return {"ok": False, "error": "duration_seconds must be between 0 and 3600 (1h cap, same conservative-by-default principle as the rest of this module)"}

    min_interval = max(MIN_INTERVAL_SECONDS[s] for s in sensors)
    effective_interval = max(interval_seconds, min_interval)

    window_id = f"xw-{uuid.uuid4().hex[:10]}"
    stop_event = threading.Event()
    stop_at_ts = time.time() + duration_seconds
    thread = threading.Thread(
        target=_window_loop,
        args=(window_id, node_ids, sensors, effective_interval, stop_event, stop_at_ts),
        daemon=True,
        name=f"experimental-window-{window_id}",
    )
    with _lock:
        _active_windows[window_id] = {
            "window_id": window_id,
            "node_ids": node_ids,
            "sensors": sensors,
            "interval_seconds": effective_interval,
            "requested_interval_seconds": interval_seconds,
            "started_at": _utc_now(),
            "duration_seconds": duration_seconds,
            "stop_event": stop_event,
        }
    thread.start()
    return {
        "ok": True, "window_id": window_id, "interval_seconds": effective_interval,
        "duration_seconds": duration_seconds, "node_ids": node_ids, "sensors": sensors,
    }


def stop_experimental_window(window_id: str) -> dict:
    with _lock:
        entry = _active_windows.get(window_id)
    if not entry:
        return {"ok": False, "error": f"no active window with id {window_id}"}
    entry["stop_event"].set()
    return {"ok": True, "window_id": window_id, "stopped_at": _utc_now()}


def get_window_status(window_id: str) -> dict:
    with _lock:
        entry = _active_windows.get(window_id)
    if not entry:
        return {"ok": False, "error": f"no active (or already-finished) window with id {window_id}"}
    return {
        "ok": True, "window_id": window_id, "node_ids": entry["node_ids"], "sensors": entry["sensors"],
        "interval_seconds": entry["interval_seconds"], "started_at": entry["started_at"],
        "duration_seconds": entry["duration_seconds"],
    }


def list_active_windows() -> list[dict]:
    with _lock:
        return [
            {
                "window_id": k, "node_ids": v["node_ids"], "sensors": v["sensors"],
                "interval_seconds": v["interval_seconds"], "started_at": v["started_at"],
                "duration_seconds": v["duration_seconds"],
            }
            for k, v in _active_windows.items()
        ]
