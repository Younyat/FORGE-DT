from __future__ import annotations

"""M4 (Post-hoc linker, investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md).
A pure, read-only function that matches one Intervention Ledger entry (M1)
against forensic_twin's own already-recorded events (both divergence
events and the neutral fault_injection_applied/reverted markers) for the
same target node, within a tolerance window around the intervention's own
real timestamps. Called strictly AFTER the fact (post-hoc) -- never during
detection, never feeding anything back into forensic_twin's own rules
(which stay exactly as blind as they already were). No new data is
captured here: every field this reads (ledger entries, forensic_twin
events) already existed before this module; it only joins them.
"""

from datetime import datetime, timezone

from .service import get_entries_for_intervention, get_intervention_by_id

# Real, measured gap (2026-10-09, campaign CMP-20261009-124327-0CB6,
# intervention atk-20261009T164617Z_T0831_MANIPULATION_OF_CONTROL_MODBUS):
# Attack Lab's own twin follow-up (attack/executor.py::_trigger_twin_followup_check,
# added 2026-10-08) runs check_node_state() AFTER the attack's own completed_at
# -- a real on-demand clock+PLC check (SSH round trip + mbpoll reads) that
# itself takes real time. The resulting plc_baseline_divergence event landed
# ~26.5s after the intervention's own effect_verified_at/recorded_at_utc --
# past the 5s default that works fine for fault_injection (whose
# FAULT_RELEVANT_CHECKS hook fires near-instantly). Without this, every
# caller that scores Attack Lab interventions (TOR/L_obs/IER in
# forge_dt_metrics, the phase-timeline widget) under-reports a REAL
# detection as "not observed" -- not because detection failed, but because
# the match window was too tight for how this specific follow-up is timed.
# A floor, not a replacement: a caller that already passed something wider
# is respected (see effective_tolerance_for below).
ATTACK_LAB_MIN_TOLERANCE_SECONDS = 40.0


def effective_tolerance_for(entry: dict, tolerance_seconds: float) -> float:
    if entry.get("source") == "attack_lab":
        return max(tolerance_seconds, ATTACK_LAB_MIN_TOLERANCE_SECONDS)
    return tolerance_seconds


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        text = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _resolve_node_id_for_entry(entry: dict) -> str | None:
    """Prefers the entry's own target_node_id (always real for
    fault_injection-sourced entries). Falls back to resolving target_ip
    against the live node inventory (needed for Attack Lab-sourced entries,
    which only carry an IP -- see intervention_ledger/README.md)."""
    if entry.get("target_node_id"):
        return entry["target_node_id"]
    target_ip = entry.get("target_ip")
    if not target_ip:
        return None
    from app_core.infrastructure.node_health.node_health_api import _list_nodes
    try:
        for node in _list_nodes():
            if target_ip in (node.get("ip_private"), node.get("ip_floating")):
                return node.get("id")
    except Exception:
        pass
    return None


def link_intervention_to_twin_events(intervention_id: str, *, tolerance_seconds: float = 5.0) -> dict:
    """Returns the intervention entry plus every forensic_twin event for
    the same node whose generated_at_utc falls within
    [earliest real timestamp - tolerance, latest real timestamp + tolerance].
    Never writes anything -- a pure read+match. `tolerance_seconds` should
    be widened by the caller for intervention types whose own effect can
    make the target's clock itself unreliable (clock_skew -- see the
    study's own section 14.4: for that type, match against a reference
    clock, not the target's own timestamps, since the target's clock is
    what the intervention changed)."""
    entry = get_intervention_by_id(intervention_id)
    if not entry:
        return {"ok": False, "error": f"no ledger entry for intervention_id={intervention_id}"}

    # Applied here, once, so every caller gets it for free -- see
    # ATTACK_LAB_MIN_TOLERANCE_SECONDS's own comment above for why.
    tolerance_seconds = effective_tolerance_for(entry, tolerance_seconds)

    node_id = _resolve_node_id_for_entry(entry)
    if not node_id:
        return {"ok": False, "error": "could not resolve a target node_id for this entry (no target_node_id and target_ip did not match any live node)", "entry": entry}

    # Real bug found verifying this against a long-duration intervention
    # (plc_io_manipulation held active ~3h15m across a full Level C
    # repetition): using only the FIRST entry's own timestamps understated
    # the window to a few seconds around "applied", since "rollback_at" is
    # only ever populated on the SEPARATE "reverted" entry sharing the same
    # intervention_id -- missing every twin event detected while the fault
    # was still active. Now merges timestamps across ALL entries for this
    # intervention_id (applied + reverted), giving the real full window.
    all_entries = get_entries_for_intervention(intervention_id) or [entry]
    timestamps = []
    for e in all_entries:
        timestamps.extend([
            _parse_ts(e.get("requested_at")),
            _parse_ts(e.get("applied_at")),
            _parse_ts(e.get("effect_verified_at")),
            _parse_ts(e.get("rollback_requested_at")),
            _parse_ts(e.get("rollback_at")),
            _parse_ts(e.get("recorded_at_utc")),
        ])
    real_timestamps = [t for t in timestamps if t is not None]
    if not real_timestamps:
        return {"ok": False, "error": "this ledger entry has no usable timestamps", "entry": entry}
    window_start = min(real_timestamps)
    window_end = max(real_timestamps)

    from app_core.infrastructure.forensic_twin.service import get_events, _node_scope_id
    scope_id = _node_scope_id(node_id)
    all_events = get_events(scope_id, limit=500)

    matched = []
    for ev in all_events:
        ev_ts = _parse_ts(ev.get("generated_at_utc"))
        if ev_ts is None:
            continue
        delta_start = (ev_ts - window_start).total_seconds()
        delta_end = (ev_ts - window_end).total_seconds()
        in_window = (-tolerance_seconds <= delta_start) and (delta_end <= tolerance_seconds)
        if in_window:
            matched.append({**ev, "_temporal_relation": "overlaps" if (ev_ts >= window_start and ev_ts <= window_end) else ("before" if delta_start < 0 else "after")})

    return {
        "ok": True,
        "intervention_id": intervention_id,
        "entry": entry,
        "ledger_entries": all_entries,
        "target_node_id": node_id,
        "window_start_utc": window_start.isoformat(),
        "window_end_utc": window_end.isoformat(),
        "tolerance_seconds": tolerance_seconds,
        "matched_events": matched,
        "matched_event_count": len(matched),
    }
