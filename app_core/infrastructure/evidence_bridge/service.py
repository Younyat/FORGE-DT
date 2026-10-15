from __future__ import annotations

"""M5 (Evidence Bridge, investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md).
Links a real forensic_twin divergence event to real evidence. Never copies
artifact content -- only references (hash/path/id/the event's own already-
real payload). support_state (supported/contradicted/ambiguous/unresolved)
is assigned by EXPLICIT rules, never inferred by a model -- section 11.1 of
the study: "I_T no es E_P" (the twin's own inference is never primary
evidence; it is the SUBJECT being evaluated, and real artifacts/payloads
are what support or contradict it).

Two evidence sources, both real, never invented:
1. Self-evidencing events -- some divergence rules (config_integrity_changed,
   listening_port_added, plc_baseline_divergence) already carry real,
   verifiable proof directly in their own payload (a real SHA-256 hash
   pair, a real new port, a real state-hash pair) -- no external artifact
   needed, `auto_link_self_evidencing_event` handles these.
2. External evidence_store artifacts (RAM/PCAP/disk/logs preserved by the
   forensic pipeline for a real case) -- NOT built in this pass: every
   real intervention tested so far this session was ad hoc (case_id=None,
   no forensic case ever opened around it), so there is no real artifact
   to cross-reference yet. Left as an explicit, documented pending item
   (see README) rather than built against hypothetical data.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = PROJECT_ROOT / "runtime" / "evidence_bridge"
LINKS_PATH = RUNTIME_DIR / "links.jsonl"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

MODEL_VERSION = "1.0.0"
VALID_SUPPORT_STATES = ("supported", "contradicted", "ambiguous", "unresolved")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def event_id(event: dict) -> str:
    """Forensic_twin events don't carry their own stable ID field -- built
    the same way digital_twin_view.js's own dedup key already does
    (scope_id|generated_at_utc|event_type), reusing the one existing
    convention for a stable per-event identifier instead of inventing a
    second one."""
    return f"{event.get('scope_id')}|{event.get('generated_at_utc')}|{event.get('event_type')}"


def link_evidence(
    *,
    divergence_event_id: str,
    evidence_refs: list[dict],
    support_state: str,
    support_reason: str,
    temporal_relation: str = "unknown",
    intervention_id: str | None = None,
    causal_relation_ids: list[str] | None = None,
    uncertainty: dict | None = None,
) -> dict:
    if support_state not in VALID_SUPPORT_STATES:
        return {"ok": False, "error": f"invalid support_state: {support_state}. Valid: {VALID_SUPPORT_STATES}"}
    entry = {
        "model_version": MODEL_VERSION,
        "linked_at_utc": _utc_now(),
        "divergence_event_id": divergence_event_id,
        "intervention_id": intervention_id,
        "evidence_refs": evidence_refs,
        "temporal_relation": temporal_relation,
        "support_state": support_state,
        "support_reason": support_reason,
        "causal_relation_ids": causal_relation_ids or [],
        "uncertainty": uncertainty or {},
    }
    with LINKS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
    return {"ok": True, "entry": entry}


def get_evidence_links(divergence_event_id: str | None = None) -> list[dict]:
    if not LINKS_PATH.is_file():
        return []
    out = []
    for line in LINKS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if divergence_event_id is None or entry.get("divergence_event_id") == divergence_event_id:
            out.append(entry)
    return out


def auto_link_self_evidencing_event(event: dict, *, intervention_id: str | None = None) -> dict:
    """Explicit, per-event_type rule -- never a generic "has extra fields
    so it's supported" heuristic. Returns {"ok": False, ...} honestly for
    any event_type without a rule yet, rather than guessing."""
    event_type = event.get("event_type")

    if event_type == "config_integrity_changed":
        differences = event.get("differences") or []
        if not differences:
            return {"ok": False, "error": "config_integrity_changed event has no differences payload"}
        evidence_refs = [
            {"kind": "config_file_hash_diff", "path": d.get("path"), "baseline_hash": d.get("baseline_hash"), "current_hash": d.get("current_hash"), "reason": d.get("reason")}
            for d in differences
        ]
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=f"{len(differences)} real file hash mismatch(es) in the event's own payload -- self-evidencing, no external artifact needed",
            intervention_id=intervention_id,
        )

    if event_type == "listening_port_added":
        new_ports = event.get("new_listening_ports") or []
        if not new_ports:
            return {"ok": False, "error": "listening_port_added event has no new_listening_ports payload"}
        evidence_refs = [{"kind": "listening_port", "port": p} for p in new_ports]
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=f"{len(new_ports)} real new listening port(s) in the event's own payload -- self-evidencing",
            intervention_id=intervention_id,
        )

    if event_type == "plc_baseline_divergence":
        comparison = event.get("comparison") or {}
        differences = comparison.get("differences") or []
        if not differences:
            return {"ok": False, "error": "plc_baseline_divergence event has no comparison differences"}
        evidence_refs = [
            {"kind": "plc_variable_diff", "canonical_name": d.get("canonical_name"), "observed_value": d.get("observed_value"), "expected_value": d.get("expected_value")}
            for d in differences
        ]
        evidence_refs.append({"kind": "state_hash_pair", "observed_state_hash": comparison.get("observed_state_hash"), "expected_state_hash": comparison.get("expected_state_hash")})
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=f"{len(differences)} real PLC variable mismatch(es) + a real state-hash pair in the event's own payload -- self-evidencing",
            intervention_id=intervention_id,
        )

    # 2026-10-15: 5 more rules added, same standard as the 3 above -- each
    # one checked against the REAL code that generates that event_type
    # (forensic_twin/service.py) before writing it, not assumed. 4 are
    # genuinely self-evidencing from the event's own payload already, same
    # as the 3 original rules; the 5th (resource_exhaustion_degraded) is the
    # one case here needing a real prior reading for an honest before/after,
    # pulled from this node's own already-persisted state history (never
    # invented) via forensic_twin.get_state_history_before(). Two more real
    # candidate types (reproducibility_degraded, scenario_validation_degraded)
    # were deliberately left out -- investigated, judged not honestly
    # self-evidencing without a bigger, separate design decision (see README).

    if event_type == "tool_regression":
        regressed = event.get("tools_no_longer_installed") or []
        if not regressed:
            return {"ok": False, "error": "tool_regression event has no tools_no_longer_installed payload"}
        evidence_refs = [{"kind": "tool_no_longer_installed", "tool_name": t} for t in regressed]
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=f"{len(regressed)} real tool(s) confirmed installed in a prior check, confirmed missing now -- self-evidencing, no external artifact needed",
            intervention_id=intervention_id,
        )

    if event_type == "service_down":
        services_down = event.get("services_down") or []
        if not services_down:
            return {"ok": False, "error": "service_down event has no services_down payload"}
        evidence_refs = [{"kind": "service_down", "service_name": s} for s in services_down]
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=f"{len(services_down)} real service(s) confirmed inactive via systemctl is-active in the event's own payload -- self-evidencing",
            intervention_id=intervention_id,
        )

    if event_type == "clock_offset_degraded":
        offset_ms = event.get("offset_ms")
        threshold_ms = event.get("threshold_ms")
        if offset_ms is None or threshold_ms is None:
            return {"ok": False, "error": "clock_offset_degraded event is missing offset_ms/threshold_ms"}
        evidence_refs = [{"kind": "clock_offset_reading", "offset_ms": offset_ms, "threshold_ms": threshold_ms}]
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=f"real measured clock offset {offset_ms}ms against the real {threshold_ms}ms threshold, both in the event's own payload -- self-evidencing",
            intervention_id=intervention_id,
        )

    if event_type == "network_latency_degraded":
        ping_avg_ms = event.get("ping_avg_ms")
        floor_ms = event.get("floor_ms")
        if ping_avg_ms is None or floor_ms is None:
            return {"ok": False, "error": "network_latency_degraded event is missing ping_avg_ms/floor_ms"}
        evidence_refs = [{"kind": "network_rtt_reading", "ping_avg_ms": ping_avg_ms, "floor_ms": floor_ms}]
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=f"real measured ping RTT {ping_avg_ms}ms against this node's own real, previously-established floor {floor_ms}ms -- self-evidencing",
            intervention_id=intervention_id,
        )

    if event_type == "resource_exhaustion_degraded":
        node_id = event.get("node_id")
        generated_at = event.get("generated_at_utc")
        if not node_id or not generated_at:
            return {"ok": False, "error": "resource_exhaustion_degraded event is missing node_id/generated_at_utc"}
        from app_core.infrastructure.forensic_twin.service import get_state_history_before
        prior = get_state_history_before(f"{node_id}:resources", generated_at)
        if not prior:
            return {"ok": False, "error": "no real prior resource reading on disk for this node yet -- cannot build an honest before/after"}
        evidence_refs = [{
            "kind": "resource_usage_before_after",
            "prior_checked_at": prior.get("checked_at"),
            "cpu_usage_pct_before": prior.get("cpu_usage_pct"), "cpu_usage_pct_after": event.get("cpu_usage_pct"),
            "memory_usage_pct_before": prior.get("memory_usage_pct"), "memory_usage_pct_after": event.get("memory_usage_pct"),
            "disk_root_use_pct_before": prior.get("disk_root_use_pct"), "disk_root_use_pct_after": event.get("disk_root_use_pct"),
        }]
        return link_evidence(
            divergence_event_id=event_id(event),
            evidence_refs=evidence_refs,
            temporal_relation="overlaps",
            support_state="supported",
            support_reason=(
                f"real prior resource reading from {prior.get('checked_at')} "
                f"(cpu {prior.get('cpu_severity')}/memory {prior.get('memory_severity')}/disk {prior.get('disk_severity')}) "
                f"vs. the current reading (cpu {event.get('cpu_severity')}/memory {event.get('memory_severity')}/disk {event.get('disk_severity')}) "
                f"-- self-evidencing via this node's own persisted check history, not invented"
            ),
            intervention_id=intervention_id,
        )

    return {"ok": False, "error": f"no self-evidencing rule for event_type={event_type} yet -- would need an external evidence_store artifact lookup, not built yet (see README)"}
