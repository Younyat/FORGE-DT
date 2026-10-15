from __future__ import annotations

"""Phase timeline -- a read-only view that assembles one intervention's
real lifecycle (Requested -> Applied -> Effect verified -> Seen by twin ->
Evidence linked -> Reverted) purely by joining data M1 (this module),
M4 (linker.py) and M5 (evidence_bridge) already produce. No new signal is
captured here: every timestamp and evidence snippet below already existed
in the Ledger, the post-hoc linker's match, or the Evidence Bridge's own
links -- this only orders them into one shape a UI can render as a
timeline, for the Digital Twin View node panel and (later) the
Reconstruction View's historical timeline to both reuse unchanged.
"""

from datetime import datetime, timezone

from .linker import link_intervention_to_twin_events
from .service import get_entries_for_intervention, get_ledger_entries

PHASE_ORDER = ("requested", "applied", "effect_verified", "twin_observed", "evidence_linked", "reverted")


def _parse_ts(value: str | None):
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


# Every matched twin event already carries forensic_twin's own
# `mitre_attck_ics` field (service.py::MITRE_ATTCK_ICS_MAPPING, 2026-10-09) --
# folding it into this one phase's detail string is enough for it to reach
# both Digital Twin View and Reconstruction View at once, since both render
# this same phase timeline through phase_timeline.js with no widget change
# needed. Plain-language: names the real adversary technique this divergence
# looks like, not just the internal event_type.
def _twin_observed_detail(matched_sorted: list[dict]) -> str:
    event_types = sorted({ev.get("event_type") for ev in matched_sorted if ev.get("event_type")})
    base = f"{len(matched_sorted)} matching twin event(s): {', '.join(event_types) or 'none yet'}"
    mitre_labels = sorted({
        f"{(ev.get('mitre_attck_ics') or {}).get('technique_id')} ({(ev.get('mitre_attck_ics') or {}).get('technique_name')})"
        for ev in matched_sorted if ev.get("mitre_attck_ics")
    })
    if mitre_labels:
        base += f" -- looks like (MITRE ATT&CK for ICS): {', '.join(mitre_labels)}"
    return base


def build_phase_timeline(intervention_id: str, *, tolerance_seconds: float = 5.0) -> dict:
    entries = get_entries_for_intervention(intervention_id)
    if not entries:
        return {"ok": False, "error": f"no ledger entry for intervention_id={intervention_id}"}

    applied_entry = next((e for e in entries if e.get("phase") in ("applied", "executed")), entries[0])
    reverted_entry = next((e for e in entries if e.get("phase") == "reverted"), None)

    effect_verification = applied_entry.get("effect_verification") or {}
    effective = effect_verification.get("effective")

    link = link_intervention_to_twin_events(intervention_id, tolerance_seconds=tolerance_seconds)
    matched = (link.get("matched_events") or []) if link.get("ok") else []
    matched_sorted = sorted(matched, key=lambda ev: _parse_ts(ev.get("generated_at_utc")) or datetime.min.replace(tzinfo=timezone.utc))
    observed_at = matched_sorted[0].get("generated_at_utc") if matched_sorted else None

    from app_core.infrastructure.evidence_bridge.service import event_id, get_evidence_links
    supporting_links = []
    for ev in matched_sorted:
        for lnk in get_evidence_links(event_id(ev)):
            if lnk.get("support_state") == "supported":
                supporting_links.append(lnk)
    supporting_links.sort(key=lambda lnk: lnk.get("linked_at_utc") or "")
    evidenced_at = supporting_links[0].get("linked_at_utc") if supporting_links else None

    requested_at = applied_entry.get("requested_at") or applied_entry.get("recorded_at_utc")
    applied_at = applied_entry.get("applied_at")
    effect_verified_at = applied_entry.get("effect_verified_at")
    reverted_at = (reverted_entry or applied_entry).get("rollback_at")

    phases = [
        {
            "phase": "requested",
            "label": "Requested",
            "at": requested_at,
            "status": "done" if requested_at else "pending",
            "detail": f"{applied_entry.get('type')} ({applied_entry.get('class')}) via {applied_entry.get('source')}",
        },
        {
            "phase": "applied",
            "label": "Applied",
            "at": applied_at,
            "status": "done" if applied_at else "pending",
            "detail": f"target: {applied_entry.get('target_node_name') or applied_entry.get('target_node_id') or applied_entry.get('target_ip') or 'n/a'}",
        },
        {
            "phase": "effect_verified",
            "label": "Effect verified",
            "at": effect_verified_at,
            "status": ("done" if effective is True else "failed" if effective is False else "pending"),
            "detail": effect_verification.get("evidence") or ("no measured effect yet" if effective is None else None),
        },
        {
            "phase": "twin_observed",
            "label": "Seen by twin",
            "at": observed_at,
            "status": "done" if matched_sorted else "pending",
            "detail": _twin_observed_detail(matched_sorted),
        },
        {
            "phase": "evidence_linked",
            "label": "Evidence linked",
            "at": evidenced_at,
            "status": "done" if supporting_links else "pending",
            "detail": f"{len(supporting_links)} supporting evidence link(s)" if supporting_links else "no supporting evidence linked yet",
        },
        {
            "phase": "reverted",
            "label": "Reverted",
            "at": reverted_at,
            "status": "done" if reverted_at else "pending",
            "detail": "rollback verified" if (reverted_entry or {}).get("rollback_verified") else None,
        },
    ]

    is_active = bool(applied_at) and not reverted_at
    return {
        "ok": True,
        "intervention_id": intervention_id,
        "type": applied_entry.get("type"),
        "class": applied_entry.get("class"),
        "source": applied_entry.get("source"),
        "target_node_id": applied_entry.get("target_node_id"),
        "target_node_name": applied_entry.get("target_node_name"),
        "campaign_id": applied_entry.get("campaign_id"),
        "case_id": applied_entry.get("case_id"),
        "is_active": is_active,
        "phases": phases,
    }


def build_latest_phase_timeline_for_node(node_id: str, *, tolerance_seconds: float = 5.0) -> dict:
    """Most recent intervention recorded against this node (by its
    "applied"/"executed" entry's own recorded_at_utc), plus the
    intervention_ids of any earlier ones for this node -- so a UI can show
    one full timeline plus a short real history list, never silently
    hiding older interventions."""
    entries = get_ledger_entries(node_id=node_id, limit=5000)
    attempts = sorted(
        (e for e in entries if e.get("phase") in ("applied", "executed")),
        key=lambda e: e.get("recorded_at_utc") or "",
        reverse=True,
    )
    if not attempts:
        return {"ok": False, "error": f"no intervention recorded yet for node_id={node_id}"}

    latest = attempts[0]
    timeline = build_phase_timeline(latest["intervention_id"], tolerance_seconds=tolerance_seconds)
    older = [
        {"intervention_id": e["intervention_id"], "type": e.get("type"), "recorded_at_utc": e.get("recorded_at_utc")}
        for e in attempts[1:6]
    ]
    timeline["older_interventions"] = older
    return timeline
