"""Intervention Ledger -- read-only API. Writes only ever happen via
record_intervention(), called from fault_injection/Attack Lab's own hooks,
never from an HTTP request directly."""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from .linker import link_intervention_to_twin_events
from .service import get_intervention_by_id, get_ledger_entries, verify_chain, verify_chain_against_checkpoints
from .timeline import build_latest_phase_timeline_for_node, build_phase_timeline

intervention_ledger_bp = Blueprint("intervention_ledger", __name__)


@intervention_ledger_bp.route("/api/intervention-ledger/entries", methods=["GET"])
def api_entries():
    entries = get_ledger_entries(
        case_id=request.args.get("case_id"),
        campaign_id=request.args.get("campaign_id"),
        node_id=request.args.get("node_id"),
        source=request.args.get("source"),
        class_=request.args.get("class"),
        limit=int(request.args.get("limit", 200)),
    )
    return jsonify({"ok": True, "entries": entries, "count": len(entries)}), 200


@intervention_ledger_bp.route("/api/intervention-ledger/entry/<intervention_id>", methods=["GET"])
def api_entry(intervention_id: str):
    entry = get_intervention_by_id(intervention_id)
    if not entry:
        return jsonify({"ok": False, "error": f"no ledger entry for intervention_id={intervention_id}"}), 404
    return jsonify({"ok": True, "entry": entry}), 200


@intervention_ledger_bp.route("/api/intervention-ledger/verify", methods=["GET"])
def api_verify():
    result = verify_chain()
    # Additive: a pure hash chain can't detect truncate-then-forge (see
    # service.py::verify_chain's own docstring) -- this cross-checks against
    # externally-written checkpoints for the real, if partial, mitigation.
    checkpoint_result = verify_chain_against_checkpoints()
    result["checkpoints"] = checkpoint_result
    overall_ok = bool(result.get("ok")) and bool(checkpoint_result.get("ok"))
    return jsonify(result), (200 if overall_ok else 409)


@intervention_ledger_bp.route("/api/intervention-ledger/linked-events/<intervention_id>", methods=["GET"])
def api_linked_events(intervention_id: str):
    tolerance = float(request.args.get("tolerance_seconds", 5.0))
    result = link_intervention_to_twin_events(intervention_id, tolerance_seconds=tolerance)
    return jsonify(result), (200 if result.get("ok") else 404)


@intervention_ledger_bp.route("/api/intervention-ledger/phase-timeline/<intervention_id>", methods=["GET"])
def api_phase_timeline(intervention_id: str):
    tolerance = float(request.args.get("tolerance_seconds", 5.0))
    result = build_phase_timeline(intervention_id, tolerance_seconds=tolerance)
    return jsonify(result), (200 if result.get("ok") else 404)


@intervention_ledger_bp.route("/api/intervention-ledger/node-timeline/<node_id>", methods=["GET"])
def api_node_timeline(node_id: str):
    tolerance = float(request.args.get("tolerance_seconds", 5.0))
    result = build_latest_phase_timeline_for_node(node_id, tolerance_seconds=tolerance)
    return jsonify(result), (200 if result.get("ok") else 404)
