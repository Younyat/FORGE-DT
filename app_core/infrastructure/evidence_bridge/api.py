"""Evidence Bridge -- API. Writes only via link_evidence/
auto_link_self_evidencing_event, never a second write path."""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from .service import auto_link_self_evidencing_event, get_evidence_links, link_evidence

evidence_bridge_bp = Blueprint("evidence_bridge", __name__)


@evidence_bridge_bp.route("/api/evidence-bridge/links", methods=["GET"])
def api_links():
    divergence_event_id = request.args.get("divergence_event_id")
    return jsonify({"ok": True, "links": get_evidence_links(divergence_event_id)}), 200


@evidence_bridge_bp.route("/api/evidence-bridge/auto-link", methods=["POST"])
def api_auto_link():
    body = request.get_json(silent=True) or {}
    event = body.get("event")
    if not event:
        return jsonify({"ok": False, "error": "event is required"}), 400
    result = auto_link_self_evidencing_event(event, intervention_id=body.get("intervention_id"))
    return jsonify(result), (200 if result.get("ok") else 400)


@evidence_bridge_bp.route("/api/evidence-bridge/link", methods=["POST"])
def api_link():
    body = request.get_json(silent=True) or {}
    required = ["divergence_event_id", "evidence_refs", "support_state", "support_reason"]
    missing = [k for k in required if k not in body]
    if missing:
        return jsonify({"ok": False, "error": f"missing fields: {missing}"}), 400
    result = link_evidence(
        divergence_event_id=body["divergence_event_id"],
        evidence_refs=body["evidence_refs"],
        support_state=body["support_state"],
        support_reason=body["support_reason"],
        temporal_relation=body.get("temporal_relation", "unknown"),
        intervention_id=body.get("intervention_id"),
        causal_relation_ids=body.get("causal_relation_ids"),
        uncertainty=body.get("uncertainty"),
    )
    return jsonify(result), (200 if result.get("ok") else 400)
