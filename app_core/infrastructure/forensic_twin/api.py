from __future__ import annotations

"""Forensic digital twin -- Flask blueprint. Read-only except the two
explicit "check" actions, which each trigger a real (on-demand, not
continuous) comparison against live/fresh data. Nothing here proxies or
duplicates another module's own endpoints; it only exposes the aggregation
service.py builds on top of them.
"""

from flask import Blueprint, jsonify, request, send_from_directory

from ..foc_reconstruction.foc_config import PROJECT_ROOT
from .service import (
    capture_config_baseline,
    capture_network_baseline,
    check_campaign_reproducibility,
    check_config_integrity,
    check_network_exposure,
    check_node_state,
    check_scenario_state,
    compute_reality_gap,
    export_case_uco,
    get_config_integrity_state,
    get_continuous_monitor_status,
    get_network_exposure_state,
    get_scenario_state,
    get_twin_state,
    list_known_scopes,
    list_recent_events,
)

forensic_twin_bp = Blueprint("forensic_twin", __name__)

STATIC_DIR = PROJECT_ROOT / "app_core" / "static"


@forensic_twin_bp.route("/forensic_twin")
def forensic_twin_view():
    return send_from_directory(STATIC_DIR, "forensic_twin.html")


@forensic_twin_bp.route("/api/forensic-twin/state/<node_id>", methods=["GET"])
def api_get_state(node_id: str):
    result = get_twin_state(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/check/<node_id>", methods=["POST"])
def api_check_node(node_id: str):
    result = check_node_state(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/check-campaign/<job_id>", methods=["POST"])
def api_check_campaign(job_id: str):
    result = check_campaign_reproducibility(job_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/events", methods=["GET"])
def api_events():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify({"events": list_recent_events(limit=limit)}), 200


@forensic_twin_bp.route("/api/forensic-twin/scopes", methods=["GET"])
def api_scopes():
    return jsonify({"scopes": list_known_scopes()}), 200


@forensic_twin_bp.route("/api/forensic-twin/scenario/state", methods=["GET"])
def api_scenario_state():
    result = get_scenario_state()
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/scenario/check", methods=["POST"])
def api_scenario_check():
    result = check_scenario_state()
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/continuous/status", methods=["GET"])
def api_continuous_status():
    return jsonify(get_continuous_monitor_status()), 200


@forensic_twin_bp.route("/api/forensic-twin/export/case-uco", methods=["GET"])
def api_export_case_uco():
    scope_id = request.args.get("scope_id")
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(export_case_uco(scope_id=scope_id, limit=limit)), 200


@forensic_twin_bp.route("/api/forensic-twin/config-baseline/<node_id>", methods=["POST"])
def api_capture_config_baseline(node_id: str):
    result = capture_config_baseline(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/check-config/<node_id>", methods=["POST"])
def api_check_config(node_id: str):
    result = check_config_integrity(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/config-state/<node_id>", methods=["GET"])
def api_config_state(node_id: str):
    result = get_config_integrity_state(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/network-baseline/<node_id>", methods=["POST"])
def api_capture_network_baseline(node_id: str):
    result = capture_network_baseline(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/check-network/<node_id>", methods=["POST"])
def api_check_network(node_id: str):
    result = check_network_exposure(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/network-state/<node_id>", methods=["GET"])
def api_network_state(node_id: str):
    result = get_network_exposure_state(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


# "Reality Gap" (hueco #5, Sammartino & Pasquini's "contextual reality
# gap") -- POST like check-config/check-network since it triggers the same
# real, fresh SSH probes; deliberately never polled or folded into any
# automatic check, see compute_reality_gap's own docstring. Takes a node
# NAME (e.g. "PLC_Instance"), not an instance_id -- a historical case's own
# host instance_id is for an already-destroyed VM and would never resolve.
@forensic_twin_bp.route("/api/forensic-twin/reality-gap/<node_name>", methods=["POST"])
def api_reality_gap(node_name: str):
    as_of = request.args.get("as_of") or (request.get_json(silent=True) or {}).get("as_of")
    if not as_of:
        return jsonify({"ok": False, "error": "as_of (ISO timestamp) is required"}), 400
    result = compute_reality_gap(node_name, as_of)
    return jsonify(result), (200 if result.get("ok") else 404)


# ---------------------------------------------------------------------------
# M3 (Experimental observation mode) -- a generic, blind, bounded-duration
# high(er)-frequency window. See experimental_window.py's own module
# docstring for why this is deliberately separate from everything above.
# ---------------------------------------------------------------------------

@forensic_twin_bp.route("/api/forensic-twin/experimental-window/start", methods=["POST"])
def api_start_experimental_window():
    from .experimental_window import start_experimental_window
    body = request.get_json(silent=True) or {}
    result = start_experimental_window(
        node_ids=body.get("node_ids") or [],
        sensors=body.get("sensors"),
        interval_seconds=float(body.get("interval_seconds", 5.0)),
        duration_seconds=float(body.get("duration_seconds", 120.0)),
    )
    return jsonify(result), (200 if result.get("ok") else 400)


@forensic_twin_bp.route("/api/forensic-twin/experimental-window/stop/<window_id>", methods=["POST"])
def api_stop_experimental_window(window_id: str):
    from .experimental_window import stop_experimental_window
    result = stop_experimental_window(window_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/experimental-window/status/<window_id>", methods=["GET"])
def api_experimental_window_status(window_id: str):
    from .experimental_window import get_window_status
    result = get_window_status(window_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forensic_twin_bp.route("/api/forensic-twin/experimental-window/active", methods=["GET"])
def api_active_experimental_windows():
    from .experimental_window import list_active_windows
    return jsonify({"ok": True, "windows": list_active_windows()}), 200
