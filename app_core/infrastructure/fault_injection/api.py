"""Fault Injection -- Flask blueprint, only the injection-specific actions.
Launching Level A/B/C campaigns is NOT proxied here: the frontend calls the
existing real endpoints directly (/api/foc/experimentation/campaigns/
proposal|create, /api/foc/paper-evidence/level-a/run,
/api/foc/paper-evidence/level-b/run, /api/level-c/launch), simply adding
`injected_faults` to the campaign-creation payload -- already supported by
campaign_service.py.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request, send_from_directory

from .catalog import FAULT_CATALOG
from .service import (
    apply_fault,
    get_modbus_precision_effectiveness,
    get_modbus_precision_status,
    list_injections,
    measure_clock_status,
    measure_effectiveness,
    revert_fault,
    set_modbus_precision_mode,
)
from ..foc_reconstruction.foc_config import PROJECT_ROOT

fault_injection_bp = Blueprint("fault_injection", __name__)

STATIC_DIR = PROJECT_ROOT / "app_core" / "static"


@fault_injection_bp.route("/fault_injection")
def fault_injection_view():
    return send_from_directory(STATIC_DIR, "fault_injection.html")


@fault_injection_bp.route("/api/fault-injection/catalog", methods=["GET"])
def api_catalog():
    return jsonify({"faults": FAULT_CATALOG}), 200


@fault_injection_bp.route("/api/fault-injection/apply", methods=["POST"])
def api_apply():
    body = request.get_json(silent=True) or {}
    fault_id = body.get("fault_id")
    node_id = body.get("node_id")
    params = body.get("params") or {}
    campaign_id = body.get("campaign_id")
    if not fault_id or not node_id:
        return jsonify({"ok": False, "error": "fault_id and node_id are required"}), 400
    result = apply_fault(fault_id, node_id, params, campaign_id=campaign_id)
    return jsonify(result), (200 if result.get("ok") else 400)


@fault_injection_bp.route("/api/fault-injection/revert", methods=["POST"])
def api_revert():
    body = request.get_json(silent=True) or {}
    injection_id = body.get("injection_id")
    if not injection_id:
        return jsonify({"ok": False, "error": "injection_id is required"}), 400
    result = revert_fault(injection_id)
    return jsonify(result), (200 if result.get("ok") else 400)


@fault_injection_bp.route("/api/fault-injection/effectiveness/<injection_id>", methods=["GET"])
def api_effectiveness(injection_id: str):
    result = measure_effectiveness(injection_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@fault_injection_bp.route("/api/fault-injection/modbus-effectiveness/<job_id>", methods=["GET"])
def api_modbus_effectiveness(job_id: str):
    result = get_modbus_precision_effectiveness(job_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@fault_injection_bp.route("/api/fault-injection/injections", methods=["GET"])
def api_injections():
    campaign_id = request.args.get("campaign_id")
    return jsonify({"injections": list_injections(campaign_id)}), 200


@fault_injection_bp.route("/api/fault-injection/clock-status/<node_id>", methods=["GET"])
def api_clock_status(node_id: str):
    result = measure_clock_status(node_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@fault_injection_bp.route("/api/fault-injection/modbus-status/<campaign_id>", methods=["GET"])
def api_modbus_status(campaign_id: str):
    result = get_modbus_precision_status(campaign_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@fault_injection_bp.route("/api/fault-injection/modbus-toggle", methods=["POST"])
def api_modbus_toggle():
    body = request.get_json(silent=True) or {}
    campaign_id = body.get("campaign_id")
    mode = body.get("mode")
    value = body.get("value")
    if not campaign_id or mode not in ("degraded", "fixed"):
        return jsonify({"ok": False, "error": "campaign_id and mode ('degraded'|'fixed') are required"}), 400
    result = set_modbus_precision_mode(campaign_id, mode, value)
    return jsonify(result), (200 if result.get("ok") else 404)
