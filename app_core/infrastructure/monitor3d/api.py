"""
3D Live Monitor — Flask blueprint. Read-only, additive.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request, send_from_directory

from .service import build_reconstruction_timeline, get_host_vitals, get_live_attack_feed, get_repetition_detail, get_sensor_coverage, get_snapshot
from ..foc_reconstruction.foc_config import PROJECT_ROOT

monitor3d_bp = Blueprint("monitor3d", __name__)

STATIC_DIR = PROJECT_ROOT / "app_core" / "static"


@monitor3d_bp.route("/monitor3d")
def monitor3d_view():
    return send_from_directory(STATIC_DIR, "monitor3d.html")


@monitor3d_bp.route("/api/monitor3d/snapshot", methods=["GET"])
def api_snapshot():
    since_hash = request.args.get("since_hash")
    return jsonify(get_snapshot(since_hash=since_hash)), 200


@monitor3d_bp.route("/api/monitor3d/hosts/<instance_id>/vitals", methods=["GET"])
def api_host_vitals(instance_id: str):
    refresh = request.args.get("refresh") in ("1", "true", "True")
    row = get_host_vitals(instance_id, refresh=refresh)
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(row), 200


@monitor3d_bp.route("/api/monitor3d/sensor-coverage", methods=["GET"])
def api_sensor_coverage():
    return jsonify(get_sensor_coverage()), 200


@monitor3d_bp.route("/api/monitor3d/repetitions/<int:rep_num>", methods=["GET"])
def api_repetition_detail(rep_num: int):
    row = get_repetition_detail(rep_num)
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(row), 200


@monitor3d_bp.route("/api/monitor3d/live-events", methods=["GET"])
def api_live_attack_feed():
    since = request.args.get("since")
    return jsonify(get_live_attack_feed(since)), 200


@monitor3d_bp.route("/api/monitor3d/reconstruction/<job_id>", methods=["GET"])
def api_reconstruction_timeline(job_id: str):
    row = build_reconstruction_timeline(job_id)
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(row), 200
