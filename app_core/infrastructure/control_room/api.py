from __future__ import annotations

"""Flask blueprint for the "Control Room" dashboard -- all routes are
read-only. See investigacion_y_novedad/08_dashboard_sala_control.md."""

from flask import Blueprint, jsonify, request, send_from_directory
from pathlib import Path

from .service import get_snapshot, get_worker_thread_census

control_room_bp = Blueprint("control_room", __name__)

STATIC_DIR = Path(__file__).resolve().parents[3] / "app_core" / "static"


@control_room_bp.route("/control-room")
def control_room_view():
    return send_from_directory(STATIC_DIR, "control_room.html")


@control_room_bp.route("/api/control-room/snapshot", methods=["GET"])
def control_room_snapshot():
    since_hash = request.args.get("since_hash")
    try:
        payload = get_snapshot(since_hash=since_hash)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(payload)


@control_room_bp.route("/api/control-room/worker/threads", methods=["GET"])
def control_room_worker_threads():
    try:
        payload = get_worker_thread_census()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(payload)
