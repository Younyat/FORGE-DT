"""Host Metrics -- real-time resource usage of the host machine running
this platform (CPU/RAM/disk/network), for the small header widget shown on
every dashboard. Read-only, no write actions."""
from __future__ import annotations

from flask import Blueprint, jsonify

from .service import get_host_resource_snapshot

host_metrics_bp = Blueprint("host_metrics", __name__)


@host_metrics_bp.route("/api/host-metrics/snapshot", methods=["GET"])
def api_snapshot():
    return jsonify(get_host_resource_snapshot()), 200
