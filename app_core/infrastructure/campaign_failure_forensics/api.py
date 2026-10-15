from __future__ import annotations

"""Flask blueprint. Most endpoints here only read already-persisted data
(job_state.json, memory_watchdog's events.jsonl) and never write. The one
exception is recover-snapshot-ids (POST), a narrow, explicit, evidence-based
repair of a single real field -- see recover_missing_snapshot_ids's own
docstring in service.py."""

from flask import Blueprint, jsonify, request

from .service import list_failed_jobs, reconstruct_failure, recover_missing_snapshot_ids

campaign_failure_forensics_bp = Blueprint("campaign_failure_forensics", __name__)


@campaign_failure_forensics_bp.route("/api/campaign-failure-forensics/failed-jobs", methods=["GET"])
def api_list_failed_jobs():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify({"ok": True, "jobs": list_failed_jobs(limit=limit)}), 200


@campaign_failure_forensics_bp.route("/api/campaign-failure-forensics/<job_id>", methods=["GET"])
def api_reconstruct_failure(job_id: str):
    result = reconstruct_failure(job_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@campaign_failure_forensics_bp.route("/api/campaign-failure-forensics/<job_id>/recover-snapshot-ids", methods=["POST"])
def api_recover_snapshot_ids(job_id: str):
    result = recover_missing_snapshot_ids(job_id)
    return jsonify(result), (200 if result.get("ok") else 404)
