"""
Level C Campaign Orchestrator — Flask blueprint.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from .service import (
    SNAPSHOTS_DIR,
    get_comparison_report,
    get_job_status,
    get_live_campaign_summary,
    launch_level_c,
    list_jobs,
)
from ..foc_experimentation.scenario_destruction_service import validate_scenario_destruction

level_c_bp = Blueprint("level_c_orchestrator", __name__)


@level_c_bp.route("/api/level-c/launch", methods=["POST"])
def api_launch():
    body = request.get_json(force=True) or {}
    campaign_id = str(body.get("campaign_id") or "").strip()
    if not campaign_id:
        return jsonify({"error": "campaign_id required"}), 400

    result = launch_level_c(
        campaign_id=campaign_id,
        level_c_repetitions=int(body.get("level_c_repetitions") or 1),
        level_b_repetitions=int(body.get("level_b_repetitions") or 10),
        level_a_repetitions=body.get("level_a_repetitions"),
        confirmation=str(body.get("confirmation") or ""),
        fault_schedule=body.get("fault_schedule"),
    )
    if result.get("error") == "confirmation_required":
        return jsonify(result), 400
    if result.get("error"):
        return jsonify(result), 409
    return jsonify(result), 202


@level_c_bp.route("/api/level-c/status/<job_id>", methods=["GET"])
def api_status(job_id: str):
    state = get_job_status(job_id)
    if not state:
        return jsonify({"error": "job_not_found"}), 404
    # Return full state but trim log to last 100 entries
    log = state.get("log") or []
    state["log"] = log[-100:]
    return jsonify(state), 200


@level_c_bp.route("/api/level-c/jobs", methods=["GET"])
def api_list_jobs():
    return jsonify({"jobs": list_jobs()}), 200


@level_c_bp.route("/api/level-c/live-summary", methods=["GET"])
def api_live_summary():
    return jsonify(get_live_campaign_summary()), 200


@level_c_bp.route("/api/level-c/preflight", methods=["GET"])
def api_preflight():
    import json as _json

    # ── 1. Scenario / blueprint check ────────────────────────────────────────
    try:
        result = validate_scenario_destruction()
    except Exception as exc:
        return jsonify({"ready": False, "message": f"Preflight check error: {exc}", "error": "preflight_exception"}), 200
    if result.get("error"):
        return jsonify({"ready": False, "message": result.get("message", ""), "error": result["error"]}), 200

    blocking = result.get("missing_blocking", [])
    # active_scenario_exists alone is not a blocker for Level C — the scenario
    # will be redeployed fresh; skip it from the hard-block list.
    lc_ready = result.get("ready", False) or (
        blocking == ["active_scenario_exists"]
        or (len(blocking) == 1 and "active_scenario" in blocking[0])
    )
    message = result.get("message", "")
    if lc_ready and not result.get("ready"):
        message = "Scenario already destroyed — Level C will redeploy directly without a destruction phase."

    # ── 2. Baseline snapshot check ───────────────────────────────────────────
    # Level C compares each repetition snapshot against a baseline.
    # A baseline snapshot MUST exist before the campaign can be launched.
    snaps = sorted(
        SNAPSHOTS_DIR.glob("SS-*/snapshot_manifest.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    snapshot_ok = bool(snaps)
    snapshot_id = None
    snapshot_captured_at = None
    if snapshot_ok:
        try:
            snap_data = _json.loads(snaps[0].read_text(encoding="utf-8"))
            snapshot_id = snap_data.get("snapshot_id") or snaps[0].parent.name
            snapshot_captured_at = snap_data.get("captured_at") or snap_data.get("created_at")
        except Exception:
            snapshot_id = snaps[0].parent.name
    else:
        # Hard blocker — no baseline means comparison is impossible
        lc_ready = False
        message = (
            "No baseline scenario snapshot found. "
            "Capture a scenario snapshot first, then launch Level C."
        )

    return jsonify({
        "ready": lc_ready,
        "message": message,
        "missing_blocking": [b for b in blocking if b != "active_scenario_exists"],
        "missing_warnings": result.get("missing_warnings", []),
        "scenario_id": result.get("scenario_id"),
        "blueprint_path": result.get("blueprint_path"),
        "snapshot_ok": snapshot_ok,
        "snapshot_id": snapshot_id,
        "snapshot_captured_at": snapshot_captured_at,
        "snapshot_count": len(snaps),
    }), 200


@level_c_bp.route("/api/level-c/stop/<job_id>", methods=["POST"])
def api_stop(job_id: str):
    from .service import stop_job
    result = stop_job(job_id)
    if result.get("error"):
        return jsonify(result), 404
    return jsonify(result), 200


@level_c_bp.route("/api/level-c/compare/<job_id>", methods=["GET"])
def api_compare(job_id: str):
    report = get_comparison_report(job_id)
    if report is None:
        state = get_job_status(job_id)
        if not state:
            return jsonify({"error": "job_not_found"}), 404
        # Comparison embedded in state
        inline = state.get("comparison_report")
        if inline:
            return jsonify(inline), 200
        return jsonify({"status": "not_yet_compared", "phase": state.get("phase")}), 200
    return jsonify(report), 200
