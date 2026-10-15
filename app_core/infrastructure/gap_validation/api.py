from __future__ import annotations

"""Flask blueprint for the Gap Registry, Experiment Catalog, and the
validation-campaign orchestrator. The only endpoint here that performs a
real action against infrastructure is the campaign launch (POST) -- it
applies/reverts faults exactly as fault_injection's own on-demand buttons
do, scoped to its own 'gapval-' job-id space (see orchestrator.py's own
docstring); every other endpoint only reads already-persisted data."""

from flask import Blueprint, jsonify, request

from .registry import GAP_REGISTRY, get_gap
from .catalog import EXPERIMENT_CATALOG, experiments_for_gap, get_experiment
from .orchestrator import get_validation_campaign_status, launch_validation_campaign, list_validation_campaigns
from .evaluator import evaluate_experiment_run
from .report import build_gap_validation_report

gap_validation_bp = Blueprint("gap_validation", __name__)


@gap_validation_bp.route("/api/gap-validation/gaps", methods=["GET"])
def api_list_gaps():
    return jsonify({"ok": True, "gaps": GAP_REGISTRY}), 200


@gap_validation_bp.route("/api/gap-validation/gaps/<gap_id>", methods=["GET"])
def api_get_gap(gap_id: str):
    gap = get_gap(gap_id)
    if not gap:
        return jsonify({"ok": False, "error": f"unknown gap_id={gap_id!r}"}), 404
    return jsonify({"ok": True, "gap": gap, "experiments": experiments_for_gap(gap_id)}), 200


@gap_validation_bp.route("/api/gap-validation/experiments", methods=["GET"])
def api_list_experiments():
    return jsonify({"ok": True, "experiments": EXPERIMENT_CATALOG}), 200


@gap_validation_bp.route("/api/gap-validation/experiments/<experiment_id>", methods=["GET"])
def api_get_experiment(experiment_id: str):
    experiment = get_experiment(experiment_id)
    if not experiment:
        return jsonify({"ok": False, "error": f"unknown experiment_id={experiment_id!r}"}), 404
    return jsonify({"ok": True, "experiment": experiment}), 200


@gap_validation_bp.route("/api/gap-validation/campaigns", methods=["GET"])
def api_list_campaigns():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify({"ok": True, "campaigns": list_validation_campaigns(limit=limit)}), 200


@gap_validation_bp.route("/api/gap-validation/campaigns", methods=["POST"])
def api_launch_campaign():
    body = request.get_json(silent=True) or {}
    experiment_id = body.get("experiment_id")
    if not experiment_id:
        return jsonify({"ok": False, "error": "experiment_id is required"}), 400
    repetitions = body.get("repetitions", 4)
    target_node_role = body.get("target_node_role")
    result = launch_validation_campaign(experiment_id, repetitions=repetitions, target_node_role=target_node_role)
    return jsonify(result), (200 if result.get("ok") else 400)


@gap_validation_bp.route("/api/gap-validation/campaigns/<job_id>", methods=["GET"])
def api_get_campaign(job_id: str):
    result = get_validation_campaign_status(job_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@gap_validation_bp.route("/api/gap-validation/campaigns/<job_id>/report", methods=["GET"])
def api_evaluate_campaign(job_id: str):
    result = evaluate_experiment_run(job_id)
    return jsonify(result), (200 if result.get("ok") else 400)


@gap_validation_bp.route("/api/gap-validation/gaps/<gap_id>/report", methods=["GET"])
def api_gap_report(gap_id: str):
    result = build_gap_validation_report(gap_id)
    return jsonify(result), (200 if result.get("ok") else 404)
