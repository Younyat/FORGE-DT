"""FORGE-DT metrics engine (M7) + CPR/WCPR reporting (M6) -- read-only API,
all computed on-demand from already-real data (M1/M4/M5), never cached."""
from __future__ import annotations

import csv
import io

from flask import Blueprint, Response, jsonify, request, send_from_directory

from ..foc_reconstruction.foc_config import PROJECT_ROOT
from .service import compute_ablation_report, compute_cpr_report, get_metrics_report

forge_dt_metrics_bp = Blueprint("forge_dt_metrics", __name__)
STATIC_DIR = PROJECT_ROOT / "app_core" / "static"


@forge_dt_metrics_bp.route("/forge_dt_metrics")
def forge_dt_metrics_view():
    return send_from_directory(STATIC_DIR, "forge_dt_metrics.html")


@forge_dt_metrics_bp.route("/api/forge-dt-metrics/report", methods=["GET"])
def api_report():
    result = get_metrics_report(
        case_id=request.args.get("case_id"),
        campaign_id=request.args.get("campaign_id"),
        source=request.args.get("source"),
        tolerance_seconds=float(request.args.get("tolerance_seconds", 5.0)),
    )
    return jsonify(result), 200


@forge_dt_metrics_bp.route("/api/forge-dt-metrics/report.csv", methods=["GET"])
def api_report_csv():
    result = get_metrics_report(
        case_id=request.args.get("case_id"),
        campaign_id=request.args.get("campaign_id"),
        source=request.args.get("source"),
        tolerance_seconds=float(request.args.get("tolerance_seconds", 5.0)),
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["metric", "value", "n", "note"])
    writer.writerow(["IRR", result["irr"].get("irr"), result["irr"].get("n_measured"), result["irr"].get("note") or ""])
    writer.writerow(["TOR", result["tor"].get("tor"), result["tor"].get("n_realized"), result["tor"].get("note") or ""])
    writer.writerow(["median_observation_latency_seconds", result["tor"].get("median_latency_seconds"), "", ""])
    writer.writerow(["IER", result["ier"].get("ier"), result["ier"].get("n_realized"), result["ier"].get("note") or ""])
    writer.writerow(["ESR", result["esr"].get("esr"), result["esr"].get("n_links"), result["esr"].get("note") or ""])
    for metric, note in result["unavailable_metrics"].items():
        writer.writerow([metric, "", "", note])
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=forge_dt_metrics.csv"})


@forge_dt_metrics_bp.route("/api/forge-dt-metrics/cpr/<job_id>", methods=["GET"])
def api_cpr(job_id: str):
    result = compute_cpr_report(job_id)
    return jsonify(result), (200 if result.get("ok") else 404)


@forge_dt_metrics_bp.route("/api/forge-dt-metrics/ablation/<job_id>", methods=["GET"])
def api_ablation(job_id: str):
    result = compute_ablation_report(
        job_id,
        campaign_id=request.args.get("campaign_id"),
        tolerance_seconds=float(request.args.get("tolerance_seconds", 5.0)),
    )
    return jsonify(result), (200 if result.get("ok") else 404)
