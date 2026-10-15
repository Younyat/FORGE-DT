"""
OT State Twin -- Flask blueprint, todo de solo lectura hacia el PLC (nunca escribe registros).
Ver service.py para el porque de cada decision.

Todas las rutas aceptan `?scope=<scope_id>` (por defecto "_manual") para consultar/operar sobre el
gemelo de una repeticion Level B/C concreta -- el orquestador usa
`repetition_scope_id(campaign_id, execution_id)` internamente para generar ese mismo id.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from .service import (
    MANUAL_SCOPE,
    capture_baseline,
    compute_corroboration_verdict,
    get_baseline,
    get_control_law_events,
    get_divergence_events,
    get_samples,
    get_status,
    list_scopes,
    poll_and_compare,
)

ot_state_twin_bp = Blueprint("ot_state_twin", __name__)


def _scope() -> str:
    return request.args.get("scope", default=MANUAL_SCOPE, type=str) or MANUAL_SCOPE


@ot_state_twin_bp.route("/api/ot-state-twin/status", methods=["GET"])
def api_status():
    return jsonify(get_status(_scope())), 200


@ot_state_twin_bp.route("/api/ot-state-twin/scopes", methods=["GET"])
def api_scopes():
    return jsonify({"scopes": list_scopes()}), 200


@ot_state_twin_bp.route("/api/ot-state-twin/baseline", methods=["GET"])
def api_get_baseline():
    baseline = get_baseline(_scope())
    if not baseline:
        return jsonify({"error": "no_baseline_captured_yet", "scope_id": _scope()}), 404
    return jsonify(baseline), 200


@ot_state_twin_bp.route("/api/ot-state-twin/baseline", methods=["POST"])
def api_capture_baseline():
    baseline = capture_baseline(_scope())
    return jsonify(baseline), 201


@ot_state_twin_bp.route("/api/ot-state-twin/poll", methods=["POST"])
def api_poll():
    result = poll_and_compare(_scope())
    return jsonify(result), 200


@ot_state_twin_bp.route("/api/ot-state-twin/events", methods=["GET"])
def api_events():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify({"scope_id": _scope(), "events": get_divergence_events(_scope(), limit=limit)}), 200


@ot_state_twin_bp.route("/api/ot-state-twin/samples", methods=["GET"])
def api_samples():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify({"scope_id": _scope(), "samples": get_samples(_scope(), limit=limit)}), 200


@ot_state_twin_bp.route("/api/ot-state-twin/control-law-events", methods=["GET"])
def api_control_law_events():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify({"scope_id": _scope(), "events": get_control_law_events(_scope(), limit=limit)}), 200


@ot_state_twin_bp.route("/api/ot-state-twin/correlate", methods=["GET"])
def api_correlate():
    """Consulta ad-hoc: dado un instante (?ts=<ISO8601>), devuelve las alertas reales de red
    (Suricata/Wazuh) en esa ventana, ya con su origen clasificado -- util para investigar a mano
    un evento de divergencia ya registrado, o cualquier otro instante de interes."""
    from app_core.infrastructure.monitor.alerts_logger import find_alerts_near

    ts = request.args.get("ts", type=str)
    if not ts:
        return jsonify({"error": "missing_ts_query_param"}), 400
    window = request.args.get("window_seconds", default=30.0, type=float)
    return jsonify({"ts": ts, "window_seconds": window, "alerts": find_alerts_near(ts, window_seconds=window)}), 200


@ot_state_twin_bp.route("/api/ot-state-twin/verdict", methods=["GET"])
def api_verdict():
    """Puntuacion de corroboracion dual para una repeticion (?scope=...): cruza lo que el gemelo
    detecto (ley de control/baseline) contra las alertas reales de la VM atacante en la misma
    ventana real de ataque -- ver compute_corroboration_verdict() para el porque de cada veredicto."""
    return jsonify(compute_corroboration_verdict(_scope())), 200
