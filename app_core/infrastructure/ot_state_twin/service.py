"""
OT State Twin -- pilot gemelo digital forense (ver investigacion_y_novedad/05_nombre_y_evolucion.md,
secciones 7/9/11/12).

Objetivo acotado de este piloto: para el PLC de la simulacion Tank Control ya desplegada, capturar
el estado real (Modbus, solo lectura), compararlo contra un baseline/"estado esperado" persistido, y
registrar la divergencia como su propio tipo de evento -- distinto de las alertas de Suricata/Wazuh,
igual que el propio grafo causal del proyecto ya separa la capa "ot" de la capa "alerts"
(app_core/infrastructure/foc_reconstruction/evidence_support/correlation.py).

No inventa ningun mecanismo de lectura nuevo: reutiliza `collect_state_batched()` de
`industrial_ops.py` -- misma resolucion de registros/validacion que ya usan los scripts de ataque
(T0802/T0831/etc. via collect_state(), sin tocar), pero agrupando las 7 lecturas en UNA sola
conexion SSH (mbpoll_read_many) en vez de una por variable, para que un sondeo mas frecuente no
multiplique el coste de handshake SSH. Nunca importa ni llama `mbpoll_write` -- este modulo es, por
diseno, incapaz de escribir en el PLC.

Escopado por repeticion (campaign_id + execution_id): cada repeticion Level B/C tiene su propio
baseline/serie temporal/eventos de divergencia, igual que el resto del proyecto escopa todo por caso
-- un baseline global unico se sobreescribiria entre repeticiones y haria imposible decir "esta
divergencia ocurrio en la repeticion N de la campana X". El uso manual/por API sin especificar scope
cae en el scope "_manual", que es el que se uso para la primera verificacion de humo de este piloto.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app_core.infrastructure.attack.industrial_ops import collect_state_batched
from app_core.infrastructure.attack.industrial_resolver import (
    RUNTIME_DIR,
    ensure_runtime_dir,
    resolve_industrial_context,
)

TWIN_ROOT = RUNTIME_DIR / "ot_state_twin"
MANUAL_SCOPE = "_manual"

EVIDENCE_LAYER = "ot"  # deliberadamente distinto de "alerts" -- ver seccion 12 del documento de investigacion
EVENT_TYPE_DIVERGENCE = "ot_state_divergence_detected"
EVENT_TYPE_CONTROL_LAW_VIOLATION = "ot_control_law_violation_detected"

# TankControl.st (industrial-scenario/PLC/plc_programs/TankControl.st) declara la logica de
# control real del PLC de este escenario. Dos categorias de variable, con dos formas distintas de
# definir "estado esperado" -- comparar ambas contra un unico baseline congelado produciria falsos
# positivos constantes en la segunda categoria, porque cambia por diseno en cada scan de 100ms:
#
#   (a) ESTATICAS -- deberian quedarse fijas en operacion normal; comparables contra un baseline
#       congelado de un unico instante. `level_max` es ademas el blanco real de los ataques
#       T0836/T0831 ya en el catalogo (subir el umbral para que la salida nunca se abra).
#   (b) DINAMICAS -- determinadas, cada scan, por la propia ley de control (funcion de
#       level/level_max/airValveOpenStatus) -- no tiene sentido un baseline congelado; se evaluan
#       con `evaluate_control_law_consistency()` en su lugar.
STATIC_EXPECTED_VARIABLES = {"level_max", "airValveOpenStatus"}
CONTROL_LAW_MODEL_SOURCE = "industrial-scenario/PLC/plc_programs/TankControl.st"

_SCOPE_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_scope_part(value: str) -> str:
    cleaned = _SCOPE_SAFE_RE.sub("_", str(value or "").strip())
    return cleaned or "unknown"


def repetition_scope_id(campaign_id: str, execution_id: str) -> str:
    return f"{_sanitize_scope_part(campaign_id)}__{_sanitize_scope_part(execution_id)}"


def _scope_dir(scope_id: str) -> Path:
    return TWIN_ROOT / _sanitize_scope_part(scope_id)


def _baseline_path(scope_id: str) -> Path:
    return _scope_dir(scope_id) / "baseline.json"


def _samples_path(scope_id: str) -> Path:
    return _scope_dir(scope_id) / "samples.jsonl"


def _divergence_path(scope_id: str) -> Path:
    return _scope_dir(scope_id) / "divergence_events.jsonl"


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_runtime_dir()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_runtime_dir()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def _read_jsonl_tail(path: Path, limit: int) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _all_canonical_names(context: dict) -> list[str]:
    names = {
        reg.get("canonical_name")
        for reg in (context.get("register_map", {}).get("registers", []) or [])
        if reg.get("canonical_name")
    }
    return sorted(names)


def _discover_source() -> tuple[str, str]:
    """Localiza la VM atacante ya desplegada -- es el unico host de esta topologia con
    `mbpoll` instalado y ruta de red al PLC (mismo mecanismo que ya usan los scripts de
    ataque). No es una eleccion conceptualmente ideal para un componente defensivo, pero es
    la que existe hoy en el laboratorio -- se documenta explicitamente, no se oculta."""
    try:
        from app_core.infrastructure.attack.ssh_launcher import manager as attack_ssh_manager

        ip, user = attack_ssh_manager.discover_attacker_instance()
        if ip and user:
            return ip, user
    except Exception:
        pass
    return "not_available", "not_available"


def _state_hash(state: dict) -> str:
    variables = state.get("variables", {}) if isinstance(state, dict) else {}
    normalized = {
        name: entry.get("value")
        for name, entry in sorted(variables.items())
        if isinstance(entry, dict) and entry.get("status") == "ok"
    }
    encoded = json.dumps(normalized, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def list_scopes() -> list[str]:
    if not TWIN_ROOT.exists():
        return []
    return sorted(p.name for p in TWIN_ROOT.iterdir() if p.is_dir())


def get_status(scope_id: str = MANUAL_SCOPE) -> dict:
    context = resolve_industrial_context()
    names = _all_canonical_names(context)
    baseline = _read_json(_baseline_path(scope_id))
    plc_ip = (context.get("register_map", {}).get("plc", {}) or {}).get("ip") or "not_available"
    return {
        "generated_at_utc": utc_now(),
        "scope_id": scope_id,
        "plc_ip": plc_ip,
        "tracked_variables": names,
        "tracked_variable_count": len(names),
        "baseline_captured": baseline is not None,
        "baseline_captured_at_utc": (baseline or {}).get("captured_at_utc"),
        "sample_count": _count_lines(_samples_path(scope_id)),
        "divergence_event_count": _count_lines(_divergence_path(scope_id)),
        "control_law_violation_count": _count_lines(_control_law_events_path(scope_id)),
        "read_only": True,
        "note": (
            "Piloto de gemelo digital forense -- solo lectura Modbus (nunca escribe en el PLC). "
            "Reutiliza la VM atacante ya desplegada como punto de red hacia el PLC, por ser el "
            "unico host de este escenario con mbpoll instalado y ruta a la subred OT."
        ),
    }


def capture_state_sample(names: list[str] | None = None) -> dict:
    context = resolve_industrial_context()
    if not names:
        names = _all_canonical_names(context)
    source_ip, source_user = _discover_source()
    sample = collect_state_batched(context, names, source_ip=source_ip, source_user=source_user)
    sample["state_hash"] = _state_hash(sample)
    return sample


def capture_baseline(scope_id: str = MANUAL_SCOPE, names: list[str] | None = None) -> dict:
    """Captura el estado real actual y lo persiste como el 'estado esperado' del gemelo
    (expectedStateHash, seccion 6/9) para este scope (una repeticion concreta, o "_manual" para
    pruebas/uso manual por API). Nunca automatica salvo cuando el orquestador la invoca
    explicitamente justo antes del ataque de esa repeticion -- ver level_b_repetition_runner.py."""
    sample = capture_state_sample(names)
    baseline = dict(sample)
    baseline["is_baseline"] = True
    baseline["scope_id"] = scope_id
    baseline["captured_as_baseline_at_utc"] = utc_now()
    _write_json(_baseline_path(scope_id), baseline)
    return baseline


def get_baseline(scope_id: str = MANUAL_SCOPE) -> dict | None:
    return _read_json(_baseline_path(scope_id))


def compare_against_baseline(sample: dict, baseline: dict) -> dict:
    """Compara SOLO las variables 'estaticas' (STATIC_EXPECTED_VARIABLES) contra el baseline
    congelado. Las variables 'dinamicas' (nivel, valvulas) cambian por diseno cada scan y se
    evaluan aparte, contra la ley de control real -- ver evaluate_control_law_consistency()."""
    baseline_vars = baseline.get("variables", {}) or {}
    sample_vars = sample.get("variables", {}) or {}
    differences = []
    for name, base_entry in baseline_vars.items():
        if name not in STATIC_EXPECTED_VARIABLES:
            continue
        if not isinstance(base_entry, dict) or base_entry.get("status") != "ok":
            continue
        sample_entry = sample_vars.get(name)
        if not isinstance(sample_entry, dict) or sample_entry.get("status") != "ok":
            differences.append(
                {
                    "canonical_name": name,
                    "reason": "not_available_in_sample",
                    "expected_value": base_entry.get("value"),
                    "observed_value": None,
                }
            )
            continue
        if sample_entry.get("value") != base_entry.get("value"):
            differences.append(
                {
                    "canonical_name": name,
                    "reason": "value_mismatch",
                    "expected_value": base_entry.get("value"),
                    "observed_value": sample_entry.get("value"),
                }
            )
    return {
        "compared_at_utc": utc_now(),
        "expected_state_hash": baseline.get("state_hash") or _state_hash(baseline),
        "observed_state_hash": sample.get("state_hash") or _state_hash(sample),
        "baseline_captured_at_utc": baseline.get("captured_at_utc"),
        "sample_captured_at_utc": sample.get("captured_at_utc"),
        "diverged": bool(differences),
        "differences": differences,
        "evidence_layer": EVIDENCE_LAYER,
    }


def _sample_value(sample: dict, name: str):
    entry = (sample.get("variables") or {}).get(name)
    if isinstance(entry, dict) and entry.get("status") == "ok":
        return entry.get("value")
    return None


def evaluate_control_law_consistency(sample: dict, previous_sample: dict | None = None) -> dict:
    """Compara el estado de las valvulas contra lo que TankControl.st (la logica real y completa
    del PLC de este escenario, no una suposicion) dictaria dado el level/level_max/
    airValveOpenStatus de esta misma lectura:

        si level > level_max y airValveOpenStatus:  abre salida, cierra entrada
        si level < level_max y airValveOpenStatus:  abre entrada, cierra salida
        si level == level_max:                       cierra ambas
        (si airValveOpenStatus es falso y level != level_max, ningun IF del programa toca las
         valvulas ese scan -- en IEC 61131 los outputs no asignados retienen su valor anterior,
         asi que el "esperado" en ese caso concreto es el estado observado en la lectura anterior,
         no algo que se pueda derivar de una sola lectura aislada)

    Una divergencia aqui es una senal forense mas fuerte que un simple cambio de valor: significa
    que el PLC esta haciendo algo que su propio programa, tal como esta escrito, nunca produciria
    por si solo -- por ejemplo T0831 (Manipulation of Control) forzando una valvula por Modbus sin
    pasar por level_max en absoluto, algo que un baseline simple sobre level_max no detectaria."""
    level = _sample_value(sample, "level")
    level_max = _sample_value(sample, "level_max")
    air_valve = _sample_value(sample, "airValveOpenStatus")
    observed = {
        "openInletValve": _sample_value(sample, "openInletValve"),
        "inletValveOpenStatus": _sample_value(sample, "inletValveOpenStatus"),
        "openOutletValve": _sample_value(sample, "openOutletValve"),
        "outletValveOpenStatus": _sample_value(sample, "outletValveOpenStatus"),
    }

    if level is None or level_max is None or air_valve is None:
        return {
            "evaluated_at_utc": utc_now(),
            "applicable": False,
            "reason": "missing_required_reads",
            "evidence_layer": EVIDENCE_LAYER,
        }

    air_valve_on = bool(air_valve)
    expected: dict[str, int] | None
    if level > level_max and air_valve_on:
        branch = "draining"
        expected = {"openInletValve": 0, "inletValveOpenStatus": 0, "openOutletValve": 1, "outletValveOpenStatus": 1}
    elif level < level_max and air_valve_on:
        branch = "filling"
        expected = {"openInletValve": 1, "inletValveOpenStatus": 1, "openOutletValve": 0, "outletValveOpenStatus": 0}
    elif level == level_max:
        branch = "holding_at_setpoint"
        expected = {"openInletValve": 0, "inletValveOpenStatus": 0, "openOutletValve": 0, "outletValveOpenStatus": 0}
    else:
        branch = "indeterminate_air_valve_off"
        expected = None

    if expected is None:
        if not previous_sample:
            return {
                "evaluated_at_utc": utc_now(),
                "applicable": False,
                "branch": branch,
                "reason": "indeterminate_without_previous_sample",
                "evidence_layer": EVIDENCE_LAYER,
            }
        expected = {name: _sample_value(previous_sample, name) for name in observed}

    differences = []
    for name, expected_value in expected.items():
        observed_value = observed.get(name)
        if expected_value is None or observed_value is None:
            continue
        if int(bool(observed_value)) != int(bool(expected_value)):
            differences.append(
                {
                    "canonical_name": name,
                    "reason": "control_law_violation",
                    "expected_value": expected_value,
                    "observed_value": observed_value,
                    "branch": branch,
                }
            )

    return {
        "evaluated_at_utc": utc_now(),
        "applicable": True,
        "branch": branch,
        "level": level,
        "level_max": level_max,
        "air_valve_open": air_valve_on,
        "diverged": bool(differences),
        "differences": differences,
        "evidence_layer": EVIDENCE_LAYER,
        "model_source": CONTROL_LAW_MODEL_SOURCE,
    }


def _control_law_events_path(scope_id: str) -> Path:
    return _scope_dir(scope_id) / "control_law_violations.jsonl"


def _correlate_with_alerts(ts_utc: str | None, window_seconds: float = 30.0) -> list[dict]:
    """Cruza un instante del gemelo (cuando se detecto una divergencia/violacion de ley de
    control) contra las alertas reales de red ya guardadas (Suricata/Wazuh), con su origen ya
    clasificado (classify_alert_origin -- ver monitor/alerts_logger.py). Convierte "el estado
    diverge" en "el estado diverge Y la escritura vino de la VM atacante, no de FUXA" cuando los
    datos lo permiten. Nunca lanza ni bloquea el registro del evento principal si falla."""
    if not ts_utc:
        return []
    try:
        from app_core.infrastructure.monitor.alerts_logger import find_alerts_near

        return find_alerts_near(ts_utc, window_seconds=window_seconds)
    except Exception:
        return []


def record_control_law_violation(scope_id: str, control_law_check: dict, sample: dict) -> dict | None:
    if not control_law_check.get("diverged"):
        return None
    sample_ts = sample.get("captured_at_utc")
    event = {
        "event_type": EVENT_TYPE_CONTROL_LAW_VIOLATION,
        "evidence_layer": EVIDENCE_LAYER,
        "scope_id": scope_id,
        "generated_at_utc": utc_now(),
        "branch": control_law_check.get("branch"),
        "level": control_law_check.get("level"),
        "level_max": control_law_check.get("level_max"),
        "differences": control_law_check.get("differences"),
        "sample_captured_at_utc": sample_ts,
        "target_ip": sample.get("target_ip"),
        "model_source": control_law_check.get("model_source"),
        "correlated_alerts": _correlate_with_alerts(sample_ts),
    }
    _append_jsonl(_control_law_events_path(scope_id), event)
    return event


def get_control_law_events(scope_id: str = MANUAL_SCOPE, limit: int = 50) -> list[dict]:
    return list(reversed(_read_jsonl_tail(_control_law_events_path(scope_id), limit)))


def record_divergence_event(scope_id: str, comparison: dict, sample: dict) -> dict | None:
    if not comparison.get("diverged"):
        return None
    sample_ts = sample.get("captured_at_utc")
    event = {
        "event_type": EVENT_TYPE_DIVERGENCE,
        "evidence_layer": EVIDENCE_LAYER,
        "scope_id": scope_id,
        "generated_at_utc": utc_now(),
        "expected_state_hash": comparison.get("expected_state_hash"),
        "observed_state_hash": comparison.get("observed_state_hash"),
        "differences": comparison.get("differences"),
        "sample_captured_at_utc": sample_ts,
        "target_ip": sample.get("target_ip"),
        "correlated_alerts": _correlate_with_alerts(sample_ts),
    }
    _append_jsonl(_divergence_path(scope_id), event)
    return event


def poll_and_compare(
    scope_id: str = MANUAL_SCOPE,
    names: list[str] | None = None,
    *,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
) -> dict:
    """Un ciclo completo: lee el estado real, lo guarda en el registro continuo de este scope
    (samples.jsonl -- la serie temporal que antes no existia, seccion 10), y lo evalua por DOS
    vias independientes (ver cabecera del modulo para el porque de separarlas):
      1. comparacion contra el baseline congelado, solo para las variables estaticas
         (level_max, airValveOpenStatus);
      2. consistencia contra la ley de control real de TankControl.st, para las variables
         dinamicas (nivel, valvulas) -- usando la lectura anterior de este mismo scope cuando la
         propia ley de control la necesita (rama 'indeterminate_air_valve_off').
    Cualquiera de las dos puede registrar su propio evento, en su propio fichero, capa 'ot'.
    `attack_started_at`/`attack_completed_at` (cuando el orquestador los conoce, ver
    level_b_repetition_runner.py) se guardan en la propia muestra para poder despues calcular
    compute_corroboration_verdict() sin tener que volver a pasarlos."""
    previous_sample = next(iter(get_samples(scope_id, limit=1)), None)

    sample = capture_state_sample(names)
    sample["scope_id"] = scope_id
    if attack_started_at:
        sample["attack_started_at"] = attack_started_at
    if attack_completed_at:
        sample["attack_completed_at"] = attack_completed_at
    _append_jsonl(_samples_path(scope_id), sample)

    control_law_check = evaluate_control_law_consistency(sample, previous_sample)
    control_law_event = record_control_law_violation(scope_id, control_law_check, sample)

    baseline = get_baseline(scope_id)
    comparison = None
    divergence_event = None
    if baseline is not None:
        comparison = compare_against_baseline(sample, baseline)
        divergence_event = record_divergence_event(scope_id, comparison, sample)

    return {
        "scope_id": scope_id,
        "sample": sample,
        "comparison": comparison,
        "divergence_event": divergence_event,
        "control_law_check": control_law_check,
        "control_law_event": control_law_event,
        "note": None if baseline is not None else "no_baseline_captured_yet",
    }


def poll_burst_and_compare(
    scope_id: str = MANUAL_SCOPE,
    *,
    count: int = 3,
    interval_seconds: float = 2.0,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
) -> dict:
    """Varias lecturas reales en sucesion rapida (por defecto 3, cada 2s) -- la aproximacion
    honesta a "sondeo continuo" dentro de las restricciones reales del orquestador: el ataque de
    cada repeticion se lanza de forma SINCRONA y bloqueante (`_launch_attack()` no devuelve el
    control hasta que termina), asi que no es posible sondear "durante" el ataque sin cambiar ese
    modelo de concurrencia -- fuera de alcance de este cambio (ver
    investigacion_y_novedad/06_implementacion_forge_dt.md). Esto da, en su lugar, una traza real
    corta del comportamiento del tanque justo despues del ataque (varios puntos, no una unica
    foto), a un coste acotado: gracias al sondeo por lotes (collect_state_batched, una sola
    conexion SSH por lectura completa), N lecturas cuestan N conexiones, no N x 7."""
    results = []
    for i in range(max(1, count)):
        result = poll_and_compare(
            scope_id,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
        )
        results.append(result)
        if i < count - 1:
            time.sleep(interval_seconds)

    diverged_any = any(
        (r.get("comparison") or {}).get("diverged") or (r.get("control_law_check") or {}).get("diverged")
        for r in results
    )
    return {
        "scope_id": scope_id,
        "burst_count": len(results),
        "interval_seconds": interval_seconds,
        "results": results,
        "diverged_any": diverged_any,
    }


def get_divergence_events(scope_id: str = MANUAL_SCOPE, limit: int = 50) -> list[dict]:
    return list(reversed(_read_jsonl_tail(_divergence_path(scope_id), limit)))


def get_samples(scope_id: str = MANUAL_SCOPE, limit: int = 50) -> list[dict]:
    return list(reversed(_read_jsonl_tail(_samples_path(scope_id), limit)))


def compute_corroboration_verdict(scope_id: str = MANUAL_SCOPE) -> dict:
    """Cruza, para una repeticion concreta, lo que el gemelo detecto (violacion de ley de control
    o divergencia de baseline) contra lo que el IDS/SIEM detecto en la MISMA ventana real de
    ataque (attack_started_at/attack_completed_at, guardados en la muestra por poll_and_compare
    cuando el orquestador los conoce) -- es la novedad propuesta en la sesion de investigacion
    (05_nombre_y_evolucion.md, "puntuacion de corroboracion dual"): ninguna de las dos capas por
    separado responde "¿coinciden fisica y red en que aqui hubo un ataque real?", esto si.

    Cuatro veredictos posibles:
      - corroborado:   el gemelo detecto Y hubo alertas reales de la VM atacante en la ventana.
      - solo_gemelo:   el gemelo detecto pero ninguna alerta de red coincide -- posible evasion
                       de firmas, o una escritura que el IDS no reconoce como ataque.
      - solo_alerta:   hubo alertas de la VM atacante pero el estado nunca salio de su propia ley
                       de control -- posible falso positivo del IDS, o el efecto fue mitigado.
      - ninguno:       no hay evidencia de ninguna de las dos capas para esta ventana.

    Sin ventana de ataque conocida (repeticiones antiguas, antes de este cambio, o uso manual) se
    devuelve 'attack_window_unknown' en vez de adivinar."""
    latest_sample = next(iter(get_samples(scope_id, limit=1)), {})
    attack_started_at = latest_sample.get("attack_started_at")
    attack_completed_at = latest_sample.get("attack_completed_at")

    control_events = get_control_law_events(scope_id, limit=1000)
    divergence_events = get_divergence_events(scope_id, limit=1000)
    twin_detected = bool(control_events) or bool(divergence_events)

    if not attack_started_at or not attack_completed_at:
        return {
            "scope_id": scope_id,
            "verdict": "attack_window_unknown",
            "twin_detected": twin_detected,
            "alert_detected": None,
            "control_law_violation_count": len(control_events),
            "state_divergence_count": len(divergence_events),
            "attacker_alerts_in_window_count": None,
            "attack_started_at": attack_started_at,
            "attack_completed_at": attack_completed_at,
            "evaluated_at_utc": utc_now(),
            "note": "no attack_started_at/attack_completed_at recorded for this scope's samples",
        }

    attacker_alerts: list[dict] = []
    try:
        from app_core.infrastructure.monitor.alerts_logger import find_alerts_in_range

        window_alerts = find_alerts_in_range(attack_started_at, attack_completed_at)
        attacker_alerts = [a for a in window_alerts if a.get("origin") == "attacker_vm"]
    except Exception:
        pass
    alert_detected = bool(attacker_alerts)

    if twin_detected and alert_detected:
        verdict = "corroborado"
    elif twin_detected:
        verdict = "solo_gemelo"
    elif alert_detected:
        verdict = "solo_alerta"
    else:
        verdict = "ninguno"

    return {
        "scope_id": scope_id,
        "verdict": verdict,
        "twin_detected": twin_detected,
        "alert_detected": alert_detected,
        "control_law_violation_count": len(control_events),
        "state_divergence_count": len(divergence_events),
        "attacker_alerts_in_window_count": len(attacker_alerts),
        "attacker_alerts_in_window": attacker_alerts,
        "attack_started_at": attack_started_at,
        "attack_completed_at": attack_completed_at,
        "evaluated_at_utc": utc_now(),
    }


# --- Entradas de conveniencia para el orquestador de repeticiones Level B/C ---
# Nunca lanzan: cualquier fallo (PLC inalcanzable, mbpoll no disponible, mapa no resuelto) se
# devuelve como {"ok": False, "reason": ...} para que quien orquesta una repeticion real decida
# como registrarlo (aviso, no bloqueo) sin que una repeticion cientifica real se caiga por esto.


def capture_baseline_for_repetition(campaign_id: str, execution_id: str) -> dict:
    scope_id = repetition_scope_id(campaign_id, execution_id)
    try:
        baseline = capture_baseline(scope_id)
        return {"ok": True, "scope_id": scope_id, "baseline": baseline}
    except Exception as exc:
        return {"ok": False, "scope_id": scope_id, "reason": str(exc)}


def poll_and_compare_for_repetition(
    campaign_id: str,
    execution_id: str,
    *,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
) -> dict:
    scope_id = repetition_scope_id(campaign_id, execution_id)
    try:
        result = poll_and_compare(
            scope_id,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
        )
        result["ok"] = True
        return result
    except Exception as exc:
        return {"ok": False, "scope_id": scope_id, "reason": str(exc)}


def poll_burst_and_compare_for_repetition(
    campaign_id: str,
    execution_id: str,
    *,
    attack_started_at: str | None = None,
    attack_completed_at: str | None = None,
    count: int = 3,
    interval_seconds: float = 2.0,
) -> dict:
    scope_id = repetition_scope_id(campaign_id, execution_id)
    try:
        result = poll_burst_and_compare(
            scope_id,
            count=count,
            interval_seconds=interval_seconds,
            attack_started_at=attack_started_at,
            attack_completed_at=attack_completed_at,
        )
        result["ok"] = True
        return result
    except Exception as exc:
        return {"ok": False, "scope_id": scope_id, "reason": str(exc)}
