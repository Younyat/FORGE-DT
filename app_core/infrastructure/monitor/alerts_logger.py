import os
import json
import select
import subprocess
import uuid
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional


# Carpeta de salida (FORensics), aunque el módulo viva en MONITOR
FORENSICS_ALERTS_BASE = os.path.abspath("app_core/infrastructure/forensics/alerts_store")


def _safe_notify_foc(event_type: str, payload: Dict[str, Any]) -> None:
    try:
        from app_core.infrastructure.foc_reconstruction import safe_notify_foc

        safe_notify_foc(event_type, payload)
    except Exception:
        return


def _utc_now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _append_jsonl(path: str, obj: Dict[str, Any]) -> None:
    _safe_mkdir(os.path.dirname(path))
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _load_runtime_asset_inventory() -> list:
    """Inventario REAL de todas las instancias desplegadas para el escenario actual.
    `industrial_runtime_assets.json` (generado por `discover_runtime_assets()`, OpenStack SDK real,
    no inventado) es la UNICA fuente que trae, para cada maquina -- PLC, FUXA, atacante, victima,
    monitor -- tanto su IP privada como su IP flotante. Es deliberadamente mejor fuente que
    consultar OpenStack en vivo por SSH/API en cada alerta: es un fichero ya persistido, no depende
    de una conexion en vivo (que en este entorno de desarrollo falla: "Auth plugin requires
    parameters"), y ya incluye la IP PRIVADA de cada rol -- la que de verdad ve un sensor de red
    dentro de la subred OT (net_private_01), no solo la flotante de acceso externo."""
    try:
        from app_core.infrastructure.attack.industrial_resolver import RUNTIME_ASSETS_PATH

        data = json.loads(RUNTIME_ASSETS_PATH.read_text(encoding="utf-8"))
        return data.get("inventory_candidates") or []
    except Exception:
        return []


def _infer_role_from_instance_name(name: Optional[str]) -> str:
    n = (name or "").lower()
    if "plc" in n:
        return "industrial_plc"
    if "fuxa" in n or "scada" in n:
        return "industrial_scada"
    if n.startswith("attack") or "attacker" in n:
        return "attacker_vm"
    if n.startswith("victim"):
        return "victim_host"
    if n.startswith("monitor"):
        return "monitor_host"
    return "unrecognized_role"


def resolve_ip_to_asset(ip: Optional[str]) -> Dict[str, Any]:
    """Resuelve una IP (privada o flotante) contra el inventario REAL de instancias ya desplegadas
    para el escenario actual. No infiere ni supone nada sobre IPs que no aparecen literalmente en
    el inventario -- esas quedan sin resolver (matched=False), nunca se les asigna un rol al azar."""
    if not ip:
        return {"matched": False, "reason": "no_ip"}
    for asset in _load_runtime_asset_inventory():
        candidates = {asset.get("private_ip"), asset.get("floating_ip")}
        for net in asset.get("networks") or []:
            if isinstance(net, dict):
                candidates.add(net.get("ip"))
        candidates.discard(None)
        if ip in candidates:
            matched_as = (
                "private" if ip == asset.get("private_ip")
                else "floating" if ip == asset.get("floating_ip")
                else "network_entry"
            )
            return {
                "matched": True,
                "role": _infer_role_from_instance_name(asset.get("name")),
                "instance_name": asset.get("name"),
                "instance_id": asset.get("instance_id"),
                "ip_matched_as": matched_as,
            }
    return {"matched": False, "reason": "ip_not_in_current_scenario_inventory"}


def classify_alert_origin(src_ip: Optional[str]) -> Dict[str, Any]:
    """Clasifica el origen real de una alerta (tipicamente una escritura Modbus) resolviendo su
    src.ip -- ya presente en cada alerta via monitor_ataques.sh's `data.src_ip` -- contra el
    inventario REAL y completo de instancias del escenario actual (PLC, FUXA, atacante, victima,
    monitor; ambas IPs de cada una -- ver resolve_ip_to_asset()). Puramente informativo: NO decide
    severidad (eso sigue siendo compute_severity() sin cambios). Responde con el nombre e id real
    de la instancia cuando se identifica, no solo una categoria generica -- para que sirva
    directamente en una investigacion, no solo como una etiqueta. Nunca lanza -- cualquier fallo de
    resolucion cae en 'unknown', nunca en una suposicion."""
    if not src_ip or src_ip in {"", "Interno", "0.0.0.0"}:
        return {"origin": "unknown", "origin_reason": "no_src_ip_available"}
    try:
        resolved = resolve_ip_to_asset(src_ip)
    except Exception:
        resolved = {"matched": False, "reason": "resolution_error"}
    if resolved.get("matched"):
        return {
            "origin": resolved["role"],
            "origin_reason": f"src_ip_matches_{resolved['ip_matched_as']}_ip_of_{resolved.get('instance_name') or 'unknown_instance'}",
            "origin_instance_name": resolved.get("instance_name"),
            "origin_instance_id": resolved.get("instance_id"),
        }
    return {"origin": "unknown", "origin_reason": "src_ip_does_not_match_any_known_asset_in_current_scenario"}


def _parse_alert_ts(value: Optional[str]):
    """Las alertas reales traen ts_utc en mas de un formato segun la fuente (Wazuh/Suricata usan
    sufijo 'Z'; el resto del proyecto usa 'datetime.isoformat()' con '+00:00') -- se normalizan
    ambos aqui en vez de asumir uno solo."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def find_alerts_in_range(lower_ts: str, upper_ts: str, base_dir: str = FORENSICS_ALERTS_BASE) -> list:
    """Busca, en TODAS las sesiones ya guardadas de alerts_store, las alertas reales cuyo ts_utc
    cae dentro de [lower_ts, upper_ts] -- y les añade el origen real (classify_alert_origin). Base
    compartida de find_alerts_near() (ventana simetrica) y de compute_corroboration_verdict()
    (ventana real de un ataque, attack_started_at/attack_completed_at). Nunca lanza -- una sesion
    con datos corruptos o un fichero inaccesible simplemente se salta."""
    lower = _parse_alert_ts(lower_ts)
    upper = _parse_alert_ts(upper_ts)
    if lower is None or upper is None:
        return []
    if lower > upper:
        lower, upper = upper, lower

    from datetime import timedelta

    matches: list = []
    try:
        session_dirs = sorted(os.listdir(base_dir))
    except Exception:
        return matches

    for session_id in session_dirs:
        session_path = os.path.join(base_dir, session_id)
        alerts_path = os.path.join(session_path, "alerts.jsonl")
        if not os.path.isfile(alerts_path):
            continue
        try:
            # Descarte barato antes de parsear linea a linea: si la ultima escritura de esta
            # sesion es muy anterior al rango buscado, o la sesion se creo muy despues de que
            # termine el rango, no puede contener nada relevante.
            mtime = datetime.fromtimestamp(os.path.getmtime(alerts_path), tz=timezone.utc)
            if mtime < lower - timedelta(hours=1):
                continue
        except Exception:
            pass

        try:
            with open(alerts_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        primary = json.loads(line)
                    except Exception:
                        continue
                    alert_ts = _parse_alert_ts(primary.get("ts_utc"))
                    if alert_ts is None or not (lower <= alert_ts <= upper):
                        continue
                    origin = classify_alert_origin((primary.get("src") or {}).get("ip"))
                    matches.append(
                        {
                            "session_id": session_id,
                            "event_id": primary.get("event_id"),
                            "ts_utc": primary.get("ts_utc"),
                            "signature": primary.get("signature"),
                            "rule_id": primary.get("rule_id"),
                            "rule_level": primary.get("rule_level"),
                            "src_ip": (primary.get("src") or {}).get("ip"),
                            **origin,
                        }
                    )
        except Exception:
            continue

    matches.sort(key=lambda m: m.get("ts_utc") or "")
    return matches


def find_alerts_near(ts_utc: str, window_seconds: float = 30.0, base_dir: str = FORENSICS_ALERTS_BASE) -> list:
    """Busca alertas reales dentro de +/- window_seconds de un instante dado. Pensado para
    responder "que mas paso justo cuando el gemelo detecto esta divergencia/violacion de ley de
    control", cruzando dos piezas de evidencia ya existentes (el estado del PLC y las alertas de
    red) sin inventar ninguna nueva."""
    target = _parse_alert_ts(ts_utc)
    if target is None:
        return []
    from datetime import timedelta

    window = timedelta(seconds=abs(window_seconds))
    return find_alerts_in_range(
        (target - window).isoformat(), (target + window).isoformat(), base_dir=base_dir
    )


class AlertsLogger:
    """
    Pre-case detection log:
      - Primary: alerts.jsonl (normalizado + raw)
      - Derived: triage.jsonl (native score / severity / decision)
    """

    def __init__(self, base_dir: str = FORENSICS_ALERTS_BASE):
        self.base_dir = os.path.abspath(base_dir)
        _safe_mkdir(self.base_dir)
        self.session_id = self._ensure_session()

    def _ensure_session(self) -> str:
        sid = f"ALERTS-{_utc_now_compact()}"
        sdir = os.path.join(self.base_dir, sid)
        _safe_mkdir(sdir)

        meta_path = os.path.join(sdir, "session.json")
        if not os.path.exists(meta_path):
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session_id": sid,
                        "ts_utc_created": _utc_now_iso(),
                        "note": "Pre-case detection log (primary alerts + derived triage).",
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        return sid

    def _paths(self) -> Dict[str, str]:
        sdir = os.path.join(self.base_dir, self.session_id)
        return {
            "alerts": os.path.join(sdir, "alerts.jsonl"),
            "triage": os.path.join(sdir, "triage.jsonl"),
        }

    def compute_severity(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Usa el score nativo de la fuente cuando esté disponible.
        Para Wazuh:
          - native_score = rule_level
          - native_scale = wazuh_rule_level_0_16

        No inventa score_0_100.
        """
        source = (ev.get("source") or "").lower()
        reasons = {"source": source or "unknown"}

        if source == "wazuh":
            level = ev.get("rule_level")
            raw_alert = (((ev.get("raw") or {}).get("data") or {}).get("alert") or {})
            raw_signature_id = str(raw_alert.get("signature_id") or "")
            raw_signature = str(raw_alert.get("signature") or ev.get("signature") or "").lower()
            raw_metadata = raw_alert.get("metadata") or {}
            attack_stages = {
                str(item).strip().lower()
                for item in (raw_metadata.get("attack_stage") or [])
                if str(item).strip()
            }
            confidence_values = {
                str(item).strip().lower()
                for item in (raw_metadata.get("confidence") or [])
                if str(item).strip()
            }

            try:
                level = int(level)
            except Exception:
                level = None

            reasons["rule_level"] = level
            reasons["suricata_signature_id"] = raw_signature_id or None
            reasons["suricata_attack_stage"] = sorted(attack_stages)
            reasons["suricata_confidence"] = sorted(confidence_values)

            # Wazuh ingests Suricata eve.json through a generic JSON localfile rule
            # (commonly level 3 / rule 86601). For ICS Modbus write detections, the
            # generic Wazuh rule level is too weak to represent the underlying event.
            if (
                raw_signature_id in {"910836101", "910836102", "910836103", "910836104"}
                or "modbus write" in raw_signature
                or ("control_manipulation" in attack_stages and "high" in confidence_values)
            ):
                reasons["derived_policy"] = "ics_modbus_write_override"
                return {
                    "native_score": level,
                    "native_scale": "wazuh_rule_level_0_16",
                    "severity": "HIGH",
                    "recommend_forensics": True,
                    "reasons": reasons,
                }

            if level is None:
                return {
                    "native_score": None,
                    "native_scale": "wazuh_rule_level_0_16",
                    "severity": "UNKNOWN",
                    "recommend_forensics": False,
                    "reasons": reasons,
                }

            # Clasificación visual simple basada en el propio nivel nativo.
           
            if level >= 12:
                sev = "CRITICAL"
            elif level >= 7:
                sev = "HIGH"
            elif level >= 5:
                sev = "MEDIUM"
            else:
                sev = "LOW"

            return {
                "native_score": level,
                "native_scale": "wazuh_rule_level_0_16",
                "severity": sev,
                "recommend_forensics": level >= 10,
                "reasons": reasons,
            }

        # Para fuentes no-Wazuh, dejamos constancia pero no inventamos score.
        return {
            "native_score": None,
            "native_scale": "none",
            "severity": "UNKNOWN",
            "recommend_forensics": False,
            "reasons": reasons,
        }

    def log_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        paths = self._paths()

        event_id = ev.get("event_id") or uuid.uuid4().hex

        # 1) ts_utc (fuente de verdad)
        ts_utc = ev.get("ts_utc") or _utc_now_iso()

        # 2) ts_epoch coherente: si no viene, lo derivamos de ts_utc (UTC)
        ts_epoch = ev.get("ts_epoch")
        if ts_epoch is None:
            derived = iso_to_epoch(ts_utc)
            ts_epoch = derived if derived > 0 else time.time()

        # 3) Construir PRIMARY
        primary = {
            "event_id": event_id,
            "ts_utc": ts_utc,
            "ts_epoch": ts_epoch,
            "source": ev.get("source", "unknown"),
            "alert_type": ev.get("alert_type", "unknown"),
            "protocol": ev.get("protocol", "unknown"),
            "src": ev.get("src", {}),
            "dst": ev.get("dst", {}),
            "rule_id": ev.get("rule_id"),
            "rule_level": ev.get("rule_level"),
            "signature": ev.get("signature"),
            "agent": ev.get("agent"),
            "raw": ev.get("raw"),
        }

        # 4) Guardar PRIMARY en alerts_store
        _append_jsonl(paths["alerts"], primary)

        # 5) Guardar DERIVED triage
        triage = self.compute_severity(primary)
        # Campo informativo aparte, no toca compute_severity()/severidad: de donde vino realmente
        # esta escritura (VM atacante ya desplegada vs. FUXA), usando el src.ip que la alerta ya
        # trae de origen -- ver classify_alert_origin(). Fusionado dentro de `triage` (no solo en
        # `derived`) para que tambien llegue al valor de retorno y a la notificacion FOC de abajo.
        triage.update(classify_alert_origin((primary.get("src") or {}).get("ip")))
        derived = {
            "event_id": event_id,
            "ts_utc": _utc_now_iso(),
            **triage,
        }
        _append_jsonl(paths["triage"], derived)

        # 6) Si el caller nos pasa case_dir, guardamos el PRIMARY dentro del CASE
        case_rel = None
        case_dir = (ev.get("case_dir") or "").strip()

        # Fallback: si no viene case_dir, usa el CASE activo
        if not case_dir:
            case_dir = _read_active_case_dir() or ""

        if case_dir:
            case_rel = _write_case_alert(case_dir, primary)

        # 7) Respuesta
        _safe_notify_foc(
            "alert_detected",
            {
                "event_id": event_id,
                "session_id": self.session_id,
                "ts_utc": ts_utc,
                "source": primary.get("source"),
                "alert_type": primary.get("alert_type"),
                "signature": primary.get("signature"),
                "rule_id": primary.get("rule_id"),
                "rule_level": primary.get("rule_level"),
                "severity": triage.get("severity"),
                "recommend_forensics": triage.get("recommend_forensics"),
                "origin": triage.get("origin"),
                "origin_reason": triage.get("origin_reason"),
                "case_rel": case_rel,
            },
        )
        return {
            "primary": primary,
            "triage": triage,
            "case_rel": case_rel,
            "session_id": self.session_id,
        }


def iso_to_epoch(iso_utc: str) -> float:
    """
    Convierte timestamps ISO UTC a epoch (UTC).
    Soporta:
      - 2026-02-19T15:31:06Z
      - 2026-02-19T15:31:06.029+0000
      - 2026-02-19T15:31:06.029+00:00
    """
    s = (iso_utc or "").strip()
    if not s:
        return 0.0

    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            # normaliza +0000 -> +00:00
            if len(s) >= 5 and (s[-5] in ["+", "-"]) and s[-3] != ":":
                s = s[:-2] + ":" + s[-2:]
            dt = datetime.fromisoformat(s)

        return dt.astimezone(timezone.utc).timestamp()
    except Exception:
        return 0.0


def _atomic_write_json(path: str, obj: Dict[str, Any]) -> None:
    """
    Escritura atómica para evitar ficheros corruptos si el proceso muere.
    """
    tmp = f"{path}.tmp"
    _safe_mkdir(os.path.dirname(path))
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _write_case_alert(case_dir: str, alert_obj: Dict[str, Any]) -> Optional[str]:
    """
    Guarda el alert PRIMARY dentro del CASE:
      CASE/.../alerts/event_<event_id>.json
    Devuelve rel_path o None si no se pudo.
    """
    try:
        if not case_dir:
            return None
        case_dir = os.path.abspath(case_dir)
        if not os.path.isdir(case_dir):
            return None

        alerts_dir = os.path.join(case_dir, "alerts")
        _safe_mkdir(alerts_dir)

        event_id = str(alert_obj.get("event_id") or "").strip()
        if not event_id:
            return None

        filename = f"event_{event_id}.json"
        abs_path = os.path.join(alerts_dir, filename)

        _atomic_write_json(abs_path, alert_obj)

        return os.path.join("alerts", filename)
    except Exception:
        return None


def attach_alert_to_case(case_dir: str, alert_event_id: str, base_dir: str = FORENSICS_ALERTS_BASE) -> Optional[str]:
    """
    Copia/adjunta al CASE un alert ya existente en alerts_store, buscándolo por event_id.
    - Busca recursivamente en alerts_store/ALERTS-*/alerts.jsonl
    - Cuando lo encuentra, escribe CASE/alerts/event_<id>.json
    Devuelve rel_path dentro del CASE o None si no se encuentra/no se pudo.
    """
    case_dir = os.path.abspath(case_dir or "")
    if not case_dir or not os.path.isdir(case_dir):
        return None

    alert_event_id = (alert_event_id or "").strip()
    if not alert_event_id:
        return None

    base_dir = os.path.abspath(base_dir or "")
    if not os.path.isdir(base_dir):
        return None

    sessions = []
    for name in os.listdir(base_dir):
        if name.startswith("ALERTS-"):
            p = os.path.join(base_dir, name)
            if os.path.isdir(p):
                sessions.append(p)
    sessions.sort(reverse=True)

    for sdir in sessions:
        alerts_path = os.path.join(sdir, "alerts.jsonl")
        if not os.path.isfile(alerts_path):
            continue
        try:
            with open(alerts_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = (line or "").strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    if str(obj.get("event_id") or "").strip() == alert_event_id:
                        return _write_case_alert(case_dir, obj)
        except Exception:
            continue

    return None


ACTIVE_CASE_PTR = os.path.abspath("app_core/infrastructure/forensics/evidence_store/_active_case.txt")


def _read_active_case_dir() -> Optional[str]:
    """
    Lee el CASE activo desde evidence_store/_active_case.txt.
    Devuelve ruta absoluta o None.
    """
    try:
        if not os.path.isfile(ACTIVE_CASE_PTR):
            return None
        with open(ACTIVE_CASE_PTR, "r", encoding="utf-8") as f:
            p = (f.readline() or "").strip()
        if not p:
            return None
        p = os.path.abspath(p)
        return p if os.path.isdir(p) else None
    except Exception:
        return None


DEFAULT_MONITOR_SCRIPT_PATH = os.path.abspath("app_core/infrastructure/monitor/scripts/monitor_ataques.sh")
DEFAULT_MONITOR_SSH_KEY_PATH = os.path.expanduser("~/.ssh/my_key")


def _normalize_nics_alert(ev: Dict[str, Any], case_dir: Optional[str] = None) -> Dict[str, Any]:
    normalized = {
        "event_id": ev.get("event_id"),
        "ts_utc": ev.get("ts_utc"),
        "source": ev.get("source", "wazuh"),
        "alert_type": ev.get("alert_type", "unknown"),
        "protocol": ev.get("protocol", "unknown"),
        "rule_id": ev.get("rule_id"),
        "rule_level": ev.get("rule_level"),
        "description": ev.get("description"),
        "signature": ev.get("signature"),
        "src": ev.get("src", {}),
        "dst": ev.get("dst", {}),
        "agent": ev.get("agent"),
        "raw": ev.get("raw", ev),
    }
    if case_dir:
        normalized["case_dir"] = case_dir
    return normalized


def run_monitor_session(
    monitor_ip: str,
    ssh_user: str = "ubuntu",
    ssh_key: Optional[str] = None,
    *,
    on_alert: Optional[Callable[[Dict[str, Any]], bool]] = None,
    stop_after_seconds: Optional[float] = 600,
    case_dir: Optional[str] = None,
    script_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Blocking, Flask-free counterpart to the /live_wazuh_stream SSE route in
    app_core.infrastructure.monitor.ssh_launcher. Spawns the same SSH monitor
    script, parses the same NICS_ALERT_JSON tagged lines, and logs every alert
    through this module's AlertsLogger -- but instead of streaming to a browser,
    it runs for up to stop_after_seconds (or until on_alert(out) returns True)
    and then terminates the subprocess itself, since this path has no SSE
    client to close the connection for it.

    on_alert receives the same dict shape returned by AlertsLogger.log_event
    ({"primary", "triage", "case_rel", "session_id"}) for every observed alert,
    and should return True to stop waiting (a match was found).
    """
    script_path = script_path or DEFAULT_MONITOR_SCRIPT_PATH
    ssh_key = ssh_key or DEFAULT_MONITOR_SSH_KEY_PATH

    if not monitor_ip:
        return {"status": "error", "reason": "monitor_ip is required", "observed_alerts": []}
    if not os.path.isfile(script_path):
        return {"status": "error", "reason": f"monitor script not found: {script_path}", "observed_alerts": []}

    logger_instance = AlertsLogger()
    cmd = ["bash", script_path, monitor_ip, ssh_user, ssh_key]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
    except Exception as exc:
        return {"status": "error", "reason": str(exc), "observed_alerts": []}

    matched_alert: Optional[Dict[str, Any]] = None
    observed_alerts: list[Dict[str, Any]] = []
    start = time.time()

    try:
        while True:
            if stop_after_seconds is not None:
                remaining = stop_after_seconds - (time.time() - start)
                if remaining <= 0:
                    break
            else:
                remaining = None

            poll_timeout = min(remaining, 1.0) if remaining is not None else 1.0
            ready, _, _ = select.select([process.stdout], [], [], poll_timeout)

            if not ready:
                if process.poll() is not None:
                    break
                continue

            raw_line = process.stdout.readline()
            if not raw_line:
                if process.poll() is not None:
                    break
                continue

            raw_line = raw_line.rstrip()
            if not (raw_line.startswith("{") and "\"__tag\":\"NICS_ALERT_JSON\"" in raw_line):
                continue

            try:
                ev = json.loads(raw_line)
            except Exception:
                continue
            if ev.get("__tag") != "NICS_ALERT_JSON":
                continue

            normalized = _normalize_nics_alert(ev, case_dir=case_dir)
            out = logger_instance.log_event(normalized)

            if case_dir and not out.get("case_rel"):
                try:
                    ev_id = (out.get("primary") or {}).get("event_id") or normalized.get("event_id")
                    if ev_id:
                        rel = attach_alert_to_case(case_dir, ev_id)
                        if rel:
                            out["case_rel"] = rel
                except Exception:
                    pass

            observed_alerts.append(out)
            if on_alert is not None and on_alert(out):
                matched_alert = out
                break
    finally:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    return {
        "status": "matched" if matched_alert is not None else "timeout",
        "matched_alert": matched_alert,
        "observed_alerts": observed_alerts,
        "session_id": logger_instance.session_id,
        "elapsed_seconds": time.time() - start,
    }
