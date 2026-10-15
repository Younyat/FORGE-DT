from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import openstack
except Exception:  # pragma: no cover - optional dependency at runtime
    openstack = None


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent.parent
PLC_ST_PATH = PROJECT_ROOT / "industrial-scenario" / "PLC" / "plc_programs" / "TankControl.st"
FUXA_PROJECT_PATH = PROJECT_ROOT / "industrial-scenario" / "FUXA" / "fuxa_mi_proyecto_simple.json"
INDUSTRIAL_STATE_PATH = PROJECT_ROOT / "industrial-scenario" / "state" / "industrial_state.json"
RUNTIME_DIR = BASE_DIR / "runtime"
PLC_MAP_PATH = RUNTIME_DIR / "industrial_plc_map.json"
SCADA_MAP_PATH = RUNTIME_DIR / "industrial_scada_map.json"
RUNTIME_ASSETS_PATH = RUNTIME_DIR / "industrial_runtime_assets.json"
ASSET_REGISTER_MAP_PATH = RUNTIME_DIR / "industrial_asset_register_map.json"
MODBUS_VALIDATION_PATH = RUNTIME_DIR / "industrial_modbus_validation.json"
ICS_POLICY_PATH = BASE_DIR / "ics_attack_policy.json"
SCENARIO_FILE_PATH = PROJECT_ROOT / "scenario" / "scenario_file.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_runtime_dir() -> Path:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_DIR


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def _normalize_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
    return normalized.replace("inllet", "inlet")


def _semantic_role(name: str) -> str:
    key = _normalize_name(name)
    mapping = {
        "level": "process_level",
        "levelmax": "setpoint_threshold",
        "openoutletvalve": "outlet_valve_command",
        "outletvalveopenstatus": "outlet_valve_status",
        "openinletvalve": "inlet_valve_command",
        "inletvalveopenstatus": "inlet_valve_status",
        "airvalveopenstatus": "process_enable_condition",
    }
    return mapping.get(key, "unknown")


def _hash_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


def derive_scenario_id() -> str:
    if SCENARIO_FILE_PATH.is_file():
        digest = hashlib.sha256(SCENARIO_FILE_PATH.read_bytes()).hexdigest()[:8]
        return f"scn-{digest}"
    return _hash_id("scn", "tank_control")


def parse_plc_structured_text() -> dict:
    ensure_runtime_dir()
    text = PLC_ST_PATH.read_text(encoding="utf-8")
    program_match = re.search(r"PROGRAM\s+([A-Za-z0-9_]+)", text)
    program_name = program_match.group(1) if program_match else "unknown"
    variables: list[dict] = []
    pattern = re.compile(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+AT\s+(?P<address>%[A-Z]{2}\d+(?:\.\d+)?)\s*:\s*(?P<type>[A-Za-z0-9_]+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        name = match.group("name").strip()
        iec_address = match.group("address").strip()
        var_type = match.group("type").strip().upper()
        addr_match = re.match(r"%(?P<area>[A-Z]{2})(?P<index>\d+)(?:\.(?P<bit>\d+))?$", iec_address)
        iec_area = addr_match.group("area") if addr_match else "unknown"
        iec_index = int(addr_match.group("index")) if addr_match else None
        iec_bit = int(addr_match.group("bit")) if addr_match and addr_match.group("bit") is not None else None
        semantic_role = _semantic_role(name)
        writable = var_type in {"INT", "DINT", "WORD", "BOOL"}
        attack_safe = semantic_role == "setpoint_threshold"
        entry = {
            "name": name,
            "iec_address": iec_address,
            "iec_area": iec_area,
            "iec_index": iec_index,
            "type": var_type,
            "semantic_role": semantic_role,
            "writable": writable,
            "attack_safe": attack_safe,
        }
        if iec_bit is not None:
            entry["iec_byte"] = iec_index
            entry["iec_bit"] = iec_bit
        variables.append(entry)

    payload = {
        "source": PLC_ST_PATH.name,
        "program": program_name,
        "generated_at_utc": utc_now(),
        "variables": variables,
    }
    _write_json(PLC_MAP_PATH, payload)
    return payload


def _find_visual_endpoints(obj: Any, out: set[str]) -> None:
    if isinstance(obj, str):
        for hit in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b", obj):
            out.add(hit)
    elif isinstance(obj, dict):
        for value in obj.values():
            _find_visual_endpoints(value, out)
    elif isinstance(obj, list):
        for value in obj:
            _find_visual_endpoints(value, out)


def parse_fuxa_project() -> dict:
    ensure_runtime_dir()
    project = _read_json(FUXA_PROJECT_PATH, {})
    devices = project.get("devices") or {}
    hmi = project.get("hmi") or {}
    hmi_views = (hmi.get("views") or []) if isinstance(hmi, dict) else []
    visual_endpoints: set[str] = set()
    _find_visual_endpoints(hmi, visual_endpoints)

    modbus_devices: list[dict] = []
    tag_index: dict[str, dict] = {}
    variable_refs: dict[str, list[dict]] = {}

    for device_id, device in devices.items():
        if not isinstance(device, dict):
            continue
        protocol = str(device.get("type") or "")
        tags = device.get("tags") or {}
        if protocol != "ModbusTCP":
            continue
        property_block = device.get("property") or {}
        tags_out = []
        for tag_id, tag in tags.items():
            if not isinstance(tag, dict):
                continue
            tag_name = str(tag.get("name") or "").strip()
            tag_entry = {
                "tag_id": tag.get("id") or tag_id,
                "name": tag_name,
                "label": tag.get("label") or tag_name,
                "type": tag.get("type") or "unknown",
                "memaddress": str(tag.get("memaddress") or ""),
                "address": tag.get("address"),
                "semantic_role": _semantic_role(tag_name),
            }
            tag_index[str(tag_entry["tag_id"])] = tag_entry
            tags_out.append(tag_entry)
        modbus_devices.append(
            {
                "device_id": device.get("id") or device_id,
                "name": device.get("name") or device_id,
                "protocol": protocol,
                "configured_endpoint": property_block.get("address"),
                "slaveid": int(property_block.get("slaveid") or 1),
                "polling_ms": int(property_block.get("polling") or device.get("polling") or 500),
                "tags": tags_out,
            }
        )

    for view in hmi_views:
        items = (view or {}).get("items") or {}
        for item_id, item in items.items():
            property_block = (item or {}).get("property") or {}
            variable_id = property_block.get("variableId")
            if not variable_id:
                continue
            variable_refs.setdefault(variable_id, []).append(
                {
                    "view_id": view.get("id") or "unknown",
                    "item_id": item_id,
                    "item_type": item.get("type") or "unknown",
                }
            )

    payload = {
        "source": FUXA_PROJECT_PATH.name,
        "scada_type": "FUXA",
        "generated_at_utc": utc_now(),
        "modbus_devices": modbus_devices,
        "hmi_variable_refs": variable_refs,
        "visual_metadata": {
            "visual_endpoints": sorted(visual_endpoints),
        },
    }
    _write_json(SCADA_MAP_PATH, payload)
    return payload


def read_industrial_state() -> dict:
    state = _read_json(INDUSTRIAL_STATE_PATH, {})
    payload = {
        "plc": {
            "role": "industrial_plc",
            "ip": (((state.get("plc") or {}).get("instance") or {}).get("ip_floating")),
            "port": 502,
            "tool": (((state.get("plc") or {}).get("tool") or {}).get("name")) or "openplc",
            "tool_status": (((state.get("plc") or {}).get("tool") or {}).get("status")) or "unknown",
            "instance_status": (((state.get("plc") or {}).get("instance") or {}).get("status")) or "unknown",
            "last_error": (((state.get("plc") or {}).get("instance") or {}).get("last_error")) or (((state.get("plc") or {}).get("tool") or {}).get("last_error")),
            "source": "industrial_state.json",
        },
        "scada": {
            "role": "industrial_scada",
            "ip": (((state.get("scada") or {}).get("instance") or {}).get("ip_floating")),
            "tool": (((state.get("scada") or {}).get("tool") or {}).get("name")) or "fuxa",
            "tool_status": (((state.get("scada") or {}).get("tool") or {}).get("status")) or "unknown",
            "instance_status": (((state.get("scada") or {}).get("instance") or {}).get("status")) or "unknown",
            "last_error": (((state.get("scada") or {}).get("instance") or {}).get("last_error")) or (((state.get("scada") or {}).get("tool") or {}).get("last_error")),
            "source": "industrial_state.json",
        },
        "generated_at_utc": utc_now(),
    }
    _write_json(RUNTIME_ASSETS_PATH, payload)
    return payload


def _probe_tcp(ip: str, port: int, timeout: float = 2.0) -> bool:
    if not ip:
        return False
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _openstack_server_entries() -> list[dict]:
    entries: list[dict] = []
    if openstack is not None:
        try:
            conn = openstack.connect()
            for server in conn.compute.servers(details=True, all_projects=True):
                addresses = getattr(server, "addresses", {}) or {}
                private_ip = None
                floating_ip = getattr(server, "access_ipv4", None) or ""
                networks = []
                for network_name, addrs in addresses.items():
                    for addr in addrs or []:
                        ip = addr.get("addr")
                        ip_type = addr.get("OS-EXT-IPS:type")
                        networks.append({"network": network_name, "ip": ip, "type": ip_type})
                        if ip_type == "floating" and ip:
                            floating_ip = ip
                        elif ip and not private_ip:
                            private_ip = ip
                image_name = ""
                try:
                    image_ref = getattr(server, "image", {}) or {}
                    image_id = image_ref.get("id")
                    if image_id:
                        image = conn.image.get_image(image_id)
                        image_name = getattr(image, "name", "") or ""
                except Exception:
                    image_name = ""
                flavor_name = ""
                try:
                    flavor_ref = getattr(server, "flavor", {}) or {}
                    flavor_id = flavor_ref.get("id")
                    if flavor_id:
                        flavor = conn.compute.get_flavor(flavor_id)
                        flavor_name = getattr(flavor, "name", "") or ""
                except Exception:
                    flavor_name = ""
                entries.append(
                    {
                        "instance_id": server.id,
                        "name": server.name,
                        "status": server.status,
                        "private_ip": private_ip,
                        "floating_ip": floating_ip,
                        "networks": networks,
                        "image": image_name,
                        "flavor": flavor_name,
                        "source": "openstack_sdk",
                    }
                )
        except Exception:
            entries = []
    if entries:
        return entries

    try:
        result = subprocess.run(
            ["openstack", "server", "list", "--long", "-f", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode == 0 and result.stdout.strip():
            raw = json.loads(result.stdout)
            for row in raw:
                networks_raw = str(row.get("Networks") or "")
                private_ip = None
                if "=" in networks_raw:
                    private_ip = networks_raw.split("=", 1)[1].split(",")[0].strip()
                entries.append(
                    {
                        "instance_id": row.get("ID"),
                        "name": row.get("Name"),
                        "status": row.get("Status"),
                        "private_ip": private_ip,
                        "floating_ip": None,
                        "networks": [{"network": networks_raw.split("=")[0], "ip": private_ip, "type": "fixed"}] if private_ip else [],
                        "image": row.get("Image"),
                        "flavor": row.get("Flavor"),
                        "source": "openstack_cli",
                    }
                )
    except Exception:
        return entries
    return entries


def _match_asset(entries: Iterable[dict], role: str) -> dict:
    aliases = {
        "plc": ["plc-1", "industrial_plc", "plc", "openplc"],
        "scada": ["scada-1", "industrial_scada", "scada", "fuxa"],
    }[role]
    best = {}
    for entry in entries:
        name = str(entry.get("name") or "").lower()
        if any(alias in name for alias in aliases):
            best = entry
            if entry.get("floating_ip") or entry.get("private_ip"):
                break
    return best


def discover_runtime_assets() -> dict:
    # Capturado ANTES de llamar a read_industrial_state(): esa funcion tambien escribe en
    # RUNTIME_ASSETS_PATH (con un payload parcial, sin `inventory_candidates`) como efecto
    # colateral -- si se lee el "ultimo bueno conocido" despues de esa llamada, ya estaria pisado.
    previous_payload = _read_json(RUNTIME_ASSETS_PATH, {})

    runtime_assets = read_industrial_state()
    entries = _openstack_server_entries()
    # Si la consulta EN VIVO a OpenStack no devuelve nada (credenciales no disponibles en este
    # proceso concreto, API caida, timeout, etc.), no hay que destruir el ultimo inventario real ya
    # conocido: sin este fallback, un fallo transitorio de OpenStack sobreescribia
    # industrial_runtime_assets.json con `inventory_candidates: []` y IPs a null, perdiendo datos
    # reales (nombre/rol/IP de cada maquina desplegada) que otros consumidores del fichero (p.ej.
    # la atribucion de origen de alertas en monitor/alerts_logger.py) siguen necesitando leer. Solo
    # se usa como respaldo -- si la consulta en vivo SI devuelve datos, el comportamiento es
    # identico al de antes de este cambio.
    if not entries:
        entries = previous_payload.get("inventory_candidates") or []
    plc_entry = _match_asset(entries, "plc")
    scada_entry = _match_asset(entries, "scada")

    plc_ip = plc_entry.get("floating_ip") or plc_entry.get("private_ip") or runtime_assets["plc"].get("ip")
    scada_ip = scada_entry.get("floating_ip") or scada_entry.get("private_ip") or runtime_assets["scada"].get("ip")

    payload = {
        "generated_at_utc": utc_now(),
        "plc": {
            **runtime_assets["plc"],
            "instance_id": plc_entry.get("instance_id"),
            "name": plc_entry.get("name") or "plc-1",
            "status": plc_entry.get("status") or runtime_assets["plc"].get("instance_status"),
            "private_ip": plc_entry.get("private_ip"),
            "floating_ip": plc_entry.get("floating_ip"),
            "ip": plc_ip,
            "image": plc_entry.get("image"),
            "flavor": plc_entry.get("flavor"),
            "networks": plc_entry.get("networks") or [],
            "tcp_502_open": _probe_tcp(plc_ip or "", 502),
            "source": plc_entry.get("source") or runtime_assets["plc"].get("source"),
        },
        "scada": {
            **runtime_assets["scada"],
            "instance_id": scada_entry.get("instance_id"),
            "name": scada_entry.get("name") or "scada-1",
            "status": scada_entry.get("status") or runtime_assets["scada"].get("instance_status"),
            "private_ip": scada_entry.get("private_ip"),
            "floating_ip": scada_entry.get("floating_ip"),
            "ip": scada_ip,
            "image": scada_entry.get("image"),
            "flavor": scada_entry.get("flavor"),
            "networks": scada_entry.get("networks") or [],
            "service_reachable": any(_probe_tcp(scada_ip or "", port) for port in (1881, 1880, 80, 443)),
            "source": scada_entry.get("source") or runtime_assets["scada"].get("source"),
        },
        "inventory_candidates": entries,
    }
    _write_json(RUNTIME_ASSETS_PATH, payload)
    return payload


def _table_from_tag(tag: dict, plc_var: dict | None) -> str:
    mem = str(tag.get("memaddress") or "").strip()
    if mem.startswith("4"):
        return "holding_register"
    if mem.startswith("0"):
        return "coil"
    if plc_var and plc_var.get("type") == "BOOL":
        return "coil"
    return "holding_register"


def build_industrial_asset_register_map() -> dict:
    plc_map = parse_plc_structured_text()
    scada_map = parse_fuxa_project()
    runtime_assets = discover_runtime_assets()
    plc_by_name = {_normalize_name(var["name"]): var for var in plc_map.get("variables", [])}
    tag_refs = scada_map.get("hmi_variable_refs", {})
    register_entries: list[dict] = []
    notes: list[str] = []
    visual_endpoints = scada_map.get("visual_metadata", {}).get("visual_endpoints", [])

    for device in scada_map.get("modbus_devices", []):
        for tag in device.get("tags", []):
            canonical_key = _normalize_name(tag.get("name") or tag.get("label") or tag.get("tag_id"))
            plc_var = plc_by_name.get(canonical_key)
            write_allowed = canonical_key == "levelmax"
            entry = {
                "canonical_name": (plc_var or {}).get("name") or tag.get("name") or tag.get("label") or canonical_key,
                "semantic_role": (plc_var or {}).get("semantic_role") or tag.get("semantic_role") or "unknown",
                "plc_variable": (plc_var or {}).get("name"),
                "plc_iec_address": (plc_var or {}).get("iec_address"),
                "plc_type": (plc_var or {}).get("type") or tag.get("type"),
                "fuxa_tag_id": tag.get("tag_id"),
                "fuxa_tag_name": tag.get("name"),
                "fuxa_address": tag.get("address"),
                "modbus_table": _table_from_tag(tag, plc_var),
                "modbus_address_candidate": (plc_var or {}).get("iec_index"),
                "fuxa_address_candidate": tag.get("address"),
                "requires_live_validation": True,
                "attack_usage": ["read_state_only"],
                "write_allowed": write_allowed,
                "hmi_refs": tag_refs.get(tag.get("tag_id"), []),
            }
            if canonical_key == "level":
                entry["attack_usage"] = ["read_pre_state", "read_post_state", "automated_collection"]
                entry["write_allowed"] = False
            elif canonical_key == "levelmax":
                entry["attack_usage"] = ["modify_parameter", "unauthorized_command_message", "read_pre_state", "read_post_state"]
                entry["write_allowed"] = True
                entry["safe_min"] = 10
                entry["safe_max"] = 90
                entry["restore_after_attack"] = True
            register_entries.append(entry)

    for plc_var in plc_map.get("variables", []):
        key = _normalize_name(plc_var["name"])
        if key in {_normalize_name(entry["canonical_name"]) for entry in register_entries}:
            continue
        register_entries.append(
            {
                "canonical_name": plc_var["name"],
                "semantic_role": plc_var.get("semantic_role"),
                "plc_variable": plc_var["name"],
                "plc_iec_address": plc_var.get("iec_address"),
                "plc_type": plc_var.get("type"),
                "fuxa_tag_id": None,
                "fuxa_tag_name": None,
                "fuxa_address": None,
                "modbus_table": "coil" if plc_var.get("type") == "BOOL" else "holding_register",
                "modbus_address_candidate": plc_var.get("iec_index"),
                "fuxa_address_candidate": None,
                "requires_live_validation": True,
                "attack_usage": ["read_state_only"],
                "write_allowed": False,
                "hmi_refs": [],
            }
        )

    configured_endpoint = None
    if scada_map.get("modbus_devices"):
        configured_endpoint = scada_map["modbus_devices"][0].get("configured_endpoint")
    runtime_endpoint = f"{runtime_assets['plc'].get('ip')}:{runtime_assets['plc'].get('port', 502)}" if runtime_assets["plc"].get("ip") else None
    if configured_endpoint and runtime_endpoint and configured_endpoint != runtime_endpoint:
        notes.append(f"configured_endpoint_conflict:{configured_endpoint}!={runtime_endpoint}")
    if visual_endpoints and configured_endpoint and configured_endpoint not in visual_endpoints:
        notes.append("visual_endpoint_metadata_differs_from_configured_endpoint")

    payload = {
        "scenario": "tank_control",
        "generated_at_utc": utc_now(),
        "scenario_id": derive_scenario_id(),
        "plc": {
            "name": runtime_assets["plc"].get("name") or "plc-1",
            "ip": runtime_assets["plc"].get("ip"),
            "port": 502,
            "protocol": "modbus_tcp",
            "program": plc_map.get("program", "unknown"),
            "openstack_instance_id": runtime_assets["plc"].get("instance_id"),
        },
        "scada": {
            "name": runtime_assets["scada"].get("name") or "scada-1",
            "ip": runtime_assets["scada"].get("ip"),
            "type": "fuxa",
            "openstack_instance_id": runtime_assets["scada"].get("instance_id"),
        },
        "registers": register_entries,
        "validation": {
            "status": "pending",
            "method": "live_modbus_read",
            "notes": notes,
            "configured_endpoint": configured_endpoint,
            "visual_endpoints": visual_endpoints,
        },
    }
    _write_json(ASSET_REGISTER_MAP_PATH, payload)
    return payload


def load_validation(default: dict | None = None) -> dict:
    return _read_json(MODBUS_VALIDATION_PATH, default or {})


def generate_ics_attack_policy(validation: dict | None = None, register_map: dict | None = None) -> dict:
    validation = validation or load_validation({})
    register_map = register_map or _read_json(ASSET_REGISTER_MAP_PATH, {})
    validated_by_name = {
        _normalize_name(item.get("canonical_name")): item
        for item in validation.get("validated_registers", []) or []
        if item.get("read_status") == "ok"
    }
    allowed_write_targets = []
    read_only_targets = []
    for reg in register_map.get("registers", []) or []:
        key = _normalize_name(reg.get("canonical_name"))
        if reg.get("write_allowed") and key == "levelmax" and key in validated_by_name:
            validated = validated_by_name[key]
            allowed_write_targets.append(
                {
                    "canonical_name": reg.get("canonical_name"),
                    "semantic_role": reg.get("semantic_role"),
                    "modbus_table": reg.get("modbus_table"),
                    "validated_modbus_address": validated.get("validated_modbus_address"),
                    "type": reg.get("plc_type"),
                    "safe_min": reg.get("safe_min", 10),
                    "safe_max": reg.get("safe_max", 90),
                    "default_attack_value": 30,
                    "restore_after_attack": True,
                    "mitre_techniques": ["T0836", "T1692.001", "T0831"],
                }
            )
        else:
            read_only_targets.append(reg.get("canonical_name"))

    payload = {
        "lab_only": True,
        "generated_at_utc": utc_now(),
        "scenario": "tank_control",
        "scenario_id": register_map.get("scenario_id", derive_scenario_id()),
        "plc_program": register_map.get("plc", {}).get("program", "TankSimple"),
        "target_role": "industrial_plc",
        "protocol": "modbus_tcp",
        "port": 502,
        "write_policy": {
            "default": "deny",
            "require_live_validation": True,
            "require_read_before_write": True,
            "require_read_after_write": True,
            "require_rollback": True,
            "require_restored_state_verification": True,
        },
        "allowed_write_targets": allowed_write_targets,
        "read_only_targets": sorted(set(filter(None, read_only_targets))),
    }
    _write_json(ICS_POLICY_PATH, payload)
    return payload


def resolve_industrial_context() -> dict:
    plc_map = parse_plc_structured_text()
    scada_map = parse_fuxa_project()
    runtime_assets = discover_runtime_assets()
    register_map = build_industrial_asset_register_map()
    validation = load_validation({"status": "not_generated"})
    policy = generate_ics_attack_policy(validation=validation, register_map=register_map)
    return {
        "plc_map": plc_map,
        "scada_map": scada_map,
        "runtime_assets": runtime_assets,
        "register_map": register_map,
        "validation": validation,
        "policy": policy,
        "paths": {
            "plc_map": str(PLC_MAP_PATH),
            "scada_map": str(SCADA_MAP_PATH),
            "runtime_assets": str(RUNTIME_ASSETS_PATH),
            "register_map": str(ASSET_REGISTER_MAP_PATH),
            "validation": str(MODBUS_VALIDATION_PATH),
            "policy": str(ICS_POLICY_PATH),
        },
    }

