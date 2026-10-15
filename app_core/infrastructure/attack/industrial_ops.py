from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app_core.infrastructure.attack.industrial_resolver import (
    ASSET_REGISTER_MAP_PATH,
    ICS_POLICY_PATH,
    MODBUS_VALIDATION_PATH,
    generate_ics_attack_policy,
    load_validation,
    resolve_industrial_context,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def python_module_invocation(path: Path) -> list[str]:
    try:
        rel = path.resolve().relative_to(PROJECT_ROOT.resolve())
        module = ".".join(rel.with_suffix("").parts)
        return [sys.executable, "-m", module]
    except Exception:
        return [sys.executable, str(path)]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_params(argv: list[str]) -> dict:
    try:
        return json.loads(argv[3]) if len(argv) > 3 and argv[3] else {}
    except Exception:
        return {}


def output_dir_from_argv(argv: list[str]) -> Path:
    path = Path(argv[4]) if len(argv) > 4 and argv[4] else Path.cwd() / "attack-output"
    path.mkdir(parents=True, exist_ok=True)
    return path


def attacker_context_from_argv(argv: list[str]) -> dict:
    return {
        "source_ip": argv[5] if len(argv) > 5 and argv[5] else "not_available",
        "source_user": argv[6] if len(argv) > 6 and argv[6] else "not_available",
    }


def write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_ref(path: Path, base_dir: Path) -> dict:
    return {
        "path": str(path.relative_to(base_dir)).replace("\\", "/"),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def emit_json_banner(payload: dict) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def clone_runtime_artifacts(output_dir: Path) -> dict[str, str]:
    context = resolve_industrial_context()
    copies = {}
    for key, src in context["paths"].items():
        src_path = Path(src)
        if src_path.is_file():
            dst = output_dir / src_path.name
            shutil.copy2(src_path, dst)
            copies[key] = str(dst.name)
    return copies


def run_command(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)


def _build_ssh_prefix(source_ip: str, source_user: str) -> list[str]:
    return [
        "ssh",
        "-i",
        os.path.expanduser("~/.ssh/my_key"),
        "-o",
        "StrictHostKeyChecking=no",
        f"{source_user}@{source_ip}",
    ]


def run_remote_or_local_command(command: str, *, source_ip: str, source_user: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    if source_ip not in {"", "not_available"} and source_user not in {"", "not_available"}:
        return run_command(_build_ssh_prefix(source_ip, source_user) + [command], timeout=timeout)
    return run_command(["bash", "-lc", command], timeout=timeout)


def tcp_probe(ip: str, port: int, *, source_ip: str, source_user: str) -> bool:
    cmd = f"timeout 3 bash -lc 'echo > /dev/tcp/{ip}/{port}' >/dev/null 2>&1"
    result = run_remote_or_local_command(cmd, source_ip=source_ip, source_user=source_user, timeout=10)
    return result.returncode == 0


def _parse_mbpoll_value(stdout: str) -> int | None:
    for line in reversed((stdout or "").splitlines()):
        nums = re.findall(r"[-+]?\d+", line)
        if nums:
            try:
                return int(nums[-1])
            except Exception:
                continue
    return None


def _mbpoll_read_command(ip: str, slave_id: int, table: str, address: int) -> str:
    """Construccion pura del comando mbpoll de lectura -- extraida de mbpoll_read() sin cambiar
    el comando que produce, para poder reutilizarla en una lectura por lotes (mbpoll_read_many)
    sin duplicar esta logica."""
    table_arg = "0" if table == "coil" else "4:int"
    return f"mbpoll -m tcp -a {slave_id} -r {address} -c 1 -t {table_arg} -1 {ip}"


def mbpoll_read(ip: str, slave_id: int, table: str, address: int, *, source_ip: str, source_user: str) -> dict:
    if shutil.which("mbpoll") is None and source_ip in {"", "not_available"}:
        return {"ok": False, "reason": "mbpoll_not_available", "stdout": "", "stderr": ""}
    cmd = _mbpoll_read_command(ip, slave_id, table, address)
    result = run_remote_or_local_command(cmd, source_ip=source_ip, source_user=source_user, timeout=20)
    value = _parse_mbpoll_value(result.stdout) if result.returncode == 0 else None
    return {
        "ok": result.returncode == 0 and value is not None,
        "value": value,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": cmd,
    }


def mbpoll_read_many(reads: list[dict], *, source_ip: str, source_user: str, timeout: int = 30) -> dict:
    """Lee VARIAS direcciones Modbus en UNA sola conexion SSH, en vez de una conexion por
    variable (lo que hacia collect_state()/mbpoll_read() llamado repetidamente). Cada entrada de
    `reads` es {"key": <nombre logico>, "ip":..., "slave_id":..., "table":..., "address":...}.
    Pensado para el sondeo del gemelo digital (ot_state_twin), donde una lectura completa del
    estado puede necesitar leer 7+ variables -- 7 conexiones SSH nuevas por sondeo son un coste de
    latencia real que un sondeo mas frecuente multiplicaria. Reutiliza exactamente el mismo
    comando mbpoll que ya produce mbpoll_read() (_mbpoll_read_command) y el mismo parser
    (_parse_mbpoll_value) -- no es un mecanismo de lectura nuevo, es la misma lectura agrupada en
    una sola sesion remota con marcadores para separar cada salida."""
    if not reads:
        return {}
    if shutil.which("mbpoll") is None and source_ip in {"", "not_available"}:
        return {r["key"]: {"ok": False, "reason": "mbpoll_not_available", "stdout": "", "stderr": ""} for r in reads}

    marker = "__OT_TWIN_READ__"
    segments = []
    for r in reads:
        cmd = _mbpoll_read_command(r["ip"], r["slave_id"], r["table"], r["address"])
        segments.append(f'echo "{marker}:{r["key"]}"; {cmd}')
    combined_cmd = " ; ".join(segments)

    result = run_remote_or_local_command(combined_cmd, source_ip=source_ip, source_user=source_user, timeout=timeout)

    out: dict[str, dict] = {}
    if result.returncode != 0:
        for r in reads:
            out[r["key"]] = {"ok": False, "reason": "ssh_or_command_failed", "stdout": result.stdout, "stderr": result.stderr}
        return out

    # Divide la salida combinada por los marcadores -- cada bloque es la salida de un mbpoll.
    raw_blocks = (result.stdout or "").split(f"{marker}:")
    block_by_key: dict[str, str] = {}
    for block in raw_blocks[1:]:
        key, _, rest = block.partition("\n")
        block_by_key[key.strip()] = rest

    for r in reads:
        block = block_by_key.get(r["key"])
        if block is None:
            out[r["key"]] = {"ok": False, "reason": "missing_output_block", "stdout": "", "stderr": result.stderr}
            continue
        value = _parse_mbpoll_value(block)
        out[r["key"]] = {
            "ok": value is not None,
            "value": value,
            "stdout": block,
            "stderr": result.stderr if value is None else "",
        }
    return out


def mbpoll_write(ip: str, slave_id: int, table: str, address: int, value: int, *, source_ip: str, source_user: str) -> dict:
    if shutil.which("mbpoll") is None and source_ip in {"", "not_available"}:
        return {"ok": False, "reason": "mbpoll_not_available", "stdout": "", "stderr": ""}
    table_arg = "0" if table == "coil" else "4:int"
    cmd = f"mbpoll -m tcp -a {slave_id} -r {address} -t {table_arg} -1 {ip} {value}"
    result = run_remote_or_local_command(cmd, source_ip=source_ip, source_user=source_user, timeout=20)
    return {
        "ok": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": cmd,
    }


def ensure_validated_context(output_dir: Path, *, require_validation: bool) -> dict:
    context = resolve_industrial_context()
    validation = load_validation({"status": "not_generated", "validated_registers": [], "conflicts": []})
    if require_validation and validation.get("status") != "validated":
        print("[INFO] Validation not yet confirmed; invoking validate_tank_modbus_map.py")
        validator = Path(__file__).resolve().parent / "scripts" / "validate_tank_modbus_map.py"
        proc = subprocess.run(
            python_module_invocation(validator) + [context["runtime_assets"]["plc"].get("ip") or "", "debian", "{}", str(output_dir)],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(PROJECT_ROOT),
        )
        if proc.stdout:
            for line in proc.stdout.splitlines():
                print(line)
        if proc.stderr:
            for line in proc.stderr.splitlines():
                print(f"[VALIDATOR STDERR] {line}")
        validation = load_validation({"status": "not_generated", "validated_registers": [], "conflicts": []})

    context["validation"] = validation
    context["policy"] = generate_ics_attack_policy(validation=validation, register_map=context["register_map"])
    clone_runtime_artifacts(output_dir)
    return context


def find_register(context: dict, canonical_name: str) -> dict | None:
    key = canonical_name.strip().lower()
    for register in context.get("register_map", {}).get("registers", []):
        if str(register.get("canonical_name") or "").strip().lower() == key:
            return register
    return None


def validated_address(context: dict, canonical_name: str) -> dict | None:
    key = canonical_name.strip().lower()
    for item in context.get("validation", {}).get("validated_registers", []) or []:
        if str(item.get("canonical_name") or "").strip().lower() == key and item.get("read_status") == "ok":
            return item
    return None


def policy_write_target(context: dict, canonical_name: str) -> dict | None:
    key = canonical_name.strip().lower()
    for item in context.get("policy", {}).get("allowed_write_targets", []) or []:
        if str(item.get("canonical_name") or "").strip().lower() == key:
            return item
    return None


def collect_state(context: dict, names: list[str], *, source_ip: str, source_user: str) -> dict:
    plc = context["register_map"]["plc"]
    slave_id = 1
    device_list = context.get("scada_map", {}).get("modbus_devices", []) or []
    if device_list:
        slave_id = int(device_list[0].get("slaveid") or 1)
    state = {
        "captured_at_utc": utc_now(),
        "target_ip": plc.get("ip"),
        "variables": {},
    }
    for name in names:
        register = find_register(context, name)
        validated = validated_address(context, name)
        if not register or not validated:
            state["variables"][name] = {
                "status": "unavailable",
                "reason": "mapping_not_validated",
            }
            continue
        read_result = mbpoll_read(
            plc["ip"],
            slave_id,
            register.get("modbus_table", "holding_register"),
            int(validated.get("validated_modbus_address")),
            source_ip=source_ip,
            source_user=source_user,
        )
        state["variables"][name] = {
            "status": "ok" if read_result.get("ok") else "error",
            "value": read_result.get("value"),
            "validated_modbus_address": validated.get("validated_modbus_address"),
            "stdout": read_result.get("stdout"),
            "stderr": read_result.get("stderr"),
        }
    return state


def collect_state_batched(context: dict, names: list[str], *, source_ip: str, source_user: str) -> dict:
    """Igual que collect_state() (misma forma de salida, mismo mapa de registros ya resuelto/
    validado), pero lee TODAS las variables en UNA sola conexion SSH via mbpoll_read_many() en vez
    de una conexion por variable. Pensado para el gemelo digital (ot_state_twin), donde un sondeo
    mas frecuente multiplicaria el coste de abrir una conexion SSH por cada una de las 7+
    variables. collect_state() se deja intacta -- los scripts de ataque que ya la usan (T0802,
    T0831, etc.) siguen sin cambios."""
    plc = context["register_map"]["plc"]
    slave_id = 1
    device_list = context.get("scada_map", {}).get("modbus_devices", []) or []
    if device_list:
        slave_id = int(device_list[0].get("slaveid") or 1)

    state = {
        "captured_at_utc": utc_now(),
        "target_ip": plc.get("ip"),
        "variables": {},
    }

    reads = []
    unresolved_names = []
    for name in names:
        register = find_register(context, name)
        validated = validated_address(context, name)
        if not register or not validated:
            unresolved_names.append(name)
            continue
        reads.append(
            {
                "key": name,
                "ip": plc.get("ip"),
                "slave_id": slave_id,
                "table": register.get("modbus_table", "holding_register"),
                "address": int(validated.get("validated_modbus_address")),
                "validated_modbus_address": validated.get("validated_modbus_address"),
            }
        )

    for name in unresolved_names:
        state["variables"][name] = {"status": "unavailable", "reason": "mapping_not_validated"}

    if reads:
        results = mbpoll_read_many(reads, source_ip=source_ip, source_user=source_user)
        for r in reads:
            read_result = results.get(r["key"], {})
            state["variables"][r["key"]] = {
                "status": "ok" if read_result.get("ok") else "error",
                "value": read_result.get("value"),
                "validated_modbus_address": r["validated_modbus_address"],
                "stdout": read_result.get("stdout"),
                "stderr": read_result.get("stderr"),
            }
    return state


def build_causal_edges(*, attack_id: str, mitre_id: str, scenario_id: str, source_ip: str, target_ip: str, target_role: str, write_target: str | None = None) -> dict:
    edges = [
        {
            "from": "attacker",
            "to": "plc_modbus_service",
            "relation": "observed_or_contacted",
            "status": "confirmed" if source_ip != "not_available" else "inferred",
        },
        {
            "from": "plc_modbus_service",
            "to": "industrial_register_map",
            "relation": "supports_register_resolution",
            "status": "confirmed",
        },
    ]
    if write_target:
        edges.extend(
            [
                {
                    "from": write_target,
                    "to": "process_logic",
                    "relation": "parameter_change_affects_logic",
                    "status": "confirmed",
                },
                {
                    "from": "process_logic",
                    "to": "scada_observation",
                    "relation": "state_propagates_to_scada",
                    "status": "inferred_high",
                },
            ]
        )
    return {
        "attack_id": attack_id,
        "mitre_id": mitre_id,
        "scenario_id": scenario_id,
        "target_ip": target_ip,
        "target_role": target_role,
        "source_ip": source_ip,
        "generated_at_utc": utc_now(),
        "edges": edges,
    }


def build_uncertainty_report(*, attack_id: str, mitre_id: str, scenario_id: str, notes: list[dict]) -> dict:
    unresolved = [note for note in notes if note.get("status") != "confirmed"]
    confidence = "high" if not unresolved else ("medium" if len(unresolved) <= 2 else "low")
    return {
        "attack_id": attack_id,
        "mitre_id": mitre_id,
        "scenario_id": scenario_id,
        "generated_at_utc": utc_now(),
        "confidence": confidence,
        "uncertainties": notes,
    }


def build_recoverability_report(*, attack_id: str, scenario_id: str, rollback_ok: bool, restored_ok: bool) -> dict:
    score = 1.0 if rollback_ok and restored_ok else (0.5 if rollback_ok else 0.0)
    return {
        "attack_id": attack_id,
        "scenario_id": scenario_id,
        "generated_at_utc": utc_now(),
        "rollback_ok": rollback_ok,
        "restored_state_verified": restored_ok,
        "causal_path_recoverability_score": score,
    }
