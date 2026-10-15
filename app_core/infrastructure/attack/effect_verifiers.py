from __future__ import annotations

"""M2 (Effect verifier, investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md)
for Attack Lab. Real, content-based verification of whether an attack's
intended effect actually occurred -- never just exit_code==0 (the gap the
study's own baseline audit identified: only T0831 had a real verifier
before this, confirmed real via its own rollback_log.json; the other 3 had
none). Each verifier parses real captured output (result["stdout"], the
same list executor.py already fills during streaming) or reads a real
artifact the attack script already writes -- nothing here invents a signal
that wasn't already produced by the attack itself.
"""

import json
import re
from pathlib import Path


def _stdout_text(result: dict) -> str:
    return "\n".join(result.get("stdout") or [])


def verify_ping_recon(result: dict, output_dir: str) -> dict:
    """T1595: the script's own real `ping -c N` output already states
    exactly how many ICMP packets came back -- parsed directly, not
    inferred from exit_code (a 100% packet loss ping still exits 0)."""
    text = _stdout_text(result)
    m = re.search(r"(\d+) packets transmitted, (\d+) received", text)
    if not m:
        return {"effective": None, "evidence": "no ping statistics found in captured output"}
    sent, received = int(m.group(1)), int(m.group(2))
    return {"effective": received > 0, "evidence": f"{received}/{sent} real ICMP packets received"}


def verify_ssh_attempt(result: dict, output_dir: str) -> dict:
    """T1110.001: the script's own `[ATTEMPT N]` markers count real SSH
    connection attempts made against the target -- the attack's real effect
    is that the attempts happened (observable by the target's own auth
    log), not whether the (deliberately invalid) credentials succeeded."""
    text = _stdout_text(result)
    attempts = len(re.findall(r"\[ATTEMPT \d+\]", text))
    if attempts == 0:
        return {"effective": None, "evidence": "no SSH attempt markers found in captured output"}
    rejected = bool(re.search(r"permission denied|connection refused|connection timed out", text, re.IGNORECASE))
    evidence = f"{attempts} real SSH connection attempt(s) made against the target"
    if rejected:
        evidence += ", rejected as expected (invalid credentials)"
    return {"effective": True, "evidence": evidence}


def verify_file_tamper(result: dict, output_dir: str) -> dict:
    """T1565.001: the script already prints real SHA-256 hashes of the
    tampered files before and after (see file_tamper_sim.sh's own "PRE
    hashes"/"POST hashes" sections) -- compared here directly instead of
    trusting the script's own exit code."""
    text = _stdout_text(result)
    if "PRE hashes" not in text or "POST hashes" not in text:
        return {"effective": None, "evidence": "no pre/post hash markers found in captured output"}
    pre_section, _, post_section = text.partition("POST hashes")
    pre_hashes = set(re.findall(r"[0-9a-f]{64}", pre_section))
    post_hashes = set(re.findall(r"[0-9a-f]{64}", post_section))
    changed = bool(pre_hashes) and pre_hashes != post_hashes
    return {
        "effective": changed,
        "evidence": f"{len(pre_hashes)} file hash(es) captured before, {len(post_hashes)} after -- {'hashes changed' if changed else 'hashes identical'}",
    }


def verify_modbus_manipulation(result: dict, output_dir: str) -> dict:
    """T0831: already has a real verifier, just never surfaced into the
    Intervention Ledger before -- reads the real rollback_log.json
    t0831_manipulation_of_control_modbus.py already writes (real Modbus
    write + a real readback confirming restoration), rather than
    re-deriving it from stdout."""
    rollback_log_path = Path(output_dir) / "rollback_log.json"
    if not rollback_log_path.is_file():
        return {"effective": None, "evidence": "rollback_log.json not found"}
    try:
        data = json.loads(rollback_log_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"effective": None, "evidence": f"rollback_log.json unreadable: {exc}"}
    rollback_ok = data.get("rollback_ok")
    restored_ok = data.get("restored_state_verified")
    effective = bool(rollback_ok and restored_ok) if rollback_ok is not None else None
    return {
        "effective": effective,
        "evidence": f"rollback_ok={rollback_ok}, restored_state_verified={restored_ok} (real Modbus write + readback)",
    }


_VERIFIERS = {
    "T1595_ACTIVE_SCANNING_ICMP_RECON": verify_ping_recon,
    "T1110_001_SSH_PASSWORD_GUESSING": verify_ssh_attempt,
    "T1565_001_STORED_DATA_MANIPULATION_FIM": verify_file_tamper,
    "T0831_MANIPULATION_OF_CONTROL_MODBUS": verify_modbus_manipulation,
}


def verify_attack_effect(attack_id: str, result: dict, output_dir: str) -> dict:
    """Never raises -- an unknown attack_id or a parsing failure returns an
    honest effective=None (not measured), never a guessed True/False."""
    verifier = _VERIFIERS.get(attack_id)
    if not verifier:
        return {"effective": None, "evidence": f"no effect verifier registered yet for {attack_id}"}
    try:
        return verifier(result, output_dir)
    except Exception as exc:
        return {"effective": None, "evidence": f"verifier error: {exc}"}
