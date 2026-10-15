from __future__ import annotations

"""Intervention Ledger -- M1 from
investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md. A single,
append-only, hash-chained JSONL log of every real intervention (fault
injection apply/revert, Attack Lab execution) applied against the live
scenario, reused as an ADAPTER over the already-real records those two
subsystems already produce -- never a second source of truth. This module
never decides whether a fault/attack is "real" or "effective" on its own;
it only projects whatever `fault_injection.apply_fault`/`revert_fault` (or,
once wired, Attack Lab's own executor) already computed into one common,
tamper-evident format, referencing the original record rather than copying
its full content.

Hash-chaining: each entry's `record_hash` covers every field except itself,
and `prev_hash` is the previous entry's `record_hash` (or the literal
string "GENESIS" for the first entry ever) -- the same tamper-evidence
principle the study's own section 8.3 asks for. A single global chain
(not one per node/case) is used deliberately: one continuous chain is
simpler to verify end-to-end than many parallel ones, and interventions are
rare, low-volume events (not high-frequency telemetry), so one shared file
never becomes a contention bottleneck.
"""

import fcntl
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .schemas import LEDGER_SCHEMA_VERSION

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = PROJECT_ROOT / "runtime" / "intervention_ledger"
LEDGER_PATH = RUNTIME_DIR / "ledger.jsonl"
LOCK_PATH = RUNTIME_DIR / "ledger.lock"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

GENESIS_HASH = "GENESIS"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(d: dict) -> str:
    return json.dumps(d, sort_keys=True, default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _read_all_entries() -> list[dict]:
    if not LEDGER_PATH.is_file():
        return []
    entries = []
    for line in LEDGER_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = _safe(lambda: json.loads(line))
        if parsed is not None:
            entries.append(parsed)
    return entries


def record_intervention(
    *,
    source: str,
    source_record_ref: str,
    class_: str,
    type_: str,
    phase: str,
    target_node_id: str | None = None,
    target_node_name: str | None = None,
    target_ip: str | None = None,
    campaign_id: str | None = None,
    case_id: str | None = None,
    params: dict | None = None,
    requested_at: str | None = None,
    applied_at: str | None = None,
    effect_verified_at: str | None = None,
    effect_verification: dict | None = None,
    rollback_requested_at: str | None = None,
    rollback_at: str | None = None,
    rollback_verified: bool | None = None,
    intervention_id: str | None = None,
) -> dict:
    """Appends one hash-chained entry. Never raises -- callers (the
    fault_injection/Attack Lab hooks) always wrap this in their own
    best-effort call, same principle as record_fault_injection_lifecycle,
    but this is defensive on its own too so a ledger failure can never
    break a real intervention."""
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        with LOCK_PATH.open("a+") as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                existing = _read_all_entries()
                last = existing[-1] if existing else None
                prev_hash = last["record_hash"] if last else GENESIS_HASH
                seq = (last["seq"] + 1) if last else 1

                entry = {
                    "schema_version": LEDGER_SCHEMA_VERSION,
                    "seq": seq,
                    "intervention_id": intervention_id or f"iv-{uuid.uuid4().hex[:10]}",
                    "recorded_at_utc": _utc_now(),
                    "source": source,
                    "source_record_ref": source_record_ref,
                    "class": class_,
                    "type": type_,
                    "target_node_id": target_node_id,
                    "target_node_name": target_node_name,
                    "target_ip": target_ip,
                    "campaign_id": campaign_id,
                    "case_id": case_id,
                    "params": params or {},
                    "phase": phase,
                    "requested_at": requested_at,
                    "applied_at": applied_at,
                    "effect_verified_at": effect_verified_at,
                    "effect_verification": effect_verification,
                    "rollback_requested_at": rollback_requested_at,
                    "rollback_at": rollback_at,
                    "rollback_verified": rollback_verified,
                    "prev_hash": prev_hash,
                }
                entry["record_hash"] = _sha256_hex(_canonical_json(entry))

                with LEDGER_PATH.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
                return entry
            finally:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def verify_chain() -> dict:
    """Recomputes every entry's hash and checks prev_hash linkage -- a real
    integrity check, not a format check. Returns the first broken link
    found, if any, rather than just a boolean, so a real tamper/corruption
    can be located.

    Known, real, DELIBERATE limitation (adversary model, see
    investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md gap #3 and
    README.md's own "Adversary model" section): a hash chain only proves
    INTERNAL self-consistency. It cannot, on its own, detect an attacker who
    truncates the file (removes the most recent N entries) and then appends
    new/forged entries continuing correctly from the new, shorter tail --
    the result re-verifies as "ok": True. Verified live with a real isolated
    test (not assumed): a 4-entry chain, with the last entry deleted and a
    forged one appended in its place, still reports {"ok": True}. This is
    the textbook rollback/truncation weakness of any pure hash-chain log
    (the same reason Certificate Transparency needs external gossip/witness
    checkpoints, not hash-chaining alone). See verify_chain_against_checkpoints()
    for the real, if partial, mitigation this module adds."""
    entries = _read_all_entries()
    expected_prev = GENESIS_HASH
    for entry in entries:
        stored_hash = entry.get("record_hash")
        body = {k: v for k, v in entry.items() if k != "record_hash"}
        recomputed_hash = _sha256_hex(_canonical_json(body))
        if entry.get("prev_hash") != expected_prev:
            return {"ok": False, "total_entries": len(entries), "broken_at_seq": entry.get("seq"), "reason": "prev_hash_mismatch"}
        if stored_hash != recomputed_hash:
            return {"ok": False, "total_entries": len(entries), "broken_at_seq": entry.get("seq"), "reason": "hash_mismatch"}
        expected_prev = stored_hash
    return {"ok": True, "total_entries": len(entries)}


CHECKPOINT_PATH = RUNTIME_DIR / "checkpoints.jsonl"


def write_checkpoint() -> dict:
    """Appends {seq, record_hash, checkpointed_at_utc} for the CURRENT last
    entry to a SEPARATE file -- real, partial mitigation for the
    truncate-then-forge gap verify_chain() cannot close on its own. If
    someone later truncates ledger.jsonl and forges a replacement tail, the
    checkpoint file still shows a later seq/hash existed at an earlier real
    time; verify_chain_against_checkpoints() can then prove the tamper
    verify_chain() alone would miss. Honest, stated limitation: this does
    NOT protect against an attacker who deletes/rewrites BOTH files --
    that would need an anchor outside this platform's own storage
    (external log shipping, a remote witness), out of scope here. Best-effort
    (never raises) and a no-op when the ledger is empty (nothing to
    checkpoint yet)."""
    try:
        entries = _read_all_entries()
        if not entries:
            return {"ok": True, "skipped": "empty_ledger"}
        last = entries[-1]
        checkpoint = {
            "seq": last["seq"],
            "record_hash": last["record_hash"],
            "checkpointed_at_utc": _utc_now(),
        }
        with LOCK_PATH.open("a+") as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                with CHECKPOINT_PATH.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(checkpoint, sort_keys=True, default=str) + "\n")
            finally:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)
        return {"ok": True, "checkpoint": checkpoint}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def verify_chain_against_checkpoints() -> dict:
    """Cross-checks every past checkpoint against the CURRENT chain: for
    each checkpoint {seq, record_hash}, the entry at that seq today must
    still exist and still have that exact record_hash. A mismatch (entry
    missing, or a different hash at that seq) is real, provable evidence of
    truncation/rewrite -- exactly the attack verify_chain() alone cannot
    see. Reports every mismatch found, not just the first, since a reader
    investigating real tampering needs the full extent, not just a
    trip-wire."""
    if not CHECKPOINT_PATH.is_file():
        return {"ok": True, "checkpoints_checked": 0, "mismatches": [], "note": "no checkpoints recorded yet"}
    by_seq = {e["seq"]: e for e in _read_all_entries() if "seq" in e}
    mismatches = []
    checked = 0
    for line in CHECKPOINT_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        checkpoint = _safe(lambda: json.loads(line))
        if not checkpoint:
            continue
        checked += 1
        seq = checkpoint.get("seq")
        current = by_seq.get(seq)
        if current is None:
            mismatches.append({"seq": seq, "reason": "entry_no_longer_present", "checkpointed_at_utc": checkpoint.get("checkpointed_at_utc")})
        elif current.get("record_hash") != checkpoint.get("record_hash"):
            mismatches.append({"seq": seq, "reason": "hash_differs_from_checkpoint", "checkpointed_at_utc": checkpoint.get("checkpointed_at_utc")})
    return {"ok": len(mismatches) == 0, "checkpoints_checked": checked, "mismatches": mismatches}


def get_ledger_entries(
    *,
    case_id: str | None = None,
    campaign_id: str | None = None,
    node_id: str | None = None,
    source: str | None = None,
    class_: str | None = None,
    limit: int = 200,
) -> list[dict]:
    entries = _read_all_entries()
    if case_id is not None:
        entries = [e for e in entries if e.get("case_id") == case_id]
    if campaign_id is not None:
        entries = [e for e in entries if e.get("campaign_id") == campaign_id]
    if node_id is not None:
        entries = [e for e in entries if e.get("target_node_id") == node_id]
    if source is not None:
        entries = [e for e in entries if e.get("source") == source]
    if class_ is not None:
        entries = [e for e in entries if e.get("class") == class_]
    return entries[-limit:]


def get_intervention_by_id(intervention_id: str) -> dict | None:
    """Real limitation found verifying M4 against a long-duration real
    intervention (plc_io_manipulation held active ~3h15m across a full
    Level C repetition): this returns only the FIRST entry sharing this
    intervention_id (normally the "applied" one). Its own `rollback_at` is
    always None (only the separate "reverted" entry has it) -- fine for a
    quick fault, but it understates the real window for anything long-lived.
    Kept as-is for callers that only want "the attempt record"; callers
    that need the FULL real window (like the linker) should use
    get_entries_for_intervention() instead."""
    for entry in _read_all_entries():
        if entry.get("intervention_id") == intervention_id:
            return entry
    return None


def get_entries_for_intervention(intervention_id: str) -> list[dict]:
    """ALL ledger entries sharing this intervention_id (typically "applied"
    + "reverted", in that order) -- needed to compute the real full window
    of an intervention, since each phase's timestamps are only partially
    populated on its own entry (see record_intervention's own field-by-phase
    logic in fault_injection/service.py's hook)."""
    return [e for e in _read_all_entries() if e.get("intervention_id") == intervention_id]
