from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from ..config import FOC_ROOT

# `attestations/alert_correlation.json` alone is ~100MB for a populated lab.
# load_foc_context() is called on every causal status poll (not only on
# explicit runs), so re-parsing it unconditionally was the dominant latency
# source in the causal cockpit. Cache the assembled context per foc_root,
# invalidated by mtime on the tracked source files (correct-by-construction)
# with a short TTL as a secondary safety net, mirroring the same pattern
# already used for the FOC dashboard payload in foc_endpoints.py.
_CONTEXT_CACHE_TTL_SECONDS = 30.0
_context_cache: dict[str, dict] = {}
_context_cache_lock = threading.Lock()

# 2026-09-25: `alert_correlation.json` grew from the ~100MB anticipated above
# to a real, measured 6.4GB (foc-reconstruction/attestations/, evidence store
# after this session's many repeated campaigns -- its `correlations` list is
# one entry per (alert x candidate attack) pair EVER produced across the
# whole lab's history, unbounded). `_build_foc_context()` used to
# `_load_json()` this file unconditionally, on every single causal-status
# poll for every case -- reading the full text into one Python string, then
# parsing it into an equally large structure, needing both in memory at
# once. Root-caused live: this was the direct cause of a real, repeated OOM
# during repetition_1_reconstruction (RSS 21GB->38GB, worker killed, 5+
# consecutive campaign failures) -- confirmed only TWO call sites in the
# entire codebase ever read the `correlations` list itself
# (foc_causal_reconstruction/service.py, both doing a single by-attack-id
# lookup, never iterating the whole thing for any other purpose), while
# every other consumer only ever needs the small `alert_correlation_summary`
# (kept eager below, ~17KB). Made lazy: the raw file is no longer parsed as
# part of the normal payload -- see `load_alert_correlation_records()`,
# called on-demand only by the two sites that actually need it. Its mtime is
# still tracked in `tracked_paths` below so the assembled context still
# invalidates correctly when the file changes -- only the eager `_load_json`
# call on its full content was removed.
_ALERT_CORRELATION_CACHE_TTL_SECONDS = 30.0
_alert_correlation_cache: dict[str, dict] = {}
_alert_correlation_cache_lock = threading.Lock()


def _load_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def load_foc_context(foc_root: Path | None = None) -> dict:
    root = Path(foc_root or FOC_ROOT)
    attestations_dir = root / "attestations"
    validation_dir = root / "validation"
    tracked_paths = (
        root / "foc_manifest.json",
        attestations_dir / "attack_attestation.json",
        attestations_dir / "detection_attestation.json",
        attestations_dir / "alert_correlation.json",
        attestations_dir / "alert_correlation_summary.json",
        attestations_dir / "forensic_intervention.json",
        attestations_dir / "forensic_analysis_manifest.json",
        attestations_dir / "foc_context_summary.json",
        attestations_dir / "case_manifest_link.json",
        attestations_dir / "scenario_ground_truth.json",
        validation_dir / "foc_readiness_report.json",
    )
    mtimes = tuple(_file_mtime(path) for path in tracked_paths)
    cache_key = str(root)
    now = time.time()
    with _context_cache_lock:
        cached = _context_cache.get(cache_key)
        if cached and cached["mtimes"] == mtimes and (now - cached["ts"]) < _CONTEXT_CACHE_TTL_SECONDS:
            return cached["payload"]

    payload = _build_foc_context(root)

    with _context_cache_lock:
        _context_cache[cache_key] = {"ts": now, "mtimes": mtimes, "payload": payload}
    return payload


def _build_foc_context(root: Path) -> dict:
    manifest = _load_json(root / "foc_manifest.json") or {}
    attestations_dir = root / "attestations"
    validation_dir = root / "validation"
    payload = {
        "root": root,
        "manifest": manifest,
        "artifact_references": dict(manifest.get("derived_context") or {}),
        "attack_attestation": _load_json(attestations_dir / "attack_attestation.json") or {},
        "detection_attestation": _load_json(attestations_dir / "detection_attestation.json") or {},
        # NOT eagerly loaded -- see comment above _ALERT_CORRELATION_CACHE_TTL_SECONDS. Kept as an
        # empty dict (not omitted) so existing `.get("alert_correlation", {})` call sites that only
        # ever touched the summary keep working unchanged; the two sites that need the real
        # `correlations` list call `load_alert_correlation_records()` directly instead.
        "alert_correlation": {},
        "alert_correlation_summary": _load_json(attestations_dir / "alert_correlation_summary.json") or {},
        "forensic_intervention": _load_json(attestations_dir / "forensic_intervention.json") or {},
        "forensic_analysis_manifest": _load_json(attestations_dir / "forensic_analysis_manifest.json") or {},
        "foc_context_summary": _load_json(attestations_dir / "foc_context_summary.json") or {},
        "case_manifest_link": _load_json(attestations_dir / "case_manifest_link.json") or {},
        "preserved_ground_truth": _load_json(attestations_dir / "scenario_ground_truth.json") or {},
        "readiness_report": _load_json(validation_dir / "foc_readiness_report.json") or {},
    }
    summary = payload["foc_context_summary"] if isinstance(payload["foc_context_summary"], dict) else {}
    preserved_ground_truth = payload["preserved_ground_truth"] if isinstance(payload["preserved_ground_truth"], dict) else {}
    manifest = payload["manifest"] if isinstance(payload["manifest"], dict) else {}
    payload["scenario_id"] = (
        summary.get("scenario_id")
        or preserved_ground_truth.get("scenario_id")
        or manifest.get("scenario_id")
        or "unknown"
    )
    payload["scenario_name"] = (
        summary.get("scenario_name")
        or preserved_ground_truth.get("scenario_name")
        or "unknown"
    )
    return payload


def load_alert_correlation_records(foc_root: Path | None = None) -> list[dict]:
    """On-demand loader for `alert_correlation.json`'s real `correlations`
    list -- the ONLY two call sites that ever need this (both in
    foc_causal_reconstruction/service.py, both a single by-attack-id lookup)
    call this directly instead of reading it out of `load_foc_context()`'s
    payload, which no longer parses it eagerly (see the comment above
    `_ALERT_CORRELATION_CACHE_TTL_SECONDS`). Cached by mtime + a short TTL,
    same shape as the main context cache, so a burst of lookups for the same
    unchanged file doesn't re-parse a multi-GB file repeatedly -- but a
    single real call is still a single real (expensive) parse; this fixes
    the "parsed on every causal-status poll for every case regardless of
    whether anything needs it" problem, not the cost of the one genuine
    lookup itself. Returns [] (never raises) if the file is missing/empty/
    unparseable, matching every other loader in this module."""
    root = Path(foc_root or FOC_ROOT)
    path = root / "attestations" / "alert_correlation.json"
    mtime = _file_mtime(path)
    cache_key = str(path)
    now = time.time()
    with _alert_correlation_cache_lock:
        cached = _alert_correlation_cache.get(cache_key)
        if cached and cached["mtime"] == mtime and (now - cached["ts"]) < _ALERT_CORRELATION_CACHE_TTL_SECONDS:
            return cached["records"]

    parsed = _load_json(path) or {}
    records = parsed.get("correlations") or parsed.get("records") or []

    with _alert_correlation_cache_lock:
        _alert_correlation_cache[cache_key] = {"ts": now, "mtime": mtime, "records": records}
    return records
