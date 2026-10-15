from __future__ import annotations

"""Lazy, read-only traversal of the platform's real job-nesting chain
(Level C -> Level B -> Level A/dry-run -> lifecycle job ->
evidence-support/executive-summary worker). See
investigacion_y_novedad/08_dashboard_sala_control.md section 3.3 for the
full design and sources.

Never writes anything, never creates threads, never triggers any new action
-- it only calls the `get_job`/`get_job_status`/`get_lifecycle_job` that each
of the platform's 4 job stores already exposes. This module is the direct
response to the most expensive finding of the 2026-09-25/26 session: a
nested job died in a gunicorn restart and nothing above it checked its
status again for over 15 hours, because each store's orphan detection is
lazy (only triggers if someone READS that specific job_id) and nothing walks
the full chain proactively. This module doesn't do it in the background
either -- it remains on-demand, but at least lets you request "the full
chain" in a single call instead of having to manually investigate level by
level like had to be done that time.
"""

import time
from datetime import datetime, timezone

MAX_DEPTH = 8
_CACHE_TTL_SECONDS = 4.0

# Documented grace threshold for each real store -- a universal threshold is
# never assumed. None means "that store has no generic time threshold"
# (either it has no orphan detection at all, or it has one based on real file
# evidence instead of time -- see the comment on each _lookup_* function).
STORE_GRACE_SECONDS: dict[str, float | None] = {
    "job_runner": 900.0,   # job_runner._ORPHAN_JOB_GRACE_SECONDS
    "level_c": 180.0,      # level_c_orchestrator._ORPHAN_LC_JOB_GRACE_SECONDS
    "lifecycle": None,     # no time threshold -- _recover_stale_lifecycle_job checks
                           # whether a real file (hypothesis_support_report.json) already
                           # exists on disk, not how much time has passed
    "volatility": None,    # no orphan recovery at all -- purely in
                           # memory (_JOBS.get), a job "disappears" (None) if the worker
                           # that held it died, instead of being marked "failed"
}

_ORPHAN_MESSAGE_MARKER = "no active worker for it exists anymore"

_cache: dict[str, dict] = {}


def _now() -> float:
    return time.time()


def _parse_ts(value) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _lookup_job_runner(job_id: str) -> dict | None:
    try:
        from app_core.infrastructure.foc_experimentation.job_runner import get_job
        return get_job(job_id)
    except Exception:
        return None


def _lookup_lifecycle(job_id: str) -> dict | None:
    try:
        from app_core.infrastructure.foc_reconstruction.evidence_lifecycle_dashboard import get_lifecycle_job
        return get_lifecycle_job(job_id)
    except Exception:
        return None


def _lookup_level_c(job_id: str) -> dict | None:
    try:
        from app_core.infrastructure.level_c_orchestrator.service import get_job_status
        return get_job_status(job_id)
    except Exception:
        return None


def _lookup_volatility(job_id: str) -> dict | None:
    try:
        from app_core.infrastructure.forensics.volatility_symbols import get_job
        return get_job(job_id)
    except Exception:
        return None


STORE_LOOKUPS = {
    "job_runner": _lookup_job_runner,
    "lifecycle": _lookup_lifecycle,
    "level_c": _lookup_level_c,
    "volatility": _lookup_volatility,
}


def _lookup_any_store(job_id: str, hint_store: str | None) -> tuple[dict | None, str | None]:
    """Tries the suggested store first (if it's known where this job_id came
    from, e.g. because the parent put it in current_lifecycle_job_id), then
    the rest in fixed order. Never invents a store -- if none of them
    recognizes it, honestly returns (None, None)."""
    order = [hint_store] if hint_store in STORE_LOOKUPS else []
    order += [store for store in STORE_LOOKUPS if store != hint_store]
    for store in order:
        payload = STORE_LOOKUPS[store](job_id)
        if payload is not None:
            return payload, store
    return None, None


def _liveness_label(payload: dict, store: str | None) -> tuple[str, float | None]:
    """Honest liveness label -- this is never collapsed into a boolean.
    Explicitly distinguishes a job that reached a normal terminal state from
    one that was recovered as an orphan (the exact same text used by
    job_runner._recover_orphaned_job)."""
    status = str(payload.get("status") or "").lower()
    updated_at = _parse_ts(payload.get("updated_at"))
    age = (_now() - updated_at) if updated_at is not None else None

    terminal_statuses = {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}
    if status in terminal_statuses:
        errors = payload.get("errors") or []
        was_orphan_recovered = any(
            _ORPHAN_MESSAGE_MARKER in str((item or {}).get("message", ""))
            for item in errors if isinstance(item, dict)
        )
        return ("orphan_recovered" if was_orphan_recovered else "terminal"), age

    grace = STORE_GRACE_SECONDS.get(store) if store else None
    if age is None:
        return "reported_alive_heartbeat_only", None
    if grace is not None and age > grace:
        return "reported_alive_but_stale", age
    return "confirmed_alive", age


def walk_job_chain(root_job_id: str, root_store: str = "job_runner", *, max_depth: int = MAX_DEPTH) -> dict:
    """Walks the real current_child_job_id / current_lifecycle_job_id chain
    starting at root_job_id. Read-only, short cache (4s) per job_id (same TTL
    as monitor3d), bounded depth so an accidental ID cycle never causes
    infinite recursion. Invoked on demand -- never in a background sweep."""
    chain: list[dict] = []
    job_id: str | None = root_job_id
    hint_store: str | None = root_store
    seen: set[str] = set()

    for _ in range(max_depth):
        if not job_id or job_id in seen:
            break
        seen.add(job_id)

        now = _now()
        cached = _cache.get(job_id)
        if cached and (now - cached["ts"]) < _CACHE_TTL_SECONDS:
            payload, store = cached["payload"], cached["store"]
        else:
            payload, store = _lookup_any_store(job_id, hint_store)
            _cache[job_id] = {"ts": now, "payload": payload, "store": store}

        if payload is None:
            chain.append({"job_id": job_id, "store": None, "liveness": "not_found", "status": None})
            break

        liveness, age = _liveness_label(payload, store)
        chain.append({
            "job_id": job_id,
            "store": store,
            "status": payload.get("status"),
            "current_phase": payload.get("current_phase"),
            "current_phase_detail": payload.get("current_phase_detail"),
            "liveness": liveness,
            "last_heartbeat_age_seconds": round(age, 1) if age is not None else None,
            "grace_seconds": STORE_GRACE_SECONDS.get(store) if store else None,
        })

        next_child = payload.get("current_child_job_id")
        next_lifecycle = payload.get("current_lifecycle_job_id")
        if next_child:
            job_id, hint_store = next_child, None
        elif next_lifecycle:
            job_id, hint_store = next_lifecycle, "lifecycle"
        else:
            job_id = None

    return {
        "root_job_id": root_job_id,
        "depth": len(chain),
        "chain": chain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
