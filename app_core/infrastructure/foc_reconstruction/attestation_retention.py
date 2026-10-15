from __future__ import annotations

"""Retention safety valve for the attestation pipeline's raw sources
(investigacion_y_novedad, user question 2026-10-10: "alert_correlation.json
es un fichero real de 6.4GB... no hace falta limpiarlo?"). Confirmed by
reading the code, not assumed: `foc_timeline_builder.build_timeline()`
globs `attack/outputs/*/result.json` and `forensics/alerts_store/ALERTS-*`
UNCONDITIONALLY, every time it runs, across the platform's ENTIRE history --
no existing retention policy covers these two directories (`retention_service.py`
only ever cleans the heavy per-case `evidence_store/CASE-*` bundles). This is
the same root cause already documented for the real OOM incident referenced
in `foc_causal_reconstruction/loaders/foc_context_loader.py`'s own docstring
(alert_correlation.json once reached a measured 6.4GB).

Deliberately conservative, matching the user's own framing ("si no ves
necesidad, no lo quites"): this is a SAFETY VALVE, not a scheduled purge.
`maybe_cleanup_attestation_sources()` is a no-op, always, unless the REAL
combined size of the two raw source directories exceeds a real cap -- it
never deletes anything just because it's old. When it does act, it only
ever removes entries OLDER than a protection window (a flat
`PROTECT_RECENT_DAYS`, plus never anything overlapping a currently-RUNNING
Level C campaign's own time window), oldest first, stopping the moment the
total is back under the cap -- never more than necessary.

Deliberately does NOT touch `foc-reconstruction/` itself (the generated
attestation files/cache built FROM these two sources) -- that directory is
fully regenerable, and trimming the sources here is what keeps its next
rebuild bounded; surgically editing large pre-built JSON files in place is
a separate, riskier problem not attempted here.
"""

import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ATTACK_OUTPUTS_DIR = PROJECT_ROOT / "app_core" / "infrastructure" / "attack" / "outputs"
ALERTS_STORE_DIR = PROJECT_ROOT / "app_core" / "infrastructure" / "forensics" / "alerts_store"

# Combined real cap across both raw source directories. Current real measured
# size (2026-10-10): ~30.7MB (attack/outputs) + ~230.9MB (alerts_store) =
# ~261.6MB -- nowhere near this cap today; it exists as a real ceiling for
# when campaign volume grows, not because cleanup is needed right now.
RETENTION_CAP_BYTES = 50 * 1024 ** 3  # 50 GB

# Never remove anything newer than this, regardless of cap -- covers both
# "just happened, not analyzed yet" and legitimate real standalone
# interventions (not every real attack/fault belongs to a Level C campaign;
# the capstone demonstration documented in intervention_ledger/README.md is
# exactly this kind of real, valuable, campaign-less data).
PROTECT_RECENT_DAYS = 7

_ATTACK_DIR_TS_RE = re.compile(r"^(\d{8})T(\d{6})Z")
_ALERTS_DIR_TS_RE = re.compile(r"^ALERTS-(\d{8})-(\d{6})Z")


def _parse_dir_ts(name: str, pattern: re.Pattern) -> datetime | None:
    m = pattern.match(name)
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)}{m.group(2)}", "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _dir_size_bytes(path: Path) -> int:
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    except Exception:
        pass
    return total


def _running_campaign_windows() -> list[tuple[datetime, datetime]]:
    """Real time window [created_at, now] for every Level C job currently
    `status == "running"` -- never remove source data overlapping one of
    these, so an active campaign's own causal reconstruction never loses
    evidence mid-run."""
    windows: list[tuple[datetime, datetime]] = []
    try:
        from ..level_c_orchestrator.service import list_jobs
        now = datetime.now(timezone.utc)
        for job in list_jobs() or []:
            if str(job.get("status") or "").lower() != "running":
                continue
            created = job.get("created_at")
            if not created:
                continue
            try:
                started = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
            except Exception:
                continue
            windows.append((started, now))
    except Exception:
        pass
    return windows


def _is_protected(ts: datetime, *, now: datetime, running_windows: list[tuple[datetime, datetime]]) -> bool:
    if (now - ts) < timedelta(days=PROTECT_RECENT_DAYS):
        return True
    return any(start <= ts <= end for start, end in running_windows)


def inspect_attestation_sources() -> dict:
    """Read-only: real current sizes and whether the cap is currently
    exceeded. Always safe to call -- never deletes anything."""
    attack_bytes = _dir_size_bytes(ATTACK_OUTPUTS_DIR) if ATTACK_OUTPUTS_DIR.is_dir() else 0
    alerts_bytes = _dir_size_bytes(ALERTS_STORE_DIR) if ALERTS_STORE_DIR.is_dir() else 0
    combined = attack_bytes + alerts_bytes
    return {
        "attack_outputs_bytes": attack_bytes,
        "alerts_store_bytes": alerts_bytes,
        "combined_bytes": combined,
        "cap_bytes": RETENTION_CAP_BYTES,
        "cap_exceeded": combined > RETENTION_CAP_BYTES,
    }


def maybe_cleanup_attestation_sources(dry_run: bool = False) -> dict:
    """The one real entry point. No-op (status "not_needed") unless the real
    combined size exceeds RETENTION_CAP_BYTES. When it IS exceeded, removes
    the oldest, unprotected entries from attack/outputs/ and
    forensics/alerts_store/ -- oldest first, by each directory's own real
    embedded timestamp -- stopping as soon as the total is back under the
    cap. `dry_run=True` reports exactly what WOULD be removed without
    touching anything, same real logic."""
    inspection = inspect_attestation_sources()
    if not inspection["cap_exceeded"]:
        return {"ok": True, "action": "not_needed", **inspection}

    now = datetime.now(timezone.utc)
    running_windows = _running_campaign_windows()

    candidates: list[tuple[datetime, Path, int]] = []
    if ATTACK_OUTPUTS_DIR.is_dir():
        for entry in ATTACK_OUTPUTS_DIR.iterdir():
            if not entry.is_dir():
                continue
            ts = _parse_dir_ts(entry.name, _ATTACK_DIR_TS_RE)
            if ts is None or _is_protected(ts, now=now, running_windows=running_windows):
                continue
            candidates.append((ts, entry, _dir_size_bytes(entry)))
    if ALERTS_STORE_DIR.is_dir():
        for entry in ALERTS_STORE_DIR.iterdir():
            if not entry.is_dir():
                continue
            ts = _parse_dir_ts(entry.name, _ALERTS_DIR_TS_RE)
            if ts is None or _is_protected(ts, now=now, running_windows=running_windows):
                continue
            candidates.append((ts, entry, _dir_size_bytes(entry)))

    candidates.sort(key=lambda item: item[0])  # oldest first

    removed = []
    remaining = inspection["combined_bytes"]
    for ts, path, size_bytes in candidates:
        if remaining <= RETENTION_CAP_BYTES:
            break
        if not dry_run:
            try:
                shutil.rmtree(path)
            except Exception as exc:
                removed.append({"path": str(path), "size_bytes": size_bytes, "timestamp": ts.isoformat(), "error": str(exc)})
                continue
        removed.append({"path": str(path), "size_bytes": size_bytes, "timestamp": ts.isoformat()})
        remaining -= size_bytes

    return {
        "ok": True,
        "action": "dry_run" if dry_run else "cleaned",
        "removed_count": len(removed),
        "removed_bytes": sum(r.get("size_bytes", 0) for r in removed),
        "removed": removed,
        "protected_recent_days": PROTECT_RECENT_DAYS,
        "running_campaign_windows": len(running_windows),
        **inspection,
    }
