from __future__ import annotations

import json
import logging
import os
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import CAMPAIGNS_ROOT
from ..foc_reconstruction.foc_sources import utc_now

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}
_THREADS: dict[str, threading.Thread] = {}

# Recommendation applied 2026-07-16: same lazy heartbeat+watchdog pattern
# already proven in foc_case_analysis._recover_orphaned_analysis_status
# (which caught the memory_analysis worker death earlier today), generalized
# to every job type that goes through this module (Level B repetitions,
# Level A reports, comparability, paper evidence). See job_runner/README.md.
#
# Ampliado de 180 a 900 (2026-09-23): _THREADS (justo abajo) vive en la memoria de UN worker de
# gunicorn concreto -- un get_job() que aterriza en un worker DISTINTO al que ejecuta el job
# (round-robin entre los 4 workers, o cualquier poll externo -- el propio panel del dashboard, o un
# script de monitorizacion) nunca encuentra el hilo en SU copia de _THREADS y cae directo a mirar
# solo la frescura de `updated_at`. Confirmado en vivo (2026-09-22/23, ver
# investigacion_y_novedad/06_implementacion_forge_dt.md): la fase de analisis de una repeticion
# real llama a regenerate_foc(), que recorre TODO el almacen de evidencia (cientos de casos, cientos
# de GB) y puede tardar bien por encima de 5 minutos con uso de CPU/memoria sostenido -- suficiente,
# combinado con un poll que cae en el worker equivocado en el momento equivocado, para que el
# heartbeat de 30s (_heartbeat_during/_heartbeat_during_analysis_phase) parezca "viejo" durante mas
# de 180s aunque el hilo siga vivo y trabajando de verdad. Tres campanas reales interrumpidas asi
# antes de este cambio. 900s sigue siendo un margen pequeno frente a la duracion real de una
# campana (horas), asi que un job genuinamente muerto se sigue detectando en un tiempo razonable.
_ORPHAN_JOB_GRACE_SECONDS = 900


def _parse_ts(raw) -> float | None:
    if not raw:
        return None
    try:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


class JobCancelled(Exception):
    pass


def _write_json(path: Path, payload: dict) -> None:
    """Atomic write. The tmp filename is unique per call (pid+thread+uuid),
    not just `path + '.tmp'` — 2026-07-17: a shared tmp name let two writers
    to the same job file (e.g. the job's own worker thread and a cross-worker
    orphan-recovery write, see get_job()/_recover_orphaned_job) race, where
    the second .replace() found the first writer's tmp already consumed and
    raised '[Errno 2] No such file or directory: ...json.tmp'. That crashed
    the whole repetition outright. A unique tmp per write makes concurrent
    writes to the same path safe (last write wins, cleanly) instead of
    raising.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def new_job(*, job_type: str, title: str, job_path: Path, meta: dict | None = None) -> dict:
    job_id = f"exp-{uuid.uuid4().hex[:12]}"
    payload = {
        "job_id": job_id,
        "job_type": job_type,
        "title": title,
        "status": "queued",
        "requested_at": utc_now(),
        "started_at": None,
        "finished_at": None,
        "current_phase": "queued",
        "progress_percent": 0.0,
        "warnings": [],
        "errors": [],
        "generated_artifacts": [],
        "meta": meta or {},
        "job_path": str(job_path),
        "updated_at": utc_now(),
    }
    with _LOCK:
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def update_job(job_id: str, job_path: Path, **changes) -> dict:
    with _LOCK:
        payload = dict(_JOBS.get(job_id) or {})
        if payload.get("hard_stop_locked") and not changes.pop("allow_post_stop_update", False):
            _JOBS[job_id] = payload
            _write_json(job_path, payload)
            return payload
        payload.update(changes)
        # Heartbeat: every update marks the job as "still being worked on" —
        # this is what the orphan watchdog in get_job() compares against, so
        # every call site gets it for free without needing to pass it itself.
        payload["updated_at"] = utc_now()
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def append_job_list(job_id: str, job_path: Path, field: str, value) -> dict:
    with _LOCK:
        payload = dict(_JOBS.get(job_id) or {})
        if payload.get("hard_stop_locked"):
            _JOBS[job_id] = payload
            _write_json(job_path, payload)
            return payload
        items = list(payload.get(field) or [])
        items.append(value)
        payload[field] = items
        payload["updated_at"] = utc_now()
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def _recover_orphaned_job(payload: dict, job_path: Path) -> dict:
    """Lazy watchdog: if a job's own status still says 'running' (or
    'cancel_requested' — see below) but nothing has touched it (no
    update_job/append_phase call, which now always stamps 'updated_at') for
    _ORPHAN_JOB_GRACE_SECONDS, and no thread in THIS worker process is
    actively running it, treat it as interrupted rather than leaving it
    stuck forever.

    Mirrors foc_reconstruction.foc_case_analysis._recover_orphaned_analysis_status
    (which already catches this for nested analysis phases) at the outer job
    level, so a dead job doesn't block new launches (see
    level_b_repetition_runner.find_active_level_b_job) or sit invisible in the
    Live Campaign Status panel forever. Does not delete or retry anything —
    only marks the truth and lets the operator decide what's next.

    'cancel_requested' is included as of 2026-07-19: a job whose thread died
    (e.g. a gunicorn worker cycled during a reload) AFTER a cancel/force-stop
    request was recorded but BEFORE the thread itself ever reached a
    job_cancel_requested() checkpoint to actually process it and set a real
    terminal status stays in 'cancel_requested' forever otherwise --
    'cancel_requested' was never in _ACTIVE_JOB_TERMINAL_STATUSES, so a job
    stuck there doesn't just look wrong, it permanently blocks
    find_active_level_b_job()'s concurrent-launch guard, silently refusing
    every future launch attempt. Confirmed live: exactly this happened
    immediately after a gunicorn reload cycled the worker running a job that
    had just been asked to cancel.

    'queued' is also included, defensively, as of the same date: new_job()
    writes status='queued' and start_job() registers _THREADS[job_id] and
    calls thread.start() immediately afterwards in the same synchronous call
    stack (no I/O in between) -- so in the overwhelming majority of cases a
    'queued' job either becomes 'running' within microseconds or was never
    persisted at all. The only way one survives on disk while stuck at
    'queued' is if the worker process was killed in that exact microscopic
    window between the two calls (e.g. OOM-kill, forced worker recycle). That
    window is far narrower than for 'running'/'cancel_requested', but the
    failure mode is identical (silently blocks future launch guards forever)
    and the fix is a one-line, zero-behavior-change addition to the same
    tuple, so it is closed the same way rather than left as a residual gap.
    """
    job_id = str(payload.get("job_id") or "")
    status = str(payload.get("status") or "").lower()
    if status not in ("running", "cancel_requested", "queued") or not job_id:
        return payload

    with _LOCK:
        thread = _THREADS.get(job_id)
    if thread and thread.is_alive():
        return payload

    last_activity = _parse_ts(payload.get("updated_at")) or _parse_ts(payload.get("started_at")) or _parse_ts(payload.get("requested_at"))
    if last_activity is None or (time.time() - last_activity) <= _ORPHAN_JOB_GRACE_SECONDS:
        return payload

    last_phase = str(payload.get("current_phase") or payload.get("current_phase_label") or "unknown")
    final_status = "cancelled" if status == "cancel_requested" else "failed"
    reason = (
        f"Job state was left in '{status}' mode at phase '{last_phase}', but no active worker for it "
        f"exists anymore (no update in over {_ORPHAN_JOB_GRACE_SECONDS}s). It was likely interrupted "
        "by a process/worker restart before it could finish. Nothing already produced was deleted — "
        "review and relaunch manually if needed."
    )
    payload = dict(payload)
    payload["status"] = final_status
    payload["finished_at"] = payload.get("finished_at") or utc_now()
    errors = list(payload.get("errors") or [])
    already_present = any(isinstance(item, dict) and str(item.get("message") or "") == reason for item in errors)
    if not already_present:
        errors.append({"message": reason, "phase": last_phase})
    payload["errors"] = errors
    payload["updated_at"] = utc_now()
    with _LOCK:
        _JOBS[job_id] = payload
    _write_json(job_path, payload)

    case_id = payload.get("current_case_id")
    if case_id:
        try:
            from ..forensics.forensics_api import release_stale_preservation_lock_for_case
            release_stale_preservation_lock_for_case(case_id, reason=reason)
        except Exception:
            pass
    return payload


def get_job(job_id: str) -> dict | None:
    with _LOCK:
        cached = dict(_JOBS.get(job_id) or {})
        owned = job_id in _THREADS
    if cached and owned:
        # This worker is genuinely running the job's background thread, so
        # its own in-memory copy is authoritative and always at least as
        # fresh as disk (every update_job/append_phase call in this process
        # writes both at once) -- no need to touch disk at all here.
        return _recover_orphaned_job(cached, Path(str(cached.get("job_path") or "")))

    # Not owned by this worker (a job started by a DIFFERENT gunicorn worker,
    # or one whose thread already finished in this same process). The naive
    # version of this function returned `cached` here whenever it was
    # non-empty -- but a non-owning worker's only way to ever populate
    # _JOBS[job_id] is the one-time disk-glob fallback further below, and
    # once cached that way it was never invalidated again: every subsequent
    # get_job() call on that SAME worker kept returning that exact frozen
    # snapshot from whenever it first happened to see this job_id, forever
    # (until the worker itself restarts) -- even while the job kept
    # genuinely progressing in its owning worker. Confirmed live 2026-07-19:
    # a Level B repetition polled from a non-owning worker showed every
    # stage as "pending" (a snapshot frozen at job creation, before even the
    # first phase fired) while the SAME job, read moments later via a path
    # that hit its owning worker, showed it already six stages further along.
    # This was very likely the single largest contributor to "80% of the
    # time showing info that has nothing to do with what's happening right
    # now" reported the same day -- with -w 4, roughly 3 of every 4 polls
    # land on a non-owning worker.
    #
    # Fix: if we already know this job's path (from an earlier cache hit,
    # however stale), re-read just that ONE file fresh every time instead of
    # trusting the frozen copy -- cheap (single file), and correct. Only the
    # very first time a given worker ever encounters a job_id does it pay
    # for the full store-wide glob below.
    job_path_str = cached.get("job_path")
    if job_path_str:
        try:
            job_path = Path(job_path_str)
            payload = json.loads(job_path.read_text(encoding="utf-8"))
            payload = _recover_orphaned_job(payload, job_path)
            with _LOCK:
                _JOBS[job_id] = payload
            return payload
        except Exception:
            pass  # file missing/corrupt transiently -- fall through to the full scan below

    # Under a multi-process server (e.g. gunicorn -w N), each worker keeps its
    # own in-memory _JOBS dict, so a job started by one worker is invisible to
    # a status poll handled by another -- the poll would otherwise report
    # job_not_found even while the job is genuinely running. Fall back to the
    # job file on disk, which every update already writes via _write_json,
    # mirroring evidence_lifecycle_dashboard.get_lifecycle_job()'s same
    # disk-fallback for the same reason.
    for job_path in CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
        try:
            payload = json.loads(job_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict) and payload.get("job_id") == job_id:
            payload = _recover_orphaned_job(payload, job_path)
            with _LOCK:
                _JOBS[job_id] = payload
            return payload
    # Disk has no matching file (deleted, or genuinely never existed) -- fall
    # back to whatever this process has cached, if anything, rather than
    # reporting not-found for a job this same process legitimately knows about.
    if cached:
        return _recover_orphaned_job(cached, Path(str(cached.get("job_path") or "")))
    return None


def job_cancel_requested(job_id: str, job_path: Path | None = None) -> bool:
    # get_job() trusts this worker's own in-memory _JOBS cache unconditionally
    # once it owns the job's thread (see get_job()'s 2026-07-19 fix) -- which
    # is exactly right for that function's purpose (the owning worker's live
    # state is always at least as fresh as disk for its OWN writes), but it
    # means the owning worker can never observe a cancel/force-stop request
    # that a DIFFERENT worker just wrote to disk: its own next natural
    # update_job() call would read its stale local copy (no
    # cancel_requested/hard_stop_locked in it) and silently overwrite the
    # stop request right back to "running". Confirmed live 2026-07-19: a
    # force-stop request was defeated exactly this way.
    #
    # When the caller already has job_path (every _wait_for_*/raise_if_cancelled
    # call site in this codebase does), read that ONE file fresh here instead
    # -- cheap (single JSON read), and guarantees disk-truth regardless of
    # which worker is asking, closing the gap for the case that actually
    # matters (the owning worker checking on its own cancellation state).
    if job_path is not None:
        try:
            payload = json.loads(job_path.read_text(encoding="utf-8"))
        except Exception:
            payload = None
        if isinstance(payload, dict):
            return bool(payload.get("cancel_requested")) or str(payload.get("status") or "").lower() in {"cancel_requested", "cancelled", "stopped"}
    payload = get_job(job_id) or {}
    return bool(payload.get("cancel_requested")) or str(payload.get("status") or "").lower() in {"cancel_requested", "cancelled", "stopped"}


def request_cancel(job_id: str) -> dict | None:
    payload = get_job(job_id)
    if not payload:
        return None
    job_path = Path(str(payload.get("job_path") or ""))
    status = str(payload.get("status") or "").lower()
    if status in {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}:
        return payload
    return update_job(
        job_id,
        job_path,
        cancel_requested=True,
        cancel_requested_at=utc_now(),
        status="cancel_requested",
    )


def request_force_stop(job_id: str) -> dict | None:
    payload = get_job(job_id)
    if not payload:
        return None
    job_path = Path(str(payload.get("job_path") or ""))
    status = str(payload.get("status") or "").lower()
    if status in {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}:
        return payload
    return update_job(
        job_id,
        job_path,
        cancel_requested=True,
        cancel_requested_at=utc_now(),
        force_stop_requested=True,
        force_stop_requested_at=utc_now(),
        status="stopped",
        finished_at=utc_now(),
        current_phase="force_stopped",
        current_phase_label="Force Stopped",
        current_phase_detail="A forced stop was requested by the operator. Nested scientific work was asked to stop, and the experimentation wrapper was closed immediately.",
        progress_percent=100.0,
        hard_stop_locked=True,
    )


def raise_if_cancelled(job_id: str, job_path: Path, *, phase_key: str | None = None, phase_label: str | None = None, detail: str | None = None) -> None:
    if not job_cancel_requested(job_id, job_path):
        return
    # Same fresh-disk-read reasoning as job_cancel_requested() above -- we
    # already know a stop was requested; read the specific file again here
    # rather than get_job() (which, for the owning worker, would trust its
    # own stale local cache and could misreport a force-stop as a plain
    # cancel, or vice versa).
    try:
        payload = json.loads(job_path.read_text(encoding="utf-8"))
    except Exception:
        payload = get_job(job_id) or {}
    force_stop = bool(payload.get("force_stop_requested")) or str(payload.get("status") or "").lower() == "stopped"
    update_job(
        job_id,
        job_path,
        status="stopped" if force_stop else "cancelled",
        finished_at=utc_now(),
        current_phase=phase_key or ("force_stopped" if force_stop else "cancelled"),
        current_phase_label=phase_label or ("Force Stopped" if force_stop else "Cancelled"),
        current_phase_detail=detail or ("A forced stop was requested by the operator." if force_stop else "Job cancellation was requested by the operator."),
        progress_percent=100.0,
        hard_stop_locked=force_stop,
    )
    raise JobCancelled(detail or "job_cancelled")


def list_jobs() -> list[dict]:
    with _LOCK:
        return [dict(item) for item in _JOBS.values()]


def append_phase(job_id: str, job_path: Path, *, phase_key: str, phase_label: str, status: str, progress_percent: float, detail: str | None = None) -> dict:
    with _LOCK:
        payload = dict(_JOBS.get(job_id) or {})
        phases = list(payload.get("phase_statuses") or [])
        phases.append(
            {
                "phase_key": phase_key,
                "phase_label": phase_label,
                "status": status,
                "detail": detail,
                "updated_at": utc_now(),
                "progress_percent": progress_percent,
            }
        )
        payload["phase_statuses"] = phases
        payload["current_phase"] = phase_key
        payload["current_phase_label"] = phase_label
        payload["current_phase_detail"] = detail
        payload["progress_percent"] = progress_percent
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def start_job(job: dict, target) -> dict:
    job_id = str(job["job_id"])
    job_path = Path(job["job_path"])

    def runner():
        update_job(
            job_id,
            job_path,
            status="running",
            started_at=utc_now(),
            current_phase="starting",
            current_phase_label="Starting",
            current_phase_detail="Preparing experimentation job runner.",
            progress_percent=1.0,
            phase_statuses=[
                {
                    "phase_key": "starting",
                    "phase_label": "Starting",
                    "status": "running",
                    "detail": "Preparing experimentation job runner.",
                    "updated_at": utc_now(),
                    "progress_percent": 1.0,
                }
            ],
        )
        try:
            target(job_id, job_path)
        except JobCancelled:
            existing = get_job(job_id) or {}
            if str(existing.get("status") or "").lower() == "stopped":
                return
            update_job(
                job_id,
                job_path,
                status="cancelled",
                finished_at=utc_now(),
                current_phase="cancelled",
                current_phase_label="Cancelled",
                current_phase_detail="Job cancellation was requested by the operator.",
                progress_percent=100.0,
            )
        except Exception as exc:
            logger.exception("Experimentation job %s failed", job_id)
            update_job(
                job_id,
                job_path,
                status="failed",
                finished_at=utc_now(),
                current_phase="failed",
                progress_percent=100.0,
                errors=[{"message": str(exc), "traceback": traceback.format_exc(limit=20)}],
            )
        finally:
            with _LOCK:
                _THREADS.pop(job_id, None)

    thread = threading.Thread(target=runner, daemon=True, name=f"foc-exp-{job_id}")
    with _LOCK:
        _THREADS[job_id] = thread
    thread.start()
    return job
