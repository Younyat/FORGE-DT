import gc
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from .foc_bootstrap import bootstrap_existing_context, read_id_mapping
from .foc_attestation_builder import build_attestations
from .foc_bom_builder import build_scenario_bom, build_tools_bom
from .foc_config import GENERATED_FILES, READ_ONLY_MODE, ensure_output_layout
from .foc_events import record_foc_event
from .foc_hashing import hash_file
from .foc_indexer import build_indexes
from .foc_paths import generated_relative_paths, relative_path
from .foc_schema import clone, empty_foc_manifest
from .foc_sources import collect_sources, utc_now
from .foc_timeline_builder import build_timeline

logger = logging.getLogger(__name__)


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=False)


def _safe_read_json(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _lifecycle_state(sources_bundle: dict) -> str:
    paths = {item.get("path"): item for item in sources_bundle.get("sources", [])}
    scenario_ref = paths.get("scenario/scenario_file.json", {})
    if scenario_ref.get("status") == "present":
        deployment_ref = paths.get("scenario/deployment_status.json", {})
        destroy_ref = paths.get("scenario/destroy_status.json", {})
        if (deployment_ref.get("mtime") or 0) >= (destroy_ref.get("mtime") or 0):
            return "active"
        destroy = _safe_read_json(Path(destroy_ref.get("path", "")))
        if isinstance(destroy, dict) and str(destroy.get("status", "")).lower() == "success":
            return "destroyed"
        return "active"
    return "unknown"


def _hash_generated_file(path: Path) -> str:
    return hash_file(path) if path.is_file() else ""


# How long a just-regenerated manifest is trusted as "still fresh enough" to
# skip a full re-run. See regenerate_foc()'s own docstring for the incident
# that motivated this.
#
# 2026-07-19: raised from 300s to 1800s after confirming a second, earlier
# redundancy: a Level A dry-run's own "Bootstrap FOC" call is ALSO
# structurally redundant with the regenerate_foc() call the case's own
# analysis already made in its LAST phase (foc_case_analysis._phase_foc_refresh,
# "foc_readiness_update") -- Level B's "store" phase (which launches the
# nested dry-run) never starts until that analysis and its reconstruction
# phase have already completed, so the exact attack-attestation data the
# dry-run's causal reconstruction needs (foc_causal_reconstruction/service.py
# _build_case_context(): looks up THIS case's own attack inside the global
# attack_attestation.json) is already there by construction. The real gap
# between "analysis finishes" and "dry-run's bootstrap runs" measured in
# practice as seconds to low minutes (reconstruction is near-instant, store
# launches right after) -- 1800s (30min) comfortably covers that with a lot
# of margin, while remaining short enough that a genuinely separate, later
# caller (a dashboard click hours later, a fresh Level B repetition on a
# different case) still gets a real, guaranteed-fresh rebuild rather than
# silently reusing unrelated data. Deliberately NOT removing the dry-run's
# own call outright (a colder, riskier change with no real safety net if the
# above ordering assumption is ever violated) -- this keeps a genuine
# fallback rebuild available while capturing effectively the same time
# savings in the common case.
_REGENERATE_SKIP_TTL_SECONDS = 1800


def _seconds_since(iso_ts) -> float | None:
    if not iso_ts:
        return None
    try:
        text = str(iso_ts).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return time.time() - dt.timestamp()
    except Exception:
        return None


def regenerate_foc(bootstrap_mode: bool = False, force: bool = False) -> dict:
    """Rebuild every generated FOC artifact (BOMs, timeline, sources,
    indexes, attestations — ~20 files, ~2GB on a populated evidence store)
    from scratch across the WHOLE evidence store, not scoped to any one
    case or campaign. Also backs the FOC Reconstruction and Evidence
    Lifecycle dashboards (see foc_endpoints.py, evidence_lifecycle_dashboard.py),
    which is why it stays store-wide rather than case-scoped.

    `force=False` (default): if the on-disk manifest was already
    regenerated within the last `_REGENERATE_SKIP_TTL_SECONDS`, this is a
    no-op returning that existing manifest instead of repeating the full
    rebuild. Investigated live 2026-07-19 (see foc_experimentation/README.md):
    a single Level A dry-run execution triggered THREE full regenerate_foc()
    calls back-to-back — dry_run_orchestrator's own "Bootstrap FOC" phase,
    then the case's own 14-phase analysis's LAST phase
    (foc_case_analysis._phase_foc_refresh, "foc_readiness_update"), then
    evidence_lifecycle_dashboard's own "Regenerate FOC context" phase
    immediately after that — with nothing evidence-relevant changing
    between the back-to-back pairs. Pass `force=True` for a caller that
    must guarantee a truly fresh rebuild regardless of timing (e.g. the
    dashboard's own user-triggered "Regenerate" button — see foc_endpoints.py).
    """
    ensure_output_layout()
    if not force:
        existing = _safe_read_json(GENERATED_FILES["manifest"])
        if isinstance(existing, dict):
            age = _seconds_since(existing.get("updated_at"))
            if age is not None and age < _REGENERATE_SKIP_TTL_SECONDS:
                logger.info("regenerate_foc: skipped, manifest is %.1fs old (< %ss TTL)", age, _REGENERATE_SKIP_TTL_SECONDS)
                return existing
    warnings: list[dict] = []
    id_mapping = read_id_mapping()
    if id_mapping is None:
        bootstrap_existing_context(force=False)
        id_mapping = read_id_mapping() or {"generated_at": utc_now(), "bootstrap_mode": True, "mappings": {}, "warnings": []}

    scenario_bom, scenario_context = build_scenario_bom(id_mapping=id_mapping)
    tools_bom = build_tools_bom(scenario_context, id_mapping=id_mapping)
    timeline = build_timeline(scenario_context, id_mapping=id_mapping)
    sources_bundle = collect_sources()
    indexes = build_indexes(scenario_bom, tools_bom, timeline, sources_bundle, id_mapping=id_mapping)
    attestations = build_attestations(
        scenario_bom,
        tools_bom,
        timeline,
        sources_bundle,
        indexes,
        id_mapping=id_mapping,
    )

    _write_json(GENERATED_FILES["scenario_bom"], scenario_bom)
    _write_json(GENERATED_FILES["tools_bom"], tools_bom)
    _write_json(GENERATED_FILES["timeline"], timeline)
    _write_json(GENERATED_FILES["attack_attestation"], attestations["attack_attestation"])
    _write_json(GENERATED_FILES["detection_attestation"], attestations["detection_attestation"])
    _write_json(GENERATED_FILES["alerts_normalized"], attestations["alerts_normalized"])
    _write_json(GENERATED_FILES["alert_correlation"], attestations["alert_correlation"])
    _write_json(GENERATED_FILES["alert_correlation_summary"], attestations["alert_correlation_summary"])
    _write_json(GENERATED_FILES["acquisition_profile"], attestations["acquisition_profile"])
    _write_json(GENERATED_FILES["forensic_intervention"], attestations["forensic_intervention"])
    _write_json(GENERATED_FILES["forensic_analysis_manifest"], attestations["forensic_analysis_manifest"])
    _write_json(GENERATED_FILES["scenario_ground_truth"], attestations["scenario_ground_truth"])
    _write_json(GENERATED_FILES["case_manifest_link"], attestations["case_manifest_link"])
    _write_json(GENERATED_FILES["foc_context_summary"], attestations["foc_context_summary"])
    _write_json(GENERATED_FILES["foc_readiness_report"], attestations["foc_readiness_report"])
    _write_json(GENERATED_FILES["id_mapping"], id_mapping)
    _write_json(GENERATED_FILES["sources_index"], indexes["sources_index"])
    _write_json(GENERATED_FILES["artifacts_index"], indexes["artifacts_index"])
    _write_json(GENERATED_FILES["relationships_index"], indexes["relationships_index"])
    _write_json(GENERATED_FILES["cases_index"], indexes["cases_index"])

    # `attestations` ya esta completamente escrita en disco a estas alturas (todos los
    # GENERATED_FILES[...] de mas arriba) y no se vuelve a leer en el resto de la funcion -- a
    # diferencia de scenario_bom/tools_bom/timeline/sources_bundle/indexes, que si hacen falta mas
    # abajo para construir `manifest` (lifecycle_state, warnings, hashes de sha256). Liberarla aqui
    # reduce algo el pico de memoria sin arriesgarse a un NameError sobre las demas.
    del attestations

    hashes_payload = {
        "generated_at": utc_now(),
        "hashes": {
            relative_path(path): _hash_generated_file(path)
            for path in GENERATED_FILES.values()
            if path.name != "foc_manifest.json"
        },
    }
    _write_json(GENERATED_FILES["hashes_index"], hashes_payload)

    existing_manifest = _safe_read_json(GENERATED_FILES["manifest"])
    manifest = clone(empty_foc_manifest())
    if isinstance(existing_manifest, dict) and existing_manifest.get("created_at"):
        manifest["created_at"] = existing_manifest["created_at"]
    else:
        manifest["created_at"] = utc_now()

    manifest["foc_id"] = f"foc-{scenario_context.get('scenario_id', 'unknown')}"
    manifest["scenario_id"] = scenario_context.get("scenario_id", "unknown")
    manifest["scenario_name"] = scenario_context.get("scenario_name", "unknown")
    manifest["updated_at"] = utc_now()
    manifest["reconstructed_at"] = utc_now()
    manifest["lifecycle_state"] = _lifecycle_state(sources_bundle)
    manifest["read_only_reconstruction"] = READ_ONLY_MODE
    manifest["bootstrap_mode"] = bool(bootstrap_mode or id_mapping.get("bootstrap_mode"))
    manifest["id_mapping_path"] = generated_relative_paths()["id_mapping"]
    manifest["scenario_bom"]["sha256"] = _hash_generated_file(GENERATED_FILES["scenario_bom"])
    manifest["tools_bom"]["sha256"] = _hash_generated_file(GENERATED_FILES["tools_bom"])
    manifest["timeline"]["sha256"] = _hash_generated_file(GENERATED_FILES["timeline"])
    manifest["warnings"] = (
        id_mapping.get("warnings", [])
        + 
        scenario_bom.get("warnings", [])
        + tools_bom.get("warnings", [])
        + timeline.get("warnings", [])
        + sources_bundle.get("warnings", [])
        + indexes.get("warnings", [])
        + warnings
    )
    manifest["generation_status"] = "warnings" if manifest["warnings"] else "ok"

    # Esta es la ultima linea que usa scenario_bom/tools_bom/timeline/sources_bundle/indexes --
    # todas ya escritas en disco hace tiempo, y de aqui en adelante `manifest` es autosuficiente.
    # Liberarlas aqui (en vez de esperar a que la funcion termine) reduce el pico real de memoria
    # durante el resto de regenerate_foc() -- motivado por un fallo real (2026-09-23) donde una
    # prueba aislada de esta misma funcion crecio de 1GB a 3.3GB de RSS en ~4 minutos, en un
    # entorno con cientos de casos acumulados en el almacen de evidencia. No cambia ningun dato ya
    # escrito ni el resultado final -- solo libera memoria que ya no hace falta.
    del scenario_bom, tools_bom, timeline, sources_bundle, indexes
    gc.collect()

    manifest["source_indexes"] = {
        "sources": generated_relative_paths()["sources_index"],
        "artifacts": generated_relative_paths()["artifacts_index"],
        "relationships": generated_relative_paths()["relationships_index"],
        "cases": generated_relative_paths()["cases_index"],
    }
    manifest["derived_context"] = {
        "attack_attestation": generated_relative_paths()["attack_attestation"],
        "detection_attestation": generated_relative_paths()["detection_attestation"],
        "alerts_normalized": generated_relative_paths()["alerts_normalized"],
        "alert_correlation": generated_relative_paths()["alert_correlation"],
        "alert_correlation_summary": generated_relative_paths()["alert_correlation_summary"],
        "acquisition_profile": generated_relative_paths()["acquisition_profile"],
        "forensic_intervention": generated_relative_paths()["forensic_intervention"],
        "forensic_analysis_manifest": generated_relative_paths()["forensic_analysis_manifest"],
        "scenario_ground_truth": generated_relative_paths()["scenario_ground_truth"],
        "case_manifest_link": generated_relative_paths()["case_manifest_link"],
        "foc_context_summary": generated_relative_paths()["foc_context_summary"],
        "foc_readiness_report": generated_relative_paths()["foc_readiness_report"],
    }

    _write_json(GENERATED_FILES["manifest"], manifest)
    hashes_payload["hashes"][relative_path(GENERATED_FILES["manifest"])] = _hash_generated_file(GENERATED_FILES["manifest"])
    _write_json(GENERATED_FILES["hashes_index"], hashes_payload)
    record_foc_event(
        "foc_regenerated",
        {
            "scenario_id": manifest["scenario_id"],
            "bootstrap_mode": manifest["bootstrap_mode"],
            "generation_status": manifest["generation_status"],
        },
    )
    logger.info("FOC regeneration completed with status=%s", manifest["generation_status"])
    return manifest


def read_generated_json(path: Path) -> dict | list | None:
    return _safe_read_json(path)
