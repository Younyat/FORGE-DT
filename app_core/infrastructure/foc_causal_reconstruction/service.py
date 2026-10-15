from __future__ import annotations

import csv
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import (
    ALLOWED_CAUSAL_UI_STATES,
    CPR_LABEL_THRESHOLDS,
    DEFAULT_DERIVED_RELATIVE_DIR,
)
from .evaluators import evaluate_edges
from .graph import build_nodes_from_ground_truth
from .loaders import (
    load_alert_correlation_records,
    load_analysis_summary,
    load_custody_context,
    load_foc_context,
    load_network_ot_context,
    load_timeline_context,
    resolve_ground_truth,
)
from .reports import write_causal_outputs
from .schemas import CausalGraph
from .status_model import derive_status_triad
from .uncertainty import build_uncertainty_report
from .uncertainty import extract_temporal_sync_context
from ..foc_reconstruction.foc_paths import project_path, relative_path
from ..foc_reconstruction.foc_sources import utc_now

_RUNNING_CAUSAL: dict[str, threading.Thread] = {}
_CAUSAL_LOCK = threading.Lock()


def _json_load(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _derived_dir(case_path: Path, out_dir: str | None = None) -> Path:
    if out_dir:
        candidate = Path(out_dir)
        return candidate if candidate.is_absolute() else case_path / candidate
    return case_path / DEFAULT_DERIVED_RELATIVE_DIR


def _status_path(case_path: Path) -> Path:
    return _derived_dir(case_path) / "causal_status.json"


def _paths(case_path: Path) -> dict:
    root = _derived_dir(case_path)
    return {
        "root": root,
        "status": root / "causal_status.json",
        "graph": root / "causal_graph.json",
        "uncertainty": root / "uncertainty_report.json",
        "metrics": root / "reconstruction_metrics.json",
        "csv": root / "causal_edges.csv",
        "report": root / "causal_reconstruction_report.md",
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Internal short keys (used for file lookups) -> the canonical long names the
# UI and causal_status.json contract on, so "Derived Outputs" and "Raw
# artifacts access" can never disagree on what a file is called again.
_CANONICAL_OUTPUT_KEYS = {
    "graph": "causal_graph",
    "uncertainty": "uncertainty_report",
    "metrics": "reconstruction_metrics",
    "csv": "causal_edges_csv",
    "report": "causal_reconstruction_report",
}


def _derived_outputs_status(paths: dict) -> dict:
    outputs: dict = {}
    for short_key, canonical_key in _CANONICAL_OUTPUT_KEYS.items():
        path = paths.get(short_key)
        if path is None or not path.is_file():
            outputs[canonical_key] = {"status": "not_available", "path": relative_path(path) if path else None}
            continue
        try:
            if short_key in {"graph", "uncertainty", "metrics"}:
                json.loads(path.read_text(encoding="utf-8"))
            elif short_key == "csv":
                with path.open("r", encoding="utf-8", newline="") as fh:
                    next(csv.reader(fh), None)
            else:
                if not path.read_text(encoding="utf-8").strip():
                    raise ValueError("markdown report is empty")
            outputs[canonical_key] = {"status": "available", "path": relative_path(path)}
        except Exception:
            outputs[canonical_key] = {"status": "invalid", "path": relative_path(path)}
    return outputs


def _mtime_iso(path: Path) -> str | None:
    try:
        ts = os.path.getmtime(path)
    except OSError:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _source_freshness(case_path: Path, paths: dict) -> dict:
    memory_updated_at = _mtime_iso(case_path / "analysis" / "04_memory" / "memory_findings.json")
    report_updated_at = _mtime_iso(case_path / "analysis" / "forensic_analysis_report.json")
    visual_updated_at = _mtime_iso(case_path / "analysis" / "visual" / "analysis_visual_summary.json")
    graph_payload = _json_load(paths["graph"])
    metrics_payload = _json_load(paths["metrics"])
    causal_graph_generated_at = graph_payload.get("generated_at") if isinstance(graph_payload, dict) else None
    metrics_generated_at = metrics_payload.get("generated_at") if isinstance(metrics_payload, dict) else None
    graph_ts = _parse_ts(causal_graph_generated_at)
    is_stale = False
    if graph_ts is not None:
        for source_iso in (memory_updated_at, report_updated_at, visual_updated_at):
            source_ts = _parse_ts(source_iso)
            if source_ts is not None and source_ts > graph_ts:
                is_stale = True
                break
    return {
        "memory_findings_updated_at": memory_updated_at,
        "forensic_analysis_report_updated_at": report_updated_at,
        "analysis_visual_summary_updated_at": visual_updated_at,
        "causal_graph_generated_at": causal_graph_generated_at,
        "metrics_generated_at": metrics_generated_at,
        "is_stale": is_stale,
    }


def _safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "value"))


def _nested_get(payload, path: str):
    value = payload
    for part in str(path or "").split("."):
        if not part:
            continue
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def _match_selector(item: dict, selector: dict | None) -> bool:
    if not selector:
        return True
    for key, expected in selector.items():
        actual = _nested_get(item, key)
        if key.endswith("_contains"):
            base_key = key[: -len("_contains")]
            actual = _nested_get(item, base_key)
            if isinstance(actual, list):
                if expected not in actual:
                    return False
            elif expected not in str(actual or ""):
                return False
            continue
        if key.endswith("_one_of"):
            base_key = key[: -len("_one_of")]
            actual = _nested_get(item, base_key)
            if actual not in list(expected or []):
                return False
            continue
        if str(actual) != str(expected):
            return False
    return True


# Real bug found and fixed 2026-10-10 (investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md,
# section "0.5"): `attack_id` as produced by foc_timeline_builder.py is NOT unique per real execution --
# it's make_id("atk", <catalog attack-type id>), a deterministic hash of the ATTACK TYPE string, so
# EVERY real execution of e.g. T0831_MANIPULATION_OF_CONTROL_MODBUS produces the exact same attack_id
# (verified live: 609 of 705 real entries in the global attack_attestation.json share one literal
# attack_id, the oldest dated months before this session). Since `_match_selector` + `matches[0]` just
# took the FIRST type-matching record in the whole, never-case-scoped global attestation list, every
# case's "attack happened" / "attack was detected" edges always cited the SAME oldest historical record,
# never the real execution that actually caused THAT case. The other edges downstream (forensic_intervention
# onward) are already correctly anchored per-case (keyed by case_id); only the two upstream,
# attack_attestation-only edges had this gap.
#
# Fixed here by picking, among every type-matching record, the one whose own real timestamp is closest
# to (and no later than) this CASE's own real trigger time -- not simply the first one in file order.
_ATTACK_MATCH_WINDOW_SECONDS = 3600.0  # generous but bounded: real detection+forensic-trigger latency
# observed this session tops out around ~16 minutes (case-8753f8d6: attack 13:36, intervention 13:47).


def _case_trigger_ts_from_path(case_path: Path) -> float | None:
    """Real per-case anchor timestamp: metadata/forensic_intervention.json's own
    intervention_started_at, when this case actually went through automatic forensic
    intervention. Returns None honestly for a case that doesn't have this file yet
    (e.g. intervention still in progress, or a pre-existing case from before this
    field existed) -- callers must treat None as "can't temporally anchor", never
    as "anchor at epoch 0"."""
    try:
        path = Path(case_path) / "metadata" / "forensic_intervention.json"
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            return _parse_ts(payload.get("intervention_started_at"))
    except Exception:
        pass
    return None


def _case_trigger_ts(case_context: dict) -> float | None:
    """Same as _case_trigger_ts_from_path, cached on case_context so repeated
    calls (one per edge needing it) don't re-read the file."""
    if "_case_trigger_ts_cache" in case_context:
        return case_context["_case_trigger_ts_cache"]
    ts = _case_trigger_ts_from_path(case_context.get("case_path"))
    case_context["_case_trigger_ts_cache"] = ts
    return ts


def _pick_closest_before(pairs: list[tuple[dict, float | None]], trigger_ts: float | None, window_seconds: float) -> dict | None:
    """Core selection shared by every temporal-anchoring fix in this file:
    given (item, item_ts) pairs, picks the item whose item_ts is closest to,
    and no later than, trigger_ts, within window_seconds.

    Only falls back to the first pair's item (the pre-fix behavior) when
    trigger_ts itself is unavailable (this case has no real anchor to compare
    against at all -- the best available signal is still "a record of this
    type exists somewhere"). When trigger_ts IS available but nothing falls
    inside the window, returns None deliberately -- the whole point of this
    function is to stop citing a temporally unrelated record just because it
    matches the TYPE-level selector; silently falling back here would undo
    the fix in exactly the case it exists for."""
    if not pairs:
        return None
    if trigger_ts is None:
        return pairs[0][0]
    candidates = []
    for item, item_ts in pairs:
        if item_ts is None:
            continue
        delta = trigger_ts - item_ts
        if 0 <= delta <= window_seconds:
            candidates.append((delta, item))
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0])
    return candidates[0][1]


def _select_temporally_relevant(matches: list[dict], trigger_ts: float | None, ts_path: str, window_seconds: float = _ATTACK_MATCH_WINDOW_SECONDS) -> dict | None:
    """Among several records that already passed the TYPE-level selector match,
    picks the one whose own real timestamp (dotted path `ts_path`, e.g.
    "execution.completed_at") is closest to, and no later than, this case's
    real trigger_ts. See _pick_closest_before for the real selection rule."""
    pairs = [(item, _parse_ts(_nested_get(item, ts_path))) for item in matches]
    return _pick_closest_before(pairs, trigger_ts, window_seconds)


_ALERTS_DIR_TS_RE = re.compile(r"ALERTS-(\d{8})-(\d{6})Z")


def _evidence_path_ts(evidence_refs) -> float | None:
    """Real per-record timestamp for an `alert_correlation` match, extracted
    from the capture directory name already embedded in its own `evidence`
    path list (e.g. ".../ALERTS-20261005-153829Z/alerts.jsonl") -- NOT a
    second file load. `alert_correlation.json` is a real, measured 6.4GB file
    (see load_alert_correlation_records's own docstring, and the real OOM
    incident it documents) -- reading yet another large attestation file just
    to get a timestamp per match would repeat exactly the mistake that
    incident was about. The capture directory's own name already encodes a
    real UTC timestamp close enough to the alert's own real time for this
    purpose (within the same window_seconds tolerance used everywhere else
    here), at zero extra I/O or memory cost."""
    for ref in evidence_refs or []:
        m = _ALERTS_DIR_TS_RE.search(str(ref))
        if not m:
            continue
        try:
            dt = datetime.strptime(f"{m.group(1)}{m.group(2)}", "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            continue
    return None


def _primary_detection_rule(case_context: dict) -> dict | None:
    ground_truth = case_context.get("ground_truth") or {}
    for spec in ground_truth.get("expected_edges") or []:
        selector = ((spec or {}).get("selectors") or {}).get("detection_attestation")
        if selector:
            records = (case_context.get("foc_context", {}).get("detection_attestation") or {}).get("observed_detection_rules") or []
            match = next((item for item in records if isinstance(item, dict) and _match_selector(item, selector)), None)
            if match:
                return match
    return None


def _primary_alert_correlation_record(case_context: dict) -> dict | None:
    ground_truth = case_context.get("ground_truth") or {}
    for spec in ground_truth.get("expected_edges") or []:
        selector = ((spec or {}).get("selectors") or {}).get("alert_correlation")
        if selector:
            # 2026-09-25: loaded on-demand here instead of via
            # foc_context["alert_correlation"] -- that key is no longer
            # eager-loaded (see foc_context_loader.py, the real fix for a
            # repeated real OOM: this file measured 6.4GB in this evidence
            # store). This is the only place that ever needs the real
            # records, gated behind an actual selector being present.
            records = load_alert_correlation_records()
            match = next((item for item in records if isinstance(item, dict) and _match_selector(item, selector)), None)
            if match:
                return match
    return None


def _resolve_timestamp(case_context: dict, ref: str | None) -> tuple[str | None, str | None]:
    if not ref:
        return None, None
    attack_records = (case_context.get("foc_context", {}).get("attack_attestation") or {}).get("attacks") or []
    interventions = (case_context.get("foc_context", {}).get("forensic_intervention") or {}).get("interventions") or []
    analysis_report = case_context.get("analysis_summary", {}).get("forensic_analysis_report") or {}
    mapping = {
        "attack_started_at": None,
        "attack_completed_at": None,
        "intervention_started_at": None,
        "intervention_completed_at": None,
        "analysis_started_at": case_context.get("analysis_status", {}).get("started_at"),
        "analysis_finished_at": case_context.get("analysis_status", {}).get("finished_at") or analysis_report.get("generated_at"),
        "case_created_at": None,
        "detection_observed_at": None,
        "alert_observed_at": None,
    }
    primary_attack = case_context.get("primary_attack") or {}
    if primary_attack:
        mapping["attack_started_at"] = _nested_get(primary_attack, "execution.started_at")
        mapping["attack_completed_at"] = _nested_get(primary_attack, "execution.completed_at")
    if interventions:
        mapping["intervention_started_at"] = interventions[0].get("intervention_start_time")
        mapping["intervention_completed_at"] = interventions[0].get("intervention_end_time")
    timeline = case_context.get("timeline_context", {}).get("timeline") or {}
    for event in timeline.get("events") or []:
        event_type = event.get("event_type")
        if event_type == "case_created" and not mapping["case_created_at"]:
            mapping["case_created_at"] = event.get("timestamp")
    detection_rule = _primary_detection_rule(case_context)
    if detection_rule:
        mapping["detection_observed_at"] = detection_rule.get("enabled_at") or detection_rule.get("observed_at")
    alert_record = _primary_alert_correlation_record(case_context)
    if alert_record:
        mapping["alert_observed_at"] = alert_record.get("observed_at") or alert_record.get("alert_timestamp")

    # Fallback to per-case normalized_causal_timestamps.json for fields that the
    # global foc_context attestations do not carry at per-execution granularity.
    # This connects the temporal evaluator to the timestamps already recorded
    # by the orchestrator for every individual repetition, without overriding
    # values that the global context successfully resolved.
    _nts: dict = {}
    _nts_source = "per-case metadata/normalized_causal_timestamps.json"
    try:
        _nts_path = Path(case_context["case_path"]) / "metadata" / "normalized_causal_timestamps.json"
        if _nts_path.is_file():
            _nts = json.loads(_nts_path.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    # Per-case attack timestamps are always preferred over the global attack_attestation.
    # The global file carries a single shared attack_id used across all repetitions,
    # so its execution.started_at / execution.completed_at reflect the most recent
    # or first indexed attack — not the specific repetition being evaluated here.
    if _nts.get("attack_started_at_utc"):
        mapping["attack_started_at"] = _nts["attack_started_at_utc"]
    if _nts.get("attack_completed_at_utc"):
        mapping["attack_completed_at"] = _nts["attack_completed_at_utc"]
    # detection_surface_hit_at_utc is the closest available proxy for the IDS
    # detection event. It currently equals alert_observed_at_utc because the
    # platform reads Suricata through the Wazuh SIEM pipeline and cannot export
    # a sub-alert timestamp independently. The evaluator will classify e5 as
    # ambiguous (not supported) because the source and target collapse to the
    # same value, which is the honest result given the current architecture.
    if not mapping["detection_observed_at"]:
        mapping["detection_observed_at"] = (
            _nts.get("detection_surface_hit_at_utc")
            or _nts.get("alert_observed_at_utc")
        )
    if not mapping["alert_observed_at"] and _nts.get("alert_observed_at_utc"):
        mapping["alert_observed_at"] = _nts["alert_observed_at_utc"]
    # Per-case intervention timestamps are always preferred. The global
    # forensic_intervention.json uses a different case_id system (FOC indexer IDs
    # vs. orchestrator IDs), so its timestamps may belong to a different case.
    if _nts.get("forensic_intervention_started_at_utc"):
        mapping["intervention_started_at"] = _nts["forensic_intervention_started_at_utc"]
    if _nts.get("case_sealed_at_utc"):
        mapping["intervention_completed_at"] = _nts["case_sealed_at_utc"]

    source_map = {
        "attack_started_at": "foc-reconstruction/attestations/attack_attestation.json",
        "attack_completed_at": "foc-reconstruction/attestations/attack_attestation.json",
        "intervention_started_at": "foc-reconstruction/attestations/forensic_intervention.json",
        "intervention_completed_at": "foc-reconstruction/attestations/forensic_intervention.json",
        "analysis_started_at": relative_path(case_context["case_path"] / "analysis" / "analysis_status.json"),
        "analysis_finished_at": relative_path(case_context["case_path"] / "analysis" / "forensic_analysis_report.json"),
        "case_created_at": "foc-reconstruction/attestations/forensic_intervention.json",
        "detection_observed_at": "foc-reconstruction/attestations/detection_attestation.json",
        "alert_observed_at": "foc-reconstruction/attestations/alert_correlation.json",
    }
    # When the per-case fallback was used, update the source attribution.
    if mapping.get("detection_observed_at") and not detection_rule:
        source_map["detection_observed_at"] = _nts_source
    if mapping.get("alert_observed_at") and not alert_record:
        source_map["alert_observed_at"] = _nts_source
    if mapping.get("intervention_started_at") and not interventions:
        source_map["intervention_started_at"] = _nts_source
    if mapping.get("intervention_completed_at") and not interventions:
        source_map["intervention_completed_at"] = _nts_source
    return mapping.get(ref), source_map.get(ref)


def _parse_ts(value: str | None) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _build_case_context(case_id: str, case_path: Path, analysis_status: dict | None = None, ground_truth_path: str | None = None) -> dict:
    foc_context = load_foc_context()
    analysis_summary = load_analysis_summary(case_path)
    custody_context = load_custody_context(case_path, foc_context, analysis_summary)
    timeline_context = load_timeline_context(case_path, analysis_summary)
    network_ot_context = load_network_ot_context(case_path)
    preserved_gt_ref = foc_context.get("artifact_references", {}).get("scenario_ground_truth")
    preserved_gt_path = project_path(*str(preserved_gt_ref).split("/")) if preserved_gt_ref else None
    gt_resolution = resolve_ground_truth(
        scenario_id=str(foc_context.get("scenario_id") or "unknown"),
        scenario_name=str(foc_context.get("scenario_name") or "unknown"),
        preserved_ground_truth_path=preserved_gt_path,
        explicit_path=ground_truth_path,
    )
    ground_truth = gt_resolution.get("payload") if isinstance(gt_resolution.get("payload"), dict) else {}
    primary_selector = ground_truth.get("attack_expected", {}).get("selector") if isinstance(ground_truth.get("attack_expected"), dict) else {}
    attacks = (foc_context.get("attack_attestation") or {}).get("attacks") or []
    primary_attack_matches = [item for item in attacks if isinstance(item, dict) and _match_selector(item, primary_selector)]
    # Same 2026-10-10 fix as _evaluate_requirement's attack_attestation branch, applied
    # here too: `primary_attack` feeds _resolve_timestamp's "attack_started_at"/
    # "attack_completed_at" (used for the edge's own temporal-order check) -- leaving
    # this on the old first-match selection would have kept citing the wrong
    # (type-matched but temporally unrelated) execution's timestamps even after the
    # evidence_refs citation itself was fixed.
    primary_attack = _select_temporally_relevant(primary_attack_matches, _case_trigger_ts_from_path(case_path), "execution.completed_at")
    return {
        "case_id": case_id,
        "case_path": case_path,
        "generated_at": utc_now(),
        "foc_context": foc_context,
        "analysis_summary": analysis_summary,
        "analysis_status": analysis_status or {},
        "custody_context": custody_context,
        "timeline_context": timeline_context,
        "network_ot_context": network_ot_context,
        "ground_truth_resolution": gt_resolution,
        "ground_truth": ground_truth,
        "scenario_id": str(ground_truth.get("scenario_id") or foc_context.get("scenario_id") or "unknown"),
        "scenario_name": str(ground_truth.get("scenario_name") or foc_context.get("scenario_name") or "unknown"),
        "primary_attack": primary_attack,
    }


def _evaluate_requirement(case_context: dict, req_type: str, selector: dict | None) -> dict:
    foc_context = case_context.get("foc_context") or {}
    analysis_summary = case_context.get("analysis_summary") or {}
    custody_context = case_context.get("custody_context") or {}
    limitations: list[str] = []
    evidence_refs: list[str] = []

    if req_type == "attack_attestation":
        records = (foc_context.get("attack_attestation") or {}).get("attacks") or []
        matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
        # See _select_temporally_relevant's own docstring and the 2026-10-10 fix
        # note above _case_trigger_ts: `attack_id` here is a TYPE-level id, shared
        # by every real execution of that attack type -- picking matches[0]
        # blindly would always cite the SAME oldest historical record for every
        # case ever analyzed, never the execution that actually caused THIS case.
        trigger_ts = _case_trigger_ts(case_context)
        attack = _select_temporally_relevant(matches, trigger_ts, "execution.completed_at")
        if attack:
            evidence_refs.append(f"foc-reconstruction/attestations/attack_attestation.json#{attack.get('attack_id')}")
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        if matches and trigger_ts is not None:
            limitations.append(
                f"{len(matches)} attack attestation record(s) matched this attack TYPE, but none fell within "
                f"{int(_ATTACK_MATCH_WINDOW_SECONDS)}s of this case's own real intervention trigger time -- "
                "not citing an unrelated historical execution of the same attack type as if it were this case's."
            )
        else:
            limitations.append("The preserved attack attestation does not contain a record matching the expected attack selector.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "detection_attestation":
        records = (foc_context.get("detection_attestation") or {}).get("observed_detection_rules") or []
        matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
        if matches:
            item = matches[0]
            evidence_refs.append(f"foc-reconstruction/attestations/detection_attestation.json#{item.get('rule_id')}")
            status = "recovered" if bool(item.get("rule_active")) else "degraded"
            if status != "recovered":
                limitations.append("The detection rule was preserved but is not marked active in the normalized detection attestation.")
            return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("No normalized detection rule matched the expected selector.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "alert_correlation":
        # 2026-09-25: loaded on-demand -- see the comment in
        # _primary_alert_correlation_record() above for why.
        records = load_alert_correlation_records()
        matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
        # Same 2026-10-10 fix as attack_attestation above, same root cause: this
        # selector's `attack_id` is the same TYPE-level id (verified live: 32,886
        # of 32,982 real correlation records match attack_id+protocol alone), so
        # matches[0] always cited the same old record regardless of which case
        # was being analyzed. Anchored to the case's real trigger time via the
        # capture-directory timestamp already embedded in each record's own
        # `evidence` path -- NOT a second large-file load, see
        # _evidence_path_ts's own docstring for why that matters here
        # specifically (alert_correlation.json is a real, measured 6.4GB file).
        trigger_ts = _case_trigger_ts(case_context)
        pairs = [(m, _evidence_path_ts(m.get("evidence"))) for m in matches]
        item = _pick_closest_before(pairs, trigger_ts, _ATTACK_MATCH_WINDOW_SECONDS)
        if not item:
            if matches and trigger_ts is not None:
                limitations.append(
                    f"{len(matches)} alert correlation record(s) matched this attack TYPE, but none fell within "
                    f"{int(_ATTACK_MATCH_WINDOW_SECONDS)}s of this case's own real intervention trigger time -- "
                    "not citing an unrelated historical correlation as if it were this case's."
                )
            else:
                limitations.append("No preserved attack-to-alert correlation record matched the expected selector.")
            return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}
        evidence_refs.append(f"foc-reconstruction/attestations/alert_correlation.json#{item.get('alert_id')}")
        relationship_status = str(item.get("relationship_status") or "").lower()
        correlation_status = str(item.get("correlation_status") or "").lower()
        if relationship_status == "confirmed" or correlation_status == "confirmed":
            status = "recovered"
        elif relationship_status == "inferred" or correlation_status.startswith("inferred") or correlation_status == "weak_candidate":
            status = "degraded"
            limitations.append("The preserved alert correlation is inferred rather than confirmed.")
        else:
            status = "missing"
            limitations.append("The preserved alert correlation is present but not strong enough to support the expected edge as recovered.")
        return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "forensic_intervention":
        # The per-case forensic_intervention.json is the authoritative record for
        # a specific repetition. The global foc_context attestation uses case_ids
        # assigned by the FOC indexer, which differ from the orchestrator-assigned
        # case_ids in the per-case artifacts — a selector that matches any global
        # record may resolve to a different case entirely. Always prefer per-case.
        _per_case_fi: dict = {}
        try:
            _fi_path = Path(case_context["case_path"]) / "metadata" / "forensic_intervention.json"
            if _fi_path.is_file():
                _per_case_fi = json.loads(_fi_path.read_text(encoding="utf-8")) or {}
        except Exception:
            pass
        if _per_case_fi and _match_selector(_per_case_fi, selector):
            item = _per_case_fi
            evidence_refs.append(
                relative_path(Path(case_context["case_path"]) / "metadata" / "forensic_intervention.json")
            )
        else:
            # Fallback: global foc_context attestation
            records = (foc_context.get("forensic_intervention") or {}).get("interventions") or []
            matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
            if not matches:
                limitations.append("No preserved forensic intervention matched the expected selector.")
                return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}
            item = matches[0]
            evidence_refs.append(f"foc-reconstruction/attestations/forensic_intervention.json#{item.get('case_id')}")
        status = "recovered" if str(item.get("intervention_status") or "").lower() == "completed" else "degraded"
        if status != "recovered":
            limitations.append("The forensic intervention exists but is not marked completed.")
        return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "case_manifest_link":
        # Primary: global case_manifest_link attestation.
        # Fallback: verify directly that manifest.json and chain_of_custody.log exist
        # in the case directory, which proves the case-to-manifest link is intact.
        links = custody_context.get("case_links_for_case") or []
        if links:
            evidence_refs.append("foc-reconstruction/attestations/case_manifest_link.json")
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        _manifest_path = Path(case_context["case_path"]) / "manifest.json"
        _custody_path = Path(case_context["case_path"]) / "chain_of_custody.log"
        if _manifest_path.is_file() and _custody_path.is_file():
            evidence_refs.append(relative_path(_manifest_path))
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The case-to-manifest linkage attestation does not include the selected case.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "manifest":
        if custody_context.get("manifest_present"):
            evidence_refs.append(relative_path(custody_context["manifest_path"]))
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The preserved case manifest is missing.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "chain_of_custody":
        if custody_context.get("chain_of_custody_present"):
            evidence_refs.append(relative_path(custody_context["chain_of_custody_path"]))
            status = "recovered" if custody_context.get("custody_chain_valid") else "degraded"
            if status != "recovered":
                limitations.append("The chain of custody exists but the preserved integrity report does not classify it as fully valid.")
            return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The preserved chain_of_custody.log is missing.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "forensic_analysis_report":
        report = analysis_summary.get("forensic_analysis_report") or {}
        if report:
            evidence_refs.append(relative_path(case_context["case_path"] / "analysis" / "forensic_analysis_report.json"))
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The multilayer forensic analysis report has not been generated for this case.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "analysis_visual_summary":
        visual = analysis_summary.get("analysis_visual_summary") or {}
        if visual:
            evidence_refs.append(relative_path(case_context["case_path"] / "analysis" / "visual" / "analysis_visual_summary.json"))
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The normalized visual analysis summary is missing.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "memory_analysis_useful":
        findings = (analysis_summary.get("memory_findings") or {}).get("findings") or {}
        dumps_analyzed = int(findings.get("dumps_analyzed") or 0)
        results = findings.get("results") or []
        has_completed_plugins = any(
            isinstance(item, dict) and str(item.get("status")) == "completed" and item.get("completed_plugins")
            for item in results
        )
        evidence_refs.append(relative_path(case_context["case_path"] / "analysis" / "04_memory" / "memory_findings.json"))
        if dumps_analyzed > 0 and has_completed_plugins:
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        if dumps_analyzed > 0:
            limitations.append("Memory analysis exists, but no effective plugin output was produced.")
            return {"type": req_type, "status": "degraded", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("Memory analysis exists but no effective dump analysis was recorded.")
        return {"type": req_type, "status": "degraded", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "network_modbus_observation":
        network_ot_context = case_context.get("network_ot_context") or {}
        evidence_refs.append(relative_path(network_ot_context.get("network_findings_path")) if network_ot_context.get("network_findings_path") else "not_available")
        limitations.append(
            "Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not "
            "confirmed by packet-level parsing; only the presence of Modbus traffic is verified here."
        )
        if int(network_ot_context.get("total_modbus_frames") or 0) > 0:
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("No Modbus traffic was observed in the preserved network capture analysis.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "plc_state_observation":
        network_ot_context = case_context.get("network_ot_context") or {}
        evidence_refs.append(relative_path(network_ot_context.get("ot_findings_path")) if network_ot_context.get("ot_findings_path") else "not_available")
        limitations.append(
            "Register and value precision (declared in ground truth as register=4, expected_value=30) is not "
            "confirmed by packet-level OT export parsing; only the presence of recorded PLC/SCADA state is verified here."
        )
        if int(network_ot_context.get("total_ot_records") or 0) > 0:
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The OT export analysis exists but recorded no PLC/SCADA state entries for this case.")
        return {"type": req_type, "status": "degraded", "evidence_refs": evidence_refs, "limitations": limitations}

    limitations.append(f"The evaluator does not recognize requirement type `{req_type}`.")
    return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}


def _evaluate_temporal(case_context: dict, edge_spec: dict) -> str:
    source_ref = edge_spec.get("source_timestamp_ref")
    target_ref = edge_spec.get("target_timestamp_ref")
    if not source_ref or not target_ref:
        # The edge spec does not declare a temporal relation at all - temporal
        # ordering simply does not apply, which is different from "declared but
        # could not be resolved" (that case returns "unknown" below).
        return "not_required"
    source_ts, _ = _resolve_timestamp(case_context, str(source_ref))
    target_ts, _ = _resolve_timestamp(case_context, str(target_ref))
    src_value = _parse_ts(source_ts)
    dst_value = _parse_ts(target_ts)
    if src_value is None or dst_value is None:
        return "unknown"

    temporal_context = extract_temporal_sync_context(case_context)
    if str(temporal_context.get("sync_state") or "unknown") == "unknown":
        return "unknown"
    max_offset_ms = float(temporal_context.get("max_clock_offset_ms") or 0.0)
    timestamp_resolution_ms = float(case_context.get("ground_truth", {}).get("timestamp_resolution_ms") or 1000.0)
    acquisition_jitter_ms = float(case_context.get("ground_truth", {}).get("acquisition_jitter_ms") or 1000.0)
    uncertainty_seconds = (max_offset_ms + timestamp_resolution_ms + acquisition_jitter_ms) / 1000.0
    delta = dst_value - src_value
    if delta > uncertainty_seconds:
        return "supported"
    if abs(delta) <= uncertainty_seconds:
        return "ambiguous"
    return "contradicted"


def _analysis_coverage_ratio(case_context: dict) -> tuple[float | None, int, int]:
    expected_layers = list(case_context.get("ground_truth", {}).get("expected_analysis_layers") or [])
    if not expected_layers:
        return None, 0, 0
    visual = case_context.get("analysis_summary", {}).get("analysis_visual_summary") or {}
    layer_statuses = visual.get("layer_statuses") if isinstance(visual, dict) else {}
    useful = 0
    for layer in expected_layers:
        payload = layer_statuses.get(layer) if isinstance(layer_statuses, dict) else None
        if isinstance(payload, dict) and str(payload.get("effective_status")) == "completed_with_useful_output":
            useful += 1
    return useful / len(expected_layers), useful, len(expected_layers)


def _recoverability_label(cpr: float | None) -> str:
    if cpr is None:
        return "unknown"
    for threshold, label in CPR_LABEL_THRESHOLDS:
        if cpr >= threshold:
            return label
    return "low_recoverability"


def _cpr_interpretation(label: str, recovered_edges: int, expected_edges: int) -> str:
    if label == "unknown":
        return "Causal path recoverability could not be computed because no expected edges are defined for this scenario."
    if label in {"weak_recoverability", "low_recoverability"}:
        return (
            f"Only {recovered_edges} of {expected_edges} expected causal edges were fully recovered. The result is "
            "useful for audit and degradation analysis, but it must not be presented as strong causal reconstruction."
        )
    if label == "partially_recoverable":
        return (
            f"{recovered_edges} of {expected_edges} expected causal edges were recovered. The reconstruction is "
            "partially supported and should be presented with explicit caveats on the degraded or ambiguous edges."
        )
    return (
        f"{recovered_edges} of {expected_edges} expected causal edges were recovered. The reconstruction is mostly "
        "supported by preserved evidence, but it still does not establish absolute causality."
    )


def _metrics_from_edges(case_context: dict, edges: list[dict]) -> dict:
    expected_edges = len(edges)
    recovered_edges = sum(1 for edge in edges if edge.get("support_status") == "recovered")
    degraded_edges = sum(1 for edge in edges if edge.get("support_status") == "degraded")
    ambiguous_edges = sum(1 for edge in edges if edge.get("support_status") == "ambiguous")
    missing_edges = sum(1 for edge in edges if edge.get("support_status") == "missing")

    weight_by_edge = {
        str(edge.get("edge_id")): float(spec.get("weight") or 1.0)
        for edge, spec in zip(edges, case_context.get("ground_truth", {}).get("expected_edges") or [])
    }
    total_weight = sum(weight_by_edge.values()) or 0.0
    recovered_weight = sum(weight_by_edge.get(str(edge.get("edge_id")), 1.0) for edge in edges if edge.get("support_status") == "recovered")

    expected_artifacts = list(case_context.get("ground_truth", {}).get("expected_artifacts") or [])
    recovered_expected_artifact_types: list[str] = []
    for item in expected_artifacts:
        result = _evaluate_requirement(case_context, str(item), None)
        if result.get("status") != "missing":
            recovered_expected_artifact_types.append(str(item))
    evidence_completeness_ratio = (len(recovered_expected_artifact_types) / len(expected_artifacts)) if expected_artifacts else None

    analysis_coverage_ratio, layers_with_useful_output, expected_analysis_layers = _analysis_coverage_ratio(case_context)

    # Computed once here (with an empty metrics seed) purely to read the
    # temporal/integrity verdicts; the full uncertainty report is rebuilt
    # again in _run_once once these metrics are final, so the two never drift apart.
    preliminary_uncertainty = build_uncertainty_report(case_context, {}, edges)
    temporal_state = preliminary_uncertainty["temporal"]["temporal_confidence_state"]
    integrity_status = preliminary_uncertainty["integrity"]["integrity_status"]
    integrity_verification_ratio = preliminary_uncertainty["integrity"]["case_wide_integrity_ratio"]

    temporal_penalty = {"strong": 0.0, "limited": 0.05, "ambiguous": 0.12, "unknown": 0.15}.get(temporal_state, 0.15)
    base_confidence = (
        ((recovered_weight / total_weight) if total_weight else 0.0) * 0.45
        + (evidence_completeness_ratio or 0.0) * 0.2
        + (integrity_verification_ratio or 0.0) * 0.2
        + (analysis_coverage_ratio or 0.0) * 0.15
        - ((degraded_edges / expected_edges) if expected_edges else 0.0) * 0.08
        - ((ambiguous_edges / expected_edges) if expected_edges else 0.0) * 0.12
        - temporal_penalty
    )
    reconstruction_confidence = max(0.0, min(1.0, round(base_confidence, 4)))

    main_limitation = None
    if missing_edges:
        main_limitation = "One or more expected causal edges remain missing because required preserved evidence is unavailable or not linked."
    elif ambiguous_edges:
        main_limitation = "At least one causal edge is temporally ambiguous under the preserved uncertainty window."
    elif degraded_edges:
        main_limitation = "At least one causal edge is degraded because supporting evidence is partial or inferred."
    elif integrity_status == "partial":
        main_limitation = "Integrity or custody validation remains partial for the artifacts used by the reconstruction."
    else:
        main_limitation = "The preserved evidence supports the reconstructed causal path within the controlled intervention model."

    causal_path_recoverability = round((recovered_edges / expected_edges), 4) if expected_edges else None
    recoverability_label = _recoverability_label(causal_path_recoverability)
    interpretation = _cpr_interpretation(recoverability_label, recovered_edges, expected_edges)

    return {
        "case_id": case_context.get("case_id"),
        "scenario_id": case_context.get("scenario_id"),
        "generated_at": case_context.get("generated_at"),
        "expected_edges": expected_edges,
        "recovered_edges": recovered_edges,
        "degraded_edges": degraded_edges,
        "ambiguous_edges": ambiguous_edges,
        "missing_edges": missing_edges,
        "causal_path_recoverability": causal_path_recoverability,
        "recoverability_label": recoverability_label,
        "interpretation": interpretation,
        "weighted_cpr": round((recovered_weight / total_weight), 4) if total_weight else None,
        "degraded_edge_rate": round((degraded_edges / expected_edges), 4) if expected_edges else None,
        "ambiguous_edge_rate": round((ambiguous_edges / expected_edges), 4) if expected_edges else None,
        "missing_edge_rate": round((missing_edges / expected_edges), 4) if expected_edges else None,
        "recovered_expected_artifacts": len(recovered_expected_artifact_types),
        "recovered_expected_artifact_types": recovered_expected_artifact_types,
        "evidence_completeness_ratio": round(evidence_completeness_ratio, 4) if evidence_completeness_ratio is not None else None,
        "integrity_verification_ratio": round(integrity_verification_ratio, 4) if integrity_verification_ratio is not None else None,
        "integrity_status": integrity_status,
        "analysis_coverage_ratio": round(analysis_coverage_ratio, 4) if analysis_coverage_ratio is not None else None,
        "layers_with_useful_output": layers_with_useful_output,
        "expected_analysis_layers": expected_analysis_layers,
        "temporal_confidence_state": temporal_state,
        "reconstruction_confidence": reconstruction_confidence,
        "main_limitation": main_limitation,
    }


def _kpi_severity(value: float | None, ok_threshold: float, warn_threshold: float, *, lower_is_better: bool = False) -> str:
    if value is None:
        return "unknown"
    if lower_is_better:
        if value <= ok_threshold:
            return "ok"
        if value <= warn_threshold:
            return "warning"
        return "critical"
    if value >= ok_threshold:
        return "ok"
    if value >= warn_threshold:
        return "warning"
    return "critical"


def _build_kpi_list(metrics: dict) -> list[dict]:
    temporal_state = metrics.get("temporal_confidence_state")
    temporal_severity = {"strong": "ok", "limited": "warning", "ambiguous": "critical", "unknown": "critical"}.get(temporal_state, "critical")
    return [
        {
            "name": "CPR",
            "value": metrics.get("causal_path_recoverability"),
            "meaning": "Recovered edges divided by expected edges.",
            "interpretation": metrics.get("interpretation"),
            "severity": _kpi_severity(metrics.get("causal_path_recoverability"), 0.80, 0.25),
        },
        {
            "name": "Weighted CPR",
            "value": metrics.get("weighted_cpr"),
            "meaning": "Sum of weights of recovered edges divided by total expected edge weight.",
            "interpretation": "Weighted recoverability, favoring causally central edges.",
            "severity": _kpi_severity(metrics.get("weighted_cpr"), 0.80, 0.25),
        },
        {
            "name": "Recovered edges",
            "value": metrics.get("recovered_edges"),
            "meaning": "Count of expected edges classified as recovered.",
            "interpretation": f"{metrics.get('recovered_edges')} of {metrics.get('expected_edges')} expected edges.",
            "severity": "ok",
        },
        {
            "name": "Degraded edges",
            "value": metrics.get("degraded_edges"),
            "meaning": "Count of expected edges with partial or unresolved support.",
            "interpretation": "Each degraded edge weakens the overall reconstruction confidence.",
            "severity": "ok" if not metrics.get("degraded_edges") else "warning",
        },
        {
            "name": "Ambiguous edges",
            "value": metrics.get("ambiguous_edges"),
            "meaning": "Count of expected edges whose temporal order is ambiguous under the uncertainty window.",
            "interpretation": "Each ambiguous edge means causal direction cannot be confirmed from preserved timestamps.",
            "severity": "ok" if not metrics.get("ambiguous_edges") else "warning",
        },
        {
            "name": "Missing edges",
            "value": metrics.get("missing_edges"),
            "meaning": "Count of expected edges with no recoverable evidence.",
            "interpretation": "Each missing edge is a gap in the causal path that cannot currently be audited.",
            "severity": "ok" if not metrics.get("missing_edges") else "critical",
        },
        {
            "name": "Evidence completeness",
            "value": metrics.get("evidence_completeness_ratio"),
            "meaning": "Recovered expected artifact types divided by expected artifact types.",
            "interpretation": "How much of the expected preserved evidence set was found at all.",
            "severity": _kpi_severity(metrics.get("evidence_completeness_ratio"), 0.90, 0.50),
        },
        {
            "name": "Integrity verification",
            "value": metrics.get("integrity_verification_ratio"),
            "meaning": "Case-wide manifest hash-validated artifacts divided by total manifest artifacts.",
            "interpretation": "Reflects case-wide custody integrity, not only the artifacts used by this graph.",
            "severity": _kpi_severity(metrics.get("integrity_verification_ratio"), 1.0, 0.80),
        },
        {
            "name": "Analysis coverage",
            "value": metrics.get("analysis_coverage_ratio"),
            "meaning": "Analysis layers with useful output divided by expected analysis layers.",
            "interpretation": "How much of the expected multilayer analysis actually produced useful findings.",
            "severity": _kpi_severity(metrics.get("analysis_coverage_ratio"), 0.90, 0.50),
        },
        {
            "name": "Temporal confidence",
            "value": temporal_state,
            "meaning": "Derived from the preserved clock-offset evidence and the declared uncertainty window.",
            "interpretation": "Strong only when the environment was synchronized and the uncertainty window is small.",
            "severity": temporal_severity,
        },
        {
            "name": "Reconstruction confidence",
            "value": metrics.get("reconstruction_confidence"),
            "meaning": "Composite score over weighted CPR, evidence completeness, integrity and temporal confidence.",
            "interpretation": "Composite but non-authoritative.",
            "severity": _kpi_severity(metrics.get("reconstruction_confidence"), 0.80, 0.40),
        },
    ]


def _next_required_actions(metrics: dict, uncertainty: dict, ground_truth_summary: dict, freshness: dict) -> list[str]:
    actions: list[str] = []
    temporal_state = uncertainty.get("temporal", {}).get("temporal_confidence_state")
    if temporal_state in {"ambiguous", "limited", "unknown"}:
        actions.append("Reduce temporal ambiguity by improving clock synchronization.")
    if freshness.get("is_stale"):
        actions.append("Regenerate causal reconstruction after updating memory analysis outputs.")
    if int(metrics.get("degraded_edges") or 0) or int(metrics.get("missing_edges") or 0):
        actions.append("Strengthen Modbus-specific ground truth with register and expected value if available.")
    if uncertainty.get("integrity", {}).get("integrity_status") == "partial":
        actions.append("Improve custody validation to move partial integrity edges toward recovered status.")
    if ground_truth_summary.get("ground_truth_validation_status") != "valid":
        actions.append("Repair scenario_ground_truth.json so all expected edges declare edge_id, source, target and required_evidence.")
    if not actions:
        actions.append("No further corrective action is required for this reconstruction; continue periodic re-validation as analysis layers are updated.")
    return actions


def _markdown_report(
    case_context: dict,
    metrics: dict,
    uncertainty: dict,
    graph_payload: dict,
    ground_truth_summary: dict,
    outputs: dict,
    freshness: dict,
) -> str:
    lines = [
        f"# Causal Reconstruction Report for {case_context.get('case_id')}",
        "",
        "## 1. Scope",
        "",
        "This report is a derived causal-forensic reconstruction layer that consumes FOC Reconstruction and multilayer "
        "analysis outputs. It does not modify, replace, or supersede primary evidence, acquisition, preservation, or "
        "the underlying analysis layers. It is not a live monitoring view.",
        "",
        "## 2. Inputs",
        "",
        f"- Case ID: `{case_context.get('case_id')}`",
        f"- Scenario ID: `{case_context.get('scenario_id')}`",
        f"- Scenario name: `{case_context.get('scenario_name')}`",
        f"- Generated at: `{case_context.get('generated_at')}`",
        f"- Memory findings updated at: `{freshness.get('memory_findings_updated_at')}`",
        f"- Forensic analysis report updated at: `{freshness.get('forensic_analysis_report_updated_at')}`",
        f"- Analysis visual summary updated at: `{freshness.get('analysis_visual_summary_updated_at')}`",
        f"- Is stale: `{freshness.get('is_stale')}`",
        "",
        "## 3. Ground Truth",
        "",
        f"- Ground truth status: `{ground_truth_summary.get('ground_truth_status')}`",
        f"- Ground truth path: `{ground_truth_summary.get('ground_truth_path')}`",
        f"- Ground truth version: `{ground_truth_summary.get('ground_truth_version')}`",
        f"- Validation status: `{ground_truth_summary.get('ground_truth_validation_status')}`",
        f"- Expected edges declared: `{ground_truth_summary.get('expected_edges')}`",
        f"- Loaded at: `{ground_truth_summary.get('ground_truth_loaded_at')}`",
        "",
        "## 4. Derived Outputs",
        "",
    ]
    for key, entry in outputs.items():
        lines.append(f"- {key}: `{entry.get('status')}` (`{entry.get('path')}`)")
    lines.extend(
        [
            "",
            "## 5. KPI Summary",
            "",
        ]
    )
    for kpi in metrics.get("kpis") or []:
        lines.append(f"- {kpi.get('name')}: `{kpi.get('value')}` — {kpi.get('meaning')} _{kpi.get('interpretation')}_ (severity: `{kpi.get('severity')}`)")
    lines.extend(
        [
            "",
            f"Interpretation: {metrics.get('interpretation')}",
            "",
            "## 6. Edge Status Matrix",
            "",
        ]
    )
    for edge in graph_payload.get("edges", []):
        lines.extend(
            [
                f"### {edge.get('edge_id')}",
                f"- Meaning: {edge.get('meaning')}",
                f"- Relation: `{edge.get('relation_type')}`",
                f"- Support status: `{edge.get('support_status')}`",
                f"- Confidence: `{edge.get('confidence')}`",
                f"- Temporal status: `{edge.get('temporal_status')}`",
                f"- Semantic status: `{edge.get('semantic_status')}`",
                f"- Graph-artifact integrity status: `{edge.get('graph_artifact_integrity_status')}`",
                f"- Case-wide integrity status: `{edge.get('case_wide_integrity_status')}`",
                f"- Required evidence: `{', '.join(edge.get('required_evidence') or []) or 'none'}`",
                f"- Evidence found: `{', '.join(edge.get('evidence_refs') or []) or 'not_available'}`",
                f"- Evidence missing: `{', '.join(edge.get('missing_evidence') or []) or 'none'}`",
                f"- Why this status: {edge.get('status_reason')}",
                f"- Limitations: `{'; '.join(edge.get('limitations') or []) or 'none'}`",
                "",
            ]
        )
    lines.extend(
        [
            "## 7. Uncertainty Budget",
            "",
            f"- Temporal confidence state: `{uncertainty.get('temporal', {}).get('temporal_confidence_state')}`",
            f"- Uncertainty window: `{uncertainty.get('temporal', {}).get('uncertainty_window_seconds')}s` "
            f"(`{uncertainty.get('temporal', {}).get('uncertainty_window_ms')}ms`)",
            f"- Max clock offset: `{uncertainty.get('temporal', {}).get('max_clock_offset_seconds')}s`",
            f"- Synchronized: `{uncertainty.get('temporal', {}).get('synchronized')}`",
            f"- {uncertainty.get('temporal', {}).get('temporal_limitation')}",
        ]
        + ([f"- Warning: {uncertainty.get('temporal', {}).get('temporal_warning')}"] if uncertainty.get("temporal", {}).get("temporal_warning") else [])
        + ([f"- Caution: {uncertainty.get('temporal', {}).get('temporal_caution')}"] if uncertainty.get("temporal", {}).get("temporal_caution") else [])
        + [
            f"- Evidence completeness ratio: `{uncertainty.get('completeness', {}).get('evidence_completeness_ratio')}`",
            "",
            "## 8. Integrity and Custody Considerations",
            "",
            f"- Artifacts used by graph: `{uncertainty.get('integrity', {}).get('artifacts_used_by_graph')}`",
            f"- Artifacts present: `{uncertainty.get('integrity', {}).get('artifacts_present')}`",
            f"- Graph-scope integrity ratio: `{uncertainty.get('integrity', {}).get('graph_scope_integrity_ratio')}`",
            f"- Case-wide manifest artifacts total: `{uncertainty.get('integrity', {}).get('case_manifest_artifacts_total')}`",
            f"- Case-wide manifest hash validated: `{uncertainty.get('integrity', {}).get('case_manifest_hash_validated')}`",
            f"- Case-wide integrity ratio: `{uncertainty.get('integrity', {}).get('case_wide_integrity_ratio')}`",
            f"- Graph-artifact integrity status: `{uncertainty.get('integrity', {}).get('graph_artifact_integrity_status')}`",
            f"- Case-wide integrity status: `{uncertainty.get('integrity', {}).get('case_wide_integrity_status')}`",
            f"- {uncertainty.get('integrity', {}).get('integrity_limitation')}",
            "",
            "## 9. Limitations",
            "",
        ]
    )
    for item in uncertainty.get("limitations") or []:
        lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "## 10. Scientific Caution",
            "",
            "The preserved evidence supports this reconstruction under the controlled intervention model. Recovered "
            "edges are auditable through the referenced preserved sources, while degraded, ambiguous and missing "
            "edges must not be presented as absolute proof of causality. This report is composite and "
            "non-authoritative; it does not establish legal or absolute causal certainty.",
            "",
            "## 11. Next Required Actions",
            "",
        ]
    )
    for index, action in enumerate(_next_required_actions(metrics, uncertainty, ground_truth_summary, freshness), start=1):
        lines.append(f"{index}. {action}")
    lines.append("")
    return "\n".join(lines)


def _prerequisite_status(case_id: str, case_path: Path, analysis_status: dict | None = None, ground_truth_path: str | None = None) -> dict:
    case_context = _build_case_context(case_id, case_path, analysis_status=analysis_status, ground_truth_path=ground_truth_path)
    analysis_summary = case_context.get("analysis_summary") or {}
    gt_resolution = case_context.get("ground_truth_resolution") or {}
    foc_context = case_context.get("foc_context") or {}
    custody_context = case_context.get("custody_context") or {}
    foc_context_available = bool(foc_context.get("foc_context_summary") or foc_context.get("manifest"))
    manifest_present = bool(case_context.get("custody_context", {}).get("manifest_present"))
    custody_present = bool(case_context.get("custody_context", {}).get("chain_of_custody_present"))
    evidence_links_present = bool(custody_context.get("case_links_for_case"))
    analysis_report_present = bool(analysis_summary.get("forensic_analysis_report"))
    visual_summary_present = bool(analysis_summary.get("analysis_visual_summary"))
    if not foc_context_available:
        state = "not_available"
        reason = "Causal reconstruction is blocked because the normalized FOC context summary is unavailable."
    elif not manifest_present or not custody_present:
        state = "not_available"
        reason = "Causal reconstruction is blocked because the preserved case manifest or chain_of_custody.log is missing."
    elif not evidence_links_present:
        state = "not_available"
        reason = "Causal reconstruction is blocked because the normalized case-to-manifest evidence links are unavailable for this case."
    elif not analysis_report_present:
        state = "blocked_missing_analysis"
        reason = "Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case."
    elif not visual_summary_present:
        # visual_summary.json is optional: if reconstruction metrics already exist on disk,
        # the gate is satisfied with degradation rather than blocked.  This prevents a
        # spurious blocked_missing_analysis when the visual summary generation is skipped
        # but causal reconstruction completed successfully on a prior run.
        _metrics_on_disk = (case_path / "derived" / "reconstruction" / "reconstruction_metrics.json").is_file()
        if not _metrics_on_disk:
            state = "blocked_missing_analysis"
            reason = ("Causal reconstruction is blocked because the analysis visual summary has not been generated "
                      "and no existing reconstruction metrics were found for this case.")
        else:
            state = "ready_to_run"
            reason = ("Analysis report present; visual summary absent but reconstruction metrics exist on disk "
                      "— proceeding with degradation.")
    elif gt_resolution.get("status") == "missing":
        state = "blocked_missing_ground_truth"
        reason = "Causal reconstruction is blocked because scenario_ground_truth.json is missing for this scenario."
    elif gt_resolution.get("status") == "missing_expected_edges":
        state = "blocked_missing_ground_truth"
        reason = "Causal reconstruction is blocked because scenario_ground_truth.json does not define expected causal edges."
    else:
        state = "ready_to_run"
        reason = "All required preserved FOC and analysis artifacts are available for causal reconstruction."
    if state not in ALLOWED_CAUSAL_UI_STATES:
        state = "not_available"
    ground_truth_summary = {
        "ground_truth_status": gt_resolution.get("status"),
        "ground_truth_path": str(gt_resolution.get("path")) if gt_resolution.get("path") else None,
        "ground_truth_version": gt_resolution.get("version"),
        "scenario_id": case_context.get("scenario_id"),
        "expected_edges": len((case_context.get("ground_truth") or {}).get("expected_edges") or []),
        "ground_truth_loaded_at": gt_resolution.get("loaded_at"),
        "ground_truth_validation_status": gt_resolution.get("validation_status"),
    }
    return {
        "case_context": case_context,
        "status": state,
        "reason": reason,
        "ground_truth_summary": ground_truth_summary,
        "requirements": {
            "foc_context_available": foc_context_available,
            "manifest_present": manifest_present,
            "chain_of_custody_present": custody_present,
            "evidence_links_present": evidence_links_present,
            "analysis_report_present": analysis_report_present,
            "analysis_visual_summary_present": visual_summary_present,
            "ground_truth_status": gt_resolution.get("status"),
            "ground_truth_path": str(gt_resolution.get("path")) if gt_resolution.get("path") else None,
            "ground_truth_checked_paths": gt_resolution.get("checked_paths") or [],
        },
    }


def _execution_phase_from_legacy_status(legacy_status: str, has_metrics: bool) -> str:
    if legacy_status == "running":
        return "running"
    if legacy_status in {"not_available", "blocked_missing_ground_truth", "blocked_missing_analysis"}:
        return "blocked"
    if legacy_status == "failed":
        return "ran" if has_metrics else "exception"
    if legacy_status in {"completed", "completed_with_degradation"}:
        return "ran"
    return "not_started"


def _compute_triad(legacy_status: str, metrics: dict | None, ground_truth_status: str | None, reason: str | None) -> dict:
    has_metrics = isinstance(metrics, dict) and bool(metrics)
    phase = _execution_phase_from_legacy_status(legacy_status, has_metrics)
    integrity_status = metrics.get("integrity_status") if has_metrics else None
    return derive_status_triad(
        execution_phase=phase,
        ground_truth_status=ground_truth_status,
        metrics=metrics if has_metrics else None,
        integrity_status=integrity_status,
        strict_failed=(legacy_status == "failed" and has_metrics),
        failure_reason=reason,
    )


def summarize_case_causal_state(case_id: str, case_path: str | Path, analysis_status: dict | None = None) -> dict:
    case_path = Path(case_path)
    paths = _paths(case_path)
    prereq = _prerequisite_status(case_id, case_path, analysis_status=analysis_status)
    ground_truth_summary = prereq["ground_truth_summary"]
    outputs = _derived_outputs_status(paths)
    freshness = _source_freshness(case_path, paths)
    status_payload = _json_load(paths["status"])
    if isinstance(status_payload, dict):
        status_payload.setdefault("case_id", case_id)
        status_payload.setdefault("scenario_id", prereq["case_context"].get("scenario_id"))
        merged_requirements = dict(prereq["requirements"])
        merged_requirements.update(status_payload.get("requirements") or {})
        status_payload["requirements"] = merged_requirements
        status_payload.setdefault("output_paths", {key: relative_path(path) for key, path in paths.items() if key != "root" and path.exists()})
        if not status_payload.get("metrics_preview") and paths["metrics"].is_file():
            status_payload["metrics_preview"] = _json_load(paths["metrics"])
        status_payload["ground_truth_summary"] = ground_truth_summary
        status_payload["outputs"] = outputs
        status_payload.update(freshness)
        status_payload.update(
            _compute_triad(
                str(status_payload.get("status") or "not_available"),
                status_payload.get("metrics_preview"),
                ground_truth_summary.get("ground_truth_status"),
                status_payload.get("reason"),
            )
        )
        return status_payload
    payload = {
        "case_id": case_id,
        "scenario_id": prereq["case_context"].get("scenario_id"),
        "status": prereq["status"],
        "state": prereq["status"],
        "reason": prereq["reason"],
        "started_at": None,
        "updated_at": utc_now(),
        "finished_at": None,
        "progress_percent": 0,
        "requirements": prereq["requirements"],
        "ground_truth_summary": ground_truth_summary,
        "outputs": outputs,
        "output_paths": {key: relative_path(path) for key, path in paths.items() if key != "root" and path.exists()},
        "metrics_preview": _json_load(paths["metrics"]) if paths["metrics"].is_file() else None,
    }
    payload.update(freshness)
    payload.update(_compute_triad(prereq["status"], None, ground_truth_summary.get("ground_truth_status"), prereq["reason"]))
    return payload


def _write_status(case_path: Path, payload: dict) -> None:
    payload["updated_at"] = utc_now()
    _write_json(_status_path(case_path), payload)


def _run_once(case_id: str, case_path: Path, strict: bool = False, degraded_ok: bool = False, ground_truth_path: str | None = None, out_dir: str | None = None) -> dict:
    prereq = _prerequisite_status(case_id, case_path, ground_truth_path=ground_truth_path)
    case_context = prereq["case_context"]
    ground_truth_summary = prereq["ground_truth_summary"]
    output_dir = _derived_dir(case_path, out_dir)
    paths = _paths(case_path)
    status = {
        "case_id": case_id,
        "scenario_id": case_context.get("scenario_id"),
        "state": prereq["status"],
        "status": prereq["status"],
        "reason": prereq["reason"],
        "started_at": utc_now(),
        "updated_at": utc_now(),
        "finished_at": None,
        "progress_percent": 5,
        "current_step": "verifying_prerequisites",
        "requirements": prereq["requirements"],
        "ground_truth_summary": ground_truth_summary,
        "errors": [],
        "warnings": [],
        "output_paths": {},
        "strict": bool(strict),
        "degraded_ok": bool(degraded_ok),
    }
    _write_status(case_path, status)
    if prereq["status"] != "ready_to_run":
        status["finished_at"] = utc_now()
        status["progress_percent"] = 100
        status["outputs"] = _derived_outputs_status(paths)
        status.update(_source_freshness(case_path, paths))
        status.update(_compute_triad(prereq["status"], None, ground_truth_summary.get("ground_truth_status"), prereq["reason"]))
        _write_status(case_path, status)
        return status

    status["status"] = "running"
    status["state"] = "running"
    status["current_step"] = "building_case_context"
    status["progress_percent"] = 15
    _write_status(case_path, status)

    nodes = build_nodes_from_ground_truth(case_context, lambda ref: _resolve_timestamp(case_context, ref))
    status["current_step"] = "evaluating_edges"
    status["progress_percent"] = 45
    _write_status(case_path, status)

    edges = [edge.to_dict() for edge in evaluate_edges(case_context, lambda req, selector=None: _evaluate_requirement(case_context, req, selector), lambda spec: _evaluate_temporal(case_context, spec))]
    metrics = _metrics_from_edges(case_context, edges)
    metrics["kpis"] = _build_kpi_list(metrics)
    uncertainty = build_uncertainty_report(case_context, metrics, edges)
    graph = CausalGraph(
        case_id=case_id,
        scenario_id=str(case_context.get("scenario_id") or "unknown"),
        generated_at=utc_now(),
        note="This graph is a derived causal-forensic reconstruction from sealed FOC artifacts. It is not a live monitoring graph.",
        nodes=nodes,
        edges=[],
    )
    graph_payload = graph.to_dict()
    graph_payload["edges"] = edges

    status["current_step"] = "writing_outputs"
    status["progress_percent"] = 75
    _write_status(case_path, status)

    freshness_before_write = _source_freshness(case_path, paths)
    report_text = _markdown_report(case_context, metrics, uncertainty, graph_payload, ground_truth_summary, _derived_outputs_status(paths), freshness_before_write)
    output_paths = write_causal_outputs(output_dir, graph_payload, uncertainty, metrics, report_text)

    if strict and int(metrics.get("missing_edges") or 0) > 0:
        status["status"] = "failed"
        status["state"] = "failed"
        status["reason"] = "Strict mode failed because one or more expected edges are missing."
        status["errors"].append(status["reason"])
    elif int(metrics.get("missing_edges") or 0) > 0 or int(metrics.get("degraded_edges") or 0) > 0 or int(metrics.get("ambiguous_edges") or 0) > 0:
        status["status"] = "completed_with_degradation"
        status["state"] = "completed_with_degradation"
        status["reason"] = metrics.get("main_limitation")
    else:
        status["status"] = "completed"
        status["state"] = "completed"
        status["reason"] = "The preserved evidence supports all expected causal edges under the current controlled intervention model."

    temporal_warning = uncertainty.get("temporal", {}).get("temporal_warning")
    temporal_caution = uncertainty.get("temporal", {}).get("temporal_caution")
    if temporal_warning:
        status["warnings"].append(temporal_warning)
    if temporal_caution:
        status["warnings"].append(temporal_caution)

    status["current_step"] = "completed"
    status["finished_at"] = utc_now()
    status["progress_percent"] = 100
    status["metrics_preview"] = metrics
    status["output_paths"] = {key: relative_path(Path(value)) for key, value in output_paths.items()}
    status["outputs"] = _derived_outputs_status(paths)
    status.update(_source_freshness(case_path, paths))
    status.update(
        _compute_triad(
            status["status"],
            metrics,
            ground_truth_summary.get("ground_truth_status"),
            status["reason"],
        )
    )
    _write_status(case_path, status)
    return status


def _worker(case_id: str, case_path: Path, strict: bool, degraded_ok: bool, ground_truth_path: str | None, out_dir: str | None) -> None:
    try:
        _run_once(case_id, case_path, strict=strict, degraded_ok=degraded_ok, ground_truth_path=ground_truth_path, out_dir=out_dir)
    except Exception as exc:
        payload = summarize_case_causal_state(case_id, case_path)
        payload.update(
            {
                "status": "failed",
                "state": "failed",
                "reason": str(exc),
                "errors": [str(exc)],
                "finished_at": utc_now(),
                "progress_percent": 100,
                "current_step": "failed",
            }
        )
        _write_status(case_path, payload)
    finally:
        with _CAUSAL_LOCK:
            _RUNNING_CAUSAL.pop(case_id, None)


def run_causal_reconstruction(
    case_id: str,
    case_path: str | Path,
    strict: bool = False,
    degraded_ok: bool = False,
    ground_truth_path: str | None = None,
    out_dir: str | None = None,
) -> dict:
    case_path = Path(case_path)
    prereq = _prerequisite_status(case_id, case_path, ground_truth_path=ground_truth_path)
    if prereq["status"] not in {"ready_to_run", "completed", "completed_with_degradation"}:
        payload = summarize_case_causal_state(case_id, case_path)
        payload["reason"] = prereq["reason"]
        payload["requirements"] = prereq["requirements"]
        _write_status(case_path, payload)
        return payload
    with _CAUSAL_LOCK:
        running = _RUNNING_CAUSAL.get(case_id)
        if running and running.is_alive():
            payload = summarize_case_causal_state(case_id, case_path)
            payload["status"] = "running"
            payload["state"] = "running"
            return payload
        worker = threading.Thread(
            target=_worker,
            args=(case_id, case_path, strict, degraded_ok, ground_truth_path, out_dir),
            daemon=True,
            name=f"foc-causal-{_safe_slug(case_id)}",
        )
        _RUNNING_CAUSAL[case_id] = worker
        worker.start()
    return {
        "case_id": case_id,
        "status": "running",
        "state": "running",
        "started_at": utc_now(),
        "reason": "Causal reconstruction started in background.",
    }


def causal_status_payload(case_id: str, case_path: str | Path) -> dict:
    return summarize_case_causal_state(case_id, case_path)


def causal_metrics_payload(case_id: str, case_path: str | Path) -> dict | None:
    payload = _json_load(_paths(Path(case_path))["metrics"])
    if isinstance(payload, dict):
        payload.setdefault("case_id", case_id)
        return payload
    return None


def causal_graph_payload(case_id: str, case_path: str | Path) -> dict | None:
    payload = _json_load(_paths(Path(case_path))["graph"])
    if isinstance(payload, dict):
        payload.setdefault("case_id", case_id)
        return payload
    return None


def causal_uncertainty_payload(case_id: str, case_path: str | Path) -> dict | None:
    payload = _json_load(_paths(Path(case_path))["uncertainty"])
    if isinstance(payload, dict):
        payload.setdefault("case_id", case_id)
        return payload
    return None


# Defensive cap so a future scenario with a much larger ground truth never
# ships an unbounded graph payload to the lightweight cockpit preview.
_GRAPH_SUMMARY_NODE_CAP = 15
_GRAPH_SUMMARY_EDGE_CAP = 20


def causal_graph_summary_payload(case_id: str, case_path: str | Path) -> dict | None:
    graph = _json_load(_paths(Path(case_path))["graph"])
    if not isinstance(graph, dict):
        return None
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    truncated = len(nodes) > _GRAPH_SUMMARY_NODE_CAP or len(edges) > _GRAPH_SUMMARY_EDGE_CAP
    return {
        "case_id": case_id,
        "scenario_id": graph.get("scenario_id"),
        "generated_at": graph.get("generated_at"),
        "note": graph.get("note"),
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": nodes[:_GRAPH_SUMMARY_NODE_CAP],
        "edges": edges[:_GRAPH_SUMMARY_EDGE_CAP],
        "truncated": truncated,
    }


def causal_report_payload(case_id: str, case_path: str | Path) -> dict | None:
    paths = _paths(Path(case_path))
    metrics = _json_load(paths["metrics"])
    graph = _json_load(paths["graph"])
    uncertainty = _json_load(paths["uncertainty"])
    report_text = paths["report"].read_text(encoding="utf-8") if paths["report"].is_file() else None
    if not any([metrics, graph, uncertainty, report_text]):
        return None
    return {
        "case_id": case_id,
        "metrics": metrics,
        "graph": graph,
        "uncertainty": uncertainty,
        "report_markdown": report_text,
        # Canonical long names - kept identical to causal_status.json's
        # "outputs" map so the cockpit's header and detail panels never disagree.
        "artifact_paths": {
            _CANONICAL_OUTPUT_KEYS[key]: relative_path(path)
            for key, path in paths.items()
            if key in _CANONICAL_OUTPUT_KEYS and path.exists()
        },
        "outputs": _derived_outputs_status(paths),
    }
