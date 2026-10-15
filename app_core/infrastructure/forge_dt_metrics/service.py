from __future__ import annotations

"""M7 (Metrics engine) + M6 (CPR/WCPR reporting),
investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md. Computes the
study's own formulas (section 12) purely from real data already produced
by M1 (Intervention Ledger) + M4 (post-hoc linker) + M5 (Evidence Bridge) +
the already-existing foc_causal_reconstruction/level_c_orchestrator CPR/
WCPR calculation -- never recomputes a signal another module already owns.

Metrics whose real inputs don't exist yet in this platform (no
benign-control runs executed, no case-linked preserved evidence, no
integration feeding Evidence Bridge support_state back into the causal
graph's own edge-recovery logic) are reported as honestly unavailable
(`None` + a `note` explaining why), never estimated or invented.
"""

from datetime import datetime, timezone


def _parse_ts(value: str | None):
    if not value:
        return None
    try:
        text = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def compute_irr(entries: list[dict]) -> dict:
    """Intervention Realization Rate: sum(R_i) / N_measured. `entries`
    should be the "applied"/"executed" phase rows (one per real
    intervention attempt) from the Intervention Ledger."""
    attempts = [e for e in entries if e.get("phase") in ("applied", "executed")]
    measured = [e for e in attempts if (e.get("effect_verification") or {}).get("effective") is not None]
    realized = [e for e in measured if (e.get("effect_verification") or {}).get("effective") is True]
    return {
        "metric": "IRR",
        "n_attempts": len(attempts),
        "n_measured": len(measured),
        "n_realized": len(realized),
        "irr": round(len(realized) / len(measured), 4) if measured else None,
        "note": None if measured else "no intervention in this set has a measured effect_verification yet",
    }


def compute_tor_and_latency(entries: list[dict], tolerance_seconds: float = 5.0) -> dict:
    """Twin Observability Rate + Observation Latency -- for every REALIZED
    intervention (effective=True), runs the real M4 linker and checks
    whether any forensic_twin event matched. The linker itself widens
    tolerance_seconds for attack_lab-sourced entries (see
    linker.py::ATTACK_LAB_MIN_TOLERANCE_SECONDS) -- not duplicated here."""
    from app_core.infrastructure.intervention_ledger.linker import link_intervention_to_twin_events

    realized = [e for e in entries if e.get("phase") in ("applied", "executed") and (e.get("effect_verification") or {}).get("effective") is True]
    observed = 0
    latencies: list[float] = []
    per_intervention = []
    for e in realized:
        link = link_intervention_to_twin_events(e["intervention_id"], tolerance_seconds=tolerance_seconds)
        matched = (link.get("matched_events") or []) if link.get("ok") else []
        is_observed = len(matched) > 0
        if is_observed:
            observed += 1
            effect_ts = _parse_ts(e.get("effect_verified_at") or e.get("applied_at"))
            event_timestamps = [t for t in (_parse_ts(ev.get("generated_at_utc")) for ev in matched) if t is not None]
            earliest_event_ts = min(event_timestamps) if event_timestamps else None
            if effect_ts and earliest_event_ts:
                latencies.append((earliest_event_ts - effect_ts).total_seconds())
        per_intervention.append({
            "intervention_id": e["intervention_id"], "type": e.get("type"),
            "observed": is_observed, "matched_event_count": len(matched),
        })
    n_realized = len(realized)
    sorted_lat = sorted(latencies)
    return {
        "metric": "TOR",
        "n_realized": n_realized,
        "n_observed": observed,
        "tor": round(observed / n_realized, 4) if n_realized else None,
        "observation_latencies_seconds": latencies,
        "median_latency_seconds": sorted_lat[len(sorted_lat) // 2] if sorted_lat else None,
        "per_intervention": per_intervention,
        "note": None if n_realized else "no realized intervention in this set yet",
    }


def compute_ier(entries: list[dict], tolerance_seconds: float = 5.0) -> dict:
    """Intervention Evidence Recall: sum(R_i*E_i) / sum(R_i) -- E_i = at
    least one of the intervention's matched twin events has a real
    Evidence Bridge link."""
    from app_core.infrastructure.intervention_ledger.linker import link_intervention_to_twin_events
    from app_core.infrastructure.evidence_bridge.service import get_evidence_links, event_id

    realized = [e for e in entries if e.get("phase") in ("applied", "executed") and (e.get("effect_verification") or {}).get("effective") is True]
    n = len(realized)
    with_evidence = 0
    for e in realized:
        link = link_intervention_to_twin_events(e["intervention_id"], tolerance_seconds=tolerance_seconds)
        matched = (link.get("matched_events") or []) if link.get("ok") else []
        has_evidence = any(get_evidence_links(event_id(ev)) for ev in matched)
        if has_evidence:
            with_evidence += 1
    return {
        "metric": "IER",
        "n_realized": n,
        "n_with_evidence": with_evidence,
        "ier": round(with_evidence / n, 4) if n else None,
        "note": None if n else "no realized intervention in this set yet",
    }


def compute_esr() -> dict:
    """Evidence Support Ratio: supported / total evaluated links, across
    the WHOLE Evidence Bridge store -- this metric describes the Bridge's
    own link quality, not any one intervention, so it is not scoped by
    case/campaign the way the other metrics are."""
    from app_core.infrastructure.evidence_bridge.service import get_evidence_links

    links = get_evidence_links()
    n = len(links)
    by_state: dict[str, int] = {}
    for link in links:
        state = link.get("support_state")
        by_state[state] = by_state.get(state, 0) + 1
    supported = by_state.get("supported", 0)
    return {
        "metric": "ESR",
        "n_links": n,
        "n_supported": supported,
        "esr": round(supported / n, 4) if n else None,
        "by_support_state": by_state,
        "note": None if n else "no evidence links recorded yet",
    }


def compute_cpr_report(job_id: str) -> dict:
    """M6: C0 baseline CPR/WCPR, reused directly from level_c_orchestrator's
    own already-real calculation (never recomputed). C3 (2026-10-10, see
    compute_c3_cpr_report) is a genuinely different number, computed via
    independent corroboration from the Intervention Ledger + post-hoc
    Linker + Evidence Bridge -- real, but intentionally NOT a replacement
    for C0: if no real case is retained yet for this job, C3 honestly
    reports why rather than estimating anything."""
    from app_core.infrastructure.level_c_orchestrator.service import get_comparison_report

    report = get_comparison_report(job_id)
    if not report:
        return {"ok": False, "error": f"no comparison report available for job_id={job_id}"}
    c3 = _safe(lambda: compute_c3_cpr_report(job_id)) or {"ok": False}
    return {
        "ok": True,
        "job_id": job_id,
        "c0_comparisons": report.get("comparisons"),
        "c0_reproducibility_index": report.get("reproducibility_index"),
        "c0_max_delta_wcpr": report.get("max_delta_wcpr"),
        "c0_all_delta_wcpr_acceptable": report.get("all_delta_wcpr_acceptable"),
        "c0_verdict": report.get("verdict"),
        "c3_cpr": c3.get("c3_cpr_mean") if c3.get("ok") else None,
        "c3_wcpr": None,
        "c3_detail": c3 if c3.get("ok") else None,
        "c3_note": (
            c3.get("note") if c3.get("ok") and c3.get("note")
            else "C3 WCPR (weighted) is not computed -- only the unweighted C3 CPR above -- edge weights "
                 "are not threaded through CausalEdge objects yet."
            if c3.get("ok")
            else "C3 could not be computed for this job (see c3_detail/error) -- reporting the real C0 baseline only, honestly."
        ),
    }


def _find_real_cases_for_campaign(campaign_id: str) -> list[dict]:
    """Real, already-verified discovery method (used manually, successfully,
    2026-10-10 investigating the causal-reconstruction fixes): a campaign's
    own `level_B/EXEC-*/retained_case_lightweight_bundle/case-*` directories
    survive the heavy-case cleanup and are the real, lightweight, permanent
    record of each real case this campaign produced. Returns
    [{"case_id": ..., "case_path": Path}, ...]."""
    from pathlib import Path as _Path
    from ..foc_experimentation.config import EVIDENCE_STORE_ROOT

    campaign_root = EVIDENCE_STORE_ROOT / "repetition_campaigns" / campaign_id
    out = []
    if not campaign_root.is_dir():
        return out
    for exec_dir in sorted(campaign_root.glob("level_B/EXEC-*")):
        bundle_root = exec_dir / "retained_case_lightweight_bundle"
        if not bundle_root.is_dir():
            continue
        for case_dir in bundle_root.glob("case-*"):
            if case_dir.is_dir():
                out.append({"case_id": case_dir.name, "case_path": case_dir})
    return out


def _case_independently_confirmed(case_id: str, case_path=None) -> dict:
    """C3's own real corroboration check: does a REAL Intervention Ledger
    entry tied to this case (M1) show, via the real post-hoc Linker (M4),
    a real intervention whose effect was verified AND was observed by the
    twin? Reuses build_phase_timeline exactly as Digital Twin View /
    Reconstruction View already do -- never a second computation of the
    same real chain.

    Real, separate gap found building this (2026-10-10): Attack Lab
    entries NEVER carry a real case_id -- `level_b_orchestrator.py`'s own
    `_launch_attack()` hardcodes `"case_dir": ""` when launching the attack,
    because the case genuinely doesn't exist yet at that point in the real
    pipeline (it's only created AFTER the alert fires and forensic
    intervention triggers -- a real causality/timing constraint, not an
    oversight). Retroactively rewriting the Ledger entry once the case
    exists is not an option (append-only, hash-chained, by design). Falls
    back to the SAME real temporal-anchoring technique built earlier today
    for attack_attestation/alert_correlation: if no case_id match exists,
    check case_id-less entries whose own real timestamp falls within the
    case's real trigger window."""
    from app_core.infrastructure.intervention_ledger.service import get_ledger_entries
    from app_core.infrastructure.intervention_ledger.timeline import build_phase_timeline

    attempts = [e for e in get_ledger_entries(case_id=case_id, limit=200) if e.get("phase") in ("applied", "executed")]
    if not attempts and case_path is not None:
        import app_core.infrastructure.foc_causal_reconstruction.service as causal_svc
        trigger_ts = causal_svc._case_trigger_ts_from_path(case_path)
        if trigger_ts is not None:
            for entry in get_ledger_entries(case_id=None, limit=5000):
                if entry.get("phase") not in ("applied", "executed") or entry.get("case_id"):
                    continue
                ts = _parse_ts(entry.get("recorded_at_utc"))
                if ts is None:
                    continue
                delta = trigger_ts - ts.timestamp()
                if 0 <= delta <= causal_svc._ATTACK_MATCH_WINDOW_SECONDS:
                    attempts.append(entry)
    for entry in attempts:
        intervention_id = entry.get("intervention_id")
        if not intervention_id:
            continue
        timeline = _safe(lambda iid=intervention_id: build_phase_timeline(iid))
        if not timeline or not timeline.get("ok"):
            continue
        phases_by_name = {p.get("phase"): p for p in timeline.get("phases") or []}
        effect_ok = (phases_by_name.get("effect_verified") or {}).get("status") == "done"
        observed_ok = (phases_by_name.get("twin_observed") or {}).get("status") == "done"
        if effect_ok and observed_ok:
            return {"confirmed": True, "intervention_id": intervention_id}
    return {"confirmed": False, "intervention_id": None}


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def compute_c3_cpr_for_case(case_id: str, case_path) -> dict:
    """C3 (investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md,
    the study's own section: "C3 adds the real proof"): re-scores C0's own
    edges using independent corroboration from the Intervention Ledger +
    Post-hoc Linker + Evidence Bridge (M1+M4+M5) -- a DIFFERENT real evidence
    path than foc_causal_reconstruction's own attestation chain. Never
    replaces or recomputes C0 -- every C0 field this reads is unchanged;
    this only ADDS a `c3_support_status`/`c3_cpr` alongside it. Only the two
    upstream edges whose `required_evidence` includes `attack_attestation`
    or `detection_attestation` are in scope for an upgrade -- those are the
    exact real-world claims ("the attack chain really happened", "it was
    really detected") the Ledger+Linker+Evidence-Bridge chain independently
    verifies too; downstream edges (forensic_intervention onward) already
    have their own case-scoped verification in C0 and are left untouched."""
    from pathlib import Path as _Path
    import app_core.infrastructure.foc_causal_reconstruction.service as causal_svc
    from app_core.infrastructure.foc_causal_reconstruction.evaluators import evaluate_edges

    case_context = causal_svc._build_case_context(case_id, _Path(case_path))
    c0_edges = evaluate_edges(
        case_context,
        lambda req, selector=None: causal_svc._evaluate_requirement(case_context, req, selector),
        lambda spec: causal_svc._evaluate_temporal(case_context, spec),
    )
    corroboration = _case_independently_confirmed(case_id, case_path)

    c3_edges = []
    upgraded_edge_ids = []
    for edge in c0_edges:
        d = dict(edge.to_dict())
        in_scope = "attack_attestation" in (d.get("required_evidence") or []) or "detection_attestation" in (d.get("required_evidence") or [])
        if in_scope and d.get("support_status") != "recovered" and corroboration["confirmed"]:
            d["c3_support_status"] = "recovered"
            d["c3_upgrade_reason"] = (
                f"Independently confirmed by intervention {corroboration['intervention_id']} "
                "(real effect verified AND observed by the twin, per the Intervention Ledger + "
                "post-hoc Linker) even though the traditional forensic attestation chain alone "
                "did not confirm this edge for this case."
            )
            upgraded_edge_ids.append(d.get("edge_id"))
        else:
            d["c3_support_status"] = d.get("support_status")
        c3_edges.append(d)

    total = len(c3_edges)
    c0_recovered = sum(1 for d in c3_edges if d.get("support_status") == "recovered")
    c3_recovered = sum(1 for d in c3_edges if d.get("c3_support_status") == "recovered")
    return {
        "ok": True,
        "case_id": case_id,
        "total_edges": total,
        "c0_recovered_edges": c0_recovered,
        "c0_cpr": round(c0_recovered / total, 4) if total else None,
        "c3_recovered_edges": c3_recovered,
        "c3_cpr": round(c3_recovered / total, 4) if total else None,
        "upgraded_edge_ids": upgraded_edge_ids,
        "independently_confirmed": corroboration["confirmed"],
        "confirming_intervention_id": corroboration["intervention_id"],
    }


def compute_c3_cpr_report(job_id: str) -> dict:
    """Real per-campaign C3 report: finds every real case this Level C job's
    campaign actually produced (via its own permanently-retained lightweight
    bundles) and runs compute_c3_cpr_for_case on each. Honestly reports "no
    real case found yet" rather than a fabricated number when none exist."""
    from app_core.infrastructure.level_c_orchestrator.service import JOBS_DIR

    state_path = JOBS_DIR / job_id / "job_state.json"
    if not state_path.is_file():
        return {"ok": False, "error": f"no job_state.json for job_id={job_id}"}
    state = _safe(lambda: __import__("json").loads(state_path.read_text(encoding="utf-8"))) or {}
    campaign_id = (state.get("config") or {}).get("campaign_id")
    if not campaign_id:
        return {"ok": False, "error": f"job {job_id} has no campaign_id in its own config"}

    cases = _find_real_cases_for_campaign(campaign_id)
    if not cases:
        return {
            "ok": True, "job_id": job_id, "campaign_id": campaign_id,
            "per_case": [], "c3_cpr_mean": None,
            "note": "No real retained case found yet for this campaign -- C3 cannot be computed until at least one repetition completes with a preserved case.",
        }

    per_case = [compute_c3_cpr_for_case(c["case_id"], c["case_path"]) for c in cases]
    valid = [c for c in per_case if c.get("c3_cpr") is not None]
    c0_values = [c["c0_cpr"] for c in valid if c.get("c0_cpr") is not None]
    c3_values = [c["c3_cpr"] for c in valid]
    return {
        "ok": True,
        "job_id": job_id,
        "campaign_id": campaign_id,
        "per_case": per_case,
        "c0_cpr_mean": round(sum(c0_values) / len(c0_values), 4) if c0_values else None,
        "c3_cpr_mean": round(sum(c3_values) / len(c3_values), 4) if c3_values else None,
        "cases_with_independent_confirmation": sum(1 for c in per_case if c.get("independently_confirmed")),
        "cases_total": len(per_case),
    }


def compute_ablation_report(job_id: str, *, campaign_id: str | None = None, tolerance_seconds: float = 5.0) -> dict:
    """M9's real ablation comparison (C0-C3), reframed from the study's own
    text: section 14.1 describes what each condition ADDS ("C1 adds
    Expected vs Observed", "C2 adds ground-truth separation + blind
    observability", "C3 adds Evidence Bridge + causal linkage") -- not a
    requirement that each condition run as a SEPARATE repetition with
    different live instrumentation active. Since M1 (Ledger)/M3 (window)/
    M5 (Bridge) are all read-or-append, post-hoc tools that never gate or
    alter the live fault_injection/Attack Lab/forensic_twin pipelines, EVERY
    repetition already collects the full data unconditionally -- so C0-C3
    are computed here as 4 progressively richer ANALYSIS LAYERS over that
    SAME data, never as 4 different live configurations needing 4 separate
    repetitions. This is lower-risk (nothing in level_c_orchestrator needed
    to change) and means even a 2-repetition campaign already supports a
    full C0-C3 comparison, with repetition-to-repetition stability as a
    separate, additional real signal on top."""
    c0 = compute_cpr_report(job_id)
    if not c0.get("ok"):
        return c0

    from app_core.infrastructure.forensic_twin.service import list_recent_events
    twin_events = [
        ev for ev in list_recent_events(limit=2000)
        if (ev.get("scope_id") or "").startswith("node:") and not str(ev.get("event_type") or "").startswith("fault_injection_")
    ]

    c1 = {
        "label": "C1 -- adds the digital twin",
        "plain_explanation": "Same campaign as C0, plus: every alert the digital twin raised on its own, without being told anything.",
        "n_divergence_events": len(twin_events),
        "event_types": sorted({ev.get("event_type") for ev in twin_events}),
    }

    metrics_scope = get_metrics_report(campaign_id=campaign_id, tolerance_seconds=tolerance_seconds)
    c2 = {
        "label": "C2 -- adds the real ground-truth record",
        "plain_explanation": "Same as C1, plus: a comparison against the real, honest record of what was actually applied and when (the Intervention Ledger) -- this is what lets us measure whether the twin really saw it (IRR, TOR).",
        "irr": metrics_scope["irr"],
        "tor": {k: v for k, v in metrics_scope["tor"].items() if k != "per_intervention"},
    }

    c3 = {
        "label": "C3 -- adds the real proof",
        "plain_explanation": "Same as C2, plus: each twin alert cross-checked against real preserved proof (a file hash, a new port, a PLC value) that confirms it's trustworthy (IER, ESR).",
        "ier": metrics_scope["ier"],
        "esr": metrics_scope["esr"],
        "c3_cpr_note": c0.get("c3_note"),
    }

    return {
        "ok": True, "job_id": job_id, "campaign_id": campaign_id,
        "c0": {
            "label": "C0 -- just what already existed",
            "plain_explanation": "The forensic reconstruction the platform already did before any of this -- no digital twin involved at all. This is the starting point every other level builds on.",
            **{k: v for k, v in c0.items() if k not in ("ok", "job_id")},
        },
        "c1": c1, "c2": c2, "c3": c3,
    }


def compute_monitoring_overhead() -> dict:
    """Real, measured M3 experimental-window cost -- not scoped by
    case/campaign (like ESR), since this describes the window mechanism's
    own cost across every real window ever run, not one intervention."""
    from app_core.infrastructure.forensic_twin.experimental_window import get_monitoring_overhead_summary
    summary = get_monitoring_overhead_summary()
    return {
        "metric": "Monitoring overhead",
        "n_windows": summary.get("n_windows", 0),
        "total_ticks": summary.get("total_ticks"),
        "mean_seconds_per_tick": summary.get("mean_seconds_per_tick"),
        "per_sensor_total_seconds": summary.get("per_sensor_total_seconds"),
        "note": summary.get("note"),
    }


def get_metrics_report(*, case_id: str | None = None, campaign_id: str | None = None, source: str | None = None, tolerance_seconds: float = 5.0) -> dict:
    """The main aggregator -- pulls a scoped slice of the Intervention
    Ledger and computes every metric that has real, available inputs."""
    from app_core.infrastructure.intervention_ledger.service import get_ledger_entries

    entries = get_ledger_entries(case_id=case_id, campaign_id=campaign_id, source=source, limit=5000)
    return {
        "ok": True,
        "scope": {"case_id": case_id, "campaign_id": campaign_id, "source": source},
        "n_ledger_entries": len(entries),
        "irr": compute_irr(entries),
        "tor": compute_tor_and_latency(entries, tolerance_seconds=tolerance_seconds),
        "ier": compute_ier(entries, tolerance_seconds=tolerance_seconds),
        "esr": compute_esr(),
        "monitoring_overhead": compute_monitoring_overhead(),
        "unavailable_metrics": {
            "TMR": "needs a labeled subset of 'transient-prone' interventions to compute separately from TOR -- not yet classified in the Ledger schema",
            "CAA": "needs a hand-annotated expected causal graph per intervention type (per the study's own section 10 decision) -- not annotated yet",
            "FRG": "needs C3 CPR -- see compute_cpr_report's own c3_note",
            "WFRG": "needs C3 WCPR -- see compute_cpr_report's own c3_note",
            "Ambiguity Reduction": "needs C0 vs C3 ambiguous-relation counts from foc_causal_reconstruction -- not integrated yet",
            "False Divergence Rate": "needs real benign-control runs (class='benign-control') -- none executed yet",
            "Cross-run stability": "needs multiple redeployments of the SAME intervention across Level C repetitions -- not run yet",
        },
    }
