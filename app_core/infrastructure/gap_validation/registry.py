from __future__ import annotations

"""Gap Registry -- data only, no logic. Every gap here is taken directly
from the platform's own literature review (investigacion_y_novedad/
02_gaps_cientificos.md, 15_huecos_de_literatura_2025_2026.md,
17_gaps_cerrados_por_mecanismo_e_industria_5_0.md -- internal, gitignored,
Spanish-language research notes; `source_doc` below is only a filename
citation, no content copied/translated from them beyond this English
one-line summary). No gap is invented for this module -- several are
deliberately left with an empty `experiment_ids` list because they are not
experimentable by this platform at all (a human-factors study, a
literature-mapping exercise) and never will be forced into a fake
experiment just to produce a verdict.

`mechanism` is the platform component that already answers (fully or
partially) the gap in question -- see gap_validation/catalog.py for the
concrete experiments that exercise each one.
"""

GAP_REGISTRY: list[dict] = [
    {
        "gap_id": "g02_01_investigative_3d_twin",
        "title": "No 3D interface is investigative/post-hoc -- every 3D cyber visualization found in the literature targets real-time situational awareness",
        "mechanism": "reconstruction",
        "summary": "Reconstruction View is a 3D interface built only from already-sealed evidence, replaying a closed campaign chronologically -- the exact missing piece.",
        "source_doc": "02_gaps_cientificos.md#gap-1",
        "experiment_ids": [],
    },
    {
        "gap_id": "g02_02_causal_reconstruction_reproducibility",
        "title": "No reviewed work measures causal-reconstruction reproducibility across real controlled repetitions",
        "mechanism": "reconstruction",
        "summary": "10 real repetitions per campaign, each with an independent causal_path_recoverability, plus a comparison_report with delta_cpr/delta_wcpr between pairs.",
        "source_doc": "02_gaps_cientificos.md#gap-2",
        "experiment_ids": ["state_divergence_baseline"],
    },
    {
        "gap_id": "g02_03_ics_ground_truth_dataset",
        "title": "No ICS/OT dataset exists with explicit causal ground truth tied to real forensic evidence",
        "mechanism": "reconstruction",
        "summary": "scenario_ground_truth.json with real expected_edges for a Modbus/ICS scenario, plus a full acquisition pipeline with a real per-artifact hash.",
        "source_doc": "02_gaps_cientificos.md#gap-3",
        "experiment_ids": [],
    },
    {
        "gap_id": "g02_04_coc_framework_ics_validation",
        "title": "Nath et al. (2024)'s chain-of-custody framework (provenance/continuity/contestability) has never been applied to an ICS case with automated hash-chaining and public verification",
        "mechanism": "ledger",
        "summary": "Real hash-chained chain_of_custody.log, with two real corruption bugs already found and fixed on this same project.",
        "source_doc": "02_gaps_cientificos.md#gap-4",
        "experiment_ids": [],
    },
    {
        "gap_id": "g02_05_forensic_readiness_e2e_validation",
        "title": "ICS forensic-readiness frameworks (Eden 2016, Azzam 2022, Shahbi 2023) are conceptual/taxonomic, never validated end-to-end against a real PLC",
        "mechanism": "forensic_twin",
        "summary": "Acquisition triggered by a real detection (not manual) against a real PLC, with hashed memory/disk/network/OT preservation. Explicit point-by-point mapping against the 3 frameworks is still pending.",
        "source_doc": "02_gaps_cientificos.md#gap-5",
        "experiment_ids": [],
    },
    {
        "gap_id": "g02_06_3d_comprehension_study",
        "title": "No study evaluates whether a 3D interface improves forensic-investigation comprehension versus a flat report/timeline",
        "mechanism": "reconstruction",
        "summary": "A human-factors study, not a platform experiment -- the interface already exists, the study itself does not. Deliberately left non-experimental.",
        "source_doc": "02_gaps_cientificos.md#gap-6",
        "experiment_ids": [],
    },
    {
        "gap_id": "g15_01_edge_evidence_strength",
        "title": "Causal dependency graphs are not typed by epistemic strength -- never distinguish confirmed causation from mere temporal ordering or co-occurrence",
        "mechanism": "reconstruction",
        "summary": "CausalEdge.evidence_strength ('causal'/'temporal'/'co_occurrence'/'unclassified') closed 2026-10-10, zero change to existing CPR/WCPR numbers.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#2",
        "experiment_ids": ["modbus_state_manipulation"],
    },
    {
        "gap_id": "g15_02_causal_discovery_from_data",
        "title": "Causal graphs are checked against a hand-written reference graph, never statistically discovered from the data itself",
        "mechanism": "reconstruction",
        "summary": "Still open -- needs a new statistical method (e.g. a PC-algorithm-style discovery step), not an extension of what already exists.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#2",
        "experiment_ids": [],
    },
    {
        "gap_id": "g15_03_ledger_hash_chain_checkpoints",
        "title": "No digital-evidence chain-of-custody framework has been applied with automated hash-chaining AND external checkpoint verification together",
        "mechanism": "ledger",
        "summary": "Intervention Ledger hash-chaining plus external checkpoints, closed partially 2026-10-09 -- caught a real truncate-and-forge attack that hash-chaining alone could not see.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#3",
        "experiment_ids": [],
    },
    {
        "gap_id": "g15_04_divergence_mitre_mapping",
        "title": "No digital twin maps its own state divergences to MITRE ATT&CK for ICS techniques",
        "mechanism": "forensic_twin",
        "summary": "Real MITRE ATT&CK for ICS mapping across forensic_twin's divergence types, closed 2026-10-09.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#1",
        "experiment_ids": ["modbus_state_manipulation"],
    },
    {
        "gap_id": "g15_05_contextual_reality_gap",
        "title": "A security digital twin's reference baseline can silently go stale without detection (the 'contextual reality gap')",
        "mechanism": "forensic_twin",
        "summary": "Reality Gap mechanism closed partially 2026-10-11 -- archives every outgoing baseline, compares against whichever was really in effect at a historical timestamp. Honest scope: config/network baselines only, PLC baseline was already versioned per repetition.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#1",
        "experiment_ids": ["temporal_inconsistency"],
    },
    {
        "gap_id": "g17_chaos_engineering_forensic_pipeline",
        "title": "No reviewed source applies chaos-engineering methodology (Netflix/Gremlin/LitmusChaos) to a forensic pipeline or to a physical-process digital twin",
        "mechanism": "fault_injection",
        "summary": "The most genuine open gap in this category -- this very module (gap_validation) is the first deliberate, chaos-engineering-style fault injector aimed at the forensic pipeline itself, not just at the scenario under investigation.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#3",
        "experiment_ids": ["acquisition_failure", "evidence_loss", "record_corruption", "orchestrator_failure"],
    },
    {
        "gap_id": "g17_retrospective_failure_forensics",
        "title": "No reviewed literature performs retrospective forensic reconstruction of a platform's own failures (chaos engineering is proactive/injected, never retrospective over failures that already happened)",
        "mechanism": "campaign_failure_forensics",
        "summary": "campaign_failure_forensics (2026-10-11/12) reconstructs why a campaign really died from evidence already recorded, distinguishing resource exhaustion from a code bug or a human action.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#4",
        "experiment_ids": ["orchestrator_failure"],
    },
    {
        "gap_id": "g17_case_uco_external_validation",
        "title": "CASE/UCO forensic export has been verified by hand but never validated against an external ontology tool",
        "mechanism": "forensic_twin",
        "summary": "export_case_uco() produces real JSON-LD against the real CASE/UCO vocabulary -- not yet checked against an independent CASE/UCO validator.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#4",
        "experiment_ids": [],
    },
    {
        "gap_id": "g17_eckhart_taxonomy_mapping",
        "title": "forensic_twin has never been mapped point-by-point against the Eckhart et al. (2023) security-digital-twin characteristics/indicators taxonomy",
        "mechanism": "forensic_twin",
        "summary": "Low-cost, high-value mapping exercise, not yet done -- a literature-mapping task, not an experiment this platform can run automatically.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#1",
        "experiment_ids": [],
    },
    {
        "gap_id": "g17_industry5_resilience_metrics",
        "title": "Industry 5.0 literature (Ali/Nguyen/Oh 2025, Szara 2025) flags resilience as the LEAST-studied of its three pillars, with a scarcity of rigorous quantitative measurement",
        "mechanism": "forge_dt_metrics",
        "summary": "IRR/TOR/IER/ESR plus CPR/C3 already answer this with real measured numbers (does the system detect a real disturbance, report it on time, link evidence, keep that evidence reliable) rather than a qualitative survey.",
        "source_doc": "17_gaps_cerrados_por_mecanismo_e_industria_5_0.md#5",
        "experiment_ids": ["service_interruption", "state_divergence_baseline"],
    },
]


def get_gap(gap_id: str) -> dict | None:
    return next((g for g in GAP_REGISTRY if g["gap_id"] == gap_id), None)


def list_gaps() -> list[dict]:
    return list(GAP_REGISTRY)
