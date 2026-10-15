from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class CausalNode:
    node_id: str
    node_type: str
    layer: str
    timestamp_utc: str | None
    label: str
    source_ref: str
    evidence_refs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CausalEdge:
    edge_id: str
    expected_edge_id: str
    source: str
    target: str
    relation_type: str
    required_evidence: list[str]
    evidence_refs: list[str]
    missing_evidence: list[str]
    support_status: str
    confidence: str
    temporal_status: str
    semantic_status: str
    integrity_status: str
    graph_artifact_integrity_status: str = ""
    case_wide_integrity_status: str = ""
    meaning: str = ""
    status_reason: str = ""
    limitations: list[str] = field(default_factory=list)
    # investigacion_y_novedad/15_huecos_de_literatura_2025_2026.md gap #1 (Kampourakis et al. 2025,
    # arXiv:2610.02955: a typed dependency graph -- causal/temporal/co-occurrence -- never claims
    # causation where only correlation or ordering is supported). One of "causal" (recovered evidence
    # AND confirmed/not-required temporal order), "temporal" (recovered evidence, but real temporal
    # order itself not confirmed), "co_occurrence" (some match, not strongly verified -- degraded or
    # ambiguous), or "unclassified" (support_status is "missing" -- nothing to classify). Purely
    # additive: derived from support_status/temporal_status/confidence, which already existed and are
    # unchanged by this field -- see edge_evaluator.py::_classify_evidence_strength.
    evidence_strength: str = "unclassified"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CausalGraph:
    case_id: str
    scenario_id: str
    generated_at: str
    note: str
    nodes: list[CausalNode] = field(default_factory=list)
    edges: list[CausalEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["nodes"] = [node.to_dict() for node in self.nodes]
        payload["edges"] = [edge.to_dict() for edge in self.edges]
        return payload
