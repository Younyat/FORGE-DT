from __future__ import annotations

import csv
import json
from pathlib import Path


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_causal_outputs(
    output_dir: Path,
    graph_payload: dict,
    uncertainty_payload: dict,
    metrics_payload: dict,
    markdown_report: str,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    graph_path = output_dir / "causal_graph.json"
    uncertainty_path = output_dir / "uncertainty_report.json"
    metrics_path = output_dir / "reconstruction_metrics.json"
    csv_path = output_dir / "causal_edges.csv"
    report_path = output_dir / "causal_reconstruction_report.md"

    _write_json(graph_path, graph_payload)
    _write_json(uncertainty_path, uncertainty_payload)
    _write_json(metrics_path, metrics_payload)
    report_path.write_text(markdown_report, encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "edge_id",
                "meaning",
                "source",
                "target",
                "relation_type",
                "support_status",
                "confidence",
                "temporal_status",
                "evidence_strength",
                "semantic_status",
                "integrity_status",
                "graph_artifact_integrity_status",
                "case_wide_integrity_status",
                "status_reason",
                "required_evidence",
                "evidence_refs",
                "missing_evidence",
                "limitations",
            ],
        )
        writer.writeheader()
        for edge in graph_payload.get("edges", []):
            writer.writerow(
                {
                    "edge_id": edge.get("edge_id"),
                    "meaning": edge.get("meaning"),
                    "source": edge.get("source"),
                    "target": edge.get("target"),
                    "relation_type": edge.get("relation_type"),
                    "support_status": edge.get("support_status"),
                    "confidence": edge.get("confidence"),
                    "temporal_status": edge.get("temporal_status"),
                    "evidence_strength": edge.get("evidence_strength"),
                    "semantic_status": edge.get("semantic_status"),
                    "integrity_status": edge.get("integrity_status"),
                    "graph_artifact_integrity_status": edge.get("graph_artifact_integrity_status"),
                    "case_wide_integrity_status": edge.get("case_wide_integrity_status"),
                    "status_reason": edge.get("status_reason"),
                    "required_evidence": ",".join(edge.get("required_evidence") or []),
                    "evidence_refs": ",".join(edge.get("evidence_refs") or []),
                    "missing_evidence": ",".join(edge.get("missing_evidence") or []),
                    "limitations": " | ".join(edge.get("limitations") or []),
                }
            )

    return {
        "causal_graph": str(graph_path),
        "uncertainty_report": str(uncertainty_path),
        "reconstruction_metrics": str(metrics_path),
        "causal_edges_csv": str(csv_path),
        "causal_reconstruction_report": str(report_path),
    }
