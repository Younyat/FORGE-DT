from pathlib import Path

from .foc_bootstrap import make_id, read_id_mapping
from .foc_hashing import hash_file
from .foc_paths import project_path, relative_path
from .foc_schema import clone, empty_artifact_reference, empty_relationship_edge
from .foc_sources import read_json_file, read_jsonl_file, utc_now


def _edge_id(*parts: str) -> str:
    raw = "|".join(parts)
    return make_id("rel", raw)


def _artifact_id(*parts: str) -> str:
    raw = "|".join(parts)
    return make_id("art", raw)


def _evidence_id(*parts: str) -> str:
    raw = "|".join(parts)
    return make_id("evd", raw)


def _artifact_classification(artifact_type: str) -> tuple[str, bool]:
    normalized = str(artifact_type or "").strip().lower()
    preserved = {"pcap", "memory_lime", "disk_raw", "industrial_ot_export_modbus_tcp"}
    metadata = {
        "pcap_metadata",
        "memory_metadata",
        "memory_sha256_file",
        "disk_metadata",
        "disk_sha256_file",
        "time_sync",
        "case_digest",
        "custody_log",
    }
    forensic_inputs = {"ir_input", "ir_snapshot", "fsr_eval"}
    analysis_outputs = {
        "vol3_output_dir",
        "tsk_output_dir",
        "analysis_status.json",
        "preflight_validation.json",
        "evidence_inventory.json",
        "integrity_custody_report.json",
        "clock_offset_report.json",
        "network_findings.json",
        "memory_preflight.json",
        "memory_findings.json",
        "vol3_execution_report.json",
        "disk_findings.json",
        "ot_findings.json",
        "alert_findings.json",
        "pipeline_findings.json",
        "unified_forensic_timeline.json",
        "cross_layer_findings.json",
        "forensic_analysis_report.json",
        "forensic_analysis_manifest.json",
        "forensic_analysis_summary.md",
        "analysis_visual_summary.json",
        "foc_readiness_update.json",
    }
    if normalized in {
        "causal_graph.json",
        "causal_path_recoverability.json",
        "uncertainty_report.json",
        "scenario_attack_chain.json",
    }:
        return "analysis_outputs", False
    if normalized in {
        "industrial_asset_register_map.json",
        "industrial_modbus_validation.json",
        "industrial_plc_map.json",
        "industrial_scada_map.json",
        "ics_attack_policy.json",
        "discovery_scan.json",
        "observed_services.json",
        "register_map.json",
        "read_register_log.json",
        "collection_summary.json",
        "collection_session.jsonl",
        "process_state_snapshot.json",
        "modbus_transaction_log.json",
        "rollback_log.json",
        "unauthorized_command_message.json",
        "causal_edges.json",
    }:
        return "acquisition_metadata", False
    if normalized in preserved:
        return "preserved_evidence", True
    if normalized in metadata:
        return "acquisition_metadata", False
    if normalized in forensic_inputs:
        return "forensic_inputs", False
    if normalized in analysis_outputs:
        return "analysis_outputs", False
    return "auxiliary", False


def _add_edge(edges: list[dict], from_type: str, from_id: str, relation: str, to_type: str, to_id: str, **kwargs) -> None:
    edge = clone(empty_relationship_edge())
    edge.update(
        {
            "edge_id": _edge_id(from_type, from_id, relation, to_type, to_id),
            "from_type": from_type,
            "from_id": from_id,
            "relation": relation,
            "to_type": to_type,
            "to_id": to_id,
        }
    )
    edge.update(kwargs)
    edges.append(edge)


def _infer_case_artifacts(case_dir: Path, warnings: list[dict]) -> list[dict]:
    manifest = read_json_file(case_dir / "manifest.json", warnings) or {}
    case_id = make_id("case", case_dir.name)
    out = []
    for entry in manifest.get("artifacts", []) or []:
        rel_path = entry.get("rel_path") or ""
        ref = clone(empty_artifact_reference())
        ref.update(
            {
                "artifact_id": _artifact_id(case_dir.name, rel_path),
                "evidence_id": _evidence_id(case_dir.name, rel_path),
                "id_origin": "derived_from_path",
                "artifact_type": entry.get("type", "unknown"),
                "artifact_class": _artifact_classification(entry.get("type", "unknown"))[0],
                "is_primary_evidence": _artifact_classification(entry.get("type", "unknown"))[1],
                "path": f"{relative_path(case_dir)}/{rel_path}" if rel_path else relative_path(case_dir),
                "case_id": case_id,
                "related_instance_id": "unresolved",
                "related_node_id": "unresolved",
                "sha256": entry.get("sha256"),
                "size": entry.get("size"),
                "status": "indexed",
                "details": {"ts": entry.get("ts")},
            }
        )
        out.append(ref)
    return out


def _binding_maps(scenario_bom: dict) -> tuple[dict, dict]:
    by_instance = {}
    by_openstack = {}
    for binding in scenario_bom.get("node_instance_bindings", []) or []:
        if binding.get("instance_id"):
            by_instance[binding["instance_id"]] = binding
        if binding.get("openstack_instance_id") not in {"", None, "not_available"}:
            by_openstack[binding["openstack_instance_id"]] = binding
    return by_instance, by_openstack


def _parse_case_pipeline(case_dir: Path, warnings: list[dict]) -> tuple[list[dict], dict, dict]:
    pipeline_path = case_dir / "metadata" / "pipeline_events.jsonl"
    events = read_jsonl_file(pipeline_path, warnings)
    artifact_meta = {}
    for event in events:
        meta = event.get("meta") or {}
        rel = meta.get("rel") or meta.get("artifact_rel")
        if rel:
            artifact_meta[str(rel)] = event
    return events, artifact_meta, {"pipeline_path": relative_path(pipeline_path)}


def _infer_case_analysis_artifacts(case_dir: Path, case_id: str) -> list[dict]:
    analysis_dir = case_dir / "analysis"
    if not analysis_dir.is_dir():
        return []
    out = []
    for path in sorted(analysis_dir.rglob("*")):
        if not path.is_file():
            continue
        artifact_type = path.name
        artifact_class, is_primary = _artifact_classification(artifact_type)
        if artifact_class != "analysis_outputs":
            continue
        ref = clone(empty_artifact_reference())
        # 2026-09-24: era `hashlib.sha256(path.read_bytes())` -- carga el fichero
        # ENTERO en memoria de golpe (hasta 8MB) por cada artefacto de analisis
        # indexado, en un bucle que puede recorrer miles de ficheros para un solo
        # caso. Cambiado a `hash_file()` (ya existente en foc_hashing.py, la misma
        # que usa collect_sources() para el resto de la plataforma), que lee en
        # trozos de 1MB -- resultado identico (mismo algoritmo, mismos bytes),
        # solo cambia como se lee. Motivado por un fallo real: un caso de 51GB
        # (CASE-20260924-104434) hizo que el RSS de este worker subiera de 21GB a
        # 37.6GB en ~5 minutos durante exactamente esta fase (regenerate_foc_context),
        # matando el worker -- documentado con evidencia real (log de heartbeat)
        # en foc_reconstruction/README.md. No confirmado con profiling en vivo que
        # esta linea sea la causa unica, pero es el candidato mas fuerte encontrado
        # por lectura de codigo, y este cambio es estrictamente mas seguro (menos
        # memoria pico, mismo resultado) sin ningun caso en que pueda ser peor.
        file_size = path.stat().st_size
        ref.update(
            {
                "artifact_id": _artifact_id(case_dir.name, relative_path(path)),
                "evidence_id": _evidence_id(case_dir.name, relative_path(path)),
                "id_origin": "derived_from_analysis_output",
                "artifact_type": artifact_type,
                "artifact_class": artifact_class,
                "is_primary_evidence": is_primary,
                "path": relative_path(path),
                "case_id": case_id,
                "related_instance_id": "unresolved",
                "related_node_id": "unresolved",
                "sha256": hash_file(path) if file_size <= 8 * 1024 * 1024 else "",
                "size": file_size,
                "status": "indexed",
                "details": {"analysis_output": True},
            }
        )
        out.append(ref)
    return out


def _case_trigger_score(event: dict, target_node_ids: set[str], target_instance_ids: set[str], case_created_epoch: float | None) -> tuple[int, list[str]]:
    details = event.get("details") or {}
    score = 0
    reasons = []
    severity = str(details.get("triage_severity") or "").upper()
    correlation = str(details.get("correlation_status") or "").lower()
    signature = str(details.get("signature") or "").lower()
    protocol = str(details.get("protocol") or "").lower()
    node_id = str(event.get("related_node_id") or "")
    instance_id = str(event.get("related_instance_id") or "")

    if correlation == "confirmed":
        score += 120
        reasons.append("confirmed_correlation")
    elif correlation == "inferred_medium":
        score += 70
        reasons.append("medium_correlation")
    elif correlation in {"weak_candidate", "inferred_low"}:
        score += 30
        reasons.append("weak_correlation")

    if severity == "CRITICAL":
        score += 95
    elif severity == "HIGH":
        score += 80
    elif severity == "MEDIUM":
        score += 25
    elif severity == "LOW":
        score -= 15

    if node_id and node_id in target_node_ids:
        score += 55
        reasons.append("target_node_match")
    if instance_id and instance_id in target_instance_ids:
        score += 35
        reasons.append("target_instance_match")

    if "modbus write" in signature:
        score += 120
        reasons.append("ot_write_signal")
    elif signature.startswith("/"):
        score += 95
        reasons.append("fim_signal")

    if details.get("recommend_forensics") is True:
        score += 35
        reasons.append("forensics_recommended")

    if protocol in {"tcp", "modbus_tcp"}:
        score += 15
    elif protocol in {"icmp", "ipv6-icmp"}:
        score -= 120
        reasons.append("icmp_penalty")

    if "ping detectado" in signature or "noise_signature" in str(details.get("correlation_reason") or ""):
        score -= 180
        reasons.append("noise_penalty")

    if case_created_epoch:
        try:
            alert_epoch = float(details.get("ts_epoch") or 0.0)
        except Exception:
            alert_epoch = 0.0
        if alert_epoch:
            delta = case_created_epoch - alert_epoch
            if 0 <= delta <= 300:
                score += 45
                reasons.append("temporal_close")
            elif 0 <= delta <= 1800:
                score += 25
                reasons.append("temporal_compatible")
            elif 0 <= delta <= 7200:
                score += 10
            else:
                score -= 20

    return score, reasons


def build_indexes(scenario_bom: dict, tools_bom: dict, timeline: dict, sources_bundle: dict, id_mapping: dict | None = None) -> dict:
    warnings: list[dict] = []
    scenario_id = scenario_bom.get("scenario_id", "unknown")
    relationships: list[dict] = []
    artifacts_index: list[dict] = []
    id_mapping = id_mapping or read_id_mapping() or {}
    binding_by_instance, binding_by_openstack = _binding_maps(scenario_bom)

    for node in scenario_bom.get("nodes", []):
        node_id = node.get("node_id", "unknown")
        _add_edge(relationships, "scenario", scenario_id, "contains_node", "node", node_id)

    for binding in scenario_bom.get("node_instance_bindings", []):
        _add_edge(
            relationships,
            "node",
            binding.get("node_id", "unknown"),
            "binds_instance",
            "instance",
            binding.get("instance_id", "unresolved"),
            status=binding.get("status", "unresolved"),
            relationship_status="confirmed" if binding.get("status") == "bound" else "inferred",
        )

    node_by_name = {node.get("name"): node for node in scenario_bom.get("nodes", []) if node.get("name")}
    binding_by_instance = {
        binding.get("instance_id"): binding
        for binding in scenario_bom.get("node_instance_bindings", [])
        if binding.get("instance_id")
    }
    for node in tools_bom.get("nodes", []):
        node_name = node.get("instance_name", "")
        matching_node = node_by_name.get(node_name)
        node_id = matching_node.get("node_id") if matching_node else binding_by_instance.get(node.get("instance_id"), {}).get("node_id", "unresolved")
        for tool in node.get("desired_tools", []):
            _add_edge(relationships, "node", node_id, "desired_tool", "tool", tool, status="ok")
        for tool in node.get("installed_tools", []):
            _add_edge(relationships, "node", node_id, "installed_tool", "tool", tool, status="ok")

    attack_mapping_by_path = {
        entry.get("source_path"): entry
        for entry in (id_mapping.get("mappings", {}).get("attacks", []) or [])
    }
    detection_events = [event for event in timeline.get("events", []) if event.get("event_type") == "detection_alert"]

    attack_by_id = {}
    for path in sorted(project_path("app_core", "infrastructure", "attack", "outputs").glob("*/result.json")):
        data = read_json_file(path, warnings)
        if not isinstance(data, dict):
            continue
        mapping_entry = attack_mapping_by_path.get(relative_path(path), {})
        attack_id = mapping_entry.get("attack_id", make_id("atk", data.get("attack_id") or relative_path(path)))
        execution_id = path.parent.name
        target_role = str(data.get("target_role") or "").lower()
        node_id = "unresolved"
        for node in scenario_bom.get("nodes", []):
            if str(node.get("type") or "").lower() == target_role:
                node_id = node.get("node_id", "unresolved")
                break
        attack_by_id[attack_id] = {
            "attack_id": attack_id,
            "target_node_id": node_id,
            "target_ip": str(data.get("target_ip") or "").strip(),
            "protocol": str(data.get("protocol") or "unknown").lower(),
            "mitre_id": str(data.get("mitre_id") or "").upper(),
        }
        _add_edge(relationships, "node", node_id, "attack_execution", "attack", attack_id, evidence=[relative_path(path)], details={"execution_id": execution_id}, relationship_status="inferred" if node_id == "unresolved" else "confirmed")
        matching_alerts = [
            event for event in detection_events
            if event.get("related_attack_id") == attack_id
        ]
        if matching_alerts:
            for event in matching_alerts:
                details = event.get("details", {}) if isinstance(event.get("details"), dict) else {}
                correlation_status = details.get("correlation_status", "inferred")
                correlation_confidence = details.get("correlation_confidence", "medium")
                relationship_status = "confirmed" if correlation_status == "confirmed" else "inferred"
                _add_edge(
                    relationships,
                    "attack",
                    attack_id,
                    "produced_alert",
                    "alert",
                    event.get("related_alert_id", "unresolved"),
                    relationship_status=relationship_status,
                    correlation_status=correlation_status,
                    correlation_confidence=correlation_confidence,
                    correlation_reason=details.get("correlation_reason", "timeline_correlation"),
                    evidence=[event.get("source_path", "")],
                    details={
                        "node_id": event.get("related_node_id", "unresolved"),
                        "instance_id": event.get("related_instance_id", "unresolved"),
                        "signature": details.get("signature", "unknown"),
                        "rule_id": details.get("rule_id", "unknown"),
                        "collector": details.get("collector", details.get("source", "unknown")),
                        "original_sensor": details.get("original_sensor", "unknown"),
                        "protocol": details.get("protocol", "unknown"),
                        "severity": details.get("triage_severity", "unknown"),
                    },
                )
        else:
            _add_edge(
                relationships,
                "attack",
                attack_id,
                "produced_alert",
                "alert",
                "unresolved",
                status="unresolved",
                relationship_status="inferred",
                correlation_status="unresolved",
                correlation_confidence="low",
                correlation_reason="no_matching_detection_event",
            )

    triage_events = {}
    for event in timeline.get("events", []):
        if event.get("event_type") == "triage_result":
            triage_events[event.get("related_alert_id", "unresolved")] = event
    for alert_id in triage_events.keys():
        _add_edge(relationships, "alert", alert_id, "triaged_as", "triage", alert_id)

    detection_by_id = {event.get("related_alert_id"): event for event in detection_events if event.get("related_alert_id")}
    case_dirs = sorted(project_path("app_core", "infrastructure", "forensics", "evidence_store").glob("CASE-*"))
    cases_index = []
    for case_dir in case_dirs:
        case_id = make_id("case", case_dir.name)
        case_artifacts = _infer_case_artifacts(case_dir, warnings)
        analysis_artifacts = _infer_case_analysis_artifacts(case_dir, case_id)
        pipeline_events, pipeline_artifact_meta, pipeline_refs = _parse_case_pipeline(case_dir, warnings)
        case_created = next((event for event in pipeline_events if str(event.get("event") or event.get("event_type") or "") == "case_created"), None)
        orchestration = next((event for event in pipeline_events if str(event.get("event") or event.get("event_type") or "") == "dfir_orchestration_start"), None)
        targeted_vm_ids = [str((event.get("meta") or {}).get("vm_id") or "") for event in pipeline_events if (event.get("meta") or {}).get("vm_id")]
        if orchestration:
            for target in ((orchestration.get("meta") or {}).get("targets") or []):
                vm_id = str(target.get("vm_id") or "").strip()
                if vm_id:
                    targeted_vm_ids.append(vm_id)
        target_bindings = [binding_by_openstack.get(vm_id) for vm_id in targeted_vm_ids if binding_by_openstack.get(vm_id)]
        target_node_ids = sorted({binding.get("node_id") for binding in target_bindings if binding.get("node_id")})
        target_instance_ids = sorted({binding.get("instance_id") for binding in target_bindings if binding.get("instance_id")})

        candidate_alerts = []
        fallback_alerts = []
        case_created_epoch = None
        if case_created and case_created.get("ts_epoch"):
            try:
                case_created_epoch = float(case_created.get("ts_epoch"))
            except Exception:
                case_created_epoch = None
        for event in detection_events:
            details = event.get("details") or {}
            if details.get("recommend_forensics") is not True and str(details.get("triage_severity") or "").upper() not in {"HIGH", "CRITICAL"}:
                continue
            if case_created_epoch:
                try:
                    alert_epoch = float(event.get("details", {}).get("ts_epoch") or 0.0)
                except Exception:
                    alert_epoch = 0.0
                if alert_epoch and alert_epoch > case_created_epoch:
                    continue
            score, reasons = _case_trigger_score(event, set(target_node_ids), set(target_instance_ids), case_created_epoch)
            enriched = dict(event)
            enriched["_trigger_score"] = score
            enriched["_trigger_reasons"] = reasons
            fallback_alerts.append(enriched)
            if not target_node_ids or event.get("related_node_id") in target_node_ids:
                candidate_alerts.append(enriched)
        candidate_pool = candidate_alerts or fallback_alerts
        candidate_pool.sort(
            key=lambda item: (
                item.get("_trigger_score", 0),
                -float((item.get("details") or {}).get("ts_epoch") or 0.0),
            ),
            reverse=True,
        )
        trigger_alert = candidate_pool[0] if candidate_pool else None

        for artifact in case_artifacts:
            rel_path = artifact.get("path", "").replace(f"{relative_path(case_dir)}/", "")
            meta_event = pipeline_artifact_meta.get(rel_path) or {}
            vm_id = str(((meta_event.get("meta") or {}).get("vm_id")) or "")
            binding = binding_by_openstack.get(vm_id) or {}
            if binding:
                artifact["related_instance_id"] = binding.get("instance_id", artifact.get("related_instance_id"))
                artifact["related_node_id"] = binding.get("node_id", artifact.get("related_node_id"))
                artifact.setdefault("details", {})
                artifact["details"]["acquisition_timestamp"] = meta_event.get("ts_utc") or meta_event.get("ts")
                artifact["details"]["pipeline_event"] = str(meta_event.get("event") or meta_event.get("event_type") or "")
        all_case_artifacts = [*case_artifacts, *analysis_artifacts]
        artifacts_index.extend(all_case_artifacts)
        cases_index.append(
            {
                "case_id": case_id,
                "source_case_name": case_dir.name,
                "path": relative_path(case_dir),
                "artifacts_count": len(all_case_artifacts),
                "manifest_path": f"{relative_path(case_dir)}/manifest.json",
                "pipeline_path": f"{relative_path(case_dir)}/metadata/pipeline_events.jsonl",
                "custody_path": f"{relative_path(case_dir)}/chain_of_custody.log",
                "target_node_ids": target_node_ids,
                "target_instance_ids": target_instance_ids,
                "trigger_alert_id": (trigger_alert or {}).get("related_alert_id", "not_available"),
                "trigger_type": "alert" if trigger_alert else ("manual_or_scheduled" if case_created else "unknown"),
                "trigger_selection_score": (trigger_alert or {}).get("_trigger_score"),
                "trigger_selection_reason": ",".join((trigger_alert or {}).get("_trigger_reasons") or []),
            }
        )
        if trigger_alert:
            _add_edge(
                relationships,
                "alert",
                trigger_alert.get("related_alert_id", "unresolved"),
                "triggered_case",
                "case",
                case_id,
                relationship_status="confirmed",
                correlation_status=(trigger_alert.get("details") or {}).get("correlation_status", "inferred_medium"),
                correlation_confidence=(trigger_alert.get("details") or {}).get("correlation_confidence", "medium"),
                correlation_reason="alert_triggered_forensic_case",
                evidence=[trigger_alert.get("source_path", ""), pipeline_refs["pipeline_path"]],
                details={
                    "trigger_selection_score": trigger_alert.get("_trigger_score"),
                    "trigger_selection_reason": ",".join(trigger_alert.get("_trigger_reasons") or []),
                },
            )
        for artifact in all_case_artifacts:
            _add_edge(relationships, "case", case_id, "contains_artifact", "artifact", artifact["artifact_id"])
            _add_edge(relationships, "evidence", artifact["evidence_id"], "preserved_in", "artifact", artifact["artifact_id"])
            if trigger_alert:
                _add_edge(
                    relationships,
                    "alert",
                    trigger_alert.get("related_alert_id", "unresolved"),
                    "linked_evidence",
                    "artifact",
                    artifact["artifact_id"],
                    relationship_status="confirmed" if artifact.get("sha256") and artifact.get("related_node_id") != "unresolved" else "inferred",
                    correlation_status="confirmed" if artifact.get("sha256") and artifact.get("related_node_id") != "unresolved" else "inferred_medium",
                    correlation_confidence="high" if artifact.get("sha256") else "medium",
                    correlation_reason="alert_case_artifact_linkage",
                    evidence=[artifact.get("path", ""), pipeline_refs["pipeline_path"], f"{relative_path(case_dir)}/manifest.json"],
                    details={
                        "case_id": case_id,
                        "artifact_type": artifact.get("artifact_type"),
                        "related_node_id": artifact.get("related_node_id", "unresolved"),
                        "related_instance_id": artifact.get("related_instance_id", "unresolved"),
                        "trigger_selection_score": trigger_alert.get("_trigger_score"),
                    },
                )
            if "/analysis/" in artifact["path"] or artifact["artifact_type"] in {"vol3_output_dir", "tsk_output_dir"}:
                _add_edge(relationships, "evidence", artifact["evidence_id"], "supports_analysis", "artifact", artifact["artifact_id"])

    for src in sources_bundle.get("sources", []):
        if src.get("status") != "present":
            continue
        if src.get("kind") != "file":
            continue
        source_type = src.get("source_type", "source_file")
        artifact_type = source_type
        if source_type in {"attack_output_artifact", "industrial_attack_runtime", "industrial_attack_policy"}:
            artifact_type = Path(src.get("path", "")).name
        artifact = clone(empty_artifact_reference())
        artifact.update(
            {
                "artifact_id": _artifact_id(src.get("path", "")),
                "evidence_id": "not_available",
                "id_origin": "derived_from_path",
                "artifact_type": artifact_type,
                "artifact_class": _artifact_classification(artifact_type)[0],
                "is_primary_evidence": False,
                "path": src.get("path", ""),
                "case_id": "not_available",
                "related_instance_id": "unresolved",
                "related_node_id": "unresolved",
                "sha256": src.get("sha256"),
                "size": src.get("size"),
                "status": src.get("status", "unknown"),
                "details": {"mtime": src.get("mtime")},
            }
        )
        artifacts_index.append(artifact)

    return {
        "generated_at": utc_now(),
        "warnings": warnings,
        "sources_index": sources_bundle,
        "artifacts_index": {"generated_at": utc_now(), "artifacts": artifacts_index},
        "relationships_index": {"generated_at": utc_now(), "scenario_id": scenario_id, "edges": relationships},
        "cases_index": {"generated_at": utc_now(), "cases": cases_index},
    }
