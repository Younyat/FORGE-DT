"""
Scenario Snapshot — service layer.

Pure aggregation, normalization, relationship building, validation and persistence.
No write operations to scenario/cases/campaigns/forensics/attacks.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve()
PROJECT_ROOT = _HERE.parents[3]  # service.py → scenario_snapshot/ → infrastructure/ → app_core/ → project root

SNAPSHOTS_ROOT = PROJECT_ROOT / "runtime" / "scenario_snapshots"
EVIDENCE_STORE = PROJECT_ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store"
CAMPAIGNS_ROOT = EVIDENCE_STORE / "repetition_campaigns"
SCIENTIFIC_MEMORY_ROOT = CAMPAIGNS_ROOT / "scientific_memory"
FOC_OUTPUT_DIR = PROJECT_ROOT / "foc-reconstruction"
SCENARIO_FILE = PROJECT_ROOT / "scenario" / "scenario_file.json"
INDUSTRIAL_FILE = PROJECT_ROOT / "industrial-scenario" / "scenarios" / "industrial_industrial_file.json"
ATTACK_OUTPUTS_DIR = PROJECT_ROOT / "app_core" / "infrastructure" / "attack" / "outputs"
TOOLS_TMP_DIR = PROJECT_ROOT / "tools-installer-tmp"
TOOLS_INSTALLED_DIR = PROJECT_ROOT / "tools-installer" / "installed"

# ---------------------------------------------------------------------------
# Sentinel values for absent data
# ---------------------------------------------------------------------------
S_AVAILABLE = "AVAILABLE"
S_NOT_AVAILABLE = "NOT_AVAILABLE"
S_NOT_CREATED = "NOT_CREATED"
S_NOT_EXECUTED = "NOT_EXECUTED"
S_NOT_APPLICABLE = "NOT_APPLICABLE"
S_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
S_NOT_RECORDED = "NOT_RECORDED"
S_NOT_VERIFIED = "NOT_VERIFIED"
S_UNRESOLVED = "UNRESOLVED"
S_COLLECTION_FAILED = "COLLECTION_FAILED"

REL_CONFIRMED = "CONFIRMED"
REL_AMBIGUOUS = "AMBIGUOUS"
REL_MISSING = "MISSING"
REL_NOT_APPLICABLE = "NOT_APPLICABLE"

SNAPSHOT_SCHEMA_VERSION = "1.0"
COLLECTOR_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_snapshot_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:4].upper()
    return f"SS-{ts}-{suffix}"


def _load_json(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _field(value: Any, status: str, source: str | None = None,
           collector: str | None = None, message: str | None = None) -> dict:
    return {
        "value": value,
        "status": status,
        "source": source,
        "observed_at": _utc_now(),
        "collector": collector,
        "message": message,
    }


def _safe(fn, collector_name: str, warnings: list, errors: list):
    try:
        return fn()
    except Exception as exc:
        msg = f"[{collector_name}] Collection failed: {exc}"
        errors.append(msg)
        return {"collector_status": S_COLLECTION_FAILED, "error": str(exc)}


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def _collect_scenario_definition(warnings: list) -> dict:
    """Read scenario definition from canonical files (IT and/or OT)."""

    def _parse_nodes(nodes: list, source: str) -> list:
        out = []
        for n in nodes if isinstance(nodes, list) else []:
            out.append({
                "logical_node_id": n.get("id") or n.get("name"),
                "name": n.get("name"),
                "type": n.get("type"),
                "role": n.get("role") or n.get("type"),
                "image": n.get("image"),
                "flavor": n.get("flavor"),
                "networks": n.get("networks") or [],
                "tools": n.get("tools") or [],
                "source": source,
                "raw": n,
            })
        return out

    result: dict = {
        "collector_status": S_NOT_AVAILABLE,
        "scenario_id": None,
        "scenario_name": None,
        "source_file": None,
        "scenario_type": None,
        "nodes_declared": [],
        "it_nodes": [],
        "ot_nodes": [],
        "edges": [],
        "deployment": {},
        "base_scenario": None,
        "raw": {},
    }

    # Industrial/OT scenario takes precedence
    if INDUSTRIAL_FILE.is_file():
        data = _load_json(INDUSTRIAL_FILE) or {}
        nodes = _parse_nodes(data.get("nodes", []), "industrial_file")
        result.update({
            "collector_status": S_AVAILABLE,
            "scenario_id": data.get("scenario_id") or data.get("scenario_name"),
            "scenario_name": data.get("scenario_name"),
            "source_file": str(INDUSTRIAL_FILE.relative_to(PROJECT_ROOT)),
            "scenario_type": "industrial_iot",
            "nodes_declared": nodes,
            "it_nodes": [n for n in nodes if n.get("type") not in {"plc", "scada", "hmi", "industrial_plc", "industrial_scada"}],
            "ot_nodes": [n for n in nodes if n.get("type") in {"plc", "scada", "hmi", "industrial_plc", "industrial_scada"}],
            "edges": data.get("edges") or [],
            "deployment": data.get("deployment") or {},
            "base_scenario": data.get("base_scenario"),
            "raw": data,
        })
        # Also load IT scenario if separate file exists
        if SCENARIO_FILE.is_file():
            it_data = _load_json(SCENARIO_FILE) or {}
            it_nodes = _parse_nodes(it_data.get("nodes", []), "scenario_file")
            # Merge: avoid duplicates by name
            existing_names = {n["name"] for n in nodes}
            new_it = [n for n in it_nodes if n["name"] not in existing_names]
            result["nodes_declared"] = nodes + new_it
            result["it_nodes"] = [n for n in nodes if n.get("type") not in {"plc", "scada", "hmi", "industrial_plc", "industrial_scada"}] + new_it
        return result

    if SCENARIO_FILE.is_file():
        data = _load_json(SCENARIO_FILE) or {}
        nodes = _parse_nodes(data.get("nodes", []), "scenario_file")
        result.update({
            "collector_status": S_AVAILABLE,
            "scenario_id": data.get("scenario_id") or data.get("scenario_name"),
            "scenario_name": data.get("scenario_name"),
            "source_file": str(SCENARIO_FILE.relative_to(PROJECT_ROOT)),
            "scenario_type": "it_only",
            "nodes_declared": nodes,
            "it_nodes": nodes,
            "ot_nodes": [],
            "edges": data.get("edges") or [],
            "deployment": {},
            "raw": data,
        })
        return result

    warnings.append("No scenario definition file found (scenario_file.json or industrial_industrial_file.json).")
    return result


def _collect_infrastructure(scenario_nodes: list, warnings: list) -> dict:
    """Read runtime OpenStack inventory. Gracefully degrades if OpenStack is unavailable."""
    result: dict = {
        "collector_status": S_NOT_AVAILABLE,
        "instances": [],
        "node_mapping": [],
        "error": None,
    }

    try:
        import openstack
        conn = openstack.connection.Connection(
            auth_url=os.environ.get("OS_AUTH_URL"),
            project_name=os.environ.get("OS_PROJECT_NAME"),
            username=os.environ.get("OS_USERNAME"),
            password=os.environ.get("OS_PASSWORD"),
            region_name=os.environ.get("OS_REGION_NAME"),
            user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
            project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
            compute_api_version="2",
            identity_interface="public",
        )

        instances = []
        for server in conn.compute.servers(details=True):
            ip_private = ip_floating = None
            networks = []
            for net_name, addrs in (server.addresses or {}).items():
                for a in addrs:
                    ip = a.get("addr")
                    ip_type = a.get("OS-EXT-IPS:type")
                    networks.append({"network": net_name, "ip": ip, "type": ip_type})
                    if ip_type == "floating":
                        ip_floating = ip
                    else:
                        ip_private = ip

            flavor_name = None
            try:
                fl = conn.compute.get_flavor(server.flavor.get("id") if server.flavor else None)
                flavor_name = fl.name if fl else None
            except Exception:
                pass

            instances.append({
                "instance_id": server.id,
                "name": server.name,
                "status": str(server.status or "UNKNOWN"),
                "ip_private": ip_private,
                "ip_floating": ip_floating,
                "ip": ip_floating or ip_private,
                "networks": networks,
                "image_id": server.image.get("id") if server.image else None,
                "flavor_id": server.flavor.get("id") if server.flavor else None,
                "flavor_name": flavor_name,
                "created_at": getattr(server, "created_at", None),
                "key_name": getattr(server, "key_name", None),
            })

        # Build logical→runtime mapping
        mapping = []
        declared_names = {n["name"]: n for n in scenario_nodes}
        runtime_names = {i["name"]: i for i in instances}

        for logical_name, logical_node in declared_names.items():
            runtime = runtime_names.get(logical_name)
            mapping.append({
                "logical_node_id": logical_node.get("logical_node_id"),
                "logical_name": logical_name,
                "logical_type": logical_node.get("type"),
                "runtime_instance_id": runtime["instance_id"] if runtime else None,
                "runtime_status": runtime["status"] if runtime else None,
                "runtime_ip": runtime["ip"] if runtime else None,
                "match_status": REL_CONFIRMED if runtime else REL_MISSING,
                "match_confidence": "name_match" if runtime else None,
            })
        # Instances without a logical node
        for runtime_name, runtime_inst in runtime_names.items():
            if runtime_name not in declared_names:
                mapping.append({
                    "logical_node_id": None,
                    "logical_name": None,
                    "logical_type": None,
                    "runtime_instance_id": runtime_inst["instance_id"],
                    "runtime_status": runtime_inst["status"],
                    "runtime_ip": runtime_inst["ip"],
                    "match_status": REL_AMBIGUOUS,
                    "match_confidence": "no_logical_node",
                })

        result.update({
            "collector_status": S_AVAILABLE,
            "instances": instances,
            "node_mapping": mapping,
        })

    except Exception as exc:
        result["error"] = str(exc)
        warnings.append(f"OpenStack inventory collection failed: {exc}")

    return result


def _collect_tools_state(instances: list) -> dict:
    """Per-node tools state from installer files."""
    by_node: dict = {}
    for inst in instances:
        instance_id = inst.get("instance_id", "")
        name = inst.get("name", "")

        # Load TMP (current pending/error states)
        tmp: dict = {}
        if name:
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name.lower())
            tmp_path = TOOLS_TMP_DIR / f"{safe_name}_tools.json"
            raw_tmp = _load_json(tmp_path)
            if isinstance(raw_tmp, dict):
                tools_val = raw_tmp.get("tools", {})
                tmp = tools_val if isinstance(tools_val, dict) else {}

        # Load installed (historical)
        installed: dict = {}
        if instance_id:
            inst_path = TOOLS_INSTALLED_DIR / f"{instance_id}.json"
            raw_inst = _load_json(inst_path)
            if isinstance(raw_inst, dict):
                tools_val = raw_inst.get("installed_tools", {})
                installed = tools_val if isinstance(tools_val, dict) else {}

        # Merge: TMP wins for negative states
        merged: dict = {}
        for tool, status in tmp.items():
            merged[tool] = status
        for tool, date in installed.items():
            if tool not in merged:
                merged[tool] = date
            elif merged[tool] not in ("error", "pending", "uninstalling"):
                merged[tool] = date

        tools_list = []
        for tool_name, tool_val in merged.items():
            if isinstance(tool_val, str) and re.match(r"^\d{4}-\d{2}-\d{2}", tool_val):
                status_label = "INSTALLED"
                installed_at = tool_val
            elif tool_val == "error":
                status_label = "FAILED"
                installed_at = None
            elif tool_val == "pending":
                status_label = "PENDING"
                installed_at = None
            elif tool_val == "uninstalling":
                status_label = "PENDING"
                installed_at = None
            else:
                status_label = "UNRESOLVED"
                installed_at = None
            tools_list.append({
                "tool_name": tool_name,
                "status": status_label,
                "installed_at": installed_at,
                "raw_value": tool_val,
            })

        by_node[instance_id or name] = {
            "instance_id": instance_id,
            "instance_name": name,
            "tools": tools_list,
            "installed_count": sum(1 for t in tools_list if t["status"] == "INSTALLED"),
            "failed_count": sum(1 for t in tools_list if t["status"] == "FAILED"),
            "pending_count": sum(1 for t in tools_list if t["status"] == "PENDING"),
        }

    return {"collector_status": S_AVAILABLE, "by_node": by_node}


def _collect_attack_catalog() -> dict:
    """Return the static attack catalog."""
    try:
        from app_core.infrastructure.attack.catalog import ATTACK_CATALOG
        profiles = []
        for atk in ATTACK_CATALOG:
            profiles.append({
                "attack_id": atk.get("attack_id"),
                "display_name": atk.get("display_name"),
                "category": atk.get("category"),
                "mitre_id": atk.get("mitre_id"),
                "mitre_technique": atk.get("mitre_technique"),
                "tactic": atk.get("tactic"),
                "severity": atk.get("severity"),
                "detection_engine": atk.get("detection_engine"),
                "target_roles": atk.get("target_roles") or [],
                "expected_alerts": atk.get("expected_alerts") or [],
                "expected_artifacts": atk.get("expected_artifacts") or [],
                "rollback_required": atk.get("rollback_required"),
                "dfir_escalation": atk.get("dfir_escalation"),
                "script": atk.get("script"),
                "safety_policy": atk.get("safety_policy"),
            })
        return {"collector_status": S_AVAILABLE, "profiles": profiles, "total": len(profiles)}
    except Exception as exc:
        return {"collector_status": S_COLLECTION_FAILED, "profiles": [], "total": 0, "error": str(exc)}


def _collect_attack_executions(warnings: list) -> dict:
    """Scan attack outputs directory for execution_result.json files."""
    executions = []
    if not ATTACK_OUTPUTS_DIR.is_dir():
        return {
            "collector_status": S_NOT_AVAILABLE,
            "executions": [],
            "total": 0,
            "message": "Attack outputs directory not found.",
        }
    try:
        for run_dir in sorted(ATTACK_OUTPUTS_DIR.iterdir()):
            if not run_dir.is_dir():
                continue
            result_file = run_dir / "execution_result.json"
            if not result_file.is_file():
                result_file = run_dir / "result.json"
            if not result_file.is_file():
                continue
            data = _load_json(result_file)
            if not isinstance(data, dict):
                continue
            executions.append({
                "attack_execution_id": data.get("execution_id") or run_dir.name,
                "run_dir": str(run_dir.relative_to(PROJECT_ROOT)),
                "attack_id": data.get("attack_id"),
                "display_name": data.get("display_name"),
                "mitre_id": data.get("mitre_id"),
                "severity": data.get("severity"),
                "status": data.get("status") or data.get("exit_code") or S_NOT_RECORDED,
                "exit_code": data.get("exit_code"),
                "started_at": data.get("started_at"),
                "finished_at": data.get("finished_at") or data.get("completed_at"),
                "target_ip": data.get("effective_target_ip") or data.get("target_ip"),
                "target_role": data.get("effective_target_role") or data.get("target_role"),
                "attacker_ip": data.get("attacker_ip"),
                "case_dir": data.get("case_dir"),
                "campaign_id": data.get("campaign_id"),
                "execution_id": data.get("execution_id"),
                "parameters": data.get("parameters") or {},
                "expected_alerts": data.get("expected_alerts") or [],
                "rollback_required": data.get("rollback_required"),
            })
        return {
            "collector_status": S_AVAILABLE,
            "executions": list(reversed(executions)),
            "total": len(executions),
        }
    except Exception as exc:
        warnings.append(f"Attack executions scan failed: {exc}")
        return {"collector_status": S_COLLECTION_FAILED, "executions": [], "total": 0, "error": str(exc)}


def _collect_forensics(scenario_id: str | None, warnings: list) -> dict:
    """Collect forensic cases from evidence_store."""
    if not EVIDENCE_STORE.is_dir():
        return {
            "collector_status": S_NOT_AVAILABLE,
            "cases": [],
            "total": 0,
            "message": "Evidence store directory not found.",
        }
    try:
        # 2026-09-04: also scan the two nested locations a "final sample"
        # case can live at -- the "preserve final case as full sample"
        # feature (2026-07-22) deliberately archives a Level B campaign's
        # last repetition's case to repetition_campaigns/<id>/final_sample_case/
        # specifically so evidence_store/'s top-level CASE-* glob (used by
        # _cleanup_candidates() to wipe old cases) can never find and delete
        # it, and campaign_package_builder.py (2026-09-04) later MOVES that
        # same case into campaign_packages/<id>_package/final_sample_case/
        # for portability. But this function used that exact same
        # top-level-only glob to COUNT existing cases, so the very feature
        # built to protect that case's evidence made it invisible here too
        # -- confirmed live: a real campaign's 10th-repetition snapshot
        # (captured right after the archival step runs) failed its "at
        # least one forensic case created" check with "0 forensic case(s)
        # found", even though the campaign had 10 real, preserved cases (by
        # the time this was found, the case had already moved again, into
        # campaign_packages/ -- had to widen for both locations, not just
        # the first one checked). Read-only widening (never deletes/moves
        # anything), so safe regardless of what else reads this output.
        case_dirs = sorted(set(
            [p for p in EVIDENCE_STORE.iterdir() if p.is_dir() and p.name.startswith("CASE-")]
            + [p for p in (EVIDENCE_STORE / "repetition_campaigns").glob("*/final_sample_case/CASE-*") if p.is_dir()]
            + [p for p in (EVIDENCE_STORE / "campaign_packages").glob("*/final_sample_case/CASE-*") if p.is_dir()]
        ))
        cases = []
        for case_dir in case_dirs:
            manifest = _load_json(case_dir / "manifest.json") or {}
            trigger = _load_json(case_dir / "metadata" / "trigger_alert_binding.json") or {}
            acquisition = _load_json(case_dir / "metadata" / "acquisition_profile.json") or {}
            analysis = _load_json(case_dir / "analysis" / "forensic_analysis_report.json") or {}
            custody_present = (case_dir / "chain_of_custody.log").is_file()
            sealed = (case_dir / "sealed_manifest.json").is_file()

            artifacts = manifest.get("artifacts", []) if isinstance(manifest, dict) else []
            artifact_types = set()
            hash_count = 0
            for art in artifacts:
                artifact_types.add(str(art.get("type") or ""))
                if art.get("sha256"):
                    hash_count += 1

            # Read full analysis content (for archived cases)
            analysis_report_full: dict | None = None
            if analysis:
                analysis_report_full = {
                    "summary": analysis.get("summary"),
                    "findings": analysis.get("findings") or [],
                    "conclusion": analysis.get("conclusion"),
                    "recommendations": analysis.get("recommendations") or [],
                    "methodology": analysis.get("methodology"),
                    "timeline": analysis.get("timeline") or [],
                }

            # Network findings
            net_findings_path = case_dir / "analysis" / "03_network" / "network_findings.json"
            net_findings = _load_json(net_findings_path) if net_findings_path.is_file() else None

            # Chain of custody log (last 100 lines)
            custody_log_tail: list = []
            if custody_present:
                try:
                    lines = (case_dir / "chain_of_custody.log").read_text(
                        encoding="utf-8", errors="replace").strip().splitlines()
                    custody_log_tail = lines[-100:]
                except Exception:
                    pass

            # Lightweight bundle presence (indicator that case can be reconstructed without raw artifacts)
            lw_bundle = (case_dir / "lightweight_case_bundle_manifest.json").is_file()

            # Check for analysis sub-directories
            analysis_sections = []
            analysis_dir = case_dir / "analysis"
            if analysis_dir.is_dir():
                analysis_sections = [d.name for d in sorted(analysis_dir.iterdir()) if d.is_dir()]

            cases.append({
                "case_id": case_dir.name,
                "case_dir": str(case_dir.relative_to(PROJECT_ROOT)),
                "scenario_id": scenario_id,
                "created_at": manifest.get("created_at") or manifest.get("timestamp"),
                "attack_id": manifest.get("attack_id") or trigger.get("attack_id") or trigger.get("attack_profile_id"),
                "alert_id": trigger.get("alert_id") or trigger.get("event_id") or trigger.get("trigger_alert_id"),
                "alert_signature": trigger.get("signature") or trigger.get("description"),
                "trigger_severity": trigger.get("severity"),
                "trigger_source": trigger.get("source") or trigger.get("original_sensor") or trigger.get("collector"),
                "acquisition_types": sorted(artifact_types - {""}),
                "artifact_count": len(artifacts),
                "hash_count": hash_count,
                "custody_chain_present": custody_present,
                "custody_log_tail": custody_log_tail,
                "sealed": sealed,
                "analysis_present": bool(analysis),
                "analysis_report": analysis_report_full,
                "network_findings": net_findings,
                "analysis_sections": analysis_sections,
                "lightweight_bundle_present": lw_bundle,
                "preservation_status": "COMPLETED" if artifacts else S_NOT_EXECUTED,
                "case_status": manifest.get("status") or S_NOT_RECORDED,
                "campaign_id": manifest.get("campaign_id"),
                "execution_id": manifest.get("execution_id") or trigger.get("execution_id"),
                "foc_reconstruction_present": (
                    (FOC_OUTPUT_DIR / "attestations" / "forensic_intervention.json").is_file()
                ),
            })

        return {
            "collector_status": S_AVAILABLE,
            "cases": list(reversed(cases)),
            "total": len(cases),
            "active_case_id": cases[-1]["case_id"] if cases else None,
        }
    except Exception as exc:
        warnings.append(f"Forensics collection failed: {exc}")
        return {"collector_status": S_COLLECTION_FAILED, "cases": [], "total": 0, "error": str(exc)}


def _collect_campaign_executions(camp_id: str, camp_dir_path: Path) -> dict:
    """Read per-level execution details including CPR/WCPR metrics and result cards."""
    levels_out: dict = {}
    for level_dir in sorted(camp_dir_path.glob("level_*")):
        level_name = level_dir.name  # e.g. "level_A", "level_B"
        level_key = level_name.upper().replace("LEVEL_", "")  # "A", "B", "C"
        executions = []
        for exec_dir in sorted(level_dir.glob("EXEC-*")):
            if not exec_dir.is_dir():
                continue
            manifest = _load_json(exec_dir / "execution_manifest.json") or {}
            result_card = _load_json(exec_dir / "forensic_result_card.json") or {}
            ground_truth = _load_json(exec_dir / "ground_truth.json") or {}
            ground_truth_seal = _load_json(exec_dir / "ground_truth_seal.json") or {}
            preservation = _load_json(exec_dir / "preservation_profile.json") or {}
            job_status = _load_json(exec_dir / "job_status.json") or {}

            # CPR/WCPR — try multiple field name variants
            cpr = (result_card.get("CPR") or result_card.get("cpr")
                   or result_card.get("forensic_continuity_ratio"))
            wcpr = (result_card.get("Weighted_CPR") or result_card.get("wcpr")
                    or result_card.get("weighted_cpr"))
            evidence_layers = result_card.get("evidence_layers_available") or []

            executions.append({
                "execution_id": exec_dir.name,
                "campaign_id": camp_id,
                "level": level_key,
                "status": manifest.get("status") or job_status.get("status"),
                "case_id": result_card.get("case_id") or manifest.get("source_case_id"),
                "attack_profile_id": result_card.get("attack_profile_id") or manifest.get("attack_profile_id"),
                "attack_name": result_card.get("attack_name"),
                "mitre_technique_id": result_card.get("mitre_technique_id"),
                "scenario_fingerprint": result_card.get("scenario_fingerprint"),
                "topology_fingerprint": result_card.get("topology_fingerprint"),
                "cpr": cpr,
                "wcpr": wcpr,
                "detection_engine": result_card.get("detection_engine"),
                "selected_trigger": result_card.get("selected_trigger"),
                "evidence_layers": evidence_layers,
                "acquisition_scope": result_card.get("acquisition_scope") or {},
                "preservation_summary": result_card.get("preservation_summary") or {},
                "ground_truth_sealed": bool(ground_truth_seal),
                "scientific_degradations": manifest.get("scientific_limitations") or [],
                "created_at": result_card.get("created_at") or manifest.get("created_at"),
            })
        levels_out[level_key] = {"executions": executions, "execution_count": len(executions)}

    # Validation reports (Level B comparison)
    comparisons = []
    comp_dir = camp_dir_path / "comparisons"
    if comp_dir.is_dir():
        for comp_sub in sorted(comp_dir.iterdir()):
            if comp_sub.is_dir():
                comp_meta = _load_json(comp_sub / "comparison_manifest.json") or {}
                comp_matrix = _load_json(comp_sub / "comparison_matrix.json") or {}
                if comp_meta or comp_matrix:
                    comparisons.append({
                        "comparison_id": comp_sub.name,
                        "created_at": comp_meta.get("created_at"),
                        "execution_ids": comp_meta.get("execution_ids") or [],
                        "delta_wcpr_allowed": comp_meta.get("delta_wcpr_allowed"),
                        "overall_result": comp_meta.get("overall_result"),
                        "matrix_summary": {
                            "executions_compared": len(comp_matrix.get("executions") or []),
                            "metrics": list((comp_matrix.get("metrics") or {}).keys()),
                        } if comp_matrix else None,
                    })

    levels_out["_comparisons"] = comparisons
    return levels_out


def _collect_campaigns(warnings: list) -> dict:
    """Collect campaign data from repetition_campaigns directory — with full execution details."""
    if not CAMPAIGNS_ROOT.is_dir():
        return {
            "collector_status": S_NOT_AVAILABLE,
            "campaigns": [],
            "level_a": [], "level_b": [], "level_c": [],
            "total": 0,
        }
    try:
        from app_core.infrastructure.foc_experimentation.campaign_service import list_campaigns
        raw = list_campaigns()
        all_campaigns = raw.get("campaigns") or []

        level_a, level_b, level_c, other = [], [], [], []
        for camp in all_campaigns:
            lvl = str(camp.get("level") or "").upper()
            camp_id = camp.get("campaign_id", "")
            camp_dir_path = CAMPAIGNS_ROOT / camp_id

            # Collect per-execution details including CPR/WCPR
            execution_detail: dict = {}
            if camp_dir_path.is_dir():
                try:
                    execution_detail = _collect_campaign_executions(camp_id, camp_dir_path)
                except Exception as exc:
                    warnings.append(f"Campaign {camp_id} execution detail failed: {exc}")

            entry = {
                "campaign_id": camp_id,
                "level": camp.get("level"),
                "status": camp.get("status"),
                "scenario_id": camp.get("scenario_id"),
                "attack_id": camp.get("attack_id"),
                "created_at": camp.get("created_at"),
                "updated_at": camp.get("updated_at"),
                "execution_count": camp.get("execution_count", 0),
                "completed_executions": camp.get("completed_executions", 0),
                "source_case_id": camp.get("source_case_id"),
                "comparison_family": camp.get("comparison_family"),
                "parent_campaign_id": camp.get("parent_campaign_id"),
                "parent_execution_id": camp.get("parent_execution_id"),
                "technical_outcome": camp.get("technical_outcome"),
                "scientific_outcome": camp.get("scientific_outcome"),
                "scientific_limitations": camp.get("scientific_limitations") or [],
                "comparison_readiness": camp.get("comparison_readiness"),
                "execution_detail": execution_detail,
            }
            if lvl in {"A", "LEVEL_A"}:
                level_a.append(entry)
            elif lvl in {"B", "LEVEL_B"}:
                level_b.append(entry)
            elif lvl in {"C", "LEVEL_C"}:
                level_c.append(entry)
            else:
                other.append(entry)

        # Compute aggregate CPR/WCPR across all Level B executions
        b_cprs = []
        b_wcprs = []
        for camp_b in level_b:
            for exec_e in (camp_b.get("execution_detail") or {}).get("B", {}).get("executions", []):
                if exec_e.get("cpr") is not None:
                    b_cprs.append(exec_e["cpr"])
                if exec_e.get("wcpr") is not None:
                    b_wcprs.append(exec_e["wcpr"])

        level_b_stats: dict = {}
        if b_cprs:
            level_b_stats = {
                "cpr_mean": round(sum(b_cprs) / len(b_cprs), 4),
                "cpr_min": round(min(b_cprs), 4),
                "cpr_max": round(max(b_cprs), 4),
                "wcpr_mean": round(sum(b_wcprs) / len(b_wcprs), 4) if b_wcprs else None,
                "execution_count": len(b_cprs),
            }

        return {
            "collector_status": S_AVAILABLE,
            "campaigns": all_campaigns,
            "level_a": level_a,
            "level_b": level_b,
            "level_c": level_c,
            "other": other,
            "total": len(all_campaigns),
            "level_b_statistics": level_b_stats,
        }
    except Exception as exc:
        warnings.append(f"Campaign collection failed: {exc}")
        return {
            "collector_status": S_COLLECTION_FAILED,
            "campaigns": [], "level_a": [], "level_b": [], "level_c": [],
            "total": 0, "error": str(exc),
        }


def _collect_foc_reconstruction(warnings: list) -> dict:
    """Read FOC reconstruction output files."""
    if not FOC_OUTPUT_DIR.is_dir():
        return {"collector_status": S_NOT_AVAILABLE, "message": "FOC output directory not found."}

    def _read(key: str) -> dict | list | None:
        from app_core.infrastructure.foc_reconstruction.foc_config import GENERATED_FILES
        path = GENERATED_FILES.get(key)
        return _load_json(path) if path else None

    manifest = _read("manifest") or {}
    scenario_bom = _read("scenario_bom") or {}
    tools_bom = _read("tools_bom") or {}
    attack_att = _read("attack_attestation") or {}
    detection_att = _read("detection_attestation") or {}
    acquisition_profile = _read("acquisition_profile") or {}
    forensic_intervention = _read("forensic_intervention") or {}
    foc_context = _read("foc_context_summary") or {}
    readiness = _read("foc_readiness_report") or {}
    cases_index = _read("cases_index") or {}
    hashes_index = _read("hashes_index") or {}
    sources_index = _read("sources_index") or {}

    initialized = bool(manifest)

    # Summary of quality
    quality_status = S_NOT_AVAILABLE
    try:
        from app_core.infrastructure.foc_reconstruction.foc_quality import build_status
        q = build_status() or {}
        quality_status = q.get("status") or S_NOT_AVAILABLE
        completeness = q.get("completeness")
        reproducibility_score = q.get("reproducibility_score")
    except Exception:
        completeness = None
        reproducibility_score = None

    paper_repetitions: dict = {}
    try:
        paper_path = SCIENTIFIC_MEMORY_ROOT / "result_registry"
        if paper_path.is_dir():
            results = []
            for rfile in sorted(paper_path.glob("*.json")):
                r = _load_json(rfile) or {}
                results.append({
                    "result_id": r.get("result_id") or rfile.stem,
                    "campaign_id": r.get("campaign_id"),
                    "execution_id": r.get("execution_id"),
                    "level": r.get("level"),
                    "cpr": r.get("cpr"),
                    "wcpr": r.get("wcpr"),
                    "created_at": r.get("created_at"),
                    "included_in_paper": r.get("included_in_paper"),
                    "exclusion_reason": r.get("exclusion_reason"),
                })
            paper_repetitions = {
                "collector_status": S_AVAILABLE,
                "results": results,
                "total": len(results),
            }
    except Exception as exc:
        paper_repetitions = {"collector_status": S_COLLECTION_FAILED, "error": str(exc)}

    return {
        "collector_status": S_AVAILABLE,
        "initialized": initialized,
        "quality_status": quality_status,
        "completeness": completeness,
        "reproducibility_score": reproducibility_score,
        "manifest": {
            "present": bool(manifest),
            "scenario_id": manifest.get("scenario_id"),
            "timestamp": manifest.get("timestamp") or manifest.get("generated_at"),
            "status": manifest.get("status"),
        },
        "scenario_bom": {
            "present": bool(scenario_bom),
            "node_count": len(scenario_bom.get("nodes") or []),
            "network_count": len(scenario_bom.get("networks") or []),
        },
        "tools_bom": {
            "present": bool(tools_bom),
            "tool_count": len(tools_bom.get("tools") or []),
        },
        "attack_attestation": {
            "present": bool(attack_att),
            "event_count": len(attack_att.get("events") or []),
        },
        "detection_attestation": {
            "present": bool(detection_att),
            "alert_count": len(detection_att.get("alerts") or []),
        },
        "acquisition_profile": {
            "present": bool(acquisition_profile),
            "targets": acquisition_profile.get("targets") or [],
        },
        "forensic_intervention": {
            "present": bool(forensic_intervention),
            "case_id": forensic_intervention.get("case_id"),
        },
        "foc_context_summary": {
            "present": bool(foc_context),
            "summary": str(foc_context.get("summary") or "")[:300],
        },
        "readiness_report": {
            "present": bool(readiness),
            "overall_ready": readiness.get("overall_ready"),
            "checks_total": len(readiness.get("checks") or []),
        },
        "cases_index": {
            "present": bool(cases_index),
            "case_count": len(cases_index.get("cases") or []),
        },
        "hashes_index": {
            "present": bool(hashes_index),
            "file_count": len(hashes_index.get("files") or hashes_index.get("hashes") or {}),
        },
        "paper_repetitions": paper_repetitions,
    }


# ---------------------------------------------------------------------------
# Relationship builder
# ---------------------------------------------------------------------------

def _build_relationships(attacks: dict, forensics: dict, campaigns: dict) -> dict:
    """Link attack executions → forensic cases → campaigns."""

    chains = []
    executions = attacks.get("executions", [])
    cases = forensics.get("cases", [])
    campaign_list = campaigns.get("campaigns", [])

    # Build lookup maps
    case_by_id = {c["case_id"]: c for c in cases}
    campaign_by_id = {c["campaign_id"]: c for c in campaign_list if c.get("campaign_id")}

    for exec_ in executions:
        exec_case_dir = str(exec_.get("case_dir") or "")
        exec_case_id = Path(exec_case_dir).name if exec_case_dir else None
        campaign_id = exec_.get("campaign_id")

        # Find forensic case
        case = None
        case_match_method = None
        if exec_case_id and exec_case_id in case_by_id:
            case = case_by_id[exec_case_id]
            case_match_method = "case_dir_reference"
        else:
            # Try by campaign_id
            for c in cases:
                if c.get("campaign_id") and c["campaign_id"] == campaign_id:
                    case = c
                    case_match_method = "campaign_id"
                    break

        chain = {
            "attack_execution_id": exec_.get("attack_execution_id"),
            "attack_id": exec_.get("attack_id"),
            "severity": exec_.get("severity"),
            "started_at": exec_.get("started_at"),
            "target_ip": exec_.get("target_ip"),
            "campaign_id": campaign_id,
            "forensic_case_id": case["case_id"] if case else None,
            "case_match_method": case_match_method,
            "case_match_status": REL_CONFIRMED if case and case_match_method == "case_dir_reference"
                else REL_AMBIGUOUS if case else REL_MISSING,
            "alert_signature": case["alert_signature"] if case else None,
            "alert_severity": case["trigger_severity"] if case else None,
            "evidence_count": case["artifact_count"] if case else 0,
            "custody_chain": case["custody_chain_present"] if case else False,
            "sealed": case["sealed"] if case else False,
        }
        chains.append(chain)

    # Campaign → execution → case linkage summary
    campaign_links = []
    for camp in campaign_list:
        cid = camp.get("campaign_id")
        related_cases = [c for c in cases if c.get("campaign_id") == cid]
        related_execs = [e for e in executions if e.get("campaign_id") == cid]
        campaign_links.append({
            "campaign_id": cid,
            "level": camp.get("level"),
            "case_count": len(related_cases),
            "execution_count": len(related_execs),
            "case_ids": [c["case_id"] for c in related_cases],
        })

    confirmed = sum(1 for c in chains if c["case_match_status"] == REL_CONFIRMED)
    missing = sum(1 for c in chains if c["case_match_status"] == REL_MISSING)

    return {
        "attack_case_chains": chains,
        "campaign_case_links": campaign_links,
        "summary": {
            "total_executions": len(executions),
            "confirmed_case_links": confirmed,
            "missing_case_links": missing,
            "ambiguous_case_links": len(chains) - confirmed - missing,
        },
    }


# ---------------------------------------------------------------------------
# Validation / readiness checks
# ---------------------------------------------------------------------------

def _validate_readiness(scenario: dict, infra: dict, tools: dict, attacks: dict,
                        forensics: dict, campaigns: dict, foc: dict) -> dict:
    checks = []

    def chk(domain: str, requirement: str, status: str, source: str | None,
            reason: str, impact: str, action: str, auto_resolvable: bool = False):
        checks.append({
            "domain": domain,
            "requirement": requirement,
            "status": status,
            "source": source,
            "reason": reason,
            "impact": impact,
            "recommended_action": action,
            "auto_resolvable": auto_resolvable,
        })

    PASS = "PASS"
    WARN = "WARNING"
    FAIL = "FAIL"
    NA = "NOT_APPLICABLE"

    # Scenario Definition
    sc_ok = scenario.get("collector_status") == S_AVAILABLE
    chk("scenario_definition", "Scenario definition file present",
        PASS if sc_ok else FAIL,
        scenario.get("source_file"),
        "Scenario file loaded." if sc_ok else "No scenario file found.",
        "Cannot verify node coverage without a scenario definition.",
        "Create or select an active scenario." if not sc_ok else "")

    node_count = len(scenario.get("nodes_declared") or [])
    chk("scenario_definition", "At least one node declared",
        PASS if node_count > 0 else FAIL,
        scenario.get("source_file"),
        f"{node_count} node(s) declared.",
        "Cannot validate infrastructure without declared nodes.",
        "Add nodes to the scenario definition." if node_count == 0 else "")

    ot_count = len(scenario.get("ot_nodes") or [])
    chk("scenario_definition", "OT nodes declared (industrial scenario)",
        PASS if ot_count > 0 else WARN,
        scenario.get("source_file"),
        f"{ot_count} OT node(s) declared.",
        "OT scenario not fully documented.",
        "Add OT nodes (PLC, SCADA) to the scenario definition." if ot_count == 0 else "")

    # Infrastructure
    inst_count = len(infra.get("instances") or [])
    mapping = infra.get("node_mapping") or []
    matched = sum(1 for m in mapping if m.get("match_status") == REL_CONFIRMED)
    chk("infrastructure", "OpenStack inventory reachable",
        PASS if infra.get("collector_status") == S_AVAILABLE else FAIL,
        "openstack_api",
        f"{inst_count} instance(s) found." if inst_count else "OpenStack unreachable.",
        "Cannot verify runtime state without OpenStack inventory.",
        "Ensure OpenStack credentials are loaded (source admin-openrc.sh)." if inst_count == 0 else "")

    chk("infrastructure", "All declared nodes have runtime instances",
        PASS if matched == node_count and node_count > 0 else (WARN if matched > 0 else FAIL),
        "node_mapping",
        f"{matched}/{node_count} declared nodes matched to runtime instances.",
        "Unmapped declared nodes may be undeployed.",
        "Deploy missing nodes or update scenario definition." if matched < node_count else "")

    # Tooling
    by_node = tools.get("by_node") or {}
    failed_nodes = [nid for nid, nd in by_node.items() if nd.get("failed_count", 0) > 0]
    chk("tooling", "No tool installation failures",
        PASS if not failed_nodes else WARN,
        "tools_installer",
        f"{len(failed_nodes)} node(s) with failed tool installations." if failed_nodes else "All tools OK.",
        "Failed tools may affect detection capability.",
        f"Re-install failed tools on: {', '.join(failed_nodes[:3])}." if failed_nodes else "")

    # Attacks executed
    exec_count = attacks.get("total", 0)
    chk("incident_replay", "At least one attack executed",
        PASS if exec_count > 0 else FAIL,
        "attack_outputs",
        f"{exec_count} attack execution(s) found.",
        "No evidence of attack execution — no baseline for replay.",
        "Execute at least one attack via the Attack module." if exec_count == 0 else "")

    # Forensic cases
    case_count = forensics.get("total", 0)
    chk("dfir_workflow", "At least one forensic case created",
        PASS if case_count > 0 else FAIL,
        "evidence_store",
        f"{case_count} forensic case(s) found.",
        "No forensic case available for DFIR replay.",
        "Trigger a forensic investigation after an attack." if case_count == 0 else "")

    sealed_cases = sum(1 for c in (forensics.get("cases") or []) if c.get("sealed"))
    chk("dfir_workflow", "At least one sealed forensic case",
        PASS if sealed_cases > 0 else WARN,
        "evidence_store",
        f"{sealed_cases}/{case_count} case(s) sealed.",
        "Unsealed cases may not be reproducible.",
        "Seal forensic cases after acquisition and analysis." if sealed_cases == 0 else "")

    custody_cases = sum(1 for c in (forensics.get("cases") or []) if c.get("custody_chain_present"))
    chk("case_traceability", "Chain of custody documented",
        PASS if custody_cases > 0 else WARN,
        "evidence_store",
        f"{custody_cases}/{case_count} case(s) with custody chain.",
        "Missing custody chain reduces reproducibility confidence.",
        "Ensure custody log is generated during acquisition." if custody_cases == 0 else "")

    # Campaigns
    b_count = len(campaigns.get("level_b") or [])
    chk("campaign_replay", "At least one Level B campaign present",
        PASS if b_count > 0 else WARN,
        "repetition_campaigns",
        f"{b_count} Level B campaign(s) found.",
        "No Level B statistical repetitions available.",
        "Run a Level B campaign to establish statistical evidence." if b_count == 0 else "")

    # FOC reconstruction
    foc_init = foc.get("initialized", False)
    chk("foc_reconstruction", "FOC reconstruction initialized",
        PASS if foc_init else FAIL,
        "foc_reconstruction_dir",
        "FOC reconstruction present." if foc_init else "FOC reconstruction not initialized.",
        "Cannot compute reproducibility without FOC reconstruction.",
        "Initialize FOC reconstruction from the FOC Reconstruction view." if not foc_init else "")

    chk("paper_traceability", "FOC quality status valid",
        PASS if foc.get("quality_status") in {"valid", "VALID"} else WARN,
        "foc_quality",
        f"FOC quality: {foc.get('quality_status') or 'unknown'}.",
        "Invalid FOC quality may indicate missing evidence.",
        "Review FOC gaps and resolve missing components." if foc.get("quality_status") not in {"valid", "VALID"} else "")

    paper_res = foc.get("paper_repetitions") or {}
    paper_count = paper_res.get("total", 0)
    chk("paper_traceability", "Paper repetition results recorded",
        PASS if paper_count > 0 else WARN,
        "result_registry",
        f"{paper_count} paper result(s) found.",
        "Cannot verify paper traceability without result records.",
        "Record paper repetition results in the result registry." if paper_count == 0 else "")

    # Level C (redeployment)
    c_count = len(campaigns.get("level_c") or [])
    chk("scenario_redeployment", "Level C campaign present",
        PASS if c_count > 0 else S_NOT_IMPLEMENTED,
        "repetition_campaigns",
        f"{c_count} Level C campaign(s) found." if c_count else "Level C not yet implemented.",
        "Scenario redeployment readiness cannot be verified.",
        "Implement Level C campaigns for full redeployment validation." if c_count == 0 else "")

    # Compute readiness flags
    def _domain_pass(domain: str) -> bool:
        domain_checks = [c for c in checks if c["domain"] == domain]
        return all(c["status"] in {PASS, WARN, NA, S_NOT_IMPLEMENTED} for c in domain_checks) and \
               any(c["status"] == PASS for c in domain_checks)

    snapshot_capture_ready = _domain_pass("scenario_definition")
    incident_replay_ready = _domain_pass("incident_replay") and _domain_pass("infrastructure")
    dfir_replay_ready = _domain_pass("dfir_workflow")
    campaign_replay_ready = _domain_pass("campaign_replay")
    paper_traceability_ready = _domain_pass("paper_traceability")
    scenario_redeployment_ready = _domain_pass("scenario_redeployment")
    overall_reproduction_ready = all([
        snapshot_capture_ready,
        incident_replay_ready,
        dfir_replay_ready,
        campaign_replay_ready,
        paper_traceability_ready,
    ]) and not any(c["status"] == FAIL for c in checks)

    passed = sum(1 for c in checks if c["status"] == PASS)
    warnings_count = sum(1 for c in checks if c["status"] == WARN)
    failed = sum(1 for c in checks if c["status"] == FAIL)

    overall_status = PASS if overall_reproduction_ready else (WARN if failed == 0 else FAIL)

    return {
        "overall_status": overall_status,
        "overall_reproduction_ready": overall_reproduction_ready,
        "snapshot_capture_ready": snapshot_capture_ready,
        "incident_replay_ready": incident_replay_ready,
        "dfir_replay_ready": dfir_replay_ready,
        "campaign_replay_ready": campaign_replay_ready,
        "paper_traceability_ready": paper_traceability_ready,
        "scenario_redeployment_ready": scenario_redeployment_ready,
        "checks": checks,
        "summary": {
            "passed": passed,
            "warnings": warnings_count,
            "failed": failed,
            "total": len(checks),
        },
    }


# ---------------------------------------------------------------------------
# Node health cache (fast, no SSH)
# ---------------------------------------------------------------------------

PROBE_CACHE_DIR = PROJECT_ROOT / "runtime" / "node_health" / "probe_cache"


def _detect_fuxa_from_probe(probe: dict) -> str:
    """
    FUXA runs as a Node.js process, not as a named systemd service.
    Check: 1) systemd service 'fuxa', 2) process list, 3) docker container.
    Returns the service status string.
    """
    services = probe.get("services") or {}
    # Direct systemd entry
    if "fuxa" in services:
        return services["fuxa"]
    # Check process tables: top_cpu and top_mem contain process names
    sections = probe.get("sections") or {}
    for table_key in ("top_cpu", "top_mem"):
        for line in (sections.get(table_key) or []):
            if "FUXA" in line or "fuxa" in str(line).lower():
                return "active (process)"
    # Check docker containers if docker is active
    if services.get("docker") == "active":
        for table_key in ("top_cpu", "top_mem"):
            for line in (sections.get(table_key) or []):
                if "npm" in str(line).lower() and "start" in str(line).lower():
                    return "active (npm/docker)"
    return S_NOT_AVAILABLE


def _collect_node_health_cache(instances: list, warnings: list) -> dict:
    """Read node health probe cache (no live SSH). Captures OS, services, resource state."""
    by_node: dict = {}
    for inst in instances:
        iid = inst.get("instance_id", "")
        name = inst.get("name", "")

        cached = _load_json(PROBE_CACHE_DIR / f"{iid}.json") if iid else None
        if not isinstance(cached, dict):
            by_node[iid or name] = {
                "instance_id": iid, "instance_name": name,
                "status": S_NOT_AVAILABLE, "source": "no_cache",
                "services": {}, "tools_running": {},
            }
            continue

        probe = cached.get("probe") or {}
        identity = probe.get("identity") or {}
        services = probe.get("services") or {}
        cpu = probe.get("cpu") or {}
        mem = probe.get("memory") or {}
        disk = probe.get("disk") or {}

        by_node[iid or name] = {
            "instance_id": iid, "instance_name": name,
            "cached_at": cached.get("generated_at"),
            "source": "probe_cache", "status": "CACHE_AVAILABLE",
            "identity": {
                "hostname": identity.get("hostname"),
                "os": identity.get("os"),
                "kernel": identity.get("kernel"),
                "machine": identity.get("machine"),
                "uptime": identity.get("uptime"),
            },
            "services": {
                "suricata": services.get("suricata", S_NOT_AVAILABLE),
                "wazuh_agent": services.get("wazuh-agent", S_NOT_AVAILABLE),
                "wazuh_manager": services.get("wazuh-manager", S_NOT_AVAILABLE),
                "docker": services.get("docker", S_NOT_AVAILABLE),
                "openplc": services.get("openplc", S_NOT_AVAILABLE),
                "fuxa": _detect_fuxa_from_probe(probe),
            },
            "resources": {
                "cpu_cores": cpu.get("cores"),
                "cpu_usage_pct": cpu.get("usage_pct"),
                "cpu_severity": cpu.get("severity"),
                "mem_total_mb": mem.get("total_mb"),
                "mem_avail_mb": mem.get("available_mb"),
                "mem_usage_pct": mem.get("usage_pct"),
                "mem_severity": mem.get("severity"),
                "disk_root_use_pct": disk.get("root_use_pct"),
                "disk_root_avail_bytes": disk.get("root_avail_bytes"),
                "disk_severity": disk.get("severity"),
                "suricata_log_size_bytes": disk.get("suricata_log_size_bytes"),
            },
            "live_verification": None,  # populated by verify_nodes_live()
        }

    return {
        "collector_status": S_AVAILABLE if by_node else S_NOT_AVAILABLE,
        "by_node": by_node,
        "live_verified": False,
        "live_verified_at": None,
    }


def verify_nodes_live(snapshot_id: str) -> dict:
    """
    SSH into each node and run tooling probe to verify actual tool presence,
    Suricata rules, and Wazuh configuration. Updates the snapshot in place.
    """
    snap_path = SNAPSHOTS_ROOT / snapshot_id / "snapshot_manifest.json"
    snapshot = _load_json(snap_path)
    if not isinstance(snapshot, dict):
        return {"error": "snapshot_not_found"}

    try:
        from app_core.infrastructure.node_health.node_health_api import (
            _build_tooling_payload, _inventory_nodes_from_health_cache,
        )
    except Exception as exc:
        return {"error": f"node_health_api unavailable: {exc}"}

    instances = (snapshot.get("infrastructure") or {}).get("instances") or []
    cache_nodes = _inventory_nodes_from_health_cache()
    cache_by_id = {n.get("id"): n for n in cache_nodes}

    node_verification = snapshot.setdefault("node_verification", {})
    by_node = node_verification.get("by_node") or {}

    verified_at = _utc_now()
    errors: list = []

    for inst in instances:
        iid = inst.get("instance_id", "")
        name = inst.get("name", "")

        # Build node dict expected by _build_tooling_payload
        cache_node = cache_by_id.get(iid, {})
        node_dict = {
            "id": iid,
            "name": name,
            "role": cache_node.get("role", "unknown"),
            "status": inst.get("status", "UNKNOWN"),
            "ssh_target_ip": inst.get("ip_floating") or inst.get("ip_private") or inst.get("ip"),
        }
        if not node_dict["ssh_target_ip"]:
            by_node.setdefault(iid or name, {})["live_verification"] = {
                "status": "SKIPPED",
                "reason": "No reachable IP address for SSH",
                "verified_at": verified_at,
            }
            continue

        try:
            payload = _build_tooling_payload(node_dict)
            runtime = payload.get("runtime") or {}
            runtime_error = payload.get("runtime_error")

            tools_merged = []
            for t in (payload.get("inventory") or {}).get("tools") or []:
                tools_merged.append({
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "declared_status": t.get("status"),
                    "runtime_presence": t.get("runtime_presence"),
                    "runtime_status": t.get("runtime_status"),
                    "runtime_version": t.get("runtime_version"),
                    "verified": t.get("runtime_presence") == "yes",
                })

            suricata_rules = (runtime.get("suricata") or {}).get("parsed_rules") or []
            wazuh_fim = (runtime.get("wazuh") or {}).get("fim_paths") or []
            wazuh_local_rules = (runtime.get("wazuh") or {}).get("local_rules") or []

            sur = runtime.get("suricata") or {}
            waz = runtime.get("wazuh") or {}
            verification = {
                "status": "VERIFIED" if not runtime_error else "PARTIAL",
                "verified_at": verified_at,
                "error": runtime_error,
                "tools": tools_merged,
                "suricata": {
                    "rules_count": len(suricata_rules),
                    "rules": suricata_rules,
                    "active_rule_files": sur.get("active_rule_files") or [],
                    "custom_signatures": sur.get("custom_signatures") or [],
                    "rule_inventory": sur.get("rule_inventory") or [],
                    "rule_contents": sur.get("rule_contents") or [],
                    "config_summary": sur.get("config_summary") or [],
                },
                "wazuh": {
                    "fim_paths": wazuh_fim,
                    "local_rules_present": bool(wazuh_local_rules),
                    "local_rules": wazuh_local_rules,
                    "local_decoders": waz.get("local_decoders") or [],
                    "rule_inventory": waz.get("rule_inventory") or [],
                    "rule_contents": waz.get("rule_contents") or [],
                    "config_summary": waz.get("config_summary") or [],
                },
            }
        except Exception as exc:
            verification = {
                "status": "FAILED",
                "verified_at": verified_at,
                "error": {"message": str(exc)},
            }
            errors.append(f"Node {name}: {exc}")

        by_node.setdefault(iid or name, {})["live_verification"] = verification

    node_verification.update({
        "live_verified": True,
        "live_verified_at": verified_at,
        "by_node": by_node,
        "verification_errors": errors,
    })
    snapshot["node_verification"] = node_verification

    # Recompute hash
    snapshot_str = json.dumps({k: v for k, v in snapshot.items() if k != "hashes"},
                               sort_keys=True, default=str)
    snapshot.setdefault("hashes", {})["snapshot_hash"] = _sha256_str(snapshot_str)

    tmp = snap_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(snap_path)
    return {"status": "OK", "verified_at": verified_at, "nodes_verified": len(by_node), "errors": errors}


# ---------------------------------------------------------------------------
# Network configuration collector (OpenStack)
# ---------------------------------------------------------------------------

def _collect_network_config(warnings: list) -> dict:
    """Read OpenStack network topology: networks, subnets, routers, security groups, FIPs."""
    result: dict = {
        "collector_status": S_NOT_AVAILABLE,
        "networks": [], "subnets": [], "routers": [],
        "security_groups": [], "floating_ips": [],
    }
    try:
        import openstack
        conn = openstack.connection.Connection(
            auth_url=os.environ.get("OS_AUTH_URL"),
            project_name=os.environ.get("OS_PROJECT_NAME"),
            username=os.environ.get("OS_USERNAME"),
            password=os.environ.get("OS_PASSWORD"),
            region_name=os.environ.get("OS_REGION_NAME"),
            user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
            project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
            identity_interface="public",
        )

        networks = []
        for net in conn.network.networks():
            networks.append({
                "id": net.id, "name": net.name,
                "status": net.status,
                "admin_state_up": getattr(net, "is_admin_state_up", None),
                "shared": getattr(net, "is_shared", None),
                "external": getattr(net, "is_router_external", None),
                "subnet_ids": list(getattr(net, "subnet_ids", None) or []),
            })

        subnets = []
        for sn in conn.network.subnets():
            subnets.append({
                "id": sn.id, "name": sn.name,
                "network_id": sn.network_id,
                "cidr": sn.cidr,
                "gateway_ip": sn.gateway_ip,
                "ip_version": sn.ip_version,
                "dns_nameservers": list(getattr(sn, "dns_nameservers", None) or []),
                "allocation_pools": list(getattr(sn, "allocation_pools", None) or []),
                "enable_dhcp": getattr(sn, "is_dhcp_enabled", None),
            })

        routers = []
        for r in conn.network.routers():
            routers.append({
                "id": r.id, "name": r.name,
                "status": r.status,
                "admin_state_up": getattr(r, "is_admin_state_up", None),
                "external_gateway": getattr(r, "external_gateway_info", None),
            })

        sgs = []
        for sg in conn.network.security_groups():
            rules = []
            for rule in (sg.security_group_rules or []):
                rules.append({
                    "direction": rule.get("direction"),
                    "protocol": rule.get("protocol"),
                    "port_range_min": rule.get("port_range_min"),
                    "port_range_max": rule.get("port_range_max"),
                    "remote_ip_prefix": rule.get("remote_ip_prefix"),
                    "ethertype": rule.get("ethertype"),
                })
            sgs.append({
                "id": sg.id, "name": sg.name,
                "description": getattr(sg, "description", None),
                "rules": rules, "rule_count": len(rules),
            })

        fips = []
        for fip in conn.network.ips():
            fips.append({
                "id": fip.id,
                "floating_ip": fip.floating_ip_address,
                "fixed_ip": fip.fixed_ip_address,
                "status": fip.status,
                "port_id": getattr(fip, "port_id", None),
                "floating_network_id": getattr(fip, "floating_network_id", None),
            })

        result.update({
            "collector_status": S_AVAILABLE,
            "networks": networks, "subnets": subnets,
            "routers": routers, "security_groups": sgs,
            "floating_ips": fips,
            "summary": {
                "network_count": len(networks),
                "subnet_count": len(subnets),
                "router_count": len(routers),
                "security_group_count": len(sgs),
                "floating_ip_count": len(fips),
            },
        })
    except Exception as exc:
        result["error"] = str(exc)
        warnings.append(f"Network config collection failed: {exc}")
    return result


# ---------------------------------------------------------------------------
# Reconstruction procedures
# ---------------------------------------------------------------------------

def _collect_reconstruction_procedures(warnings: list) -> dict:
    """Document exact procedures to build, configure and destroy the scenario."""

    DEPLOY_SCRIPT = PROJECT_ROOT / "app_core" / "infrastructure" / "redeployment_module" / "deploy_scenario_from_json.sh"
    GENERATOR_SCRIPT = PROJECT_ROOT / "scenario" / "main_generator_inicial_openstack.sh"
    DESTROY_SCRIPT = PROJECT_ROOT / "scenario" / "destroy_scenario_openstack_mejorado.sh"
    PLC_CLOUD_INIT = PROJECT_ROOT / "industrial-scenario" / "PLC" / "cloud_init_plc.yaml"
    FUXA_CLOUD_INIT = PROJECT_ROOT / "industrial-scenario" / "FUXA" / "cloud_init_fuxa.yaml"
    MODBUS_SIM = PROJECT_ROOT / "industrial-scenario" / "modbustcp" / "modbustcp_traffic_capture.py"
    INSTALL_DIR = PROJECT_ROOT / "tools-installer" / "scripts-host"
    UNINSTALL_DIR = PROJECT_ROOT / "tools_uninstall_manager" / "uninstall_scripts-host"
    ANSIBLE_SURICATA = PROJECT_ROOT / "ansible" / "suricata-auto" / "playbooks" / "suricata-aio.yml"
    ANSIBLE_WAZUH = PROJECT_ROOT / "ansible" / "wazuh-agent-pro" / "install_agent.yml"

    def _si(path: Path) -> dict:
        exists = path.is_file() or path.is_dir()
        return {
            "path": str(path.relative_to(PROJECT_ROOT)),
            "exists": exists,
            "size_bytes": path.stat().st_size if path.is_file() else None,
            "sha256": _sha256_file(path) if path.is_file() and path.stat().st_size < 2_000_000 else None,
        }

    # Install/uninstall scripts
    install_scripts = []
    if INSTALL_DIR.is_dir():
        for s in sorted(INSTALL_DIR.glob("install_*.sh")):
            tool_name = s.stem.replace("install_", "").replace(" copy", "").replace(" 2", "")
            if tool_name not in {t["tool"] for t in install_scripts}:
                install_scripts.append({"tool": tool_name, "script": str(s.relative_to(PROJECT_ROOT)),
                                        "exists": True, "sha256": _sha256_file(s)})

    uninstall_scripts = []
    if UNINSTALL_DIR.is_dir():
        for s in sorted(UNINSTALL_DIR.glob("uninstall_*.sh")):
            tool_name = s.stem.replace("uninstall_", "")
            uninstall_scripts.append({"tool": tool_name, "script": str(s.relative_to(PROJECT_ROOT)), "exists": True})

    return {
        "collector_status": S_AVAILABLE,
        "snapshot_preservation_policy": {
            "rule": "Snapshots are NEVER automatically deleted during scenario destruction.",
            "reason": "Snapshots are the sole reconstruction blueprint — deleting them would make reproduction impossible.",
            "manual_deletion": "Only explicit user action via 'Delete Snapshot' can remove a snapshot.",
        },
        "it_scenario_construction": {
            "description": "Deploy IT scenario virtual machines on OpenStack from scenario_file.json",
            "input_file": str(SCENARIO_FILE.relative_to(PROJECT_ROOT)),
            "openstack_credentials": "source admin-openrc.sh (OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_PROJECT_NAME, OS_REGION_NAME)",
            "steps": [
                "1. Ensure OpenStack credentials are loaded: source admin-openrc.sh",
                "2. Validate scenario definition: scenario/scenario_file.json — check nodes, flavors, images",
                "3. Execute: bash app_core/infrastructure/redeployment_module/deploy_scenario_from_json.sh",
                "4. Script calls scenario/main_generator_inicial_openstack.sh which creates:",
                "   - OpenStack networks and subnets (net_private_01 / subnet_net_private_01)",
                "   - Security groups with rules",
                "   - SSH key pair (my_key)",
                "   - VM instances per node definition (image, flavor, network, key_name)",
                "5. Post-deployment: platform queries OpenStack API to get assigned IPs (private + floating)",
                "6. Scenario state updated with runtime IP assignments",
            ],
            "scripts": {"deploy": _si(DEPLOY_SCRIPT), "generator": _si(GENERATOR_SCRIPT)},
            "typical_duration_minutes": "3-8 per node depending on image size",
        },
        "ot_node_mounting": {
            "description": "Deploy OT nodes (PLC, SCADA) via OpenStack cloud-init templates",
            "plc": {
                "software": "OpenPLC Runtime (open-source PLC)",
                "protocol": "Modbus TCP port 502",
                "linked_to_node_type": "victim",
                "cloud_init_template": _si(PLC_CLOUD_INIT),
                "steps": [
                    "1. In industrial topology editor, link PLC to target IT node",
                    "2. Click 'Install PLC' — platform creates OpenStack instance with cloud_init_plc.yaml",
                    "3. Cloud-init auto-installs OpenPLC on first boot (~5 min)",
                    "4. Verify: systemctl status openplc on the PLC instance",
                    "5. Update industrial_industrial_file.json: 'openplc_installed': true",
                ],
            },
            "scada": {
                "software": "FUXA SCADA/HMI (Node.js-based)",
                "protocol": "Modbus TCP, REST API port 1881",
                "linked_to_node_type": "victim",
                "cloud_init_template": _si(FUXA_CLOUD_INIT),
                "steps": [
                    "1. In industrial topology editor, link SCADA to target IT node",
                    "2. Click 'Install SCADA' — platform creates OpenStack instance with cloud_init_fuxa.yaml",
                    "3. Cloud-init auto-installs Node.js and FUXA on first boot (~8 min)",
                    "4. Verify: systemctl status fuxa OR docker ps | grep fuxa",
                    "5. Update industrial_industrial_file.json: 'fuxa_installed': true",
                ],
            },
            "traffic_simulator": _si(MODBUS_SIM),
        },
        "detection_system_configuration": {
            "suricata": {
                "description": "Suricata IDS — network threat detection, rule-based",
                "ansible_playbook": _si(ANSIBLE_SURICATA),
                "deployment_method": "Ansible playbook via platform SSH",
                "key_config": {
                    "log_dir": "/var/log/suricata/",
                    "eve_log": "/var/log/suricata/eve.json",
                    "fast_log": "/var/log/suricata/fast.log",
                    "rule_path": "/var/lib/suricata/rules/",
                    "rule_file": "/var/lib/suricata/rules/suricata.rules",
                    "home_net": "[10.0.2.0/24]",
                },
                "rule_reload": "suricatasc -c reload-rules OR systemctl restart suricata",
                "steps": [
                    "1. Platform SSHes to target node",
                    "2. Runs Ansible playbook: ansible/suricata-auto/playbooks/suricata-aio.yml",
                    "3. Ansible installs suricata, configures suricata.yaml, deploys rules",
                    "4. Validates config: suricata -T -c /etc/suricata/suricata.yaml",
                    "5. Starts suricata service",
                ],
            },
            "wazuh": {
                "description": "Wazuh SIEM agent — FIM, log analysis, alerting",
                "ansible_playbook": _si(ANSIBLE_WAZUH),
                "manager_ip": "10.0.2.160",
                "agent_version": "4.7.3-1",
                "key_config": {
                    "config_file": "/var/ossec/etc/ossec.conf",
                    "local_rules": "/var/ossec/etc/rules/local_rules.xml",
                    "local_decoders": "/var/ossec/etc/decoders/local_decoders.xml",
                    "log_dir": "/var/ossec/logs/",
                    "fim_realtime": True,
                },
                "steps": [
                    "1. Platform SSHes to target node",
                    "2. Removes previous Wazuh installation completely",
                    "3. Adds Wazuh GPG key and APT repository",
                    "4. Installs wazuh-agent=4.7.3-1",
                    "5. Configures manager IP in /var/ossec/etc/ossec.conf",
                    "6. Enrolls agent with Wazuh manager (authd)",
                    "7. Starts and enables wazuh-agent service",
                ],
            },
        },
        "tool_management": {
            "description": "Forensic/network tools installed on nodes via SSH scripts",
            "available_tools": install_scripts,
            "uninstall_scripts": uninstall_scripts,
            "install_steps": [
                "1. Select target node in Tools view",
                "2. Choose tool(s) to install",
                "3. Platform SSHes into node and runs install script from tools-installer/scripts-host/",
                "4. Result logged to tools-installer/installed/{instance_id}.json",
                "5. Verify via Node Health > Tooling probe",
            ],
            "uninstall_steps": [
                "1. Select target node in Tools view",
                "2. Choose tool(s) to uninstall",
                "3. Platform SSHes and runs uninstall script from tools_uninstall_manager/uninstall_scripts-host/",
                "4. tools-installer/installed/{instance_id}.json updated",
            ],
        },
        "scenario_destruction": {
            "description": "Destroy all IT and OT scenario infrastructure in OpenStack",
            "script": _si(DESTROY_SCRIPT),
            "what_gets_destroyed": [
                "OpenStack VM instances (all scenario nodes)",
                "OpenStack virtual networks and subnets",
                "OpenStack security groups (scenario-specific)",
                "OpenStack floating IP allocations",
                "OpenStack SSH key pair (if created by platform)",
            ],
            "what_is_PRESERVED": [
                "Forensic evidence: app_core/infrastructure/forensics/evidence_store/",
                "Campaigns: evidence_store/repetition_campaigns/",
                "FOC reconstruction: foc-reconstruction/",
                "Scenario snapshots: runtime/scenario_snapshots/ — NEVER auto-deleted",
                "Scenario definitions: scenario/scenario_file.json, industrial-scenario/",
                "Attack catalog and profiles",
                "Scientific memory and result registries",
                "Platform source code and configuration",
            ],
            "steps": [
                "1. RECOMMENDED: Capture and seal a scenario snapshot before destruction",
                "2. Verify all forensic cases are preserved",
                "3. Verify all campaigns are completed",
                "4. Execute: bash scenario/destroy_scenario_openstack_mejorado.sh",
                "5. Script identifies and deletes: instances, networks, FIPs, security groups",
                "6. Validate: openstack server list (should show empty or non-scenario nodes)",
            ],
            "api_endpoint": "POST /api/foc-experimentation/scenario-destruction/validate",
        },
        "level_c_redeployment": {
            "description": "Full scenario redeployment from snapshot blueprint (Level C validation)",
            "status": S_NOT_IMPLEMENTED,
            "planned_steps": [
                "1. Load sealed scenario snapshot",
                "2. Re-provision OpenStack IT infrastructure from scenario_file.json",
                "3. Re-deploy OT nodes from cloud-init templates",
                "4. Re-install tools using snapshot tool manifests",
                "5. Apply Suricata rules from snapshot node_verification.suricata",
                "6. Apply Wazuh configuration from snapshot node_verification.wazuh",
                "7. Validate infrastructure drift vs original snapshot (node mapping, IPs, services)",
                "8. Execute Level C campaign: replay attack in fresh environment",
                "9. Compare Level C results with Level A/B baseline (CPR, WCPR, detection consistency)",
            ],
            "note": "Level C validates that the experiment is fully reproducible from the snapshot alone, without any shared state from the original run.",
        },
    }


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def _hash_key_files() -> dict:
    """SHA-256 of key canonical files (lightweight files only)."""
    hashes = {}
    targets = [
        ("scenario_file", SCENARIO_FILE),
        ("industrial_scenario_file", INDUSTRIAL_FILE),
        ("foc_manifest", FOC_OUTPUT_DIR / "foc_manifest.json"),
        ("scenario_bom", FOC_OUTPUT_DIR / "scenario_bom.json"),
        ("tools_bom", FOC_OUTPUT_DIR / "tools_bom.json"),
        ("foc_readiness_report", FOC_OUTPUT_DIR / "validation" / "foc_readiness_report.json"),
        ("attack_attestation", FOC_OUTPUT_DIR / "attestations" / "attack_attestation.json"),
        ("detection_attestation", FOC_OUTPUT_DIR / "attestations" / "detection_attestation.json"),
    ]
    for key, path in targets:
        if path.is_file() and path.stat().st_size < 8 * 1024 * 1024:
            hashes[key] = {
                "path": str(path.relative_to(PROJECT_ROOT)),
                "sha256": _sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        else:
            hashes[key] = {
                "path": str(path.relative_to(PROJECT_ROOT)),
                "sha256": None,
                "status": S_NOT_AVAILABLE if not path.is_file() else "SKIPPED_TOO_LARGE",
            }
    return hashes


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _save_snapshot(snapshot: dict) -> Path:
    sid = snapshot["snapshot_id"]
    snap_dir = SNAPSHOTS_ROOT / sid
    snap_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = snap_dir / "snapshot_manifest.json"
    tmp = manifest_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(manifest_path)
    return manifest_path


# ---------------------------------------------------------------------------
# Concurrency guard
# ---------------------------------------------------------------------------

import threading

_capture_lock = threading.Lock()
_capture_in_progress: bool = False

# Single-shot, opt-in test hook for gap_validation's own acquisition_failure
# experiment (app_core/infrastructure/gap_validation/catalog.py -- evaluates
# g17_chaos_engineering_forensic_pipeline, "no reviewed source applies
# chaos-engineering methodology to a forensic pipeline"). No other code path
# ever creates this file -- a normal capture_snapshot() call is completely
# unaffected; this only exists so the acquisition pipeline's OWN failure
# handling can be exercised for real, without touching any real collector.
_FORCE_FAILURE_ONCE_FLAG = PROJECT_ROOT / "runtime" / "gap_validation" / "sandbox" / "force_capture_snapshot_failure_once.flag"


def force_capture_snapshot_failure_once() -> None:
    """Arms the single-shot flag -- the NEXT capture_snapshot() call fails
    immediately (before any real collector runs) and clears this flag the
    moment it consumes it. Calling this twice in a row without an
    intervening capture_snapshot() call is harmless (the flag is just
    re-written)."""
    _FORCE_FAILURE_ONCE_FLAG.parent.mkdir(parents=True, exist_ok=True)
    _FORCE_FAILURE_ONCE_FLAG.write_text("1", encoding="utf-8")


def is_capture_snapshot_failure_armed() -> bool:
    return _FORCE_FAILURE_ONCE_FLAG.is_file()


def disarm_capture_snapshot_failure_once() -> None:
    """Idempotent -- a no-op if nothing is armed."""
    _FORCE_FAILURE_ONCE_FLAG.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def capture_snapshot() -> dict:
    """
    Orchestrate a full snapshot capture.
    Returns the complete snapshot dict.
    Safe to call from any thread.
    """
    global _capture_in_progress

    with _capture_lock:
        if _capture_in_progress:
            return {"status": "ERROR", "error": "Capture already in progress."}
        _capture_in_progress = True

    try:
        if _FORCE_FAILURE_ONCE_FLAG.is_file():
            disarm_capture_snapshot_failure_once()
            return {
                "status": "ERROR",
                "error": "Forced failure (gap_validation acquisition_failure experiment, single-shot -- see force_capture_snapshot_failure_once()).",
            }

        warnings: list = []
        errors: list = []

        sid = _new_snapshot_id()
        started = _utc_now()

        # --- Collectors ---
        scenario = _safe(lambda: _collect_scenario_definition(warnings), "scenario", warnings, errors)
        scenario_nodes = scenario.get("nodes_declared") or []
        scenario_id = scenario.get("scenario_id")

        infra = _safe(lambda: _collect_infrastructure(scenario_nodes, warnings), "infrastructure", warnings, errors)
        instances = infra.get("instances") or []

        tools = _safe(lambda: _collect_tools_state(instances), "tools", warnings, errors)
        node_health = _safe(lambda: _collect_node_health_cache(instances, warnings), "node_health", warnings, errors)
        network_config = _safe(lambda: _collect_network_config(warnings), "network_config", warnings, errors)
        procedures = _safe(lambda: _collect_reconstruction_procedures(warnings), "procedures", warnings, errors)

        attack_catalog = _safe(_collect_attack_catalog, "attack_catalog", warnings, errors)
        attack_executions = _safe(lambda: _collect_attack_executions(warnings), "attack_executions", warnings, errors)
        attacks = {**attack_catalog, **attack_executions}

        forensics = _safe(lambda: _collect_forensics(scenario_id, warnings), "forensics", warnings, errors)
        campaigns = _safe(lambda: _collect_campaigns(warnings), "campaigns", warnings, errors)
        foc = _safe(lambda: _collect_foc_reconstruction(warnings), "foc", warnings, errors)

        relationships = _safe(
            lambda: _build_relationships(attack_executions, forensics, campaigns),
            "relationships", warnings, errors,
        )

        validation = _safe(
            lambda: _validate_readiness(scenario, infra, tools, attack_executions, forensics, campaigns, foc),
            "validation", warnings, errors,
        )

        key_hashes = _safe(_hash_key_files, "hashing", warnings, errors)

        completed = _utc_now()

        # Determine snapshot status
        has_critical_failure = bool(errors) and any(
            s.get("collector_status") == S_COLLECTION_FAILED
            for s in [scenario, infra, forensics]
        )
        if has_critical_failure:
            status = "INCOMPLETE"
        elif warnings:
            status = "COMPLETED_WITH_WARNINGS"
        else:
            status = "COMPLETED"

        snapshot = {
            "snapshot_id": sid,
            "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
            "status": status,
            "captured_at_utc": started,
            "completed_at_utc": completed,
            "collector_version": COLLECTOR_VERSION,
            "sealed": False,
            "scenario": scenario,
            "infrastructure": infra,
            "network_config": network_config,
            "tools": tools,
            "node_verification": node_health,  # will be enriched by verify_nodes_live()
            "attacks": attacks,
            "forensics": forensics,
            "campaigns": campaigns,
            "foc": foc,
            "relationships": relationships,
            "procedures": procedures,
            "validation": validation,
            "provenance": {
                "sources_consulted": [
                    str(SCENARIO_FILE.relative_to(PROJECT_ROOT)),
                    str(INDUSTRIAL_FILE.relative_to(PROJECT_ROOT)),
                    "openstack_api",
                    "openstack_network_api",
                    str(PROBE_CACHE_DIR.relative_to(PROJECT_ROOT)),
                    str(ATTACK_OUTPUTS_DIR.relative_to(PROJECT_ROOT)),
                    str(EVIDENCE_STORE.relative_to(PROJECT_ROOT)),
                    str(CAMPAIGNS_ROOT.relative_to(PROJECT_ROOT)),
                    str(FOC_OUTPUT_DIR.relative_to(PROJECT_ROOT)),
                ],
                "warnings": warnings,
                "errors": errors,
                "warning_count": len(warnings),
                "error_count": len(errors),
            },
            "hashes": {
                "key_files": key_hashes,
                "snapshot_hash": None,
            },
        }

        # Hash the snapshot itself
        snapshot_str = json.dumps(snapshot, sort_keys=True, default=str)
        snapshot["hashes"]["snapshot_hash"] = _sha256_str(snapshot_str)

        _save_snapshot(snapshot)
        return snapshot

    finally:
        with _capture_lock:
            _capture_in_progress = False


def get_capture_status() -> dict:
    with _capture_lock:
        return {"in_progress": _capture_in_progress}


def list_snapshots() -> list[dict]:
    """Return summary of all stored snapshots, newest first."""
    if not SNAPSHOTS_ROOT.is_dir():
        return []
    summaries = []
    for snap_dir in sorted(SNAPSHOTS_ROOT.iterdir(), reverse=True):
        manifest = _load_json(snap_dir / "snapshot_manifest.json")
        if not isinstance(manifest, dict):
            continue
        summaries.append({
            "snapshot_id": manifest.get("snapshot_id"),
            "status": manifest.get("status"),
            "captured_at_utc": manifest.get("captured_at_utc"),
            "completed_at_utc": manifest.get("completed_at_utc"),
            "sealed": manifest.get("sealed", False),
            "scenario_id": (manifest.get("scenario") or {}).get("scenario_id"),
            "scenario_name": (manifest.get("scenario") or {}).get("scenario_name"),
            "overall_ready": (manifest.get("validation") or {}).get("overall_reproduction_ready", False),
            "case_count": (manifest.get("forensics") or {}).get("total", 0),
            "campaign_count": (manifest.get("campaigns") or {}).get("total", 0),
            "warnings": (manifest.get("provenance") or {}).get("warning_count", 0),
            "errors": (manifest.get("provenance") or {}).get("error_count", 0),
        })
    return summaries


def get_snapshot(snapshot_id: str) -> dict | None:
    path = SNAPSHOTS_ROOT / snapshot_id / "snapshot_manifest.json"
    data = _load_json(path)
    return data if isinstance(data, dict) else None


def seal_snapshot(snapshot_id: str) -> dict:
    """Mark a snapshot as sealed (immutable). Returns the updated snapshot."""
    path = SNAPSHOTS_ROOT / snapshot_id / "snapshot_manifest.json"
    snapshot = _load_json(path)
    if not isinstance(snapshot, dict):
        return {"error": "snapshot_not_found"}
    if snapshot.get("sealed"):
        return {"error": "already_sealed"}
    if snapshot.get("status") in {"INCOMPLETE", "FAILED"}:
        return {"error": "cannot_seal_incomplete_snapshot"}
    snapshot["sealed"] = True
    snapshot["sealed_at_utc"] = _utc_now()
    snapshot["status"] = "SEALED"
    # Recompute hash
    snapshot_str = json.dumps({k: v for k, v in snapshot.items() if k != "hashes"},
                               sort_keys=True, default=str)
    snapshot.setdefault("hashes", {})["snapshot_hash"] = _sha256_str(snapshot_str)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)
    return snapshot


def export_snapshot(snapshot_id: str) -> dict:
    """Return the full snapshot for download."""
    return get_snapshot(snapshot_id) or {"error": "snapshot_not_found"}


def delete_snapshot(snapshot_id: str) -> dict:
    """
    Permanently delete a snapshot. Sealed snapshots require explicit confirmation.
    Returns {deleted: True} or {error: ...}.
    """
    import shutil
    snap_dir = SNAPSHOTS_ROOT / snapshot_id
    if not snap_dir.is_dir():
        return {"error": "snapshot_not_found"}
    snap = _load_json(snap_dir / "snapshot_manifest.json") or {}
    if snap.get("sealed"):
        return {"error": "cannot_delete_sealed", "message": "Sealed snapshots cannot be deleted. Unseal first or pass force=true."}
    try:
        shutil.rmtree(snap_dir)
        return {"deleted": True, "snapshot_id": snapshot_id}
    except Exception as exc:
        return {"error": str(exc)}


def delete_snapshot_force(snapshot_id: str) -> dict:
    """Delete even a sealed snapshot — use with extreme caution."""
    import shutil
    snap_dir = SNAPSHOTS_ROOT / snapshot_id
    if not snap_dir.is_dir():
        return {"error": "snapshot_not_found"}
    try:
        shutil.rmtree(snap_dir)
        return {"deleted": True, "snapshot_id": snapshot_id, "forced": True}
    except Exception as exc:
        return {"error": str(exc)}


def diff_snapshots(id_a: str, id_b: str) -> dict:
    """High-level diff between two snapshots."""
    a = get_snapshot(id_a)
    b = get_snapshot(id_b)
    if not a:
        return {"error": f"snapshot {id_a} not found"}
    if not b:
        return {"error": f"snapshot {id_b} not found"}

    def _count(snap: dict, path: list) -> Any:
        cur = snap
        for key in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
        return cur

    return {
        "snapshot_a": id_a,
        "snapshot_b": id_b,
        "captured_a": a.get("captured_at_utc"),
        "captured_b": b.get("captured_at_utc"),
        "diff": {
            "scenario_name": {
                "a": _count(a, ["scenario", "scenario_name"]),
                "b": _count(b, ["scenario", "scenario_name"]),
            },
            "node_count": {
                "a": len(_count(a, ["scenario", "nodes_declared"]) or []),
                "b": len(_count(b, ["scenario", "nodes_declared"]) or []),
            },
            "instance_count": {
                "a": len(_count(a, ["infrastructure", "instances"]) or []),
                "b": len(_count(b, ["infrastructure", "instances"]) or []),
            },
            "attack_execution_count": {
                "a": _count(a, ["attacks", "total"]) or 0,
                "b": _count(b, ["attacks", "total"]) or 0,
            },
            "forensic_case_count": {
                "a": _count(a, ["forensics", "total"]) or 0,
                "b": _count(b, ["forensics", "total"]) or 0,
            },
            "campaign_count": {
                "a": _count(a, ["campaigns", "total"]) or 0,
                "b": _count(b, ["campaigns", "total"]) or 0,
            },
            "validation_status": {
                "a": _count(a, ["validation", "overall_status"]),
                "b": _count(b, ["validation", "overall_status"]),
            },
            "overall_reproduction_ready": {
                "a": _count(a, ["validation", "overall_reproduction_ready"]),
                "b": _count(b, ["validation", "overall_reproduction_ready"]),
            },
            "snapshot_hash": {
                "a": _count(a, ["hashes", "snapshot_hash"]),
                "b": _count(b, ["hashes", "snapshot_hash"]),
            },
        },
    }
