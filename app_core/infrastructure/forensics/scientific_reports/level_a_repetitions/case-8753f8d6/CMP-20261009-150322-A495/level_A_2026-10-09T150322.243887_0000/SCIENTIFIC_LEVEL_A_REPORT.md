# Level A Scientific Report

- Generated at: `2026-10-09T15:03:22.243887+00:00`
- Campaign ID: `CMP-20261009-150322-A495`
- Anchor execution ID: `EXEC-0001`
- Requested dry-run repetitions: `1`
- Generated dry-run repetitions: `EXEC-0001`
- Preserved case ID: `case-8753f8d6`
- Report directory: `app_core/infrastructure/forensics/scientific_reports/level_a_repetitions/case-8753f8d6/CMP-20261009-150322-A495/level_A_2026-10-09T150322.243887_0000`

## Executive scientific summary

This report audits a Level A repetition campaign over the same preserved case. It launched the same `Run Dry-Run Execution` scientific backend path **1** times against the same preserved evidence set in read-only mode, then consolidated those outputs into one auditable report. The preserved case shows **15 / 15** analysis layers with useful output, a causal recovery of **7 / 8** expected relations, and a repeatability comparison status of **Insufficient Data**.

The scientific position is therefore limited but defensible: the Level A repetition shows stable analytical behavior over the preserved case, while causal completeness remains partial where alert-to-intervention, intervention-to-preservation, timestamp ordering, or packet-level Modbus specificity are not fully supported.

## Level A repetition scope

- Same preserved case: yes
- Same preserved evidence set: yes
- Same dry-run scientific path launched several times: `1` repetition(s)
- New attack launched: no
- New scenario execution: no
- New heavy preservation: no
- Scientific purpose: verify analytical repeatability over preserved evidence, not universal reproducibility.

### Generated Level A dry-run executions

- Repetition 1: `EXEC-0001`

This workflow is equivalent to pressing `Run Dry-Run Execution` several times from the Level A campaign and then generating one consolidated scientific report from those fresh repetitions.

## Preserved case identity

- Case ID: `case-8753f8d6`
- Scenario ID: `scn-b83dbbfb`
- Source case name: `CASE-20261009-133733`
- Summary status: `current`
- Integrity status: `completed`
- Case-wide integrity ratio: `0.9905`

## Evidence inventory

- Evidence available: `True`
- Available layers: `network, memory, disk, ot_exports, alerts, chain_of_custody, time_sync`
- Inventory summary: `{'acquisition_profile': 1, 'alert_json': 1, 'case_digest': 15, 'critical_evidence_gate': 1, 'custody_log': 15, 'disk_metadata': 3, 'disk_raw': 3, 'disk_sha256_file': 3, 'evidence_inventory': 1, 'forensic_intervention': 1, 'industrial_ot_export_modbus_tcp': 1, 'integrity_custody_report': 1, 'ir_input': 669, 'ir_snapshot': 1, 'memory_lime': 3, 'memory_metadata': 3, 'memory_sha256_file': 3, 'network_context_manifest': 1, 'network_pcap': 9, 'normalized_causal_timestamps': 1, 'time_sync': 2, 'trigger_alert_binding': 1}`

## Multilayer analysis results

- Execution status: `completed`
- Analysis confidence: `strong`
- Layers completed: `15` / `15`
- Useful output layers: `15`
- Main limitation: `Semantic reconstruction has not been generated.`

## Memory analysis results

- Memory dumps analyzed: `3`
- Interpretation: memory analysis completed and produced reusable Volatility-based outputs for the preserved dumps included in this case.

## Network analysis results

- PCAPs analyzed: `9`
- Modbus specificity summary: `The evidence supports the presence of Modbus/TCP activity toward the PLC. However, register-level and value-level causal precision remain partial because packet-level parsing does not fully confirm all Modbus parameters.`
- Packet-level limitation: `Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.`

## Disk analysis results

- Disk images analyzed: `3`
- Interpretation: disk analysis completed and contributed preserved filesystem and bodyfile outputs to the unified timeline and causal reconstruction.

## OT analysis results

- OT files analyzed: `1`
- OT evidence position: `partial`
- OT limitation: `function code, register, value, and OT state relation.`

## Alert and trigger analysis

- Alerts summarized: `1`
- Selected trigger: `NICS CyberLab ICS Modbus write multiple registers`
- Trigger source: `alert`
- Trigger selection method: `fallback_prior_alert`
- Trigger limitation: The operational acquisition trigger must not be treated as complete causal proof of the OT incident path.

## Timeline reconstruction

- Timeline entries: `227`
- Cross-layer findings: `1`

### Narrative storyline

- story step: Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.
- story step: Packet-level re-check failed: timeout.
- story step: IDS signature name asserts a write; not confirmed at packet level (see network layer counter-evidence).
- story step: OT export record counts confirm export activity but contain no setpoint or process-value content.
- story step: Case-wide manifest validation is partial (0.9905); some artifacts remain hash-unvalidated.
- story step: IDS signature name asserts a write; not confirmed at packet level (see network layer counter-evidence).
- story step: Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.

## Causal reconstruction results

- Causal status: `completed_with_degradation`
- Expected causal edges: `8`
- Recovered causal edges: `7`
- Degraded causal edges: `not_available`
- Missing causal edges: `not_available`
- CPR: `0.875`
- Weighted CPR: `0.8767`
- Reconstruction confidence: `0.8776`
- Causal interpretation confidence: `limited`
- Main limitation: `At least one causal edge is temporally ambiguous under the preserved uncertainty window.`

### Recovered, degraded, and missing relations

- `edge_attack_execution_to_ot_write`: status=`recovered` | reason=`All required evidence (attack_attestation, network_modbus_observation) is present, temporal order is supported, graph-scope integrity is verified.`
- `edge_ot_write_to_network_modbus_write`: status=`recovered` | reason=`All required evidence (network_modbus_observation) is present, temporal order is not_required, graph-scope integrity is verified.`
- `edge_network_modbus_write_to_detection_surface`: status=`recovered` | reason=`All required evidence (attack_attestation, detection_attestation) is present, temporal order is supported, graph-scope integrity is verified.`
- `edge_ot_write_to_plc_state_observation`: status=`recovered` | reason=`All required evidence (plc_state_observation) is present, temporal order is not_required, graph-scope integrity is verified.`
- `edge_detection_surface_to_alert_observation`: status=`ambiguous` | reason=`No degradation reason was recorded.`
- `edge_alert_observation_to_forensic_case`: status=`recovered` | reason=`All required evidence (alert_correlation, forensic_intervention) is present, temporal order is supported, graph-scope integrity is verified.`
- `edge_forensic_case_to_preserved_case_evidence`: status=`recovered` | reason=`All required evidence (forensic_intervention, case_manifest_link, manifest, chain_of_custody) is present, temporal order is supported, graph-scope integrity is verified.`
- `edge_preserved_case_evidence_to_multilayer_analysis`: status=`recovered` | reason=`All required evidence (manifest, chain_of_custody, forensic_analysis_report, analysis_visual_summary, memory_analysis_useful) is present, temporal order is supported, graph-scope integrity is verified.`

## Hypothesis support results

- Global support level: `moderate_support`
- Final claimability status: `the hypothesis can receive moderate support, not absolute causality.`
- Main limitation: `Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.`

## Level A repeatability and comparison results

- Comparison status: `Insufficient Data`
- Comparison type: `not_enough_generated_level_a_repetitions`
- Max |ΔCPR|: `not_available`
- Max |ΔWCPR|: `not_available`
- Max support-rank shift: `not_available`

## Evidence-to-claim audit table

| Claim ID | Status | Confidence | Claim |
| --- | --- | --- | --- |
| `CLAIM-LEVELA-SCOPE-READONLY` | `supported` | `strong` | This report is a Level A reanalysis of the same preserved case and does not represent a new attack, new scenario execution, or new heavy preservation event. |
| `CLAIM-LEVELA-MULTILAYER-COMPLETED` | `supported` | `strong` | The preserved case has complete multilayer analytical coverage with useful outputs across the expected layers. |
| `CLAIM-LEVELA-NETWORK-MODBUS` | `partial` | `moderate` | Network evidence confirms Modbus/TCP activity, but the current extraction layer does not fully prove packet-level register and value precision. |
| `CLAIM-LEVELA-MEMORY-COMPLETED` | `supported` | `strong` | Memory analysis completed successfully and produced reusable Volatility-based outputs for all preserved dumps included in this case. |
| `CLAIM-LEVELA-TRIGGER-LIMITATION` | `partial` | `moderate` | The operational acquisition trigger is not a complete causal proof of the OT incident path and must be interpreted separately from OT causal evidence. |
| `CLAIM-LEVELA-ALERT-INTERVENTION-PRESERVATION-CHAIN` | `partial` | `limited` | The alert-to-intervention-to-preservation chain is not fully proven by the preserved artifacts in this case. |
| `CLAIM-LEVELA-CAUSAL-PARTIAL` | `partial` | `moderate` | The causal reconstruction is partial rather than complete: some expected causal relations were recovered, some remain degraded, and some remain missing. |
| `CLAIM-LEVELA-HYPOTHESIS-MODERATE` | `partial` | `moderate` | The reconstructed incident hypothesis currently receives moderate support, not absolute causality. |
| `CLAIM-LEVELA-CPR-STABLE` | `unsupported` | `moderate` | This Level A repetition can be compared with previous Level A executions using CPR and Weighted CPR drift metrics derived from the generated comparison profiles. |

## Limitations and degraded states

- Semantic reconstruction has not been generated.
- At least one causal edge is temporally ambiguous under the preserved uncertainty window.
- Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable.
- Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.
- 1 causal edges remain temporally ambiguous under the current uncertainty window.
- Case-wide integrity remains partial.

## Scientific conclusion

The preserved evidence supports a partial causal-forensic reconstruction of a controlled OT incident. The evidence processing coverage is strong because the multilayer analysis completed and produced useful outputs across 15 layers. The causal reconstruction recovered 7 of 8 expected causal relations and degraded 0 relations due to partial or inferred evidence. The hypothesis receives moderate support, not strong support. Causal temporal ordering confidence is limited, case-wide integrity status is partial, and the stated Modbus/trigger limitations remain. The normalized Evidence Support Extract assesses the controlling hypothesis as moderate support.

The correct scientific interpretation for this Level A run is therefore:

The preserved case provides strong evidence preservation and complete multilayer analytical coverage. The Level A repetition shows stable analytical repeatability over the same preserved case. However, the causal reconstruction remains partial where alert-to-intervention, intervention-to-preservation, or Modbus register/value confirmation are not fully supported by the available evidence.

## Source files used for this report

- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/03_network/network_findings.json` | network_analysis | role: network_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/04_memory/memory_findings.json` | memory_analysis | role: memory_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/05_disk/disk_findings.json` | disk_analysis | role: disk_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/06_ot/ot_findings.json` | ot_analysis | role: ot_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/07_alerts/alert_findings.json` | alerts_analysis | role: alerts_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/09_timeline/unified_forensic_timeline.json` | timeline_analysis | role: timeline_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/10_findings/cross_layer_findings.json` | cross_layer_findings | role: cross_layer_findings extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/forensic_analysis_report.json` | analysis_report | role: multilayer analysis completeness and layer outputs
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/analysis/visual/analysis_visual_summary.json` | analysis_visual_summary | role: layer usefulness and indexed outputs
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/chain_of_custody.log` | chain_of_custody | role: custody validation and preservation linkage
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/evidence_support/claimability_report.json` | claimability_report | role: supported, partial, unsupported claim structure
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/evidence_support/counter_evidence_report.json` | counter_evidence_report | role: contradictions and counter-evidence review
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/evidence_support/forensic_storyline.json` | forensic_storyline | role: semantic readable storyline
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/evidence_support/hypothesis_support_report.json` | hypothesis_support | role: hypothesis support and claimability evaluation
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/executive/evidence_lifecycle_summary.json` | evidence_lifecycle_summary | role: evidence_lifecycle_summary extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/reconstruction/causal_graph.json` | causal_graph | role: edge-level causal audit and degraded/missing relation review
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/reconstruction/causal_status.json` | causal_status | role: causal reconstruction status
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/reconstruction/reconstruction_metrics.json` | causal_metrics | role: causal recovery metrics
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/derived/reconstruction/uncertainty_report.json` | uncertainty_report | role: temporal and integrity uncertainty interpretation
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/manifest.json` | case_manifest | role: case identity and preserved artifact inventory
- `app_core/infrastructure/forensics/evidence_store/CASE-20261009-133733/metadata/time_sync.json` | time_sync_metadata | role: time_sync_metadata extraction
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20261009-150322-A495/level_A/EXEC-0001/analysis_repeatability_profile.json` | analysis_repeatability_profile | role: Level A repeatability metrics
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20261009-150322-A495/level_A/EXEC-0001/forensic_comparison_profile.json` | comparison_profile | role: Level A execution comparison profile
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20261009-150322-A495/level_A/EXEC-0001/forensic_result_card.json` | forensic_result_card | role: lightweight Level A result card
