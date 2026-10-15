# FORGE-VI Level C — CPR Edge Matrix Interpretation

**Campaign:** `CMP-20261010-101053-B301`  
**Paper level:** Level C (provisional — using Level B standing-scenario repetitions)  
**Executions accepted:** 2/6  
**Generated:** 2026-10-10T16:14:53Z

---

## Aggregate CPR

| Metric | Value |
|--------|-------|
| Expected causal edges | 8 |
| Recovered edges | 7 |
| Degraded edges | 0 |
| Missing edges | 0 |
| Ambiguous edges | 1 |
| CPR | 0.875 (= 7/8) |
| Weighted CPR | 0.8767 |
| Recoverability | mostly_recoverable |
| Reconstruction confidence | 0.8777 |
| CPR stable across runs | True (identical in all 2 runs) |

---

## Per-Edge Status

| Edge | State | Temporal | Meaning |
|------|-------|----------|---------|
| `edge_attack_execution_to_ot_write` | ✅ recovered | supported | Attack Execution → OT Modbus Write |
| `edge_ot_write_to_network_modbus_write` | ✅ recovered | not_required | OT Modbus Write → Observable Network Traffic |
| `edge_network_modbus_write_to_detection_surface` | ✅ recovered | supported | Network Modbus Write → Detection Surface |
| `edge_ot_write_to_plc_state_observation` | ✅ recovered | not_required | OT Modbus Write → PLC State Observation |
| `edge_detection_surface_to_alert_observation` | 🔶 ambiguous | ambiguous | Detection Surface → Alert Observation |
| `edge_alert_observation_to_forensic_case` | ✅ recovered | supported | Alert Observation → Forensic Case |
| `edge_forensic_case_to_preserved_case_evidence` | ✅ recovered | supported | Forensic Case → Preserved Case Evidence |
| `edge_preserved_case_evidence_to_multilayer_analysis` | ✅ recovered | supported | Preserved Case Evidence → Multilayer Analysis |

---

## Scientific Interpretation

The system demonstrates partial causal recoverability (CPR=0.5). The attack→OT write→network→PLC chain is fully recovered (4 edges). The detection chain is degraded (2 edges) due to unresolved UTC temporal links between network traffic and alert observation. The alert→intervention→case→evidence chain is broken (2 edges missing) because `forensic_intervention.json` does not carry the `trigger_alert_id → case_id` causal link as an explicit artifact field.

### What this means for the paper

- **Recovered (4/8):** Attack execution, OT traffic, PLC state observation, multilayer analysis — all confirmed with artifact references.
- **Degraded (2/8):** Detection surface and alert observation — evidence present but temporal UTC resolution incomplete.
- **Missing (2/8):** Alert→case and case→evidence causal links — artifacts exist but forensic_intervention.json does not create the explicit causal chain.
- **CPR=0.5 is stable** across all 6 runs: the structural limitation is in the artifact design, not in execution variability.

### To improve CPR to 6/8 (CPR=0.75)

1. **Resolve degraded edges:** Normalize `detection_observed_at_utc` and `network_event_observed_at_utc` in `normalized_causal_timestamps.json`. No rerun required.
2. **Resolve missing edges:** Add `trigger_alert_id`, `alert_timestamp`, `case_id`, and `preserved_case_directory` to `forensic_intervention.json`. No rerun required; artifacts already exist.

### To improve CPR to 8/8 (CPR=1.0)

Implement a pre-run validation gate that records `detection_observed_at_utc` directly from the sensor pipeline and update `forensic_intervention.json` schema in the acquisition runner.

---

## Level C Manual Completion

The following fields are not available from the current Level B campaign and require manual completion or a real Level C redeployment campaign:

- `teardown_completed` — Level B uses a standing scenario
- `redeploy_completed` — no redeployment between runs
- `deployment_time_s` / `redeployment_time_s` — not applicable
- `validation_time_s` — no pre-run gate with timing exists

These fields are marked `not_applicable` or `not_available_from_current_campaign` in all paper exports. They do not block the CPR computation or the paper report.