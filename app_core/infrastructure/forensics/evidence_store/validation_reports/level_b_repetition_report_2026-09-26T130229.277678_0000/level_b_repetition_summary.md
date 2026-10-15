# Level B Repetition Report

- Generated at: `2026-09-26T18:08:40.727150+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `3a0a8948a1b6f684462cd789`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `3`
- Nested Level A repetitions per Level B case: `10`
- Completed repetitions: `0`
- Partial repetitions: `3`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Insufficient Data`
- Comparison type: `not_available`
- Compared executions: `EXEC-0001, EXEC-0002, EXEC-0003, EXEC-0004, EXEC-0005, EXEC-0006, EXEC-0007, EXEC-0008, EXEC-0009, EXEC-0010, EXEC-0020, EXEC-0021, EXEC-0022, EXEC-0023, EXEC-0029, EXEC-0032, EXEC-0033, EXEC-0034, EXEC-0035, EXEC-0039, EXEC-0040, EXEC-0041, EXEC-0042, EXEC-0043, EXEC-0044, EXEC-0055, EXEC-0057, EXEC-0058, EXEC-0059, EXEC-0060`

## Nested Level A Repeatability

- Completed nested reports: `3`
- Failed nested reports: `0`
- Nested comparison statuses: `Comparable With Degradation, Comparable With Degradation, Comparable With Degradation`

## Aggregate Timing Metrics

- `N_B`: `3`
- Alert -> memory start mean/std: `39.793667` / `9.101653`
- Alert -> memory preserved mean/std: `607.470667` / `25.022033`
- Alert -> case sealed mean/std: `1738.257` / `148.780547`
- Total duration mean/std: `1848.772` / `202.499346`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.0` / `0.0`
- Weighted recoverability mean/std: `0.0` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `0`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0058`
- Case ID: `case-662f99fc`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260926T130237Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `completed`
- Reconstruction status: `blocked_missing_analysis`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Comparable With Degradation` / `direct_level_a_repeatability_comparison`
- Previous heavy case cleaned before next repetition: `skipped`
- Recoverability / weighted / confidence: `None` / `None` / `None`
- Relations recovered/degraded/ambiguous/missing: `None` / `None` / `None` / `None`
- Alert -> memory start: `50.018` seconds
- Alert -> case sealed: `1566.723` seconds
- Total repetition duration: `1614.999` seconds
- Warnings: `Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Semantic reconstruction has not been generated. | Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-0059`
- Case ID: `case-601eda86`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260926T144001Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `completed`
- Reconstruction status: `blocked_missing_analysis`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Comparable With Degradation` / `direct_level_a_repeatability_comparison`
- Previous heavy case cleaned before next repetition: `skipped`
- Recoverability / weighted / confidence: `None` / `None` / `None`
- Relations recovered/degraded/ambiguous/missing: `None` / `None` / `None` / `None`
- Alert -> memory start: `32.575` seconds
- Alert -> case sealed: `1832.253` seconds
- Total repetition duration: `1969.974` seconds
- Warnings: `Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Semantic reconstruction has not been generated. | Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 3

- Execution ID: `EXEC-0060`
- Case ID: `case-66dc197c`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260926T163218Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `completed`
- Reconstruction status: `blocked_missing_analysis`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Comparable With Degradation` / `direct_level_a_repeatability_comparison`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `None` / `None` / `None`
- Relations recovered/degraded/ambiguous/missing: `None` / `None` / `None` / `None`
- Alert -> memory start: `36.788` seconds
- Alert -> case sealed: `1815.795` seconds
- Total repetition duration: `1961.343` seconds
- Warnings: `Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Semantic reconstruction has not been generated. | Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis. | This was the final repetition of the campaign -- case case-66dc197c was kept fully intact as a complete result sample instead of being reduced to the lightweight bundle.`
