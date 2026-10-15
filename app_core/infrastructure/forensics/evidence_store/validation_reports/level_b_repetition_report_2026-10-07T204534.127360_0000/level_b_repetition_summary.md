# Level B Repetition Report

- Generated at: `2026-10-07T23:59:53.258826+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `3a0a8948a1b6f684462cd789`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `1`
- Nested Level A repetitions per Level B case: `10`
- Completed repetitions: `0`
- Partial repetitions: `1`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Not Comparable`
- Comparison type: `exploratory_comparison_only`
- Compared executions: `EXEC-0001, EXEC-0002`

## Nested Level A Repeatability

- Completed nested reports: `1`
- Failed nested reports: `0`
- Nested comparison statuses: `Comparable With Degradation`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `82.287` / `0.0`
- Alert -> memory preserved mean/std: `691.832` / `0.0`
- Alert -> case sealed mean/std: `1185.308` / `0.0`
- Total duration mean/std: `3929.078` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.75` / `0.0`
- Weighted recoverability mean/std: `0.7397` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `2`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0002`
- Case ID: `case-3dfbd95c`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20261007T204540Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Comparable With Degradation` / `direct_level_a_repeatability_comparison`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.75` / `0.7397` / `0.7822`
- Relations recovered/degraded/ambiguous/missing: `6` / `0` / `2` / `0`
- Alert -> memory start: `82.287` seconds
- Alert -> case sealed: `1185.308` seconds
- Total repetition duration: `3929.078` seconds
- Warnings: `6 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here. | This was the final repetition of the campaign -- case case-3dfbd95c was kept fully intact as a complete result sample instead of being reduced to the lightweight bundle.`
