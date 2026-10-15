# Level B Repetition Report

- Generated at: `2026-10-10T16:14:07.619038+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `3a0a8948a1b6f684462cd789`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `1`
- Nested Level A repetitions per Level B case: `1`
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
- Nested comparison statuses: `Insufficient Data`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `87.176` / `0.0`
- Alert -> memory preserved mean/std: `657.815` / `0.0`
- Alert -> case sealed mean/std: `1721.23` / `0.0`
- Total duration mean/std: `4965.852` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.625` / `0.0`
- Weighted recoverability mean/std: `0.6233` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `1`
- Missing relations total: `2`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0002`
- Case ID: `case-9c310aa4`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20261010T140305Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `completed`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Insufficient Data` / `not_enough_generated_level_a_repetitions`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.625` / `0.6233` / `0.7414`
- Relations recovered/degraded/ambiguous/missing: `5` / `0` / `1` / `2`
- Alert -> memory start: `87.176` seconds
- Alert -> case sealed: `1721.23` seconds
- Total repetition duration: `4965.852` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | One or more expected causal edges remain missing because required preserved evidence is unavailable or not linked. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | 33605 alert correlation record(s) matched this attack TYPE, but none fell within 3600s of this case's own real intervention trigger time -- not citing an unrelated historical correlation as if it were this case's. | This was the final repetition of the campaign -- case case-9c310aa4 was kept fully intact as a complete result sample instead of being reduced to the lightweight bundle.`
