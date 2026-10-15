# Level B Repetition Report

- Generated at: `2026-09-22T15:58:09.878580+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `not_available`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `1`
- Nested Level A repetitions per Level B case: `1`
- Completed repetitions: `0`
- Partial repetitions: `0`
- Failed repetitions: `1`

## Higher-Level Level B Comparability

- Comparison status: `Not Comparable`
- Comparison type: `exploratory_comparison_only`
- Compared executions: `EXEC-0001, EXEC-0002, EXEC-0003, EXEC-0004, EXEC-0005, EXEC-0006, EXEC-0007, EXEC-0008, EXEC-0009, EXEC-0010, EXEC-0020, EXEC-0021, EXEC-0022, EXEC-0023, EXEC-0029, EXEC-0032, EXEC-0033, EXEC-0034, EXEC-0035, EXEC-0039, EXEC-0040, EXEC-0041, EXEC-0042, EXEC-0043, EXEC-0044`

## Nested Level A Repeatability

- Completed nested reports: `0`
- Failed nested reports: `0`
- Nested comparison statuses: `not_available`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `0.0` / `0.0`
- Alert -> memory preserved mean/std: `0.0` / `0.0`
- Alert -> case sealed mean/std: `0.0` / `0.0`
- Total duration mean/std: `19.365` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.0` / `0.0`
- Weighted recoverability mean/std: `0.0` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `0`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0045`
- Case ID: `not_created`
- Status: `failed`
- Scientific case status: `diagnostic_failed`
- Attack output: `app_core/infrastructure/attack/outputs/20260922T155729Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `10`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `False`
- Memory / network / disk acquisition: `skipped` / `skipped` / `skipped`
- Analysis status: `failed`
- Reconstruction status: `failed`
- Nested Level A status: `not_available`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `None` / `None` / `None`
- Relations recovered/degraded/ambiguous/missing: `0` / `0` / `0` / `0`
- Alert -> memory start: `None` seconds
- Alert -> case sealed: `None` seconds
- Total repetition duration: `19.365` seconds
- Warnings: `Forensic preservation was never armed because DFIR mode remained OFF during the repeated attack attempts. Alerts may have been observed, but the platform was not in forensic intervention mode.`
- Blockers: `dfir_mode_off_during_trigger_arming`
