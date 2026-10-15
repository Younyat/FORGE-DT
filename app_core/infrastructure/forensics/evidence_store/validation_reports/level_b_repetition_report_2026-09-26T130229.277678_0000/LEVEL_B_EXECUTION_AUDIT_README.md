# Level B Execution Audit

## Executive Summary

- Campaign ID: `CMP-20260707-000220-CBFB`
- Requested Level B repetitions: `3`
- Attempted repetitions: `3`
- Not-started repetitions: `0`
- Completed / partial / failed: `0` / `3` / `0`
- Job status: `running`

## Where The Workflow Stopped

- Phase: `Generate Level B report`
- Detail: `Aggregating per-repetition timing, acquisition, reconstruction, warnings, blockers, and case outputs into the final Level B validation report bundle.`

## Generated Outputs

- Level B execution workspaces: `EXEC-0058, EXEC-0059, EXEC-0060`
- Forensic cases created: `case-662f99fc, case-601eda86, case-66dc197c`
- Cases with analysis outputs present: `case-662f99fc, case-601eda86, case-66dc197c`
- Nested Level A reports completed: `CMP-20260926-132934-E2D3, CMP-20260926-151254-FD4B, CMP-20260926-170501-DD55`
- Heavy-case cleanups completed: `case-662f99fc, case-601eda86, case-66dc197c`
- Final Level B report bundle emitted: `True`

## Missing Or Pending Outputs

- Remaining Level B repetitions not started: `0`
- Missing nested Level A reports: `0`
- Missing heavy-case cleanups: `0`
- Higher-level comparison ready: `False`

## Reviewer-Facing Interpretation

This audit distinguishes between physical preservation success and full Level B scientific completion. A preserved case may already contain memory, disk, network, alerts, and partial or complete analysis outputs while the orchestration still fails before nested Level A, cleanup, or cross-run comparison complete.

## Expected Professional End State

For a successful Level B batch, every requested repetition should create a fresh case, complete multilayer analysis, complete nested Level A reporting, clean the heavy case while retaining a lightweight bundle, and then continue to the next repetition until the batch report can compare all runs.
