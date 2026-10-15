#!/bin/bash
# Introduces a real, bounded clock offset. Run via
# node_health_api._run_remote_script_capture (bash -s over stdin, SSH
# already established). Same preflight pattern as time_sync_preflight.sh: if
# passwordless sudo isn't available, fail cleanly instead of half-doing it.
#
# Stops chrony FIRST -- a real bug found live: this node runs chrony
# continuously, and chrony's own default burst-correction behavior
# (makestep, allowed for its first few corrections) re-steps a sudden large
# jump within its next poll cycle, almost always inside a few seconds --
# faster than any SSH-based measurement (fault_injection's own before/after
# snapshot included) can round-trip. Confirmed live: a real apply/revert
# showed the offset already back near zero in the very first "after_apply"
# reading. Stopping the service that would otherwise immediately undo the
# fault is the same principle a real anti-forensic timestamp-tampering
# attacker would need (suppress time sync before tampering, e.g. MITRE
# ATT&CK T1070.006 "Indicator Removal: Timestomp"), not an invented step --
# revert_clock_skew.sh already re-enables/starts chrony, this was simply
# never paired with a stop on the inject side.
set -u
OFFSET_SECONDS="${OFFSET_SECONDS:-120}"

sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 10; }

sudo -n systemctl stop chrony >/dev/null 2>&1 || true

echo "FAULT_INJECTION_BEFORE date=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
sudo -n date -u -s "@$(($(date -u +%s) + OFFSET_SECONDS))" >/dev/null 2>&1
rc=$?
echo "FAULT_INJECTION_AFTER date=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) offset_requested_seconds=${OFFSET_SECONDS} apply_rc=${rc}"
exit $rc
