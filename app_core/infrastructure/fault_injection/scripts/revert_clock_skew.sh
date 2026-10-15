#!/bin/bash
# Real revert: the SAME corrective call already used by
# tools-installer/scripts-host/host_clock_sync.sh and
# app_core/infrastructure/forensics/scripts/time_sync_preflight.sh -- never a
# separately invented revert.
set -u

sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 10; }

sudo -n systemctl enable --now chrony >/dev/null 2>&1 || sudo -n systemctl start chrony >/dev/null 2>&1 || true
sudo -n chronyc -a makestep >/dev/null 2>&1
rc=$?
echo "FAULT_INJECTION_REVERTED date=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) makestep_rc=${rc}"
exit $rc
