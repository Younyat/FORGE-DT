#!/bin/bash
# Time-bounded detection omission (Hsueh, Tsai, Iyer 1997 -- omission/timing
# fault category). Targets whichever REAL detection/SIEM service this
# platform already recognizes is actually active on this node -- the same
# two unit names forensic_twin/service.py::SERVICE_TOOL_TO_UNIT checks
# (suricata, wazuh-manager). Never assumes a single specific tool: a real
# scenario deployment can have either installed. Found and fixed
# 2026-10-14 against a real monitor node running only Wazuh (no Suricata
# at all installed) -- the previous Suricata-only version of this script
# refused to apply there ("suricata service not active before injection"),
# scoring a false zero-coverage result for gap_validation's
# service_interruption experiment, for a real mechanism that does work,
# just under a different service name.
set -u
DURATION_SECONDS="${DURATION_SECONDS:-60}"

sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 10; }

SERVICE=""
for svc in suricata wazuh-manager; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        SERVICE="$svc"
        break
    fi
done

if [ -z "$SERVICE" ]; then
    echo "FAULT_INJECTION_ERROR: no known detection service (suricata, wazuh-manager) active before injection, refusing to proceed"
    exit 13
fi

sudo -n systemctl stop "$SERVICE"
rc=$?
echo "FAULT_INJECTION_APPLIED service=${SERVICE} duration_seconds=${DURATION_SECONDS} stop_rc=${rc}"
exit $rc
