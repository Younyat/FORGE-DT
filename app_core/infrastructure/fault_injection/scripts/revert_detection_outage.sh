#!/bin/bash
# Exact revert: restarts whichever known detection/SIEM service this
# platform recognizes (suricata, wazuh-manager -- same two names as
# forensic_twin/service.py::SERVICE_TOOL_TO_UNIT and inject_detection_outage.sh)
# is installed on this host but not currently active. Revert scripts run
# with no parameters (fault_injection/service.py::revert_fault calls them
# with an empty env, by design -- confirmed by reading that function
# before writing this), so this can't be told which one the matching
# apply call stopped; instead it starts whichever known unit exists here
# and isn't active, which is always exactly the one that was stopped --
# nothing else in this platform ever stops these services on its own, and
# forensic_twin's own continuous monitor expects them always active
# outside of a deliberate, bounded fault window like this one.
set -u

sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 10; }

started=""
for svc in suricata wazuh-manager; do
    if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 && ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        sudo -n systemctl start "$svc"
        rc=$?
        echo "FAULT_INJECTION_REVERTED service=${svc} start_rc=${rc} active_now=$(systemctl is-active ${svc} 2>/dev/null)"
        started="$svc"
        [ "$rc" -ne 0 ] && exit $rc
    fi
done

if [ -z "$started" ]; then
    echo "FAULT_INJECTION_REVERT_NOOP: no known detection service found inactive to revert (nothing to do, or already running)"
fi
exit 0
