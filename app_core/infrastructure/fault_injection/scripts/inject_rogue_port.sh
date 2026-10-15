#!/bin/bash
# Rogue listening port (MITRE ATT&CK for ICS T0848 "Rogue Master"). Opens a
# real TCP listener on an unused port for a bounded window using python3
# (already present on every node in this lab), tracked by a dedicated pidfile
# so revert_rogue_port.sh can always find and kill the exact same process.
set -u
PORT="${PORT:-8765}"
DURATION_SECONDS="${DURATION_SECONDS:-60}"
PIDFILE="/tmp/fault_injection_rogue_port.pid"

nohup python3 -m http.server "${PORT}" --bind 0.0.0.0 >/tmp/fault_injection_rogue_port.log 2>&1 &
PID=$!
echo "$PID" > "$PIDFILE"
disown

nohup bash -c "sleep ${DURATION_SECONDS}; kill ${PID} 2>/dev/null; rm -f '${PIDFILE}'" >/tmp/fault_injection_rogue_port_cleanup.log 2>&1 &
disown
echo "FAULT_INJECTION_APPLIED port=${PORT} pid=${PID} duration_seconds=${DURATION_SECONDS}"
exit 0
