#!/bin/bash
# Exact revert: kills the one, pidfile-tracked listener inject_rogue_port.sh
# started. Safe to run even if the safety-net timeout already killed it.
set -u
PIDFILE="/tmp/fault_injection_rogue_port.pid"
if [ -f "$PIDFILE" ]; then
  PID="$(cat "$PIDFILE")"
  kill "$PID" 2>/dev/null || true
  rm -f "$PIDFILE"
fi
echo "FAULT_INJECTION_REVERTED"
exit 0
