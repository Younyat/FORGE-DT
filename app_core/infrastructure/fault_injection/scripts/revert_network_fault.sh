#!/bin/bash
# Exact revert: the inverse tc command to inject_network_fault.sh.
set -u

sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 10; }

IFACE="$(ip route | awk '/default/ {print $5; exit}')"
if [ -z "$IFACE" ]; then
  echo "FAULT_INJECTION_ERROR: could not resolve default network interface"
  exit 11
fi

sudo -n tc qdisc del dev "$IFACE" root >/dev/null 2>&1
rc=$?
echo "FAULT_INJECTION_REVERTED iface=${IFACE} rc=${rc}"
exit 0
