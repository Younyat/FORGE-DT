#!/bin/bash
# Latency/packet loss via tc/netem -- a classic, reversible-by-design
# technique (Hemminger, "Network Emulation with NetEm", 2005).
set -u
DELAY_MS="${DELAY_MS:-200}"
LOSS_PCT="${LOSS_PCT:-10}"

sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 10; }

IFACE="$(ip route | awk '/default/ {print $5; exit}')"
if [ -z "$IFACE" ]; then
  echo "FAULT_INJECTION_ERROR: could not resolve default network interface"
  exit 11
fi

sudo -n tc qdisc del dev "$IFACE" root >/dev/null 2>&1 || true
sudo -n tc qdisc add dev "$IFACE" root netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
rc=$?
echo "FAULT_INJECTION_APPLIED iface=${IFACE} delay_ms=${DELAY_MS} loss_pct=${LOSS_PCT} rc=${rc}"
exit $rc
