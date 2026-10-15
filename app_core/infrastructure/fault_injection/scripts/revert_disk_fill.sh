#!/bin/bash
# Exact revert: deletes the one, dedicated file inject_disk_fill.sh ever
# creates. Safe to run even if the safety-net timeout already deleted it.
set -u
FILL_PATH="/tmp/fault_injection_disk_fill.bin"
rm -f "$FILL_PATH"
echo "FAULT_INJECTION_REVERTED path=${FILL_PATH}"
exit 0
