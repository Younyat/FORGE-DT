#!/bin/bash
# Exact revert: restores the real backup inject_config_tamper.sh saved --
# never reconstructs or guesses at original content.
set -u
BACKUP_PATH="/tmp/fault_injection_config_tamper.bak"
MARKER_PATH="/tmp/fault_injection_config_tamper.path"
if [ ! -f "$MARKER_PATH" ] || [ ! -f "$BACKUP_PATH" ]; then
  echo "FAULT_INJECTION_ERROR: no active config_tamper marker/backup found on this node"
  exit 10
fi
REAL_PATH="$(cat "$MARKER_PATH")"
sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 11; }
sudo -n cp -p "$BACKUP_PATH" "$REAL_PATH"
rm -f "$BACKUP_PATH" "$MARKER_PATH"
echo "FAULT_INJECTION_REVERTED path=${REAL_PATH}"
exit 0
