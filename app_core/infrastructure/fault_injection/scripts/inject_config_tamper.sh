#!/bin/bash
# Config/rule file tampering (MITRE ATT&CK for ICS T0809 "Data Destruction").
# Appends one harmless, clearly-marked line to an already-tracked Suricata
# rule file or Wazuh config file, after saving a real backup copy -- this is
# a direct test of forensic_twin's own config-integrity sensor
# (check_config_integrity), not a new sensor. Reverted by restoring the
# exact backup, never by guessing at the original content.
set -u
TARGET_FILE="${TARGET_FILE:-suricata_rules}"
BACKUP_PATH="/tmp/fault_injection_config_tamper.bak"
MARKER_PATH="/tmp/fault_injection_config_tamper.path"

case "$TARGET_FILE" in
  suricata_rules) REAL_PATH="/var/lib/suricata/rules/suricata.rules" ;;
  wazuh_ossec_conf) REAL_PATH="/var/ossec/etc/ossec.conf" ;;
  *) echo "FAULT_INJECTION_ERROR: unknown target_file '${TARGET_FILE}'"; exit 10 ;;
esac

if [ ! -f "$REAL_PATH" ]; then
  echo "FAULT_INJECTION_ERROR: ${REAL_PATH} does not exist on this node"
  exit 11
fi
sudo -n true >/dev/null 2>&1 || { echo "FAULT_INJECTION_ERROR: sudo -n not available on this node"; exit 12; }

sudo -n cp -p "$REAL_PATH" "$BACKUP_PATH"
echo "$REAL_PATH" > "$MARKER_PATH"
echo "# fault_injection config_tamper marker $(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo -n tee -a "$REAL_PATH" >/dev/null
echo "FAULT_INJECTION_APPLIED path=${REAL_PATH} backup=${BACKUP_PATH}"
exit 0
