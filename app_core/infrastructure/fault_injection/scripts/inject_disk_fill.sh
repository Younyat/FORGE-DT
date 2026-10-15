#!/bin/bash
# Bounded disk-space exhaustion (same resource-exhaustion category as
# inject_cpu_stress.sh: Basiri et al., Chaos Engineering, IEEE Software 2016).
# Fills a dedicated, always-known file path up to TARGET_PCT of root
# filesystem usage -- never beyond it, never if already at/above it (a safe
# no-op in that case, never pushes a node to 100%). Explicit revert via
# revert_disk_fill.sh deletes the exact same path; a background safety-net
# also self-deletes it after DURATION_SECONDS in case nobody reverts.
set -u
TARGET_PCT="${TARGET_PCT:-85}"
DURATION_SECONDS="${DURATION_SECONDS:-60}"
FILL_PATH="/tmp/fault_injection_disk_fill.bin"

read -r total used avail pct <<< "$(df -P / | awk 'NR==2 {gsub("%","",$5); print $2, $3, $4, $5}')"
if [ -z "${total:-}" ]; then
  echo "FAULT_INJECTION_ERROR: could not read df output for /"
  exit 10
fi
if [ "$pct" -ge "$TARGET_PCT" ]; then
  echo "FAULT_INJECTION_APPLIED path=${FILL_PATH} skipped=already_at_or_above_target current_pct=${pct} target_pct=${TARGET_PCT}"
  exit 0
fi

# total/used/avail are in 1K blocks (df -P default) -- convert the target
# into a byte count relative to TOTAL capacity, then subtract what is
# already used, so the file brings usage up to (not past) TARGET_PCT.
target_used_kb=$(( total * TARGET_PCT / 100 ))
fill_kb=$(( target_used_kb - used ))
if [ "$fill_kb" -le 0 ]; then
  echo "FAULT_INJECTION_APPLIED path=${FILL_PATH} skipped=target_not_above_current current_pct=${pct} target_pct=${TARGET_PCT}"
  exit 0
fi
if [ "$fill_kb" -gt "$avail" ]; then
  fill_kb=$avail
fi

fallocate -l "${fill_kb}K" "$FILL_PATH" 2>/dev/null || dd if=/dev/zero of="$FILL_PATH" bs=1K count="$fill_kb" >/dev/null 2>&1
if [ ! -f "$FILL_PATH" ]; then
  echo "FAULT_INJECTION_ERROR: could not create fill file at ${FILL_PATH}"
  exit 11
fi

nohup bash -c "sleep ${DURATION_SECONDS}; rm -f '${FILL_PATH}'" >/tmp/fault_injection_disk_fill_cleanup.log 2>&1 &
disown
echo "FAULT_INJECTION_APPLIED path=${FILL_PATH} fill_kb=${fill_kb} target_pct=${TARGET_PCT} duration_seconds=${DURATION_SECONDS}"
exit 0
