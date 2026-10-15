#!/bin/bash
# Time-bounded CPU/RAM exhaustion (Chaos Engineering: Basiri et al., IEEE
# Software 2016). Self-terminates via --timeout -- never needs a separate
# revert step. Launched in the background (nohup) so the SSH connection can
# close without killing the stress run midway.
set -u
DURATION_SECONDS="${DURATION_SECONDS:-60}"
WORKERS="${WORKERS:-2}"

if ! command -v stress-ng >/dev/null 2>&1; then
  sudo -n true >/dev/null 2>&1 && sudo -n apt-get install -y stress-ng >/dev/null 2>&1
fi
if ! command -v stress-ng >/dev/null 2>&1; then
  echo "FAULT_INJECTION_ERROR: stress-ng not available and could not be installed"
  exit 12
fi

nohup stress-ng --cpu "${WORKERS}" --vm "${WORKERS}" --vm-bytes 256M --timeout "${DURATION_SECONDS}s" >/tmp/fault_injection_cpu_stress.log 2>&1 &
disown
echo "FAULT_INJECTION_APPLIED workers=${WORKERS} duration_seconds=${DURATION_SECONDS} pid=$!"
exit 0
