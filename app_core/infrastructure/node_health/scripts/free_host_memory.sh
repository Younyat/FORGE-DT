#!/usr/bin/env bash
# ============================================================
# Frees LOCAL, RECLAIMABLE OS memory on THIS host -- the OpenStack
# controller / gunicorn server itself, never any of the scenario's
# SSH-probed VMs (those are a completely separate, unrelated code path).
#
# Deliberately limited to what the Linux kernel documents as always safe
# to drop: page cache, dentries and inodes. Nothing here deletes files,
# stops processes, or touches swap -- swap needs enough free RAM to hold
# what gets paged back in, so it stays a manual, confirmed action (see
# node_health/README.md for the exact swapoff/swapon commands).
# ============================================================
set -euo pipefail

# Probe sentinel (same pattern as acquire_disk_kolla_libvirt.sh): lets the
# sudoers rule be verified with a clean exit-code=0, without running the
# real cleanup.
if [[ "${1:-}" == "__nics_probe__" ]]; then
  exit 0
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  # /bin/bash explicit to match the Cmnd_Alias rule in
  # /etc/sudoers.d/nicscyberlab-free-host-memory:
  #   Cmnd_Alias NICS_FREE_HOST_MEMORY = /bin/bash <this_script> *
  sudo -n /bin/bash "$0" "$@" || {
    echo "[ERROR] Freeing host memory requires non-interactive sudo/root privileges."
    echo "[ERROR] Install the NOPASSWD sudoers rule (see node_health/README.md) and retry."
    exit 77
  }
  exit 0
fi

echo "[INFO] free -m before:"
free -m || true

echo "[INFO] sync"
sync

echo "[INFO] Dropping page cache, dentries and inodes (rebuilt on demand, no data deleted)"
echo 1 > /proc/sys/vm/drop_caches

echo "[INFO] free -m after:"
free -m || true

echo "[INFO] Done."
