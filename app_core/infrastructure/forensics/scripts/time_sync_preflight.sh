#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
OPENRC="${OPENRC:-$PROJECT_ROOT/admin-openrc.sh}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/my_key}"
SSH_USERS_DEFAULT=("ubuntu" "debian")
SSH_TIMEOUT="${SSH_TIMEOUT:-6}"
FILTER_STATUS="${FILTER_STATUS:-ACTIVE}"
PREFERRED_IP_PREFIX="${PREFERRED_IP_PREFIX:-10.0.2.}"
DO_FIX_TIME="${DO_FIX_TIME:-0}"
TIME_SYNC_THRESHOLD_MS="${TIME_SYNC_THRESHOLD_MS:-1000}"
TIME_SYNC_DEGRADED_THRESHOLD_MS="${TIME_SYNC_DEGRADED_THRESHOLD_MS:-5000}"
CASE_ID="${CASE_ID:-}"
TIME_SYNC_OUT="${TIME_SYNC_OUT:-}"
TIME_SYNC_BEFORE_OUT="${TIME_SYNC_BEFORE_OUT:-}"
TIME_SYNC_AFTER_OUT="${TIME_SYNC_AFTER_OUT:-}"
FILTER_INSTANCE_ID="${FILTER_INSTANCE_ID:-}"
FILTER_INSTANCE_NAME="${FILTER_INSTANCE_NAME:-}"

die(){ echo "[ERROR] $*" >&2; exit 1; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Falta comando: $1"; }
py_num_or_none(){ local value="${1:-}"; [[ -n "$value" ]] && printf '%s' "$value" || printf 'None'; }

usage() {
  cat <<'EOF'
Usage:
  bash app_core/infrastructure/forensics/scripts/time_sync_preflight.sh [--case-id CASE-*] [--out PATH] [--fix-time] [--threshold-ms N] [--instance-id UUID]

Safe mode is the default:
  DO_FIX_TIME=0

Correction mode is explicit:
  DO_FIX_TIME=1 SSH_KEY="$HOME/.ssh/my_key" bash app_core/infrastructure/forensics/scripts/time_sync_preflight.sh --case-id CASE-YYYY...

Environment variables still supported:
  SSH_KEY
  DO_FIX_TIME
  TIME_SYNC_OUT
  TIME_SYNC_BEFORE_OUT
  TIME_SYNC_AFTER_OUT
  TIME_SYNC_THRESHOLD_MS
  TIME_SYNC_DEGRADED_THRESHOLD_MS
  FILTER_STATUS
  PREFERRED_IP_PREFIX
  FILTER_INSTANCE_ID
  FILTER_INSTANCE_NAME
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case-id)
      CASE_ID="${2:-}"; shift 2 ;;
    --out)
      TIME_SYNC_OUT="${2:-}"; shift 2 ;;
    --fix-time)
      DO_FIX_TIME="1"; shift ;;
    --threshold-ms)
      TIME_SYNC_THRESHOLD_MS="${2:-}"; shift 2 ;;
    --status-filter)
      FILTER_STATUS="${2:-}"; shift 2 ;;
    --ip-prefix)
      PREFERRED_IP_PREFIX="${2:-}"; shift 2 ;;
    --instance-id)
      FILTER_INSTANCE_ID="${2:-}"; shift 2 ;;
    --instance-name)
      FILTER_INSTANCE_NAME="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "Argumento no reconocido: $1" ;;
  esac
done

default_time_sync_out() {
  if [[ -n "$CASE_ID" ]]; then
    echo "$PROJECT_ROOT/app_core/infrastructure/forensics/evidence_store/$CASE_ID/metadata/time_sync.json"
  else
    echo "$PROJECT_ROOT/runtime/time_sync/latest_time_sync.json"
  fi
}

if [[ -z "$TIME_SYNC_OUT" ]]; then
  TIME_SYNC_OUT="$(default_time_sync_out)"
fi

OUT_DIR="$(cd "$(dirname "$TIME_SYNC_OUT")" && pwd -P 2>/dev/null || dirname "$TIME_SYNC_OUT")"
mkdir -p "$OUT_DIR"
if [[ -z "$TIME_SYNC_BEFORE_OUT" ]]; then
  TIME_SYNC_BEFORE_OUT="$OUT_DIR/time_sync_before.json"
fi
if [[ -z "$TIME_SYNC_AFTER_OUT" ]]; then
  TIME_SYNC_AFTER_OUT="$OUT_DIR/time_sync_after.json"
fi
NODE_LOG_DIR="$OUT_DIR/time_sync_logs"
mkdir -p "$NODE_LOG_DIR"
export CASE_ID FILTER_STATUS PREFERRED_IP_PREFIX DO_FIX_TIME TIME_SYNC_THRESHOLD_MS TIME_SYNC_DEGRADED_THRESHOLD_MS FILTER_INSTANCE_ID FILTER_INSTANCE_NAME

extract_preferred_ipv4() {
  local addrs="$1" pref="$2"
  local ip_pref
  ip_pref="$(echo "$addrs" | grep -Eo "(${pref//./\\.})([0-9]{1,3})" | head -n 1 || true)"
  [[ -n "$ip_pref" ]] && { echo "$ip_pref"; return 0; }
  echo "$addrs" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1 || true
}

ssh_run() {
  local user="$1" ip="$2" cmd="$3"
  ssh -i "$SSH_KEY" \
    -o BatchMode=yes \
    -o ConnectTimeout="$SSH_TIMEOUT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$user@$ip" "$cmd"
}

pick_ssh_user() {
  local ip="$1"
  local users=("${SSH_USERS_DEFAULT[@]}")
  if [[ -n "${SSH_USERS:-}" ]]; then
    IFS=',' read -r -a users <<< "${SSH_USERS}"
  fi
  local u
  for u in "${users[@]}"; do
    if ssh_run "$u" "$ip" "true" >/dev/null 2>&1; then
      echo "$u"; return 0
    fi
  done
  echo ""
}

chrony_exists() {
  # Real bug found live: this only checked whether the chronyc BINARY was
  # installed, not whether the chronyd DAEMON was actually running and
  # reachable. With the daemon stopped (e.g. fault_injection's
  # inject_clock_skew.sh now deliberately stops it so an injected offset
  # isn't instantly self-corrected), `chronyc tracking` fails, but this
  # function still reported "chrony available" -- so the script kept
  # retrying the chrony-based measurement and never fell back to
  # measure_offset_fallback (the plain SSH-epoch comparison, which doesn't
  # need chronyd at all), ending in a reported "unknown"/no-offset failure
  # even while a real, measurable clock offset existed. Now checks that
  # chronyc can actually talk to the daemon, not just that the binary
  # exists.
  local user="$1" ip="$2"
  ssh_run "$user" "$ip" "command -v chronyc >/dev/null 2>&1 && chronyc tracking >/dev/null 2>&1" >/dev/null 2>&1
}

install_and_enable_chrony() {
  local user="$1" ip="$2"
  local cmd='
set -e
sudo -n true >/dev/null 2>&1 || exit 10
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get update -y
sudo -n apt-get install -y chrony
sudo -n systemctl enable --now chrony
'
  ssh_run "$user" "$ip" "$cmd" >/dev/null 2>&1
}

start_chrony() {
  local user="$1" ip="$2"
  ssh_run "$user" "$ip" "sudo -n systemctl enable --now chrony >/dev/null 2>&1 || sudo -n systemctl start chrony >/dev/null 2>&1 || true" >/dev/null 2>&1
}

makestep_and_restart() {
  local user="$1" ip="$2"
  local makestep_rc restart_rc
  ssh_run "$user" "$ip" "sudo -n chronyc -a makestep >/dev/null 2>&1" >/dev/null 2>&1; makestep_rc=$?
  ssh_run "$user" "$ip" "sudo -n systemctl restart chrony >/dev/null 2>&1 || true" >/dev/null 2>&1; restart_rc=$?
  ssh_run "$user" "$ip" "sleep 3" >/dev/null 2>&1 || true
  echo "$makestep_rc $restart_rc"
}

capture_remote_logs() {
  local user="$1" ip="$2" prefix="$3"
  ssh_run "$user" "$ip" "chronyc tracking 2>/dev/null || true" > "${prefix}.tracking.txt" 2>/dev/null || true
  ssh_run "$user" "$ip" "chronyc sources -v 2>/dev/null || true" > "${prefix}.sources.txt" 2>/dev/null || true
  ssh_run "$user" "$ip" "timedatectl status 2>/dev/null || true" > "${prefix}.timedatectl.txt" 2>/dev/null || true
}

measure_offset_chrony() {
  local user="$1" ip="$2"
  local line
  line="$(ssh_run "$user" "$ip" "chronyc tracking 2>/dev/null | grep -E '^System time'" 2>/dev/null || true)"
  [[ -n "$line" ]] || { echo "FAIL no_system_time"; return 0; }
  local sec sign offset_ms abs_ms
  sec="$(echo "$line" | awk '{print $4}')"
  sign="+"
  echo "$line" | tr '[:upper:]' '[:lower:]' | grep -q "slow" && sign="-"
  offset_ms="$(awk -v s="$sec" -v sign="$sign" 'BEGIN{v=s*1000.0; if(sign=="-") v=-v; printf "%.3f", v}')"
  abs_ms="$(awk -v v="$offset_ms" 'BEGIN{a=v; if(a<0) a=-a; printf "%.3f", a}')"
  echo "OK $offset_ms $abs_ms"
}

remote_epoch_seconds() {
  local user="$1" ip="$2"
  ssh_run "$user" "$ip" "python3 -c 'import time; print(\"%.6f\" % time.time())' 2>/dev/null || date -u +%s.%N 2>/dev/null || date -u +%s" 2>/dev/null || true
}

measure_offset_fallback() {
  local user="$1" ip="$2"
  local host_before host_after remote_epoch midpoint offset_ms abs_ms jitter_ms
  host_before="$(python3 -c 'import time; print("%.6f" % time.time())' 2>/dev/null || true)"
  remote_epoch="$(remote_epoch_seconds "$user" "$ip")"
  host_after="$(python3 -c 'import time; print("%.6f" % time.time())' 2>/dev/null || true)"
  [[ -n "$host_before" && -n "$remote_epoch" && -n "$host_after" ]] || { echo "FAIL no_system_time"; return 0; }
  midpoint="$(awk -v a="$host_before" -v b="$host_after" 'BEGIN{printf "%.6f", (a+b)/2.0}')"
  offset_ms="$(awk -v r="$remote_epoch" -v m="$midpoint" 'BEGIN{printf "%.3f", (r-m)*1000.0}')"
  abs_ms="$(awk -v v="$offset_ms" 'BEGIN{a=v; if(a<0) a=-a; printf "%.3f", a}')"
  jitter_ms="$(awk -v a="$host_before" -v b="$host_after" 'BEGIN{printf "%.3f", (b-a)*1000.0}')"
  echo "OK $offset_ms $abs_ms $jitter_ms"
}

append_node_json() {
  local file="$1"; shift
  NODE_JSON_PAYLOAD="$*" python3 - "$file" <<'PY'
import json, os, sys
path = sys.argv[1]
payload = json.loads(os.environ["NODE_JSON_PAYLOAD"])
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
PY
}

need_cmd openstack
need_cmd ssh
need_cmd awk
need_cmd grep
need_cmd python3

[[ -f "$OPENRC" ]] || die "No encuentro $OPENRC"
[[ -f "$SSH_KEY" ]] || die "No encuentro SSH_KEY=$SSH_KEY"
# shellcheck disable=SC1090
source "$OPENRC"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
BEFORE_JSONL="$TMPDIR/before.jsonl"
AFTER_JSONL="$TMPDIR/after.jsonl"
FINAL_JSONL="$TMPDIR/final.jsonl"
FAILURES_JSONL="$TMPDIR/failures.jsonl"

echo "[INFO] OpenStack auth check..."
openstack token issue >/dev/null 2>&1 || die "No puedo autenticar contra OpenStack."

echo "[INFO] Listando servidores..."
if [[ -n "$FILTER_STATUS" ]]; then
  mapfile -t SERVER_LINES < <(openstack server list --status "$FILTER_STATUS" -f value -c ID -c Name)
else
  mapfile -t SERVER_LINES < <(openstack server list -f value -c ID -c Name)
fi
[[ "${#SERVER_LINES[@]}" -gt 0 ]] || die "No hay servidores."

if [[ -n "$FILTER_INSTANCE_ID" || -n "$FILTER_INSTANCE_NAME" ]]; then
  FILTERED_SERVER_LINES=()
  for server_line in "${SERVER_LINES[@]}"; do
    current_vm_id="$(echo "$server_line" | awk '{print $1}')"
    current_vm_name="$(echo "$server_line" | awk '{$1=""; sub(/^ /,""); print}')"
    if [[ -n "$FILTER_INSTANCE_ID" && "$current_vm_id" != "$FILTER_INSTANCE_ID" ]]; then
      continue
    fi
    if [[ -n "$FILTER_INSTANCE_NAME" && "$current_vm_name" != "$FILTER_INSTANCE_NAME" ]]; then
      continue
    fi
    FILTERED_SERVER_LINES+=("$server_line")
  done
  SERVER_LINES=("${FILTERED_SERVER_LINES[@]}")
fi
[[ "${#SERVER_LINES[@]}" -gt 0 ]] || die "No hay servidores que coincidan con el filtro solicitado."

printf "\n%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
  "VM_ID" "NAME" "IP" "USER" "OFFSET_ms" "ABS_ms" "STATUS"
printf "%s\n" "---------------------------------------------------------------------------------------------------------------"

for line in "${SERVER_LINES[@]}"; do
  vm_id="$(echo "$line" | awk '{print $1}')"
  vm_name="$(echo "$line" | awk '{$1=""; sub(/^ /,""); print}')"
  addrs="$(openstack server show "$vm_id" -f value -c addresses 2>/dev/null || true)"
  ip="$(extract_preferred_ipv4 "$addrs" "$PREFERRED_IP_PREFIX")"
  if [[ -z "$ip" ]]; then
    append_node_json "$FAILURES_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"","reason":"node_unreachable","stage":"before"}))
PY
)"
    continue
  fi

  user="$(pick_ssh_user "$ip")"
  if [[ -z "$user" ]]; then
    printf "%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
      "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "FAIL" "N/A" "N/A" "ssh_failed"
    append_node_json "$FAILURES_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"$ip","reason":"ssh_failed","stage":"before"}))
PY
)"
    continue
  fi

  chrony_before=false
  chrony_after=false
  chrony_installed_by_script=false
  chrony_started_by_script=false
  makestep_applied=false
  makestep_failed=false
  before_offset_ms=""
  before_abs_ms=""
  before_jitter_ms=""
  before_measurement_source=""
  after_offset_ms=""
  after_abs_ms=""
  after_jitter_ms=""
  after_measurement_source=""

  if chrony_exists "$user" "$ip"; then
    chrony_before=true
    before_res="$(measure_offset_chrony "$user" "$ip")"
    if [[ "$before_res" == OK* ]]; then
      before_offset_ms="$(echo "$before_res" | awk '{print $2}')"
      before_abs_ms="$(echo "$before_res" | awk '{print $3}')"
      before_measurement_source="chrony"
    fi
    capture_remote_logs "$user" "$ip" "$NODE_LOG_DIR/${vm_id}.before"
  else
    before_res="$(measure_offset_fallback "$user" "$ip")"
    if [[ "$before_res" == OK* ]]; then
      before_offset_ms="$(echo "$before_res" | awk '{print $2}')"
      before_abs_ms="$(echo "$before_res" | awk '{print $3}')"
      before_jitter_ms="$(echo "$before_res" | awk '{print $4}')"
      before_measurement_source="ssh_epoch_fallback"
      capture_remote_logs "$user" "$ip" "$NODE_LOG_DIR/${vm_id}.before"
    fi
  fi

  if [[ "$DO_FIX_TIME" == "1" ]]; then
    if [[ "$chrony_before" != true ]]; then
      if install_and_enable_chrony "$user" "$ip"; then
        chrony_installed_by_script=true
        chrony_started_by_script=true
      fi
    else
      start_chrony "$user" "$ip" && chrony_started_by_script=true
    fi
    if chrony_exists "$user" "$ip"; then
      chrony_after=true
      read -r makestep_rc restart_rc <<<"$(makestep_and_restart "$user" "$ip")"
      if [[ "${makestep_rc:-1}" == "0" ]]; then
        makestep_applied=true
      else
        makestep_failed=true
      fi
    fi
  else
    chrony_after="$chrony_before"
  fi

  if [[ "$chrony_after" != true && "$DO_FIX_TIME" == "1" ]]; then
    chrony_installed_py=$([[ "$chrony_installed_by_script" == true ]] && echo True || echo False)
    chrony_started_py=$([[ "$chrony_started_by_script" == true ]] && echo True || echo False)
    makestep_applied_py=$([[ "$makestep_applied" == true ]] && echo True || echo False)
    before_offset_py="$(py_num_or_none "$before_offset_ms")"
    before_abs_py="$(py_num_or_none "$before_abs_ms")"
    printf "%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
      "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "$user" "N/A" "N/A" "no_chrony"
    append_node_json "$FINAL_JSONL" "$(python3 - <<PY
import json
print(json.dumps({
  "vm_id":"$vm_id","name":"$vm_name","ip":"$ip","ssh_user":"$user",
  "chrony_available":False,"chrony_installed_by_script":$chrony_installed_py,
  "chrony_started_by_script":$chrony_started_py,"makestep_applied":$makestep_applied_py,
  "status":"failed","reason":"no_chrony","before_offset_ms":$before_offset_py,"before_abs_offset_ms":$before_abs_py
}))
PY
)"
    append_node_json "$FAILURES_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"$ip","reason":"no_chrony","stage":"after"}))
PY
)"
    continue
  fi

  if [[ "$chrony_after" == true ]]; then
    after_res="$(measure_offset_chrony "$user" "$ip")"
    if [[ "$after_res" == OK* ]]; then
      chrony_installed_py=$([[ "$chrony_installed_by_script" == true ]] && echo True || echo False)
      chrony_started_py=$([[ "$chrony_started_by_script" == true ]] && echo True || echo False)
      makestep_applied_py=$([[ "$makestep_applied" == true ]] && echo True || echo False)
      makestep_failed_py=$([[ "$makestep_failed" == true ]] && echo True || echo False)
      before_offset_py="$(py_num_or_none "$before_offset_ms")"
      before_abs_py="$(py_num_or_none "$before_abs_ms")"
      after_offset_ms="$(echo "$after_res" | awk '{print $2}')"
      after_abs_ms="$(echo "$after_res" | awk '{print $3}')"
      after_measurement_source="chrony"
      capture_remote_logs "$user" "$ip" "$NODE_LOG_DIR/${vm_id}.after"
      printf "%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
        "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "$user" "$after_offset_ms" "$after_abs_ms" "ok"
      append_node_json "$FINAL_JSONL" "$(python3 - <<PY
import json
print(json.dumps({
  "vm_id":"$vm_id",
  "name":"$vm_name",
  "ip":"$ip",
  "ssh_user":"$user",
  "chrony_available":True,
  "chrony_installed_by_script":$chrony_installed_py,
  "chrony_started_by_script":$chrony_started_py,
  "makestep_applied":$makestep_applied_py,
  "makestep_failed":$makestep_failed_py,
  "offset_ms":$after_offset_ms,
  "abs_offset_ms":$after_abs_ms,
  "measurement_source":"$after_measurement_source",
  "before_offset_ms":$before_offset_py,
  "before_abs_offset_ms":$before_abs_py,
  "before_measurement_source":"${before_measurement_source:-chrony}",
  "status":"ok",
  "tracking_log":"$NODE_LOG_DIR/${vm_id}.after.tracking.txt",
  "sources_log":"$NODE_LOG_DIR/${vm_id}.after.sources.txt",
  "timedatectl_log":"$NODE_LOG_DIR/${vm_id}.after.timedatectl.txt"
}))
PY
)"
      if [[ -n "$before_abs_ms" ]]; then
        append_node_json "$BEFORE_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"$ip","ssh_user":"$user","offset_ms":$before_offset_py,"abs_offset_ms":$before_abs_py,"measurement_source":"${before_measurement_source:-chrony}","status":"ok"}))
PY
)"
      fi
      append_node_json "$AFTER_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"$ip","ssh_user":"$user","offset_ms":$after_offset_ms,"abs_offset_ms":$after_abs_ms,"status":"ok"}))
PY
)"
      continue
    fi
  fi

  if [[ "$chrony_after" != true && "$DO_FIX_TIME" != "1" ]]; then
    after_res="$(measure_offset_fallback "$user" "$ip")"
    if [[ "$after_res" == OK* ]]; then
      chrony_installed_py=$([[ "$chrony_installed_by_script" == true ]] && echo True || echo False)
      chrony_started_py=$([[ "$chrony_started_by_script" == true ]] && echo True || echo False)
      makestep_applied_py=$([[ "$makestep_applied" == true ]] && echo True || echo False)
      makestep_failed_py=$([[ "$makestep_failed" == true ]] && echo True || echo False)
      before_offset_py="$(py_num_or_none "$before_offset_ms")"
      before_abs_py="$(py_num_or_none "$before_abs_ms")"
      before_jitter_py="$(py_num_or_none "$before_jitter_ms")"
      after_offset_ms="$(echo "$after_res" | awk '{print $2}')"
      after_abs_ms="$(echo "$after_res" | awk '{print $3}')"
      after_jitter_ms="$(echo "$after_res" | awk '{print $4}')"
      after_measurement_source="ssh_epoch_fallback"
      capture_remote_logs "$user" "$ip" "$NODE_LOG_DIR/${vm_id}.after"
      printf "%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
        "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "$user" "$after_offset_ms" "$after_abs_ms" "ok_fallback"
      append_node_json "$FINAL_JSONL" "$(python3 - <<PY
import json
print(json.dumps({
  "vm_id":"$vm_id",
  "name":"$vm_name",
  "ip":"$ip",
  "ssh_user":"$user",
  "chrony_available":False,
  "chrony_installed_by_script":$chrony_installed_py,
  "chrony_started_by_script":$chrony_started_py,
  "makestep_applied":$makestep_applied_py,
  "makestep_failed":$makestep_failed_py,
  "offset_ms":$after_offset_ms,
  "abs_offset_ms":$after_abs_ms,
  "measurement_source":"$after_measurement_source",
  "acquisition_jitter_ms":$after_jitter_ms,
  "before_offset_ms":$before_offset_py,
  "before_abs_offset_ms":$before_abs_py,
  "before_acquisition_jitter_ms":$before_jitter_py,
  "before_measurement_source":"${before_measurement_source:-unknown}",
  "status":"ok",
  "tracking_log":"$NODE_LOG_DIR/${vm_id}.after.tracking.txt",
  "sources_log":"$NODE_LOG_DIR/${vm_id}.after.sources.txt",
  "timedatectl_log":"$NODE_LOG_DIR/${vm_id}.after.timedatectl.txt"
}))
PY
)"
      append_node_json "$AFTER_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"$ip","ssh_user":"$user","offset_ms":$after_offset_ms,"abs_offset_ms":$after_abs_ms,"measurement_source":"$after_measurement_source","acquisition_jitter_ms":$after_jitter_ms,"status":"ok"}))
PY
)"
      if [[ -n "$before_abs_ms" ]]; then
        append_node_json "$BEFORE_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"$ip","ssh_user":"$user","offset_ms":$before_offset_py,"abs_offset_ms":$before_abs_py,"measurement_source":"${before_measurement_source:-unknown}","acquisition_jitter_ms":$before_jitter_py,"status":"ok"}))
PY
)"
      fi
      continue
    fi
  fi

  reason="chronyc_failed"
  if [[ "$chrony_before" != true && "$DO_FIX_TIME" != "1" ]]; then
    reason="no_chrony"
  fi
  chrony_available_py=$([[ "$chrony_after" == true ]] && echo True || echo False)
  chrony_installed_py=$([[ "$chrony_installed_by_script" == true ]] && echo True || echo False)
  chrony_started_py=$([[ "$chrony_started_by_script" == true ]] && echo True || echo False)
  makestep_applied_py=$([[ "$makestep_applied" == true ]] && echo True || echo False)
  makestep_failed_py=$([[ "$makestep_failed" == true ]] && echo True || echo False)
  before_offset_py="$(py_num_or_none "$before_offset_ms")"
  before_abs_py="$(py_num_or_none "$before_abs_ms")"
  before_jitter_py="$(py_num_or_none "$before_jitter_ms")"
  printf "%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
    "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "$user" "N/A" "N/A" "$reason"
  append_node_json "$FINAL_JSONL" "$(python3 - <<PY
import json
print(json.dumps({
  "vm_id":"$vm_id","name":"$vm_name","ip":"$ip","ssh_user":"$user",
  "chrony_available":$chrony_available_py,
  "chrony_installed_by_script":$chrony_installed_py,
  "chrony_started_by_script":$chrony_started_py,
  "makestep_applied":$makestep_applied_py,
  "makestep_failed":$makestep_failed_py,
  "before_offset_ms":$before_offset_py,
  "before_abs_offset_ms":$before_abs_py,
  "before_acquisition_jitter_ms":$before_jitter_py,
  "before_measurement_source":"${before_measurement_source:-unknown}",
  "status":"failed","reason":"$reason"
}))
PY
)"
  append_node_json "$FAILURES_JSONL" "$(python3 - <<PY
import json
print(json.dumps({"vm_id":"$vm_id","name":"$vm_name","ip":"$ip","reason":"$reason","stage":"after"}))
PY
)"
done

python3 - "$FINAL_JSONL" "$FAILURES_JSONL" "$BEFORE_JSONL" "$AFTER_JSONL" "$TIME_SYNC_OUT" "$TIME_SYNC_BEFORE_OUT" "$TIME_SYNC_AFTER_OUT" <<'PY'
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path

final_path, failures_path, before_path, after_path, out_path, before_out, after_out = sys.argv[1:8]
threshold_ms = float(os.environ.get("TIME_SYNC_THRESHOLD_MS", "1000"))
degraded_threshold_ms = float(os.environ.get("TIME_SYNC_DEGRADED_THRESHOLD_MS", "5000"))
do_fix = str(os.environ.get("DO_FIX_TIME", "0")) == "1"
case_id = os.environ.get("CASE_ID") or None
filter_status = os.environ.get("FILTER_STATUS", "ACTIVE")
preferred_ip_prefix = os.environ.get("PREFERRED_IP_PREFIX", "10.0.2.")

def load_jsonl(path):
    items = []
    p = Path(path)
    if not p.is_file():
        return items
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        items.append(json.loads(line))
    return items

def summarize(nodes):
    ok = [n for n in nodes if n.get("status") == "ok" and n.get("abs_offset_ms") is not None]
    failures = [n for n in nodes if n.get("status") != "ok"]
    worst = None
    for node in ok:
        if worst is None or float(node.get("abs_offset_ms", 0.0)) > float(worst.get("abs_offset_ms", 0.0)):
            worst = node
    max_ms = float(worst.get("abs_offset_ms", 0.0)) if worst else None
    if max_ms is None:
        sync_state = "unknown"
        sync_bool = False
    elif max_ms <= threshold_ms:
        sync_state = "synchronized"
        sync_bool = True
    elif max_ms <= degraded_threshold_ms:
        sync_state = "degraded"
        sync_bool = False
    else:
        sync_state = "not_synchronized"
        sync_bool = False
    return {
        "nodes_ok": len(ok),
        "nodes_failed": len(failures),
        "max_clock_offset_ms": round(max_ms, 3) if max_ms is not None else None,
        "max_clock_offset_seconds": round((max_ms or 0.0) / 1000.0, 6) if max_ms is not None else None,
        "synchronized": sync_bool,
        "temporal_sync_status": sync_state,
        "worst_node": {
            "vm_id": worst.get("vm_id"),
            "name": worst.get("name"),
            "ip": worst.get("ip"),
            "offset_ms": worst.get("abs_offset_ms"),
        } if worst else None,
        "nodes": nodes,
    }

final_nodes = load_jsonl(final_path)
failures = load_jsonl(failures_path)
before_nodes = load_jsonl(before_path)
after_nodes = load_jsonl(after_path)
before_summary = summarize(before_nodes)
after_summary = summarize(after_nodes if after_nodes else final_nodes)
effective_summary = after_summary if do_fix else summarize(final_nodes)

payload = {
    "schema": "nics_time_sync_v2",
    "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "case_id": case_id,
    "mode": "measure_and_fix" if do_fix else "measure_only",
    "do_fix_time": do_fix,
    "correction_applied": do_fix,
    "openstack_status_filter": filter_status,
    "preferred_ip_prefix": preferred_ip_prefix,
    "filter_instance_id": os.environ.get("FILTER_INSTANCE_ID") or None,
    "filter_instance_name": os.environ.get("FILTER_INSTANCE_NAME") or None,
    "synchronization_threshold_ms": threshold_ms,
    "degraded_threshold_ms": degraded_threshold_ms,
    **effective_summary,
    "nodes": final_nodes,
    "failures": failures,
}
if do_fix:
    payload["before"] = {k: v for k, v in before_summary.items() if k != "nodes"}
    payload["after"] = {k: v for k, v in after_summary.items() if k != "nodes"}

Path(out_path).parent.mkdir(parents=True, exist_ok=True)
Path(out_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
if do_fix:
    Path(before_out).write_text(json.dumps(before_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    Path(after_out).write_text(json.dumps(after_summary, indent=2, ensure_ascii=False), encoding="utf-8")
PY

python3 - "$TIME_SYNC_OUT" <<'PY'
import json, sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print()
print(f"[RESULT] Nodes OK={payload.get('nodes_ok', 0)} FAIL={payload.get('nodes_failed', 0)}")
if payload.get("max_clock_offset_ms") is None:
    print("[RESULT] E2 max clock offset/skew (ms) = N/A (no nodes measured)")
else:
    print(f"[RESULT] E2 max clock offset/skew (ms) = {payload.get('max_clock_offset_ms')}")
    worst = payload.get("worst_node") or {}
    print(f"[RESULT] Worst node: {worst.get('name')} | {worst.get('vm_id')} | {worst.get('ip')}")
    print(f"[RESULT] Temporal sync status: {payload.get('temporal_sync_status')}")
    print(f"[RESULT] JSON: {sys.argv[1]}")
PY
