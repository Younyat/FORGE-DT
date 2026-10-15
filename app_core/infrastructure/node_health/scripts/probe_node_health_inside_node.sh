#!/usr/bin/env bash
set -u

kv() {
  printf 'KV\t%s\t%s\n' "$1" "$2"
}

section_begin() {
  printf 'SECTION\t%s\tBEGIN\n' "$1"
}

section_end() {
  printf 'SECTION\t%s\tEND\n' "$1"
}

read_os_pretty() {
  if [[ -r /etc/os-release ]]; then
    grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"' || true
  fi
}

cpu_usage_pct() {
  top -bn1 2>/dev/null | awk '
    /Cpu\(s\)|%Cpu/ {
      for (i = 1; i <= NF; i++) {
        gsub(",", "", $i)
        if ($i == "id" || $i == "id%") {
          idle = $(i-1)
          gsub(",", "", idle)
          printf "%.2f\n", 100 - idle
          exit
        }
      }
    }'
}

root_bytes="$(df -P -B1 / 2>/dev/null | awk 'NR==2 {print $2"\t"$3"\t"$4"\t"$5}')"
root_inodes="$(df -Pi / 2>/dev/null | awk 'NR==2 {print $5}')"
mem_line="$(free -m 2>/dev/null | awk '/^Mem:/ {print $2"\t"$3"\t"$7}')"
swap_line="$(free -m 2>/dev/null | awk '/^Swap:/ {print $2"\t"$3"\t"$4}')"
loadavg="$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}')"
cpu_pct="$(cpu_usage_pct)"

root_total_bytes="$(echo "${root_bytes}" | awk '{print $1}')"
root_used_bytes="$(echo "${root_bytes}" | awk '{print $2}')"
root_avail_bytes="$(echo "${root_bytes}" | awk '{print $3}')"
root_use_pct="$(echo "${root_bytes}" | awk '{print $4}')"

mem_total_mb="$(echo "${mem_line}" | awk '{print $1}')"
mem_used_mb="$(echo "${mem_line}" | awk '{print $2}')"
mem_avail_mb="$(echo "${mem_line}" | awk '{print $3}')"

swap_total_mb="$(echo "${swap_line}" | awk '{print $1}')"
swap_used_mb="$(echo "${swap_line}" | awk '{print $2}')"
swap_free_mb="$(echo "${swap_line}" | awk '{print $3}')"

net_stats="$(awk -F'[: ]+' 'NR>2 {iface=$2; if (iface != "" && iface != "lo") {rx+=$3; tx+=$11}} END {printf "%.0f\t%.0f\n", rx+0, tx+0}' /proc/net/dev 2>/dev/null)"
net_rx_bytes="$(echo "${net_stats}" | awk '{print $1}')"
net_tx_bytes="$(echo "${net_stats}" | awk '{print $2}')"

var_log_size="$(du -sb /var/log 2>/dev/null | awk '{print $1}')"
suricata_log_size="$(du -sb /var/log/suricata 2>/dev/null | awk '{print $1}')"
tmp_size="$(du -sb /tmp 2>/dev/null | awk '{print $1}')"
var_tmp_size="$(du -sb /var/tmp 2>/dev/null | awk '{print $1}')"
apt_cache_size="$(du -sb /var/cache/apt 2>/dev/null | awk '{print $1}')"

kv hostname "$(hostname 2>/dev/null || echo not_available)"
kv os_pretty "$(read_os_pretty || echo not_available)"
kv kernel "$(uname -r 2>/dev/null || echo not_available)"
kv machine "$(uname -m 2>/dev/null || echo not_available)"
kv date_utc "$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo not_available)"
kv uptime_pretty "$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo not_available)"
kv loadavg "${loadavg:-not_available}"
kv cpu_cores "$(nproc 2>/dev/null || echo not_available)"
kv cpu_usage_pct "${cpu_pct:-not_available}"
kv mem_total_mb "${mem_total_mb:-not_available}"
kv mem_used_mb "${mem_used_mb:-not_available}"
kv mem_avail_mb "${mem_avail_mb:-not_available}"
kv swap_total_mb "${swap_total_mb:-not_available}"
kv swap_used_mb "${swap_used_mb:-not_available}"
kv swap_free_mb "${swap_free_mb:-not_available}"
kv root_total_bytes "${root_total_bytes:-not_available}"
kv root_used_bytes "${root_used_bytes:-not_available}"
kv root_avail_bytes "${root_avail_bytes:-not_available}"
kv root_use_pct "${root_use_pct:-not_available}"
kv root_inodes_use_pct "${root_inodes:-not_available}"
kv net_rx_bytes "${net_rx_bytes:-not_available}"
kv net_tx_bytes "${net_tx_bytes:-not_available}"
kv var_log_size_bytes "${var_log_size:-not_available}"
kv suricata_log_size_bytes "${suricata_log_size:-not_available}"
kv tmp_size_bytes "${tmp_size:-not_available}"
kv var_tmp_size_bytes "${var_tmp_size:-not_available}"
kv apt_cache_size_bytes "${apt_cache_size:-not_available}"

section_begin services
for svc in suricata wazuh-agent wazuh-manager zeek snort openplc docker; do
  printf '%s=%s\n' "$svc" "$(systemctl is-active "$svc" 2>/dev/null || echo not_installed)"
done
section_end services

section_begin filesystems
df -hP / /var/log /tmp /var/tmp 2>/dev/null || true
section_end filesystems

section_begin top_cpu
ps -eo pid,comm,%cpu,%mem --sort=-%cpu 2>/dev/null | head -n 8 || true
section_end top_cpu

section_begin top_mem
ps -eo pid,comm,%cpu,%mem --sort=-%mem 2>/dev/null | head -n 8 || true
section_end top_mem

section_begin largest_var
du -xh /var 2>/dev/null | sort -h | tail -n 12 || true
section_end largest_var

# Two volatile-evidence categories NIST SP 800-86 ("Guide to Integrating
# Forensic Techniques into Incident Response", Section 5.1.2 "Volatile
# Data") names explicitly as significant types to collect during live
# response: "Network Connections" ("a list of the ports and IP addresses at
# which the system is listening for connections") and "Login Sessions"
# ("information about currently logged-in users... Some OSs have built-in
# commands for listing the currently logged on users, such as the w command
# for UNIX systems", Section 5.2). Neither existed anywhere in this
# platform before -- same SSH session already open for everything above,
# so this adds no new round-trip, only two more fast local commands.
section_begin listening_ports
ss -tulwn 2>/dev/null || netstat -tulwn 2>/dev/null || true
section_end listening_ports

section_begin login_sessions
who 2>/dev/null || true
section_end login_sessions

