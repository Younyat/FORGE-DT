from __future__ import annotations

"""Real resource usage of THIS host machine (the one running gunicorn),
never a remote scenario VM -- node_health/forensic_twin measure remote
nodes over SSH, this reads this process's own /proc filesystem directly.
No psutil dependency, matching memory_watchdog.service's own convention
(see its read_meminfo() docstring) -- plain /proc parsing throughout.
"""

import os
import time

from ..memory_watchdog.service import get_memory_pressure_snapshot


def _read_cpu_count() -> int | None:
    """Real core count this host actually has, from /proc/cpuinfo (counts
    "processor" lines) -- used to turn CPU% into a real "N of M cores busy"
    reading, not just a percentage with no absolute unit."""
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.startswith("processor"))
    except Exception:
        return os.cpu_count()


def _read_proc_stat_cpu_fields() -> tuple[int, int] | None:
    try:
        with open("/proc/stat", "r", encoding="utf-8") as fh:
            line = fh.readline()
        parts = line.split()
        if not parts or parts[0] != "cpu":
            return None
        values = [int(x) for x in parts[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle + iowait
        total = sum(values)
        return total - idle, total  # (busy, total)
    except Exception:
        return None


def read_cpu_percent(sample_seconds: float = 0.2) -> float | None:
    """Real, instantaneous CPU busy% for the host -- two /proc/stat samples
    a short interval apart (the same technique top/vmstat use), never a
    cached or guessed value."""
    first = _read_proc_stat_cpu_fields()
    if first is None:
        return None
    time.sleep(sample_seconds)
    second = _read_proc_stat_cpu_fields()
    if second is None:
        return None
    busy_delta = second[0] - first[0]
    total_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, busy_delta / total_delta * 100.0)), 1)


def read_disk_percent(path: str = "/") -> dict:
    """Real root-filesystem usage of the host, via statvfs (no shell-out)."""
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
        pct = round(used / total * 100.0, 1) if total else None
        return {"disk_total_bytes": total, "disk_used_bytes": used, "disk_used_pct": pct}
    except Exception:
        return {"disk_total_bytes": None, "disk_used_bytes": None, "disk_used_pct": None}


def _default_route_iface() -> str | None:
    """Real kernel routing table (/proc/net/route), not a shell-out to `ip`
    -- the default route row has Destination 00000000; its Iface column is
    the interface this host actually uses to reach the outside world."""
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as fh:
            lines = fh.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) > 1 and parts[1] == "00000000":
                return parts[0]
    except Exception:
        pass
    return None


def _is_physical_iface(iface: str) -> bool:
    """A real bug found live: this host (an OpenStack hypervisor) has 20+
    virtual interfaces (OVS bridges, linux bridges, veth pairs, tap devices
    -- one whole chain per VM's NIC), and summing bytes across ALL of them
    massively over-counts real traffic (the same packet is often visible on
    3-4 of these virtual interfaces as it crosses a bridge). A real physical
    NIC has a `device` symlink under /sys/class/net/<iface>/ (a real PCI/USB
    device behind it); none of the virtual ones do -- confirmed live: only
    `ens33`/`enx7cc2c647cee8` have one on this host, the other ~25 don't."""
    return os.path.exists(f"/sys/class/net/{iface}/device")


def _read_iface_speed_mbps(iface: str) -> float | None:
    """Real link speed from the NIC driver, only trusted for a confirmed
    physical interface (see _is_physical_iface -- virtual interfaces often
    report a fake default like 10000 regardless of any real capacity)."""
    try:
        with open(f"/sys/class/net/{iface}/speed", "r", encoding="utf-8") as fh:
            value = int(fh.read().strip())
        return float(value) if value > 0 else None
    except Exception:
        return None


def _read_iface_counters(iface: str) -> tuple[int, int, int] | None:
    """(bytes_total, errors_and_drops_total, packets_total) for ONE named
    interface from /proc/net/dev."""
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as fh:
            lines = fh.readlines()[2:]
        for line in lines:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            if name.strip() != iface:
                continue
            f = rest.split()
            if len(f) < 16:
                return None
            rx_bytes, rx_packets, rx_errs, rx_drop = int(f[0]), int(f[1]), int(f[2]), int(f[3])
            tx_bytes, tx_packets, tx_errs, tx_drop = int(f[8]), int(f[9]), int(f[10]), int(f[11])
            return rx_bytes + tx_bytes, rx_errs + rx_drop + tx_errs + tx_drop, rx_packets + tx_packets
    except Exception:
        pass
    return None


def read_network_health(sample_seconds: float = 0.2) -> dict:
    """Real throughput (Mbps) and real link utilization% for the host's
    actual default-route PHYSICAL interface only (see _is_physical_iface --
    summing every virtual OpenStack interface instead, an earlier version
    of this function did, both inflated throughput via duplicate counting
    AND pinned the error-rate-based "health" percentage at a constant 0,
    which looked indistinguishable from broken on the dashboard even though
    it was technically correct: real errors on this host's real network are
    genuinely rare, so a percentage that can only ever show real problems
    never shows real ACTIVITY either, unlike CPU/RAM/disk which always move).
    utilization_pct (throughput / this interface's own real link speed) is
    now the headline percentage -- it behaves like the other three metrics,
    rising with real usage instead of sitting at zero during normal
    operation. error_pct is kept as a secondary field (still computed, still
    exposed, still real) and overrides the color to red if nonzero even
    when utilization is low, since a real transmission error is a worse
    sign than high-but-healthy throughput."""
    iface = _default_route_iface()
    if not iface or not _is_physical_iface(iface):
        return {"throughput_mbps": None, "error_pct": None, "utilization_pct": None, "iface": iface}
    speed_mbps = _read_iface_speed_mbps(iface)
    first = _read_iface_counters(iface)
    if first is None:
        return {"throughput_mbps": None, "error_pct": None, "utilization_pct": None, "iface": iface}
    time.sleep(sample_seconds)
    second = _read_iface_counters(iface)
    if second is None:
        return {"throughput_mbps": None, "error_pct": None, "utilization_pct": None, "iface": iface}
    bytes_delta = max(0, second[0] - first[0])
    errors_delta = max(0, second[1] - first[1])
    packets_delta = second[2] - first[2]
    throughput_mbps = round(bytes_delta * 8 / 1_000_000 / sample_seconds, 2)
    error_pct = round(errors_delta / packets_delta * 100.0, 2) if packets_delta > 0 else 0.0
    utilization_pct = round(min(100.0, throughput_mbps / speed_mbps * 100.0), 2) if speed_mbps else None
    return {
        "throughput_mbps": throughput_mbps, "error_pct": error_pct,
        "utilization_pct": utilization_pct, "iface": iface, "speed_mbps": speed_mbps,
    }


def get_host_resource_snapshot() -> dict:
    """One real reading of this host's own CPU/RAM/disk/network, meant to
    be polled every ~10s by the dashboard header widget. Memory is reused
    directly from memory_watchdog's own already-built snapshot (same real
    number the watchdog itself acts on), never recomputed a second way."""
    cpu_pct = read_cpu_percent()
    cpu_count = _read_cpu_count()
    net = read_network_health()
    disk = read_disk_percent("/")
    mem = get_memory_pressure_snapshot()
    mem_used_pct = None
    if mem.get("mem_available_pct") is not None:
        mem_used_pct = round(100.0 - mem["mem_available_pct"], 1)
    return {
        "generated_at": mem.get("generated_at"),
        "cpu_used_pct": cpu_pct,
        "cpu_count": cpu_count,
        "mem_used_pct": mem_used_pct,
        "mem_total_mb": mem.get("mem_total_mb"),
        "mem_available_mb": mem.get("mem_available_mb"),
        "swap_used_pct": mem.get("swap_used_pct"),
        "disk_used_pct": disk.get("disk_used_pct"),
        "disk_total_bytes": disk.get("disk_total_bytes"),
        "disk_used_bytes": disk.get("disk_used_bytes"),
        # The headline number: real link utilization (throughput / this
        # interface's own real speed), None only when neither a physical
        # default-route interface nor its speed could be confirmed.
        "network_used_pct": net.get("utilization_pct"),
        "network_error_pct": net.get("error_pct"),
        # True whenever a real transmission error/drop happened in this
        # sampling window -- the frontend forces red on this regardless of
        # how low utilization_pct is, since an active error is a worse sign
        # than merely high-but-healthy throughput.
        "network_degraded": bool(net.get("error_pct")),
        "network_throughput_mbps": net.get("throughput_mbps"),
        "network_iface": net.get("iface"),
        "network_speed_mbps": net.get("speed_mbps"),
    }
