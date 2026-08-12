"""System-wide metrics."""

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Optional, Union

from qutil._common import (
    AF_INET,
    AF_INET6,
    SOCK_DGRAM,
    SOCK_STREAM,
    _TCP_STATES,
    addr,
    pconn,
    scpufreq,
    scpustats,
    scputimes,
    sdiskio,
    sdiskpart,
    sdiskusage,
    snetio,
    snicaddr,
    snicstats,
    sswap,
    suser,
    svmem,
    usage_percent,
)
from qutil._linux import clock_ticks, hex_ip_port, parse_meminfo, parse_stat_cpu_line, read_file, read_lines

_last_cpu: Optional[tuple[float, list]] = None
_last_percpu: Optional[tuple[float, list]] = None
_last_cpu_times: Optional[scputimes] = None
_last_percpu_times: Optional[list] = None


def _cpu_times_list(percpu: bool = False) -> Union[scputimes, list]:
    lines = [ln for ln in read_lines("/proc/stat") if ln.startswith("cpu")]
    if not percpu:
        return scputimes(*parse_stat_cpu_line(lines[0]))
    return [scputimes(*parse_stat_cpu_line(ln)) for ln in lines[1:] if ln.startswith("cpu")]


def cpu_times(percpu: bool = False):
    return _cpu_times_list(percpu)


def cpu_count(logical: bool = True) -> Optional[int]:
    if logical:
        try:
            return os.cpu_count()
        except Exception:
            return None
    try:
        cores = set()
        current = None
        for line in read_lines("/proc/cpuinfo"):
            if line.lower().startswith("physical id"):
                current = line.split(":")[1].strip()
            elif line.lower().startswith("core id") and current is not None:
                cores.add((current, line.split(":")[1].strip()))
        return len(cores) or os.cpu_count()
    except FileNotFoundError:
        return os.cpu_count()


def cpu_percent(interval: Optional[float] = None, percpu: bool = False):
    global _last_cpu, _last_percpu

    def _pct(t1, t2):
        idle1 = t1.idle + t1.iowait
        idle2 = t2.idle + t2.iowait
        tot1 = sum(t1)
        tot2 = sum(t2)
        dt = tot2 - tot1
        di = idle2 - idle1
        if dt <= 0:
            return 0.0
        return round(max(0.0, min(100.0, (1.0 - di / dt) * 100.0)), 1)

    if interval is not None and interval > 0:
        t1 = _cpu_times_list(percpu)
        time.sleep(interval)
        t2 = _cpu_times_list(percpu)
        if percpu:
            return [_pct(a, b) for a, b in zip(t1, t2)]
        return _pct(t1, t2)

    now = time.time()
    cur = _cpu_times_list(percpu)
    if percpu:
        prev = _last_percpu
        _last_percpu = (now, cur)
        if prev is None:
            return [0.0] * len(cur)
        return [_pct(a, b) for a, b in zip(prev[1], cur)]
    prev = _last_cpu
    _last_cpu = (now, cur)
    if prev is None:
        return 0.0
    return _pct(prev[1], cur)


def cpu_times_percent(interval: Optional[float] = None, percpu: bool = False):
    global _last_cpu_times, _last_percpu_times

    def _diff(t1, t2):
        fields = [max(0.0, b - a) for a, b in zip(t1, t2)]
        tot = sum(fields) or 1.0
        return scputimes(*[round(x / tot * 100.0, 1) for x in fields])

    if interval is not None and interval > 0:
        t1 = _cpu_times_list(percpu)
        time.sleep(interval)
        t2 = _cpu_times_list(percpu)
        if percpu:
            return [_diff(a, b) for a, b in zip(t1, t2)]
        return _diff(t1, t2)

    cur = _cpu_times_list(percpu)
    if percpu:
        prev = _last_percpu_times
        _last_percpu_times = cur
        if prev is None:
            z = scputimes(*([0.0] * 10))
            return [z] * len(cur)
        return [_diff(a, b) for a, b in zip(prev, cur)]
    prev = _last_cpu_times
    _last_cpu_times = cur
    if prev is None:
        return scputimes(*([0.0] * 10))
    return _diff(prev, cur)


def cpu_freq(percpu: bool = False):
    def _one(cpu_id: int) -> scpufreq:
        base = f"/sys/devices/system/cpu/cpu{cpu_id}/cpufreq"
        def _r(name, default=0.0):
            try:
                return int(read_file(os.path.join(base, name)).strip()) / 1000.0
            except (FileNotFoundError, OSError, ValueError):
                return default

        return scpufreq(_r("scaling_cur_freq"), _r("cpuinfo_min_freq"), _r("cpuinfo_max_freq"))

    n = cpu_count() or 1
    vals = [_one(i) for i in range(n)]
    if percpu:
        return vals
    if not vals:
        return scpufreq(0.0, 0.0, 0.0)
    cur = sum(v.current for v in vals) / len(vals)
    return scpufreq(cur, min(v.min for v in vals), max(v.max for v in vals))


def cpu_stats() -> scpustats:
    ctx = 0
    intr = 0
    soft = 0
    for line in read_lines("/proc/stat"):
        if line.startswith("ctxt "):
            ctx = int(line.split()[1])
        elif line.startswith("intr "):
            intr = int(line.split()[1])
        elif line.startswith("softirq "):
            soft = int(line.split()[1])
    return scpustats(ctx, intr, soft, 0)


def virtual_memory() -> svmem:
    m = parse_meminfo()
    total = m.get("MemTotal", 0)
    free = m.get("MemFree", 0)
    buffers = m.get("Buffers", 0)
    cached = m.get("Cached", 0) + m.get("SReclaimable", 0)
    shared = m.get("Shmem", 0)
    active = m.get("Active", 0)
    inactive = m.get("Inactive", 0)
    slab = m.get("Slab", 0)
    avail = m.get("MemAvailable")
    if avail is None:
        avail = free + buffers + cached
    used = total - free - buffers - cached
    if used < 0:
        used = total - avail
    percent = usage_percent(total - avail, total)
    return svmem(total, avail, percent, used, free, active, inactive, buffers, cached, shared, slab)


def swap_memory() -> sswap:
    m = parse_meminfo()
    total = m.get("SwapTotal", 0)
    free = m.get("SwapFree", 0)
    used = total - free
    sin = sout = 0
    try:
        for line in read_lines("/proc/vmstat"):
            if line.startswith("pswpin "):
                sin = int(line.split()[1]) * 4096
            elif line.startswith("pswpout "):
                sout = int(line.split()[1]) * 4096
    except FileNotFoundError:
        pass
    return sswap(total, used, free, usage_percent(used, total), sin, sout)


def disk_usage(path: str) -> sdiskusage:
    st = os.statvfs(path)
    total = st.f_frsize * st.f_blocks
    free = st.f_frsize * st.f_bavail
    used = total - st.f_frsize * st.f_bfree
    return sdiskusage(total, used, free, usage_percent(used, total))


def disk_partitions(all: bool = False) -> list:
    parts = []
    try:
        lines = read_lines("/proc/mounts")
    except FileNotFoundError:
        return parts
    phys_prefixes = ("/dev/",)
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        device, mount, fstype, opts = fields[0], fields[1], fields[2], fields[3]
        if not all:
            if not device.startswith(phys_prefixes):
                continue
            if fstype in ("proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "pstore", "bpf", "tracefs", "debugfs", "securityfs", "fusectl", "configfs", "nsfs"):
                continue
        parts.append(sdiskpart(device, mount.replace("\\040", " "), fstype, opts))
    return parts


def disk_io_counters(perdisk: bool = False):
    counters = {}
    try:
        lines = read_lines("/proc/diskstats")
    except FileNotFoundError:
        return sdiskio(0, 0, 0, 0, 0, 0)
    for line in lines:
        f = line.split()
        if len(f) < 14:
            continue
        name = f[2]
        reads, rmerged, rsect, rtime = int(f[3]), int(f[4]), int(f[5]), int(f[6])
        writes, wmerged, wsect, wtime = int(f[7]), int(f[8]), int(f[9]), int(f[10])
        counters[name] = sdiskio(reads, writes, rsect * 512, wsect * 512, rtime, wtime)
    if perdisk:
        return counters
    agg = [0] * 6
    for name, c in counters.items():
        # skip partitions like sda1 if parent exists
        if name[-1].isdigit() and name.rstrip("0123456789") in counters:
            continue
        for i, v in enumerate(c):
            agg[i] += v
    return sdiskio(*agg)


def net_io_counters(pernic: bool = False):
    nics = {}
    try:
        lines = read_lines("/proc/net/dev")
    except FileNotFoundError:
        return snetio(0, 0, 0, 0, 0, 0, 0, 0)
    for line in lines[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        f = rest.split()
        if len(f) < 16:
            continue
        bytes_recv, pkts_recv, errin, dropin = int(f[0]), int(f[1]), int(f[2]), int(f[3])
        bytes_sent, pkts_sent, errout, dropout = int(f[8]), int(f[9]), int(f[10]), int(f[11])
        nics[name] = snetio(bytes_sent, bytes_recv, pkts_sent, pkts_recv, errin, errout, dropin, dropout)
    if pernic:
        return nics
    agg = [0] * 8
    for c in nics.values():
        for i, v in enumerate(c):
            agg[i] += v
    return snetio(*agg)


def _parse_proc_net(path: str, family: int, typ: int, udp: bool = False) -> list:
    conns = []
    try:
        lines = read_lines(path)
    except (FileNotFoundError, PermissionError):
        return conns
    ipv6 = family == AF_INET6
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            laddr = hex_ip_port(parts[1], ipv6)
            raddr = hex_ip_port(parts[2], ipv6)
        except (ValueError, OSError):
            continue
        status = "NONE" if udp else _TCP_STATES.get(parts[3].upper(), "NONE")
        inode = parts[9]
        fd = -1
        conns.append(pconn(fd, family, typ, addr(*laddr), addr(*raddr) if raddr[1] else (), status))
    return conns


def net_connections(kind: str = "inet") -> list:
    mapping = {
        "tcp": [("/proc/net/tcp", AF_INET, SOCK_STREAM, False), ("/proc/net/tcp6", AF_INET6, SOCK_STREAM, False)],
        "udp": [("/proc/net/udp", AF_INET, SOCK_DGRAM, True), ("/proc/net/udp6", AF_INET6, SOCK_DGRAM, True)],
        "unix": [],
    }
    kinds = []
    if kind in ("inet", "all"):
        kinds.extend(mapping["tcp"])
        kinds.extend(mapping["udp"])
    elif kind == "tcp":
        kinds.extend(mapping["tcp"])
    elif kind == "udp":
        kinds.extend(mapping["udp"])
    elif kind == "inet4":
        kinds = [mapping["tcp"][0], mapping["udp"][0]]
    elif kind == "inet6":
        kinds = [mapping["tcp"][1], mapping["udp"][1]]
    out = []
    for args in kinds:
        out.extend(_parse_proc_net(*args))
    return out


def net_if_addrs() -> dict:
    import fcntl

    result = {}
    max_if = 64
    buf = array_mod = None
    try:
        import array
        import struct as st

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array("B", b"\0" * 32 * max_if)
        ifreq = st.pack("iL", len(names), names.buffer_info()[0])
        # SIOCGIFCONF
        try:
            outbytes = st.unpack("iL", fcntl.ioctl(s.fileno(), 0x8912, ifreq))[0]
            names_bytes = names.tobytes() if hasattr(names, "tobytes") else names.tostring()
            for i in range(0, outbytes, 40):
                name = names_bytes[i : i + 16].split(b"\0", 1)[0].decode()
                ip = socket.inet_ntoa(names_bytes[i + 20 : i + 24])
                result.setdefault(name, []).append(snicaddr(AF_INET, ip, None, None, None))
        except OSError:
            pass
        s.close()
    except Exception:
        pass
    # fallback: parse `ip` is not wanted; use /sys
    if not result:
        try:
            for name in os.listdir("/sys/class/net"):
                result[name] = []
        except FileNotFoundError:
            pass
    return result


def net_if_stats() -> dict:
    stats = {}
    try:
        nics = os.listdir("/sys/class/net")
    except FileNotFoundError:
        return stats
    for name in nics:
        base = f"/sys/class/net/{name}"
        def _g(p, default="0"):
            try:
                return read_file(os.path.join(base, p)).strip()
            except (OSError, FileNotFoundError):
                return default

        isup = _g("operstate") == "up" or _g("carrier") == "1"
        try:
            mtu = int(_g("mtu", "0"))
        except ValueError:
            mtu = 0
        try:
            speed = int(_g("speed", "0"))
        except (ValueError, OSError):
            speed = 0
        stats[name] = snicstats(isup, 0, speed, mtu)
    return stats


def boot_time() -> float:
    for line in read_lines("/proc/stat"):
        if line.startswith("btime "):
            return float(line.split()[1])
    return time.time() - _uptime()


def _uptime() -> float:
    try:
        return float(read_file("/proc/uptime").split()[0])
    except (FileNotFoundError, ValueError):
        return 0.0


def users() -> list:
    path = "/var/run/utmp"
    if not os.path.exists(path):
        path = "/run/utmp"
    out = []
    if not os.path.exists(path):
        # fallback from who via /dev/pts isn't reliable; return empty
        return out
    # Linux utmp record is typically 384 bytes
    rec_size = 384
    try:
        data = open(path, "rb").read()
    except OSError:
        return out
    for i in range(0, len(data) - rec_size + 1, rec_size):
        rec = data[i : i + rec_size]
        ut_type = struct.unpack_from("h", rec, 0)[0]
        if ut_type != 7:  # USER_PROCESS
            continue
        pid = struct.unpack_from("i", rec, 4)[0]
        line = rec[8:40].split(b"\0", 1)[0].decode("utf-8", "replace")
        user = rec[44:76].split(b"\0", 1)[0].decode("utf-8", "replace")
        host = rec[76:332].split(b"\0", 1)[0].decode("utf-8", "replace")
        tv_sec = struct.unpack_from("i", rec, 340)[0] if len(rec) > 344 else 0
        if user:
            out.append(suser(user, line, host, float(tv_sec), pid))
    return out
