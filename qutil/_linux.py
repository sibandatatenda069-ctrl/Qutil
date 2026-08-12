"""Linux /proc and /sys helpers."""

from __future__ import annotations

import os
import socket
import struct
from typing import Optional

from qutil._common import AccessDenied, NoSuchProcess


def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def read_lines(path: str) -> list[str]:
    return read_file(path).splitlines()


def proc_path(pid: int, *parts: str) -> str:
    return os.path.join("/proc", str(pid), *parts)


def assert_pid_exists(pid: int) -> None:
    if pid < 0:
        raise NoSuchProcess(pid)
    if not os.path.exists(proc_path(pid)):
        raise NoSuchProcess(pid)


def wrap_os_error(pid: int, exc: OSError) -> Exception:
    if exc.errno in (os.errno.ENOENT, 2) if hasattr(os, "errno") else (exc.errno == 2):
        raise NoSuchProcess(pid) from exc
    if exc.errno in (13,):  # EACCES
        raise AccessDenied(pid) from exc
    if exc.errno in (1,):  # EPERM
        raise AccessDenied(pid) from exc
    return exc


def safe_read(pid: int, *parts: str) -> str:
    path = proc_path(pid, *parts)
    try:
        return read_file(path)
    except FileNotFoundError as e:
        raise NoSuchProcess(pid) from e
    except PermissionError as e:
        raise AccessDenied(pid) from e
    except OSError as e:
        if e.errno == 2:
            raise NoSuchProcess(pid) from e
        if e.errno in (1, 13):
            raise AccessDenied(pid) from e
        raise


def parse_meminfo() -> dict[str, int]:
    info: dict[str, int] = {}
    for line in read_lines("/proc/meminfo"):
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.split()
        if not parts:
            continue
        value = int(parts[0])
        unit = parts[1].lower() if len(parts) > 1 else "kb"
        if unit == "kb":
            value *= 1024
        elif unit == "mb":
            value *= 1024 * 1024
        info[key] = value
    return info


def parse_stat_cpu_line(line: str) -> tuple:
    fields = line.split()
    # cpu user nice system idle iowait irq softirq steal guest guest_nice
    nums = [int(x) for x in fields[1:11]]
    while len(nums) < 10:
        nums.append(0)
    clk = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK"))
    return tuple(n / clk for n in nums[:10])


def hex_ip_port(hexstr: str, ipv6: bool = False) -> tuple[str, int]:
    ip_hex, port_hex = hexstr.split(":")
    port = int(port_hex, 16)
    if ipv6:
        # 32 hex chars, little-endian 32-bit words
        raw = bytes.fromhex(ip_hex)
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        packed = b"".join(words)
        ip = socket.inet_ntop(socket.AF_INET6, packed)
    else:
        packed = struct.pack("<I", int(ip_hex, 16))
        ip = socket.inet_ntoa(packed)
    return ip, port


def clock_ticks() -> int:
    return os.sysconf("SC_CLK_TCK")


def page_size() -> int:
    return os.sysconf("SC_PAGE_SIZE")
