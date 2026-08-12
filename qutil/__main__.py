"""CLI: qutil — compact system / process snapshot."""

from __future__ import annotations

import argparse
import os
import sys

import qutil


def _fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024:
            return f"{n:6.1f}{unit}"
        n /= 1024
    return f"{n:6.1f}P"


def cmd_sys(_args) -> int:
    vm = qutil.virtual_memory()
    sw = qutil.swap_memory()
    cpu = qutil.cpu_percent(interval=0.2)
    print(f"qutil {qutil.__version__}  pid={os.getpid()}  cpus={qutil.cpu_count()}")
    print(f"cpu     {cpu:5.1f}%")
    print(f"memory  {vm.percent:5.1f}%  used={_fmt_bytes(vm.used)}  avail={_fmt_bytes(vm.available)}  total={_fmt_bytes(vm.total)}")
    print(f"swap    {sw.percent:5.1f}%  used={_fmt_bytes(sw.used)}  total={_fmt_bytes(sw.total)}")
    try:
        root = qutil.disk_usage("/")
        print(f"disk /  {root.percent:5.1f}%  used={_fmt_bytes(root.used)}  free={_fmt_bytes(root.free)}")
    except OSError:
        pass
    net = qutil.net_io_counters()
    print(f"net     sent={_fmt_bytes(net.bytes_sent)}  recv={_fmt_bytes(net.bytes_recv)}")
    return 0


def cmd_ps(args) -> int:
    attrs = ["pid", "name", "username", "status", "cpu_percent", "memory_percent"]
    print(f"{'PID':>7} {'USER':<12} {'STAT':<10} {'CPU%':>6} {'MEM%':>6} NAME")
    rows = []
    for p in qutil.process_iter(attrs=attrs, ad_value="?"):
        info = p.info
        try:
            cpu = float(info.get("cpu_percent") or 0)
            mem = float(info.get("memory_percent") or 0)
        except (TypeError, ValueError):
            cpu = mem = 0.0
        rows.append((info.get("pid"), info.get("username") or "?", info.get("status") or "?", cpu, mem, info.get("name") or "?"))
    if args.sort == "cpu":
        rows.sort(key=lambda r: r[3], reverse=True)
    elif args.sort == "mem":
        rows.sort(key=lambda r: r[4], reverse=True)
    else:
        rows.sort(key=lambda r: r[0])
    limit = args.n or len(rows)
    for pid, user, stat, cpu, mem, name in rows[:limit]:
        print(f"{pid:7} {str(user)[:12]:<12} {str(stat)[:10]:<10} {cpu:6.1f} {mem:6.1f} {name}")
    return 0


def cmd_proc(args) -> int:
    try:
        p = qutil.Process(args.pid)
    except qutil.NoSuchProcess:
        print(f"no such process: {args.pid}", file=sys.stderr)
        return 1
    info = p.as_dict()
    for k in sorted(info):
        print(f"{k:16} {info[k]}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="qutil", description="Process and system utilities (psutil-like)")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("sys", help="system snapshot")

    ps = sub.add_parser("ps", help="list processes")
    ps.add_argument("-n", type=int, default=None, help="limit rows")
    ps.add_argument("--sort", choices=["pid", "cpu", "mem"], default="pid")

    pr = sub.add_parser("proc", help="inspect one process")
    pr.add_argument("pid", type=int)

    args = parser.parse_args(argv)
    if args.cmd == "ps":
        return cmd_ps(args)
    if args.cmd == "proc":
        return cmd_proc(args)
    return cmd_sys(args)


if __name__ == "__main__":
    raise SystemExit(main())
