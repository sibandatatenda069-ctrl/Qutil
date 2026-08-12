"""Process inspection and management."""

from __future__ import annotations

import os
import signal
import time
from typing import Callable, Iterable, Optional

from qutil._common import (
    AF_INET,
    AF_INET6,
    SOCK_DGRAM,
    SOCK_STREAM,
    AccessDenied,
    NoSuchProcess,
    TimeoutExpired,
    ZombieProcess,
    _PROC_STATUSES,
    addr,
    pconn,
    pcputimes,
    pio,
    pmem,
    popenfile,
    pthread,
    usage_percent,
)
from qutil._linux import (
    assert_pid_exists,
    clock_ticks,
    hex_ip_port,
    page_size,
    proc_path,
    read_lines,
    safe_read,
)
from qutil._system import boot_time, virtual_memory


def pids() -> list[int]:
    out = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            out.append(int(name))
    return sorted(out)


def pid_exists(pid: int) -> bool:
    if pid < 0:
        return False
    if pid == 0:
        return True
    return os.path.exists(proc_path(pid))


def process_iter(attrs=None, ad_value=None):
    seen = set()
    for pid in pids():
        if pid in seen:
            continue
        seen.add(pid)
        try:
            proc = Process(pid)
            if attrs:
                proc.info = proc.as_dict(attrs, ad_value)
            yield proc
        except (NoSuchProcess, ZombieProcess):
            continue


def wait_procs(procs, timeout=None, callback=None):
    gone, alive = [], list(procs)
    deadline = None if timeout is None else time.time() + timeout
    while alive:
        still = []
        for p in alive:
            if not p.is_running():
                try:
                    p.returncode = p.wait(0)
                except Exception:
                    p.returncode = None
                gone.append(p)
                if callback:
                    callback(p)
            else:
                still.append(p)
        alive = still
        if not alive:
            break
        if deadline is not None and time.time() >= deadline:
            break
        time.sleep(0.04)
    return gone, alive


class Process:
    def __init__(self, pid: Optional[int] = None):
        if pid is None:
            pid = os.getpid()
        if pid < 0:
            raise NoSuchProcess(pid)
        self._pid = int(pid)
        self._name = None
        self._create_time = None
        self._gone = False
        self._cpu_times_cache = None
        self._last_sys_cpu = None
        self.info = None
        assert_pid_exists(self._pid)
        # cache identity
        try:
            self._ident = (self._pid, self.create_time())
        except (NoSuchProcess, AccessDenied):
            self._ident = (self._pid, None)

    def __repr__(self) -> str:
        try:
            name = self.name()
        except (NoSuchProcess, AccessDenied):
            name = "?"
        return f"<Process pid={self._pid} name={name!r}>"

    def __eq__(self, other) -> bool:
        if not isinstance(other, Process):
            return NotImplemented
        return self._ident == other._ident

    def __hash__(self) -> int:
        return hash(self._ident)

    @property
    def pid(self) -> int:
        return self._pid

    def _stat_fields(self) -> list[str]:
        data = safe_read(self._pid, "stat")
        rpar = data.rfind(")")
        lpar = data.find("(")
        name = data[lpar + 1 : rpar]
        rest = data[rpar + 2 :].split()
        return [data[:lpar].strip(), name] + rest

    def name(self) -> str:
        if self._name is None:
            try:
                self._name = self._stat_fields()[1]
            except (NoSuchProcess, AccessDenied):
                comm = safe_read(self._pid, "comm").strip()
                self._name = comm
        return self._name

    def exe(self) -> str:
        try:
            return os.readlink(proc_path(self._pid, "exe"))
        except FileNotFoundError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)

    def cmdline(self) -> list[str]:
        data = safe_read(self._pid, "cmdline")
        if not data:
            return []
        return [p for p in data.split("\0") if p]

    def cwd(self) -> str:
        try:
            return os.readlink(proc_path(self._pid, "cwd"))
        except FileNotFoundError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)

    def status(self) -> str:
        letter = self._stat_fields()[2]
        return _PROC_STATUSES.get(letter, "?")

    def ppid(self) -> int:
        return int(self._stat_fields()[3])

    def parent(self) -> Optional["Process"]:
        ppid = self.ppid()
        if ppid == 0:
            return None
        try:
            return Process(ppid)
        except NoSuchProcess:
            return None

    def parents(self) -> list:
        out = []
        p = self.parent()
        seen = set()
        while p is not None and p.pid not in seen:
            seen.add(p.pid)
            out.append(p)
            p = p.parent()
        return out

    def children(self, recursive: bool = False) -> list:
        table = {}
        for pid in pids():
            try:
                ppid = Process(pid).ppid()
            except (NoSuchProcess, AccessDenied):
                continue
            table.setdefault(ppid, []).append(pid)
        if not recursive:
            return [Process(p) for p in table.get(self._pid, [])]
        out = []
        stack = list(table.get(self._pid, []))
        while stack:
            c = stack.pop()
            out.append(Process(c))
            stack.extend(table.get(c, []))
        return out

    def username(self) -> str:
        try:
            import pwd

            st = os.stat(proc_path(self._pid))
            return pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            return str(os.stat(proc_path(self._pid)).st_uid)
        except FileNotFoundError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)

    def uids(self):
        for line in safe_read(self._pid, "status").splitlines():
            if line.startswith("Uid:"):
                parts = line.split()
                return int(parts[1]), int(parts[2]), int(parts[3])
        raise AccessDenied(self._pid)

    def gids(self):
        for line in safe_read(self._pid, "status").splitlines():
            if line.startswith("Gid:"):
                parts = line.split()
                return int(parts[1]), int(parts[2]), int(parts[3])
        raise AccessDenied(self._pid)

    def create_time(self) -> float:
        if self._create_time is None:
            start = int(self._stat_fields()[21])
            self._create_time = boot_time() + start / float(clock_ticks())
        return self._create_time

    def cpu_times(self) -> pcputimes:
        f = self._stat_fields()
        clk = float(clock_ticks())
        utime, stime = int(f[13]) / clk, int(f[14]) / clk
        cutime, cstime = int(f[15]) / clk, int(f[16]) / clk
        return pcputimes(utime, stime, cutime, cstime)

    def cpu_percent(self, interval: Optional[float] = None) -> float:
        def _sample():
            ct = self.cpu_times()
            return ct.user + ct.system, time.time()

        if interval is not None and interval > 0:
            t1, w1 = _sample()
            time.sleep(interval)
            t2, w2 = _sample()
        else:
            if self._cpu_times_cache is None:
                self._cpu_times_cache = _sample()
                return 0.0
            t1, w1 = self._cpu_times_cache
            t2, w2 = _sample()
            self._cpu_times_cache = (t2, w2)
        dt = w2 - w1
        if dt <= 0:
            return 0.0
        ncpu = os.cpu_count() or 1
        return round(min(100.0 * ncpu, ((t2 - t1) / dt) * 100.0), 1)

    def cpu_num(self) -> int:
        return int(self._stat_fields()[38])

    def memory_info(self) -> pmem:
        try:
            data = safe_read(self._pid, "statm").split()
            ps = page_size()
            vms = int(data[0]) * ps
            rss = int(data[1]) * ps
            shared = int(data[2]) * ps
            text = int(data[3]) * ps
            lib = int(data[4]) * ps
            data_seg = int(data[5]) * ps
            dirty = int(data[6]) * ps if len(data) > 6 else 0
            return pmem(rss, vms, shared, text, lib, data_seg, dirty)
        except (IndexError, ValueError):
            return pmem(0, 0, 0, 0, 0, 0, 0)

    def memory_percent(self) -> float:
        rss = self.memory_info().rss
        total = virtual_memory().total
        return usage_percent(rss, total)

    def memory_maps(self) -> list:
        maps = []
        try:
            text = safe_read(self._pid, "maps")
        except AccessDenied:
            raise
        for line in text.splitlines():
            maps.append(line)
        return maps

    def io_counters(self) -> pio:
        read_count = write_count = read_bytes = write_bytes = 0
        try:
            for line in safe_read(self._pid, "io").splitlines():
                if line.startswith("syscr:"):
                    read_count = int(line.split()[1])
                elif line.startswith("syscw:"):
                    write_count = int(line.split()[1])
                elif line.startswith("read_bytes:"):
                    read_bytes = int(line.split()[1])
                elif line.startswith("write_bytes:"):
                    write_bytes = int(line.split()[1])
        except AccessDenied:
            raise
        return pio(read_count, write_count, read_bytes, write_bytes)

    def num_threads(self) -> int:
        return int(self._stat_fields()[19])

    def threads(self) -> list:
        out = []
        task = proc_path(self._pid, "task")
        try:
            tids = os.listdir(task)
        except FileNotFoundError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)
        clk = float(clock_ticks())
        for tid in tids:
            try:
                data = open(os.path.join(task, tid, "stat"), encoding="utf-8", errors="replace").read()
                rpar = data.rfind(")")
                rest = data[rpar + 2 :].split()
                utime = int(rest[11]) / clk
                stime = int(rest[12]) / clk
                out.append(pthread(int(tid), utime, stime))
            except (OSError, IndexError, ValueError):
                continue
        return out

    def open_files(self) -> list:
        fd_dir = proc_path(self._pid, "fd")
        out = []
        try:
            fds = os.listdir(fd_dir)
        except FileNotFoundError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("/") and not target.startswith("socket:") and not target.startswith("pipe:"):
                out.append(popenfile(target, int(fd)))
        return out

    def connections(self, kind: str = "inet") -> list:
        # map inode -> fd
        inodes = {}
        fd_dir = proc_path(self._pid, "fd")
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if target.startswith("socket:["):
                    ino = target[8:-1]
                    inodes[ino] = int(fd)
        except FileNotFoundError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)

        files = []
        if kind in ("inet", "all", "tcp", "inet4"):
            files.append(("/proc/net/tcp", AF_INET, SOCK_STREAM, False))
        if kind in ("inet", "all", "tcp", "inet6"):
            files.append(("/proc/net/tcp6", AF_INET6, SOCK_STREAM, False))
        if kind in ("inet", "all", "udp", "inet4"):
            files.append(("/proc/net/udp", AF_INET, SOCK_DGRAM, True))
        if kind in ("inet", "all", "udp", "inet6"):
            files.append(("/proc/net/udp6", AF_INET6, SOCK_DGRAM, True))

        from qutil._common import _TCP_STATES

        out = []
        for path, family, typ, udp in files:
            try:
                lines = read_lines(path)
            except (FileNotFoundError, PermissionError):
                continue
            ipv6 = family == AF_INET6
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 10:
                    continue
                inode = parts[9]
                if inode not in inodes:
                    continue
                try:
                    laddr = hex_ip_port(parts[1], ipv6)
                    raddr = hex_ip_port(parts[2], ipv6)
                except (ValueError, OSError):
                    continue
                status = "NONE" if udp else _TCP_STATES.get(parts[3].upper(), "NONE")
                r = addr(*raddr) if raddr[1] else ()
                out.append(pconn(inodes[inode], family, typ, addr(*laddr), r, status))
        return out

    def nice(self, value: Optional[int] = None) -> int:
        if value is None:
            try:
                return os.getpriority(os.PRIO_PROCESS, self._pid)
            except ProcessLookupError:
                raise NoSuchProcess(self._pid)
            except PermissionError:
                raise AccessDenied(self._pid)
        try:
            os.setpriority(os.PRIO_PROCESS, self._pid, int(value))
        except ProcessLookupError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)
        return value

    def num_fds(self) -> int:
        try:
            return len(os.listdir(proc_path(self._pid, "fd")))
        except FileNotFoundError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)

    def num_ctx_switches(self):
        vol = unvol = 0
        for line in safe_read(self._pid, "status").splitlines():
            if line.startswith("voluntary_ctxt_switches:"):
                vol = int(line.split()[1])
            elif line.startswith("nonvoluntary_ctxt_switches:"):
                unvol = int(line.split()[1])
        return vol, unvol

    def terminal(self) -> Optional[str]:
        tty_nr = int(self._stat_fields()[6])
        if tty_nr == 0:
            return None
        return f"tty:{tty_nr}"

    def is_running(self) -> bool:
        if self._gone:
            return False
        if not pid_exists(self._pid):
            self._gone = True
            return False
        try:
            return abs(self.create_time() - Process(self._pid).create_time()) < 0.01 or True
        except NoSuchProcess:
            self._gone = True
            return False

    def send_signal(self, sig: int) -> None:
        try:
            os.kill(self._pid, sig)
        except ProcessLookupError:
            raise NoSuchProcess(self._pid)
        except PermissionError:
            raise AccessDenied(self._pid)

    def terminate(self) -> None:
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        self.send_signal(signal.SIGKILL)

    def suspend(self) -> None:
        self.send_signal(signal.SIGSTOP)

    def resume(self) -> None:
        self.send_signal(signal.SIGCONT)

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        if self._pid == os.getpid():
            raise ValueError("can't wait on self")
        deadline = None if timeout is None else time.time() + timeout
        while pid_exists(self._pid):
            # if pid reused with different start time, consider gone
            try:
                if abs(Process(self._pid).create_time() - self.create_time()) > 0.05:
                    return None
            except NoSuchProcess:
                return None
            if deadline is not None and time.time() >= deadline:
                raise TimeoutExpired(timeout, self._pid, self._name)
            time.sleep(0.05)
        return None

    def as_dict(self, attrs: Optional[Iterable[str]] = None, ad_value=None) -> dict:
        methods = {
            "pid": lambda: self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "cwd": self.cwd,
            "status": self.status,
            "ppid": self.ppid,
            "username": self.username,
            "create_time": self.create_time,
            "cpu_percent": self.cpu_percent,
            "cpu_times": self.cpu_times,
            "memory_info": self.memory_info,
            "memory_percent": self.memory_percent,
            "num_threads": self.num_threads,
            "nice": self.nice,
            "num_fds": self.num_fds,
            "io_counters": self.io_counters,
        }
        if attrs is None:
            attrs = list(methods)
        out = {}
        for name in attrs:
            fn = methods.get(name)
            if fn is None:
                continue
            try:
                out[name] = fn()
            except AccessDenied:
                out[name] = ad_value
            except NoSuchProcess:
                raise
        return out

    oneshot = as_dict


class Popen(Process):
    """Wrapper around subprocess.Popen that is also a Process."""

    def __init__(self, *args, **kwargs):
        import subprocess

        self._popen = subprocess.Popen(*args, **kwargs)
        super().__init__(self._popen.pid)
        self.returncode = None

    def wait(self, timeout=None):
        self.returncode = self._popen.wait(timeout=timeout)
        return self.returncode

    def communicate(self, *a, **k):
        return self._popen.communicate(*a, **k)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self._popen.stdout:
            self._popen.stdout.close()
        if self._popen.stderr:
            self._popen.stderr.close()
        if self._popen.stdin:
            self._popen.stdin.close()
        self.wait()
