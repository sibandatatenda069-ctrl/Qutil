"""Shared exceptions and named tuples."""

from collections import namedtuple

STATUS_RUNNING = "running"
STATUS_SLEEPING = "sleeping"
STATUS_DISK_SLEEP = "disk-sleep"
STATUS_STOPPED = "stopped"
STATUS_TRACING_STOP = "tracing-stop"
STATUS_ZOMBIE = "zombie"
STATUS_DEAD = "dead"
STATUS_WAKE_KILL = "wake-kill"
STATUS_WAKING = "waking"
STATUS_IDLE = "idle"
STATUS_LOCKED = "locked"
STATUS_WAITING = "waiting"
STATUS_PARKED = "parked"

CONN_ESTABLISHED = "ESTABLISHED"
CONN_SYN_SENT = "SYN_SENT"
CONN_SYN_RECV = "SYN_RECV"
CONN_FIN_WAIT1 = "FIN_WAIT1"
CONN_FIN_WAIT2 = "FIN_WAIT2"
CONN_TIME_WAIT = "TIME_WAIT"
CONN_CLOSE = "CLOSE"
CONN_CLOSE_WAIT = "CLOSE_WAIT"
CONN_LAST_ACK = "LAST_ACK"
CONN_LISTEN = "LISTEN"
CONN_CLOSING = "CLOSING"
CONN_NONE = "NONE"

AF_INET = 2
AF_INET6 = 10
SOCK_STREAM = 1
SOCK_DGRAM = 2

_TCP_STATES = {
    "01": CONN_ESTABLISHED,
    "02": CONN_SYN_SENT,
    "03": CONN_SYN_RECV,
    "04": CONN_FIN_WAIT1,
    "05": CONN_FIN_WAIT2,
    "06": CONN_TIME_WAIT,
    "07": CONN_CLOSE,
    "08": CONN_CLOSE_WAIT,
    "09": CONN_LAST_ACK,
    "0A": CONN_LISTEN,
    "0B": CONN_CLOSING,
}

_PROC_STATUSES = {
    "R": STATUS_RUNNING,
    "S": STATUS_SLEEPING,
    "D": STATUS_DISK_SLEEP,
    "T": STATUS_STOPPED,
    "t": STATUS_TRACING_STOP,
    "Z": STATUS_ZOMBIE,
    "X": STATUS_DEAD,
    "x": STATUS_DEAD,
    "K": STATUS_WAKE_KILL,
    "W": STATUS_WAKING,
    "I": STATUS_IDLE,
    "P": STATUS_PARKED,
}


class Error(Exception):
    pass


class NoSuchProcess(Error):
    def __init__(self, pid=None, name=None, msg=None):
        self.pid = pid
        self.name = name
        if msg is None:
            msg = f"process PID {pid} no longer exists"
        super().__init__(msg)


class ZombieProcess(NoSuchProcess):
    def __init__(self, pid=None, name=None, ppid=None, msg=None):
        self.ppid = ppid
        if msg is None:
            msg = f"process PID {pid} is a zombie"
        super().__init__(pid, name, msg)


class AccessDenied(Error):
    def __init__(self, pid=None, name=None, msg=None):
        self.pid = pid
        self.name = name
        if msg is None:
            msg = f"access denied for process PID {pid}"
        super().__init__(msg)


class TimeoutExpired(Error):
    def __init__(self, seconds, pid=None, name=None):
        self.seconds = seconds
        self.pid = pid
        self.name = name
        super().__init__(f"timeout after {seconds} seconds (pid={pid})")


svmem = namedtuple(
    "svmem",
    ["total", "available", "percent", "used", "free", "active", "inactive", "buffers", "cached", "shared", "slab"],
)
sswap = namedtuple("sswap", ["total", "used", "free", "percent", "sin", "sout"])
sdiskusage = namedtuple("sdiskusage", ["total", "used", "free", "percent"])
sdiskpart = namedtuple("sdiskpart", ["device", "mountpoint", "fstype", "opts"])
sdiskio = namedtuple(
    "sdiskio",
    ["read_count", "write_count", "read_bytes", "write_bytes", "read_time", "write_time"],
)
snetio = namedtuple(
    "snetio",
    ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv", "errin", "errout", "dropin", "dropout"],
)
snicaddr = namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])
snicstats = namedtuple("snicstats", ["isup", "duplex", "speed", "mtu"])
suser = namedtuple("suser", ["name", "terminal", "host", "started", "pid"])
scputimes = namedtuple("scputimes", ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"])
scpufreq = namedtuple("scpufreq", ["current", "min", "max"])
scpustats = namedtuple("scpustats", ["ctx_switches", "interrupts", "soft_interrupts", "syscalls"])
pmem = namedtuple("pmem", ["rss", "vms", "shared", "text", "lib", "data", "dirty"])
pcputimes = namedtuple("pcputimes", ["user", "system", "children_user", "children_system"])
pio = namedtuple("pio", ["read_count", "write_count", "read_bytes", "write_bytes"])
pconn = namedtuple("pconn", ["fd", "family", "type", "laddr", "raddr", "status"])
popenfile = namedtuple("popenfile", ["path", "fd"])
pthread = namedtuple("pthread", ["id", "user_time", "system_time"])
addr = namedtuple("addr", ["ip", "port"])


def usage_percent(used, total, round_=1):
    try:
        ret = (float(used) / total) * 100
    except ZeroDivisionError:
        return 0.0
    if round_ is not None:
        ret = round(ret, round_)
    return ret
