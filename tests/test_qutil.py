import os
import time

import qutil


def test_version():
    assert qutil.__version__


def test_cpu():
    n = qutil.cpu_count()
    assert n is None or n >= 1
    times = qutil.cpu_times()
    assert times.idle >= 0
    pct = qutil.cpu_percent(interval=0.05)
    assert 0 <= pct <= 100 * (n or 1)


def test_memory():
    vm = qutil.virtual_memory()
    assert vm.total > 0
    assert 0 <= vm.percent <= 100
    sw = qutil.swap_memory()
    assert sw.total >= 0


def test_disk():
    du = qutil.disk_usage("/")
    assert du.total > 0
    parts = qutil.disk_partitions(all=True)
    assert isinstance(parts, list)
    io = qutil.disk_io_counters()
    assert io.read_bytes >= 0


def test_net():
    io = qutil.net_io_counters()
    assert io.bytes_recv >= 0
    stats = qutil.net_if_stats()
    assert isinstance(stats, dict)


def test_boot_time():
    bt = qutil.boot_time()
    assert bt < time.time()
    assert bt > 0


def test_pids_and_self():
    me = os.getpid()
    assert me in qutil.pids()
    assert qutil.pid_exists(me)
    assert not qutil.pid_exists(-1)
    p = qutil.Process()
    assert p.pid == me
    assert p.name()
    assert p.ppid() >= 0
    assert p.memory_info().rss > 0
    assert p.cpu_times().user >= 0
    assert isinstance(p.cmdline(), list)
    assert p.is_running()
    d = p.as_dict(attrs=["pid", "name", "status"])
    assert d["pid"] == me


def test_process_iter():
    found = False
    for proc in qutil.process_iter(attrs=["pid", "name"]):
        if proc.pid == os.getpid():
            found = True
            break
    assert found


def test_no_such_process():
    try:
        qutil.Process(2**22)
        assert False, "expected NoSuchProcess"
    except qutil.NoSuchProcess:
        pass
