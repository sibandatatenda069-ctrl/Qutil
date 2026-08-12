# Qutil

A lightweight, **psutil-compatible** process and system utilities library for Linux.

Qutil reads `/proc` and `/sys` (no C extensions) and exposes the familiar
`psutil` surface: `Process`, `cpu_percent`, `virtual_memory`, disk and net
counters, and a small CLI.

## Install

```bash
pip install -e .
```

## Library

```python
import qutil

print(qutil.cpu_percent(interval=0.2))
print(qutil.virtual_memory())
print(qutil.disk_usage("/"))

p = qutil.Process()          # this process
print(p.name(), p.memory_info().rss)

for proc in qutil.process_iter(["pid", "name", "cpu_percent"]):
    print(proc.info)
```

### System APIs

| Function | Meaning |
|---|---|
| `cpu_count`, `cpu_times`, `cpu_percent`, `cpu_freq`, `cpu_stats` | CPU |
| `virtual_memory`, `swap_memory` | RAM / swap |
| `disk_usage`, `disk_partitions`, `disk_io_counters` | Disk |
| `net_io_counters`, `net_connections`, `net_if_stats`, `net_if_addrs` | Network |
| `boot_time`, `users` | Host |

### Process APIs

`Process(pid)`: `name`, `exe`, `cmdline`, `cwd`, `status`, `ppid`, `parent`,
`children`, `username`, `create_time`, `cpu_times`, `cpu_percent`,
`memory_info`, `memory_percent`, `io_counters`, `num_threads`, `threads`,
`open_files`, `connections`, `nice`, `num_fds`, `terminate`, `kill`, `wait`,
`as_dict`.

Also: `pids()`, `pid_exists()`, `process_iter()`, `wait_procs()`, `Popen`.

Exceptions: `NoSuchProcess`, `ZombieProcess`, `AccessDenied`, `TimeoutExpired`.

## CLI

```bash
qutil              # system snapshot
qutil sys
qutil ps --sort cpu -n 20
qutil proc 1
```

## Tests

```bash
python -m pytest tests -q
```

Linux only (uses `/proc`). Python 3.8+.
