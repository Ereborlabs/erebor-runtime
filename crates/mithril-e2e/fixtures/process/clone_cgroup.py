import ctypes
import mmap
import os
import resource
import signal
import sys
import time


class CloneArgs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "flags", "pidfd", "child_tid", "parent_tid", "exit_signal", "stack",
        "stack_size", "tls", "set_tid", "set_tid_size", "cgroup",
    )]


SYS_CLONE3 = 435
CLONE_INTO_CGROUP = 0x200000000
PR_SET_PDEATHSIG = 1
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.open.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                       ctypes.c_ulong, ctypes.c_ulong]
target = os.fsencode(sys.argv[2])
limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
parent = os.getpid()
gate = mmap.mmap(-1, 1)
group = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
args = CloneArgs(flags=CLONE_INTO_CGROUP, exit_signal=signal.SIGCHLD, cgroup=group)
pid = libc.syscall(SYS_CLONE3, ctypes.byref(args), ctypes.c_size_t(ctypes.sizeof(args)))
if pid < 0:
    raise OSError(ctypes.get_errno(), "clone3(CLONE_INTO_CGROUP)")
if pid == 0:
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(ctypes.get_errno())
    if os.getppid() != parent:
        os._exit(0)
    os.closerange(3, limit)
    gate[0] = 1
    while gate[0] == 1:
        libc.sched_yield()
    if gate[0] != 2:
        os._exit(0)
    fd = libc.open(target, os.O_RDONLY | os.O_CLOEXEC)
    code = ctypes.get_errno() if fd < 0 else 0
    if fd >= 0:
        libc.close(fd)
    os._exit(code)

os.close(group)
reaped = False
try:
    deadline = time.monotonic() + 5
    while gate[0] != 1:
        gone, status = os.waitpid(pid, os.WNOHANG)
        if gone:
            reaped = True
            raise RuntimeError(f"clone root exited before readiness: {status}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"clone root {pid} did not reach its gate: {gate[0]}")
        time.sleep(0.005)
    with open(sys.argv[3], "w") as output:
        output.write(str(pid))
    print("native-fixture-ready", flush=True)
    command = sys.stdin.readline()
    if command and command != "open\n":
        raise ValueError(f"unexpected command: {command!r}")
    gate[0] = 2 if command else 3
    _, status = os.waitpid(pid, 0)
    reaped = True
    sys.exit(os.waitstatus_to_exitcode(status))
finally:
    if not reaped:
        gate[0] = 3
        os.waitpid(pid, 0)
    gate.close()
