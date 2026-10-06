import ctypes
import mmap
import os
from pathlib import Path
import resource
import signal
import sys
import time


class CloneArgs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "flags", "pidfd", "child_tid", "parent_tid", "exit_signal", "stack",
        "stack_size", "tls", "set_tid", "set_tid_size", "cgroup",
    )]


class CloneState(ctypes.Structure):
    _fields_ = [("phase", ctypes.c_ubyte), ("child", ctypes.c_int)]


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
path = Path(sys.argv[3])
gate = mmap.mmap(-1, ctypes.sizeof(CloneState))
state = CloneState.from_buffer(gate)
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
    state.phase = 1
    while state.phase == 1:
        libc.sched_yield()
    if state.phase == 4:
        root = os.getpid()
        child = libc.fork()
        if child < 0:
            state.child = child
            os._exit(ctypes.get_errno())
        if child:
            state.child = child
            _, status = os.waitpid(child, 0)
            os._exit(os.waitstatus_to_exitcode(status))
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(ctypes.get_errno())
        if os.getppid() != root:
            os._exit(0)
        state.phase = 5
        while state.phase == 5:
            libc.sched_yield()
    if state.phase != 2:
        os._exit(0)
    fd = libc.open(target, os.O_RDONLY | os.O_CLOEXEC)
    code = ctypes.get_errno() if fd < 0 else 0
    if fd >= 0:
        libc.close(fd)
    os._exit(code)

os.close(group)
reaped = False
try:
    ready = 1
    while True:
        deadline = time.monotonic() + 5
        while state.phase != ready:
            gone, status = os.waitpid(pid, os.WNOHANG)
            if gone:
                reaped = True
                if ready == 5:
                    path.with_suffix(".fork").write_text(str(state.child))
                    sys.exit(os.waitstatus_to_exitcode(status))
                raise RuntimeError(f"clone root exited before gate {ready}: {status}")
            if time.monotonic() >= deadline:
                raise TimeoutError(f"clone root {pid}; expected {ready}; last gate {state.phase}")
            time.sleep(0.005)
        if ready == 1:
            path.write_text(str(pid))
            print("native-fixture-ready", flush=True)
        command = sys.stdin.readline()
        if command == "fork\n" and ready == 1:
            state.phase = 4
            ready = 5
            continue
        if command and command != "open\n":
            raise ValueError(f"unexpected command: {command!r}")
        state.phase = 2 if command else 3
        break
    _, status = os.waitpid(pid, 0)
    reaped = True
    sys.exit(os.waitstatus_to_exitcode(status))
finally:
    if not reaped:
        state.phase = 3
        os.waitpid(pid, 0)
    del state
    gate.close()
