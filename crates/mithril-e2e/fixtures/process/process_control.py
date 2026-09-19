import ctypes
import os
import select
import signal
import sys
import time


PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PR_SET_DUMPABLE = 4
PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
work = sys.argv[1]
mode = sys.argv[2]
if mode not in {"ptrace", "signal-zero", "signal-cont"}:
    raise ValueError(f"unsupported process-control mode: {mode}")
result_path = os.path.join(work, "control-result")
write_result = "no-result" not in sys.argv[2:]


def wait(name):
    while not os.path.exists(os.path.join(work, name)):
        time.sleep(0.01)

if write_result:
    with open(result_path, "w", encoding="ascii"):
        pass
print("native-fixture-ready", flush=True)
wait("spawn")

read_fd, release_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(release_fd)
    if libc.prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE)")
    poller = select.poll()
    poller.register(read_fd, select.POLLIN | select.POLLHUP)
    poller.poll()
    os._exit(0)
os.close(read_fd)

wait("act")

ctypes.set_errno(0)
if mode == "ptrace":
    result = libc.ptrace(PTRACE_ATTACH, child, None, None)
    error = ctypes.get_errno() if result == -1 else 0
else:
    try:
        os.kill(child, 0 if mode == "signal-zero" else signal.SIGCONT)
        result = 0
        error = 0
    except OSError as failure:
        result = -1
        error = failure.errno
if write_result:
    with open(result_path, "w", encoding="ascii") as output:
        output.write(f"{error}\n")
if mode == "ptrace" and result == 0:
    os.waitpid(child, os.WUNTRACED)
    libc.ptrace(PTRACE_DETACH, child, None, None)
if not write_result:
    name = ctypes.create_string_buffer(f"{mode}-{error}".encode("ascii"))
    if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
    wait("release")
    os.close(release_fd)
    os.waitpid(child, 0)
    sys.exit(error)
wait("release")
os.close(release_fd)
os.waitpid(child, 0)
sys.exit(error)
