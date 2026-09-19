import ctypes
import os
import sys
import time


PTRACE_ATTACH = 16
PTRACE_DETACH = 17
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
work = sys.argv[1]
result_path = os.path.join(work, "ptrace-result")
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
    os.read(read_fd, 1)
    os._exit(0)
os.close(read_fd)

wait("ptrace")

ctypes.set_errno(0)
result = libc.ptrace(PTRACE_ATTACH, child, None, None)
error = ctypes.get_errno() if result == -1 else 0
if write_result:
    with open(result_path, "w", encoding="ascii") as output:
        output.write(f"{error}\n")
if result == 0:
    os.waitpid(child, os.WUNTRACED)
    libc.ptrace(PTRACE_DETACH, child, None, None)
if not write_result:
    os.close(release_fd)
    os.waitpid(child, 0)
    sys.exit(error)
wait("release")
os.close(release_fd)
os.waitpid(child, 0)
sys.exit(error)
