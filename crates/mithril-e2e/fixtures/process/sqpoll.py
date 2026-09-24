import ctypes
import errno
import os
import sys
import time


if os.uname().machine not in ("aarch64", "x86_64"):
    raise RuntimeError(f"unsupported architecture: {os.uname().machine}")

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
work = sys.argv[1]
print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()

params = ctypes.create_string_buffer(120)
ctypes.c_uint32.from_buffer(params, 8).value = (1 << 6) | (1 << 12) | (1 << 1)
ctypes.set_errno(0)
fd = libc.syscall(425, 2, ctypes.byref(params))
if fd >= 0:
    os.close(fd)
error = ctypes.get_errno() if fd < 0 else 0
name = ctypes.create_string_buffer(f"sqpoll-{error}".encode("ascii"))
if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
while not os.path.exists(os.path.join(work, "release")):
    time.sleep(0.01)
sys.exit(error if error != errno.EACCES else 0)
