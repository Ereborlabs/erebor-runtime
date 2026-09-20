import ctypes
import os
import sys
import time


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
work = sys.argv[1]


def wait(name):
    while not os.path.exists(os.path.join(work, name)):
        time.sleep(0.01)


print("native-fixture-ready", flush=True)
wait("act")
try:
    descriptor = os.open("/proc/self/environ", os.O_RDONLY)
except OSError as failure:
    error = failure.errno
else:
    os.close(descriptor)
    error = 0
name = ctypes.create_string_buffer(f"proc-read-{error}".encode("ascii"))
if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
wait("release")
sys.exit(error)
