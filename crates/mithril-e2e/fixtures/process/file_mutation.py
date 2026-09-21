import ctypes
import os
import sys


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
action = sys.argv[2]
target = sys.argv[3]

print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()
try:
    if action != "create":
        raise ValueError(f"unsupported file action: {action}")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except OSError as failure:
    error = failure.errno
else:
    os.close(descriptor)
    error = 0
name = ctypes.create_string_buffer(f"effect-{error}".encode("ascii"))
if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
sys.stdin.buffer.readline()
sys.exit(error)
