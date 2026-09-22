import ctypes
import os
import select
import sys


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
action = sys.argv[2]
target = sys.argv[3]
next_path = sys.argv[4] if action in ("link", "rename") else None
descriptor = None

if action == "truncate":
    descriptor = os.open(target, os.O_WRONLY)

print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()
try:
    if action == "create":
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    elif action == "chmod":
        os.chmod(target, 0)
    elif action == "truncate":
        os.ftruncate(descriptor, 0)
    elif action == "unlink":
        os.unlink(target)
    elif action == "link":
        os.link(target, next_path)
    elif action == "rename":
        os.rename(target, next_path)
    else:
        raise ValueError(f"unsupported file action: {action}")
except OSError as failure:
    error = failure.errno
else:
    error = 0
name = ctypes.create_string_buffer(f"effect-{error}".encode("ascii"))
if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
release = select.poll()
release.register(sys.stdin, select.POLLIN | select.POLLHUP | select.POLLERR)
release.poll()
sys.exit(error)
