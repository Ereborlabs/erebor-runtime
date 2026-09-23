import ctypes
import select
import socket
import sys


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]

print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.connect(("127.0.0.1", 9))
except OSError as failure:
    error = failure.errno
else:
    error = 0
name = ctypes.create_string_buffer(f"connect-{error}".encode("ascii"))
if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
release = select.poll()
release.register(sys.stdin, select.POLLIN | select.POLLHUP | select.POLLERR)
release.poll()
sys.exit(error)
