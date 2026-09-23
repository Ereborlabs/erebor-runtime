import ctypes
import errno
import mmap
import os
import sys


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
secret_path = "/tmp/mithril-descriptor-secret"
allowed_path = "/tmp/mithril-descriptor-allowed"
os.makedirs("/tmp", exist_ok=True)
for path, content in [(secret_path, b"secret\n"), (allowed_path, b"allowed\n")]:
    with open(path, "wb") as output:
        output.write(content)
secret = os.open(secret_path, os.O_RDONLY)
allowed = os.open(allowed_path, os.O_RDONLY)


def result(action):
    try:
        action()
    except OSError as failure:
        return failure.errno
    return 0


def read(descriptor):
    os.read(descriptor, 1)


def map_read(descriptor):
    mmap.mmap(descriptor, 1, access=mmap.ACCESS_READ).close()


print("native-fixture-ready", flush=True)
if sys.stdin.buffer.readline() != b"act\n":
    sys.exit(2)
results = [
    result(lambda: os.close(os.open(allowed_path, os.O_RDONLY))),
    result(lambda: read(secret)),
    result(lambda: map_read(secret)),
    result(lambda: read(allowed)),
    result(lambda: map_read(allowed)),
]
expected = [0, errno.EACCES, errno.EACCES, 0, 0]
name = ctypes.create_string_buffer(("fd-" + "-".join(map(str, results))).encode("ascii"))
if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
released = sys.stdin.buffer.readline() == b"release\n"
if results != expected or not released:
    sys.exit(3)
