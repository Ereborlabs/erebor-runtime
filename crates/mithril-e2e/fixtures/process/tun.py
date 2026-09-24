import ctypes
import errno
import fcntl
import os
import stat
import struct
import sys
import time


device = "/dev/net/tun"
info = os.stat(device)
if not stat.S_ISCHR(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (10, 200):
    raise RuntimeError(f"{device} is not the TUN device")

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()

stage = "open"
try:
    with open(device, "r+b", buffering=0) as tun:
        stage = "ioctl"
        request = struct.pack("16sH22x", b"mithril0", 0x0001 | 0x1000)
        fcntl.ioctl(tun, 0x400454CA, request)
except OSError as failure:
    error = failure.errno or errno.EIO
else:
    error = 0
name = ctypes.create_string_buffer(f"tun-{stage}-{error}".encode("ascii"))
if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
while not os.path.exists(os.path.join(sys.argv[1], "release")):
    time.sleep(0.01)
sys.exit(0 if error == errno.EACCES else error or 1)
