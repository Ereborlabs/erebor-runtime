import ctypes
import os
import sys
import time


MAP_CREATE = 0
MAP_TYPE = 2
PR_SET_NAME = 15
calls = {"aarch64": 280, "x86_64": 321}
call_no = calls.get(os.uname().machine)
if call_no is None:
    raise RuntimeError(f"unsupported architecture: {os.uname().machine}")
work = sys.argv[1]


class MapAttr(ctypes.Structure):
    _fields_ = [
        ("map_type", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
    ]


libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()
attr = MapAttr(MAP_TYPE, 4, 4, 1)
ctypes.set_errno(0)
fd = libc.syscall(call_no, MAP_CREATE, ctypes.byref(attr), ctypes.sizeof(attr))
if fd >= 0:
    os.close(fd)
error = ctypes.get_errno() if fd < 0 else 0
name = ctypes.create_string_buffer(f"bpf-map-{error}".encode("ascii"))
if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
while not os.path.exists(os.path.join(work, "release")):
    time.sleep(0.01)
sys.exit(error)
