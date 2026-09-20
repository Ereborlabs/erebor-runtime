import ctypes
import os
import sys


MAP_CREATE = 0
MAP_TYPE = 2
calls = {"aarch64": 280, "x86_64": 321}
call_no = calls.get(os.uname().machine)
if call_no is None:
    raise RuntimeError(f"unsupported architecture: {os.uname().machine}")


class MapAttr(ctypes.Structure):
    _fields_ = [
        ("map_type", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
    ]


libc = ctypes.CDLL(None, use_errno=True)
print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()
attr = MapAttr(MAP_TYPE, 4, 4, 1)
ctypes.set_errno(0)
fd = libc.syscall(call_no, MAP_CREATE, ctypes.byref(attr), ctypes.sizeof(attr))
if fd >= 0:
    os.close(fd)
error = ctypes.get_errno() if fd < 0 else 0
sys.exit(error)
