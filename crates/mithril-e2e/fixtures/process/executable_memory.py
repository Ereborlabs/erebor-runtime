import ctypes
import errno
import mmap
import os
import sys
import time


libc = ctypes.CDLL(None, use_errno=True)
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.pkey_mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int]
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]


def error(action):
    try:
        action()
    except OSError as failure:
        return failure.errno or errno.EIO
    return 0


def map_page(protection):
    with mmap.mmap(-1, 1, flags=mmap.MAP_PRIVATE, prot=protection):
        pass


def protect(protection, key=False):
    with mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE,
                   prot=mmap.PROT_READ | mmap.PROT_WRITE) as region:
        address = ctypes.addressof(ctypes.c_char.from_buffer(region))
        if key:
            status = libc.pkey_mprotect(address, mmap.PAGESIZE, protection, 0)
        else:
            status = libc.mprotect(address, mmap.PAGESIZE, protection)
        if status != 0:
            raise OSError(ctypes.get_errno(), "memory protection")


def name(value):
    text = ctypes.create_string_buffer(value.encode("ascii"))
    if libc.prctl(15, ctypes.addressof(text), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "run\n":
    sys.exit(2)

results = [
    error(lambda: protect(mmap.PROT_READ | mmap.PROT_EXEC)),
    error(lambda: map_page(mmap.PROT_EXEC)),
    error(lambda: map_page(mmap.PROT_READ)),
    error(lambda: protect(mmap.PROT_READ | mmap.PROT_EXEC, True)),
    error(lambda: protect(mmap.PROT_READ, True)),
]
name("m-" + "-".join(map(str, results)))
while not os.path.exists(os.path.join(sys.argv[1], "release")):
    time.sleep(0.01)
