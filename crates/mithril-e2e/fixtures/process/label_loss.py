import ctypes
import mmap
import select
import sys


libc = ctypes.CDLL(None, use_errno=True)
release = select.poll()
release.register(sys.stdin, select.POLLHUP | select.POLLERR)
with open(sys.argv[1], "r+b") as source, mmap.mmap(source.fileno(), 1) as control:
    if libc.prctl(15, b"label-held", 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "set held process name")
    print("native-fixture-ready", flush=True)
    while control[0] == 0:
        if release.poll(10):
            sys.exit(0)
    if control[0] != 1:
        raise RuntimeError("expected read")
    with open("/etc/hostname", "rb") as hostname:
        if not hostname.read():
            raise RuntimeError("the hostname read returned no bytes")
    if libc.prctl(15, b"label-read-ok", 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "set read result process name")
    release.poll()
