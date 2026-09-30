import array
import ctypes
import fcntl
import os
import sys
import time

# Linux UAPI: _IOR('T', 0x30, unsigned int), on x86-64 and AArch64.
TIOCGPTN = 0x80045430


class Device:
    def __init__(self):
        if os.uname().machine not in ("aarch64", "x86_64"):
            raise RuntimeError("unsupported ioctl ABI")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.prctl.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                                   ctypes.c_ulong, ctypes.c_ulong]
        self.fd = os.open("/dev/pts/ptmx", os.O_RDWR | os.O_NOCTTY)

    def number(self):
        number = array.array("I", [0xFFFFFFFF])
        fcntl.ioctl(self.fd, TIOCGPTN, number, True)
        if number[0] == 0xFFFFFFFF:
            raise RuntimeError("TIOCGPTN did not return a PTY number")

    def name(self, value):
        name = ctypes.create_string_buffer(value.encode("ascii"))
        if self.libc.prctl(15, name, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")

    def close(self):
        os.close(self.fd)


device = Device()
try:
    device.number()
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "number\n":
        raise RuntimeError("expected number")
    try:
        device.number()
        error = 0
    except OSError as failure:
        error = failure.errno
    device.name(f"ioctl-{error}")
    while not os.path.exists(os.path.join(sys.argv[1], "release")):
        time.sleep(0.01)
finally:
    device.close()
device.name("ioctl-clean")
while not os.path.exists(os.path.join(sys.argv[1], "finish")):
    time.sleep(0.01)
