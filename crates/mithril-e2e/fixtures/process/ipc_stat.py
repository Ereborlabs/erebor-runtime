import ctypes
import os
import sys
import time

IPC_PRIVATE = 0
IPC_RMID = 0
IPC_STAT = 2
SHM_RDONLY = 0o10000
PR_SET_NAME = 15


class IpcPerm(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_int),
        ("uid", ctypes.c_uint),
        ("gid", ctypes.c_uint),
        ("cuid", ctypes.c_uint),
        ("cgid", ctypes.c_uint),
        ("mode", ctypes.c_uint),
        ("sequence", ctypes.c_ushort),
        ("padding", ctypes.c_ushort),
        ("reserved", ctypes.c_ulong * 2),
    ]


class SegmentInfo(ctypes.Structure):
    _fields_ = [
        ("permission", IpcPerm),
        ("size", ctypes.c_size_t),
        ("attached", ctypes.c_long),
        ("detached", ctypes.c_long),
        ("changed", ctypes.c_long),
        ("creator", ctypes.c_int),
        ("last_pid", ctypes.c_int),
        ("attachments", ctypes.c_ulong),
        ("reserved", ctypes.c_ulong * 2),
    ]


class Segment:
    def __init__(self):
        if os.uname().machine not in ("aarch64", "x86_64"):
            raise RuntimeError("unsupported SysV libc ABI")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
        self.libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.libc.shmat.restype = ctypes.c_void_p
        self.libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(SegmentInfo)]
        self.libc.shmdt.argtypes = [ctypes.c_void_p]
        self.id = self.libc.shmget(IPC_PRIVATE, os.sysconf("SC_PAGESIZE"), 0o600)
        if self.id < 0:
            raise OSError(ctypes.get_errno(), "shmget(IPC_PRIVATE)")
        self.address = self.libc.shmat(self.id, None, SHM_RDONLY)
        if self.address == ctypes.c_void_p(-1).value:
            error = ctypes.get_errno()
            self.libc.shmctl(self.id, IPC_RMID, None)
            raise OSError(error, "shmat(SHM_RDONLY)")
        if self.libc.shmctl(self.id, IPC_RMID, None) != 0:
            error = ctypes.get_errno()
            self.libc.shmdt(self.address)
            raise OSError(error, "shmctl(IPC_RMID)")

    def stat(self):
        info = SegmentInfo()
        ctypes.set_errno(0)
        result = self.libc.shmctl(self.id, IPC_STAT, ctypes.byref(info))
        return ctypes.get_errno() if result < 0 else 0

    def close(self):
        if self.libc.shmdt(self.address) != 0:
            raise OSError(ctypes.get_errno(), "shmdt")


segment = Segment()
try:
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "stat\n":
        raise RuntimeError("expected stat")
    result = segment.stat()
    name = ctypes.create_string_buffer(f"ipc-{result}".encode("ascii"))
    segment.libc.prctl.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                                  ctypes.c_ulong, ctypes.c_ulong]
    if segment.libc.prctl(PR_SET_NAME, name, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
    while not os.path.exists(os.path.join(sys.argv[1], "release")):
        time.sleep(0.01)
finally:
    segment.close()
