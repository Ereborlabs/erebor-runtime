import ctypes
import sys


CLONE_NEWUTS = 0x04000000
libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.argtypes = [ctypes.c_int]


print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()
ctypes.set_errno(0)
result = libc.unshare(CLONE_NEWUTS)
error = ctypes.get_errno() if result == -1 else 0
sys.exit(error)
