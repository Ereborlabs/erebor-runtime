import ctypes
import os
import sys
import threading
import time

ready = sys.argv[1]
release = sys.argv[2]
print("native-fixture-ready", flush=True)
sys.stdin.readline()

def worker():
    temporary = f"{ready}.tmp"
    with open(temporary, "x", encoding="ascii") as output:
        output.write(f"{threading.get_native_id()}\n")
    os.replace(temporary, ready)
    while not os.path.exists(release):
        time.sleep(0.01)

thread = threading.Thread(target=worker)
thread.start()
while not os.path.exists(ready):
    time.sleep(0.01)
libc = ctypes.CDLL(None, use_errno=True)
libc.pthread_exit.argtypes = [ctypes.c_void_p]
libc.pthread_exit.restype = None
libc.pthread_exit(None)
raise RuntimeError("pthread_exit returned")

