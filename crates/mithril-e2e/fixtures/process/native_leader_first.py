import ctypes
import os
import sys
import threading
import time


def wait(path):
    limit = time.monotonic() + 30
    while not os.path.exists(path):
        if time.monotonic() >= limit:
            raise RuntimeError(f"timed out waiting for {path}")
        time.sleep(0.01)


work = sys.argv[1]
ready = os.path.join(work, "leader-first-ready")
release = os.path.join(work, "leader-first-release")
print("native-fixture-ready", flush=True)
sys.stdin.readline()

def worker():
    temporary = f"{ready}.tmp"
    with open(temporary, "x", encoding="ascii") as output:
        output.write(f"{threading.get_native_id()}\n")
    os.replace(temporary, ready)
    wait(release)

thread = threading.Thread(target=worker)
thread.start()
wait(ready)
libc = ctypes.CDLL(None, use_errno=True)
libc.pthread_exit.argtypes = [ctypes.c_void_p]
libc.pthread_exit.restype = None
libc.pthread_exit(None)
raise RuntimeError("pthread_exit returned")
