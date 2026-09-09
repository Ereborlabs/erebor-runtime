import ctypes
import os
import signal
import sys

ready = sys.argv[1]
print("native-fixture-ready", flush=True)
sys.stdin.readline()
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "set child subreaper")
middle = os.fork()
if middle == 0:
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/bin/sleep", ["/bin/sleep", "300"])
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()} {child}\n")
    os.waitpid(child, 0)
    os._exit(0)
os.waitpid(middle, 0)
os.waitpid(-1, 0)
