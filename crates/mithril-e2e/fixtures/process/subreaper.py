import ctypes
import os
import signal
import sys
import time


def wait(path):
    limit = time.monotonic() + 30
    while not os.path.exists(path):
        if time.monotonic() >= limit:
            raise RuntimeError(f"timed out waiting for {path}")
        time.sleep(0.01)


work = sys.argv[1]
start = os.path.join(work, "subreaper-start")
exit_ready = os.path.join(work, "subreaper-exit")
exec_ready = os.path.join(work, "subreaper-exec")
child_ready = os.path.join(work, "subreaper-child")
print("native-fixture-ready", flush=True)
wait(start)
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "set child subreaper")
middle = os.fork()
if middle == 0:
    child = os.fork()
    if child == 0:
        wait(exec_ready)
        os.execv("/usr/bin/sleep", ["/usr/bin/sleep", "300"])
    with open(child_ready, "x", encoding="ascii") as output:
        output.write(f"{child}\n")
    wait(exit_ready)
    os._exit(0)
os.waitpid(middle, 0)
wait(child_ready)
with open(child_ready, encoding="ascii") as source:
    child = int(source.read())
sys.stdin.buffer.read()
os.kill(child, signal.SIGTERM)
os.waitpid(child, 0)
