import os
import sys
import time


def wait(path):
    limit = time.monotonic() + 30
    while not os.path.exists(path):
        if time.monotonic() >= limit:
            raise RuntimeError(f"timed out waiting for {path}")
        time.sleep(0.01)


work = sys.argv[1]
start = os.path.join(work, "double-fork-start")
exit_ready = os.path.join(work, "double-fork-exit")
exec_ready = os.path.join(work, "double-fork-exec")
print("native-fixture-ready", flush=True)
wait(start)
middle = os.fork()
if middle == 0:
    child = os.fork()
    if child == 0:
        wait(exec_ready)
        os.execv("/usr/bin/sleep", ["/usr/bin/sleep", "300"])
    wait(exit_ready)
    os._exit(0)
os.waitpid(middle, 0)
time.sleep(300)
