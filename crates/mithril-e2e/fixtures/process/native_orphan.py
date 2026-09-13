import os
import sys
import time

work = sys.argv[1]
fork_ready = os.path.join(work, "orphan-fork")
exit_ready = os.path.join(work, "orphan-exit")
print("native-fixture-ready", flush=True)
while not os.path.exists(fork_ready):
    time.sleep(0.01)

pid = os.fork()
if pid == 0:
    parent = os.getppid()
    while not os.path.exists(exit_ready):
        time.sleep(0.01)
    deadline = time.monotonic() + 30
    while os.getppid() == parent:
        if time.monotonic() >= deadline:
            raise RuntimeError("parent did not exit")
        time.sleep(0.01)
    os.closerange(0, 3)
    os.execv("/usr/bin/sleep", ["/usr/bin/sleep", "300"])

while not os.path.exists(exit_ready):
    ended, status = os.waitpid(pid, os.WNOHANG)
    if ended:
        raise RuntimeError(f"child exited before release: {status}")
    time.sleep(0.01)
