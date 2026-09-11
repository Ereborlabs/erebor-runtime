import os
import signal
import sys
from pathlib import Path

ready = Path(sys.argv[1]) / "child"
print("native-fixture-ready", flush=True)
sys.stdin.readline()

pid = os.fork()
if pid == 0:
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    os.execv("/usr/bin/sleep", ["/usr/bin/sleep", "300"])

sys.stdin.readline()
os.kill(pid, signal.SIGCONT)
sys.stdin.readline()
os.kill(pid, signal.SIGTERM)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
