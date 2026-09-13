import os
import sys
import time
from pathlib import Path


stop = Path(sys.argv[1], "recovery-stop")
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "fork\n":
    sys.exit(2)

pid = os.fork()
if pid == 0:
    while not stop.exists():
        time.sleep(0.01)
    os._exit(0)

_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
