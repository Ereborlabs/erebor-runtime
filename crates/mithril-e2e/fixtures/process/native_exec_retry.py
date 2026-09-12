import os
from pathlib import Path
import signal
import sys

work = Path(sys.argv[1])
ready = work / "child"
failed = work / "failed"
target = Path(__file__)
print("native-fixture-ready", flush=True)
sys.stdin.readline()

pid = os.fork()
if pid == 0:
    with ready.open("x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    try:
        os.execv(target, [target])
    except OSError:
        with failed.open("x", encoding="ascii") as output:
            output.write(f"{os.getpid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    os.execv("/usr/bin/sleep", ["/usr/bin/sleep", "300"])

for _ in range(2):
    if sys.stdin.readline().strip() != "continue":
        raise RuntimeError("expected continue")
    os.kill(pid, signal.SIGCONT)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
