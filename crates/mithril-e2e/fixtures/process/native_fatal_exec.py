import os
import signal
import sys

work, target = sys.argv[1:]
ready = os.path.join(work, "fatal-child")
print("native-fixture-ready", flush=True)
sys.stdin.readline()

pid = os.fork()
if pid == 0:
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    os.execv(target, [target])

sys.stdin.readline()
os.kill(pid, signal.SIGCONT)
_, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
if code < 0:
    os.kill(os.getpid(), -code)
sys.exit(code)
