import os
import signal
import sys

ready, target = sys.argv[1:]
print("native-fixture-ready", flush=True)
sys.stdin.readline()

pid = os.fork()
if pid == 0:
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    os.execv(target, [target])

_, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
if code < 0:
    os.kill(os.getpid(), -code)
sys.exit(code)
