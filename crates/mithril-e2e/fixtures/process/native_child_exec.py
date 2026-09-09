import os
import signal
import sys

ready = sys.argv[1]
print("native-fixture-ready", flush=True)
sys.stdin.readline()

pid = os.fork()
if pid == 0:
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
