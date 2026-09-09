import os
import signal
import sys


def host_pid():
    with open("/proc/self/status", encoding="ascii") as status:
        for line in status:
            if line.startswith("NSpid:"):
                return int(line.split()[1])
    raise RuntimeError("NSpid is missing")


init_ready = sys.argv[1]
mid_ready = sys.argv[2]
child_ready = sys.argv[3]
with open(init_ready, "x", encoding="ascii") as output:
    output.write(f"{host_pid()}\n")
print("native-fixture-ready", flush=True)
sys.stdin.readline()
middle = os.fork()
if middle == 0:
    with open(mid_ready, "x", encoding="ascii") as output:
        output.write(f"{host_pid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    child = os.fork()
    if child == 0:
        with open(child_ready, "x", encoding="ascii") as output:
            output.write(f"{host_pid()}\n")
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/bin/sleep", ["/bin/sleep", "300"])
    os.waitpid(child, 0)
    os._exit(0)
os.waitpid(middle, 0)
os.waitpid(-1, 0)
