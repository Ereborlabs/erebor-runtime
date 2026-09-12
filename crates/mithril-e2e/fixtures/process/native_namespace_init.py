import os
import signal
import sys


def namespace_pid():
    with open("/proc/self/status", encoding="ascii") as status:
        for line in status:
            if line.startswith("NSpid:"):
                return int(line.split()[-1])
    raise RuntimeError("NSpid is missing")


work = sys.argv[1]
init_ready = os.path.join(work, "native-child-ready")
mid_ready = os.path.join(work, "namespace-mid-ready")
child_ready = os.path.join(work, "namespace-exec-ready")
with open(init_ready, "x", encoding="ascii") as output:
    output.write(f"{namespace_pid()}\n")
print("native-fixture-ready", flush=True)
sys.stdin.readline()
reader, writer = os.pipe()
middle = os.fork()
if middle == 0:
    os.close(reader)
    with open(mid_ready, "x", encoding="ascii") as output:
        output.write(f"{namespace_pid()}\n")
    os.kill(os.getpid(), signal.SIGSTOP)
    child = os.fork()
    if child == 0:
        os.close(writer)
        with open(child_ready, "x", encoding="ascii") as output:
            output.write(f"{namespace_pid()}\n")
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/usr/bin/sleep", ["/usr/bin/sleep", "300"])
    os.write(writer, str(child).encode("ascii"))
    os.close(writer)
    os.waitpid(child, 0)
    os._exit(0)
os.close(writer)
sys.stdin.readline()
os.kill(middle, signal.SIGCONT)
sys.stdin.readline()
os.kill(middle, signal.SIGTERM)
os.waitpid(middle, 0)
os.kill(int(os.read(reader, 32)), signal.SIGCONT)
os.close(reader)
os.waitpid(-1, 0)
