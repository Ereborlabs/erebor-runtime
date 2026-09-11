import os
import sys

work, target = sys.argv[1:]
ready = os.path.join(work, "moved-child")
print("native-fixture-ready", flush=True)
sys.stdin.readline()

read_fd, write_fd = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(write_fd)
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
    os.read(read_fd, 1)
    try:
        os.execv(target, [target])
    except OSError as error:
        os._exit(error.errno or 255)

os.close(read_fd)
sys.stdin.readline()
os.write(write_fd, b"x")
os.close(write_fd)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
