import os
import sys


read_fd, write_fd = os.pipe()
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "fork\n":
    sys.exit(2)

pid = os.fork()
if pid == 0:
    os.close(write_fd)
    os.read(read_fd, 1)
    os._exit(0)

os.close(read_fd)
if sys.stdin.readline() != "stop\n":
    sys.exit(2)
os.write(write_fd, b"1")
os.close(write_fd)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
