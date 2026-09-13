import os
import sys


print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "fork\n":
    sys.exit(125)

try:
    pid = os.fork()
except OSError as error:
    sys.exit(error.errno or 125)

if pid == 0:
    os._exit(0)
os.waitpid(pid, 0)
sys.exit(126)
