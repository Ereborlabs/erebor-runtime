import os
import sys


print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "effect\n":
    sys.exit(2)

pid = os.fork()
if pid == 0:
    try:
        os.execv("/usr/bin/false", ["/usr/bin/false"])
    except OSError as error:
        os._exit(error.errno)

_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
