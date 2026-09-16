import errno
import os
import sys
import time


with open("/fixtures/policy_replace.py", "rb"):
    pass
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "effect\n":
    sys.exit(2)

try:
    with open("/fixtures/policy_replace.py", "rb"):
        pass
except OSError as error:
    if error.errno != errno.EACCES:
        sys.exit(error.errno)
else:
    sys.exit(3)

pid = os.fork()
if pid == 0:
    try:
        os.execv("/usr/bin/false", ["/usr/bin/false"])
    except OSError as error:
        os._exit(error.errno)

_, status = os.waitpid(pid, 0)
if os.waitstatus_to_exitcode(status) != 1:
    sys.exit(4)
while True:
    time.sleep(60)
