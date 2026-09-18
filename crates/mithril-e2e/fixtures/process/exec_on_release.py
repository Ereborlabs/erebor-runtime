import os
import sys


target = sys.argv[1]
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "exec\n":
    raise RuntimeError("expected exec")
try:
    os.execv(target, [target])
except OSError as error:
    sys.exit(error.errno or 255)
