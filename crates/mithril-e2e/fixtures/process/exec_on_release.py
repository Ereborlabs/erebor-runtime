import os
import sys


target = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "path"
image = open(target, "rb") if mode == "fd" else None
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "exec\n":
    raise RuntimeError("expected exec")
try:
    if mode == "fd":
        os.execve(image.fileno(), [target], os.environ)
    elif mode == "path":
        os.execv(target, [target])
    else:
        raise ValueError(f"unknown exec mode: {mode}")
except OSError as error:
    sys.exit(error.errno or 255)
