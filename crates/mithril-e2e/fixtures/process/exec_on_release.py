import ctypes
import os
import sys
import time


target = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "path"
work = sys.argv[3] if len(sys.argv) > 3 else None
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                       ctypes.c_ulong, ctypes.c_ulong]
image = open(target, "rb") if mode in {"fd", "fork-fd"} else None
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "exec\n":
    raise RuntimeError("expected exec")
if mode == "fork-fd":
    pid = os.fork()
    if pid != 0:
        _, status = os.waitpid(pid, 0)
        sys.exit(os.waitstatus_to_exitcode(status))
    while not os.path.exists(os.path.join(work, "exec")):
        time.sleep(0.01)
try:
    if image is not None:
        os.execve(image.fileno(), [target], os.environ)
    elif mode == "path":
        os.execv(target, [target])
    else:
        raise ValueError(f"unknown exec mode: {mode}")
except OSError as error:
    code = error.errno or 255
    if image is not None:
        image.close()
    if work is not None:
        name = ctypes.create_string_buffer(f"exec-{code}".encode("ascii"))
        if libc.prctl(15, name, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
        while not os.path.exists(os.path.join(work, "release")):
            time.sleep(0.01)
    sys.exit(code)
