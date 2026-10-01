import ctypes
import os
import sys
import time


target = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "path"
work = sys.argv[3] if len(sys.argv) > 3 else None
AT_FDCWD = -100
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                       ctypes.c_ulong, ctypes.c_ulong]
if mode == "fork-at":
    call_at = libc.execveat
    call_at.argtypes = [ctypes.c_int, ctypes.c_char_p,
                       ctypes.POINTER(ctypes.c_char_p),
                       ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
image = open(target, "rb") if mode in {"fd", "fork-fd"} else None
if mode == "fork-deleted":
    import shutil

    path = os.path.join(work, "exec-image")
    shutil.copy2(target, path)
    image = open(path, "rb")
    os.unlink(path)
elif mode == "fork-memfd":
    MFD_EXEC = 0x0010
    image = os.fdopen(os.memfd_create("mithril-exec-fixture", MFD_EXEC), "w+b")
    with open(target, "rb") as source:
        image.write(source.read())
    image.flush()
    image.seek(0)
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "exec\n":
    raise RuntimeError("expected exec")
if mode in {"fork-fd", "fork-path", "fork-at", "fork-deleted", "fork-memfd"}:
    pid = os.fork()
    if pid != 0:
        _, status = os.waitpid(pid, 0)
        sys.exit(os.waitstatus_to_exitcode(status))
    while not os.path.exists(os.path.join(work, "exec")):
        time.sleep(0.01)
try:
    if image is not None:
        os.execve(image.fileno(), [target], os.environ)
    elif mode in {"path", "fork-path"}:
        os.execv(target, [target])
    elif mode == "fork-at":
        args = (ctypes.c_char_p * 2)(os.fsencode(target), None)
        empty = (ctypes.c_char_p * 1)()
        if call_at(AT_FDCWD, os.fsencode(target), args, empty, 0) != 0:
            raise OSError(ctypes.get_errno(), "execveat")
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
