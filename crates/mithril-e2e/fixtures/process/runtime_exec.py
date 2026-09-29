import ctypes
import errno
import os
import shutil
import subprocess
import sys
from pathlib import Path


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.open.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.open.restype = ctypes.c_int
work = Path(sys.argv[1])
target = work / "bin/python-runtime"
target.parent.mkdir(exist_ok=True)
shutil.copy2(Path(sys.executable).resolve(), target)
print("native-fixture-ready", flush=True)
for command in sys.stdin:
    if command == "read\n":
        content = Path("/fixtures/runtime_copy.txt").read_text(encoding="ascii")
        if content != "Mithril runtime copy fixture.\n":
            raise RuntimeError("unexpected runtime copy fixture")
        name = ctypes.create_string_buffer(b"app-read-0")
        if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
    elif command.startswith("burst "):
        count = int(command.split()[1])
        for _ in range(count):
            descriptor = libc.open(b"/work/application.denied", os.O_RDONLY)
            if descriptor >= 0:
                os.close(descriptor)
                raise RuntimeError("the protected burst read was allowed")
            error = ctypes.get_errno()
            if error != errno.EACCES:
                raise OSError(error, "the protected burst read failed unexpectedly")
        (work / "burst").write_text(f"{count}\n", encoding="ascii")
    elif command == "exec\n":
        subprocess.run(["/usr/bin/true"], check=True)
        (work / "exec").write_text("allowed\n", encoding="ascii")
    elif command == "loader\n":
        paths = {
            line.split()[-1]
            for line in Path("/proc/self/maps").read_text(encoding="ascii").splitlines()
            if "ld-linux" in line or "ld-musl" in line
        }
        if not paths:
            raise RuntimeError("no mapped dynamic loader")
        for path in sorted(paths):
            print(path, flush=True)
    elif command == "stop\n":
        break
    else:
        raise RuntimeError(f"unexpected command: {command!r}")
