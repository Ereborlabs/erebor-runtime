import ctypes
import shutil
import sys
from pathlib import Path


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
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
    elif command == "stop\n":
        break
    else:
        raise RuntimeError(f"unexpected command: {command!r}")
