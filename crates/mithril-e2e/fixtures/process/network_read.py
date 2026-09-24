import ctypes
import errno
import json
import mmap
import os
from pathlib import Path
import sys


work = Path(sys.argv[1])
token = Path("/tmp/mithril-network-token")
token.parent.mkdir(parents=True, exist_ok=True)
token.write_bytes(b"token")
held = os.open(token, os.O_RDONLY)

with open(token, "rb", buffering=0) as source:
    zero_byte = source.read(0) == b""
with open(token, "rb", buffering=0) as source:
    source.seek(0, os.SEEK_END)
    end_of_file = source.read(1) == b""
with open(token, "rb", buffering=0) as source:
    partial = source.read(32)
partial_positive = 0 < len(partial) < 32
with mmap.mmap(held, 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ) as view:
    mapped = view[0] == partial[0]

child = os.fork()
if child == 0:
    os._exit(0 if os.pread(held, 1, 0) == b"t" else 1)
_, status = os.waitpid(child, 0)
inherited_descriptor = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0

with open("/proc/self/mem", "rb", buffering=0) as memory:
    try:
        os.pread(memory.fileno(), 1, 0)
    except OSError as failure:
        io_error = failure.errno == errno.EIO
    else:
        io_error = False

(work / "read-result.json").write_text(
    json.dumps({
        "zero_byte": zero_byte,
        "end_of_file": end_of_file,
        "partial_positive": partial_positive,
        "mapped": mapped,
        "inherited_descriptor": inherited_descriptor,
        "io_error": io_error,
    }),
    encoding="ascii",
)
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "act\n":
    raise RuntimeError("expected act")

if os.pread(held, 1, 0) != b"t":
    raise RuntimeError("retained token read changed")
with mmap.mmap(held, 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ) as view:
    if view[0] != ord("t"):
        raise RuntimeError("retained token mapping changed")

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
name = ctypes.create_string_buffer(b"token-read-ok")
if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
if sys.stdin.readline() != "release\n":
    raise RuntimeError("expected release")
