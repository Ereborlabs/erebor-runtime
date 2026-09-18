import ctypes
import json
import os
import sys


libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
]
CLONE_NEWNS = 0x00020000
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18


def check(result):
    if result:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


root = os.path.join(sys.argv[1], "mount")
secret = os.path.join(root, "secret")
allowed = os.path.join(root, "allowed")
denied_alias = os.path.join(root, "denied-alias")
allowed_alias = os.path.join(root, "allowed-alias")
for path in (secret, allowed, denied_alias, allowed_alias):
    os.makedirs(path)
with open(os.path.join(secret, "blocked"), "w", encoding="utf-8") as output:
    output.write("restricted bind source\n")
with open(os.path.join(allowed, "open"), "w", encoding="utf-8") as output:
    output.write("allowed bind source\n")

check(libc.unshare(CLONE_NEWNS))
check(libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None))
check(libc.mount(secret.encode(), denied_alias.encode(), None, MS_BIND, None))
check(libc.mount(allowed.encode(), allowed_alias.encode(), None, MS_BIND, None))
print("native-fixture-ready", flush=True)
if sys.stdin.readline() != "read\n":
    sys.exit(2)

try:
    with open(os.path.join(denied_alias, "blocked"), encoding="utf-8"):
        denied = 0
except OSError as error:
    denied = error.errno
try:
    with open(os.path.join(allowed_alias, "open"), encoding="utf-8") as source:
        value = source.read()
except OSError as error:
    value = f"errno:{error.errno}"
print(json.dumps({"denied": denied, "allowed": value}), file=sys.stderr, flush=True)
