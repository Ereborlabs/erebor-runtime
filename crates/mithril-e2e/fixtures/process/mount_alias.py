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


args = sys.argv[2:]
if args not in ([], ["late"], ["recursive"]):
    sys.exit(2)
mode = args[0] if args else "early"
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
result_path = os.path.join(sys.argv[1], "mount-result.json")
with open(result_path, "w", encoding="utf-8"):
    pass

check(libc.unshare(CLONE_NEWNS))
check(libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None))
if mode == "early":
    check(libc.mount(secret.encode(), denied_alias.encode(), None, MS_BIND, None))
if mode != "recursive":
    check(libc.mount(allowed.encode(), allowed_alias.encode(), None, MS_BIND, None))
print("native-fixture-ready", flush=True)
command = sys.stdin.readline()
mount_error = 0
allowed_mount_error = 0
if mode in ("late", "recursive") and command == "mount-read\n":
    flags = MS_BIND | (MS_REC if mode == "recursive" else 0)
    result = libc.mount(secret.encode(), denied_alias.encode(), None, flags, None)
    mount_error = ctypes.get_errno() if result else 0
    if mode == "recursive":
        result = libc.mount(allowed.encode(), allowed_alias.encode(), None, flags, None)
        allowed_mount_error = ctypes.get_errno() if result else 0
elif command != "read\n":
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
with open(result_path, "r+", encoding="utf-8") as output:
    json.dump(
        {
            "mount": mount_error,
            "allowed_mount": allowed_mount_error,
            "denied": denied,
            "allowed": value,
        },
        output,
    )
