import ctypes
import os
import sys


libc = ctypes.CDLL(None, use_errno=True)
libc.open_tree.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
libc.move_mount.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint
]
libc.setns.argtypes = [ctypes.c_int, ctypes.c_int]
libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
CLONE_NEWNS = 0x00020000
AT_FDCWD = -100
OPEN_TREE_CLONE = 1
MOVE_FROM_EMPTY = 4
MOVE_TO_EMPTY = 64


def check(result, operation):
    if result < 0:
        raise OSError(ctypes.get_errno(), operation)


pid, source = sys.argv[1:]
root = os.open(f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY)
namespace = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
tree = libc.open_tree(AT_FDCWD, os.fsencode(source), OPEN_TREE_CLONE | os.O_CLOEXEC)
check(tree, "clone real BPF link mount")
target = os.open("work/protected", os.O_PATH | os.O_CLOEXEC, dir_fd=root)
check(libc.setns(namespace, CLONE_NEWNS), "enter actor mount namespace")
check(libc.move_mount(tree, b"", target, b"", MOVE_FROM_EMPTY | MOVE_TO_EMPTY),
      "mount real BPF link directory")
for descriptor in (tree, target, namespace):
    os.close(descriptor)
os.fchdir(root)
try:
    print("native-fixture-ready", flush=True)
    sys.stdin.buffer.read()
finally:
    check(libc.umount2(b"work/protected", 0), "clean up real BPF link directory")
    os.close(root)
