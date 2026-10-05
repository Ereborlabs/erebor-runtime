import ctypes
import errno
import mmap
import os
import select
import socket
import sys


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
secret_path = "/tmp/mithril-descriptor-secret"
allowed_path = "/tmp/mithril-descriptor-allowed"


def result(action):
    try:
        action()
    except OSError as failure:
        return failure.errno
    return 0


if sys.argv[-1] == "independent":
    secret = os.open(secret_path, os.O_RDWR)
    allowed = os.open(allowed_path, os.O_RDONLY)
    print("native-fixture-ready", flush=True)
    if sys.stdin.buffer.readline() != b"act\n":
        sys.exit(2)
    results = [
        result(lambda: mmap.mmap(secret, 1, flags=mmap.MAP_SHARED, prot=mmap.PROT_WRITE).close()),
        result(lambda: mmap.mmap(allowed, 1, access=mmap.ACCESS_READ).close()),
    ]
    name = ctypes.create_string_buffer(("map-" + "-".join(map(str, results))).encode("ascii"))
    if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
    released = sys.stdin.buffer.readline() == b"release\n"
    if results != [errno.EACCES, 0] or not released:
        sys.exit(3)
    sys.exit(0)


os.makedirs("/tmp", exist_ok=True)
for path, content in [(secret_path, b"secret\n"), (allowed_path, b"allowed\n")]:
    with open(path, "wb") as output:
        output.write(content)
if sys.argv[-1] == "control":
    print("native-fixture-ready", flush=True)
    if sys.stdin.buffer.readline() != b"act\n":
        sys.exit(2)
    results = []
    for _ in range(2):
        descriptor = -1
        try:
            descriptor = os.open(allowed_path, os.O_RDONLY)
            if os.read(descriptor, 1) != b"a":
                raise RuntimeError("the control read returned the wrong byte")
            results.append(0)
        except OSError as failure:
            results.append(failure.errno)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    name = ctypes.create_string_buffer(("control-" + "-".join(map(str, results))).encode("ascii"))
    if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
    release = select.poll()
    release.register(sys.stdin, select.POLLIN | select.POLLHUP)
    events = release.poll()
    if results != [0, 0] or not any(flags & select.POLLIN for _, flags in events):
        sys.exit(3)
    sys.exit(0)
if sys.argv[-1] == "passed":
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    with receiver, sender:
        receiver.settimeout(5)
        sender.settimeout(5)
        child = os.fork()
        if child == 0:
            receiver.close()
            for path in (secret_path, allowed_path):
                with open(path, "rb") as source:
                    socket.send_fds(sender, [b"1"], [source.fileno()])
            os._exit(0)
        sender.close()
        files = []
        for path in (secret_path, allowed_path):
            payload, files_in, flags, _ = socket.recv_fds(receiver, 1, 1)
            if payload != b"1" or flags & socket.MSG_CTRUNC or len(files_in) != 1:
                raise RuntimeError("incomplete SCM_RIGHTS file transfer")
            received = os.fstat(files_in[0])
            original = os.stat(path)
            if (received.st_dev, received.st_ino) != (original.st_dev, original.st_ino):
                raise RuntimeError("SCM_RIGHTS delivered a different file")
            files.extend(files_in)
        _, status = os.waitpid(child, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("SCM_RIGHTS sender failed")
        secret, allowed = files
else:
    secret = os.open(secret_path, os.O_RDONLY)
    allowed = os.open(allowed_path, os.O_RDONLY)


def read(descriptor):
    byte = os.read(descriptor, 1)
    if descriptor == allowed and byte != b"a":
        raise RuntimeError("the control read returned the wrong byte")


def map_read(descriptor):
    mmap.mmap(descriptor, 1, access=mmap.ACCESS_READ).close()


print("native-fixture-ready", flush=True)
if sys.stdin.buffer.readline() != b"act\n":
    sys.exit(2)
results = [
    result(lambda: os.close(os.open(allowed_path, os.O_RDONLY))),
    result(lambda: read(secret)),
    result(lambda: map_read(secret)),
    result(lambda: read(allowed)),
    result(lambda: map_read(allowed)),
]
expected = [0, errno.EACCES, errno.EACCES, 0, 0]
name = ctypes.create_string_buffer(("fd-" + "-".join(map(str, results))).encode("ascii"))
if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
released = sys.stdin.buffer.readline() == b"release\n"
if results != expected or not released:
    sys.exit(3)
os.close(secret)
os.close(allowed)
