import ctypes
import socket
import sys


PR_SET_NAME = 15
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]


def set_name(value):
    name = ctypes.create_string_buffer(value.encode("ascii"))
    if libc.prctl(PR_SET_NAME, ctypes.addressof(name), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


def result(name, action):
    try:
        action()
    except OSError as failure:
        error = failure.errno or errno.EIO
    else:
        error = 0
    set_name(f"{name}-{error}")


def nodelay():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            client.connect(("127.0.0.1", 9))
        except ConnectionRefusedError:
            pass


print("native-fixture-ready", flush=True)
for command in sys.stdin:
    if command == "nodelay\n":
        result("nodelay", nodelay)
    elif command == "release\n":
        break
