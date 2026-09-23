import ctypes
import errno
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
        print(f"{name}: {failure}", file=sys.stderr, flush=True)
    else:
        error = 0
    set_name(f"{name}-{error}")
    return error


def nodelay():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            client.connect(("127.0.0.1", 9))
        except ConnectionRefusedError:
            pass


def roundtrip():
    stage = "socket setup"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.settimeout(3)
            stage = "bind"
            server.bind(("127.0.0.1", 19091))
            stage = "listen"
            server.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                stage = "connect"
                client.connect(server.getsockname())
                stage = "accept"
                with server.accept()[0] as peer:
                    peer.settimeout(3)
                    stage = "request send"
                    client.sendall(b"request")
                    stage = "request receive"
                    if peer.recv(7, socket.MSG_WAITALL) != b"request":
                        raise OSError(errno.EIO, "server received the wrong payload")
                    stage = "response send"
                    peer.sendall(b"response")
                    stage = "response receive"
                    if client.recv(8, socket.MSG_WAITALL) != b"response":
                        raise OSError(errno.EIO, "client received the wrong payload")
    except OSError as failure:
        raise OSError(failure.errno or errno.EIO, f"{stage}: {failure}") from failure


print("native-fixture-ready", flush=True)
for command in sys.stdin:
    if command == "nodelay\n":
        result("nodelay", nodelay)
    elif command == "roundtrip\n":
        error = result("roundtrip", roundtrip)
        if error:
            sys.exit(error)
        break
    elif command == "release\n":
        break
