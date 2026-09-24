import ctypes
import errno
import os
import signal
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


def receive(peer, size):
    data = bytearray()
    while len(data) < size:
        chunk = peer.recv(size - len(data))
        if not chunk:
            raise OSError(errno.EIO, "peer closed before the payload arrived")
        data.extend(chunk)
    return bytes(data)


def roundtrip():
    stage = "socket setup"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.settimeout(3)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                    if receive(peer, 7) != b"request":
                        raise OSError(errno.EIO, "server received the wrong payload")
                    stage = "response send"
                    peer.sendall(b"response")
                    stage = "response receive"
                    if receive(client, 8) != b"response":
                        raise OSError(errno.EIO, "client received the wrong payload")
    except OSError as failure:
        raise OSError(failure.errno or errno.EIO, f"{stage}: {failure}") from failure


def ipv6_tcp():
    stage = "socket setup"
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
            server.settimeout(3)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stage = "bind"
            server.bind(("::1", 19094))
            server.listen(1)
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                stage = "connect"
                client.connect(server.getsockname())
                with server.accept()[0] as peer:
                    peer.settimeout(3)
                    stage = "send"
                    client.sendall(b"ipv6")
                    stage = "receive"
                    if receive(peer, 4) != b"ipv6":
                        raise OSError(errno.EIO, "IPv6 payload changed")
    except OSError as failure:
        raise OSError(failure.errno or errno.EIO, f"{stage}: {failure}") from failure


def send_variants():
    stage = "socket setup"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.settimeout(3)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stage = "bind"
            server.bind(("127.0.0.1", 19092))
            server.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                stage = "connect"
                client.connect(server.getsockname())
                with server.accept()[0] as peer:
                    peer.settimeout(3)
                    stage = "sendmsg"
                    payload = b"sendmsg"
                    if client.sendmsg([payload]) != len(payload):
                        raise OSError(errno.EIO, "sendmsg was short")
                    if receive(peer, len(payload)) != payload:
                        raise OSError(errno.EIO, "sendmsg payload changed")

                    with open(__file__, "rb") as source:
                        payload = source.read(16)
                        stage = "sendfile"
                        if os.sendfile(client.fileno(), source.fileno(), 0, len(payload)) != len(payload):
                            raise OSError(errno.EIO, "sendfile was short")
                        if receive(peer, len(payload)) != payload:
                            raise OSError(errno.EIO, "sendfile payload changed")

                    source_fd = os.open(__file__, os.O_RDONLY)
                    try:
                        payload = os.pread(source_fd, 16, 0)
                        read_fd, write_fd = os.pipe()
                        try:
                            stage = "splice file"
                            copied = os.splice(source_fd, write_fd, len(payload))
                            if copied != len(payload):
                                raise OSError(errno.EIO, "file splice was short")
                            stage = "splice socket"
                            if os.splice(read_fd, client.fileno(), copied) != copied:
                                raise OSError(errno.EIO, "socket splice was short")
                        finally:
                            os.close(read_fd)
                            os.close(write_fd)
                        if receive(peer, len(payload)) != payload:
                            raise OSError(errno.EIO, "splice payload changed")
                    finally:
                        os.close(source_fd)
    except OSError as failure:
        raise OSError(failure.errno or errno.EIO, f"{stage}: {failure}") from failure


def prepare_inheritance():
    stage = "socket setup"
    client = None
    peer = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.settimeout(3)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stage = "bind"
            server.bind(("127.0.0.1", 19093))
            server.listen(1)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(3)
            stage = "connect"
            client.connect(server.getsockname())
            peer = server.accept()[0]
            peer.settimeout(3)
            stage = "fork"
            child = os.fork()
            if child == 0:
                try:
                    server.close()
                    peer.close()
                    set_name("fork-ready")
                    os.kill(os.getpid(), signal.SIGSTOP)
                    client.sendall(b"fork")
                    set_name("fork-send")
                    os.kill(os.getpid(), signal.SIGSTOP)
                    os._exit(0)
                except OSError as failure:
                    os._exit((failure.errno or errno.EIO) & 0xFF)
            waited, status = os.waitpid(child, os.WUNTRACED)
            if waited != child or not os.WIFSTOPPED(status):
                raise OSError(errno.EIO, "fork child did not prepare")
            return client, peer, child
    except OSError as failure:
        if peer is not None:
            peer.close()
        if client is not None:
            client.close()
        raise OSError(failure.errno or errno.EIO, f"{stage}: {failure}") from failure


def send_inheritance(state):
    client, peer, child = state
    with client.dup() as duplicate:
        duplicate.sendall(b"dup")
    if receive(peer, 3) != b"dup":
        raise OSError(errno.EIO, "duplicate payload changed")
    os.kill(child, signal.SIGCONT)
    if receive(peer, 4) != b"fork":
        raise OSError(errno.EIO, "fork payload changed")
    waited, status = os.waitpid(child, os.WUNTRACED)
    if waited != child or not os.WIFSTOPPED(status):
        raise OSError(errno.EIO, "fork child did not stop")


held = None
print("native-fixture-ready", flush=True)
for command in sys.stdin:
    if command == "nodelay\n":
        result("nodelay", nodelay)
    elif command == "roundtrip\n":
        error = result("roundtrip", roundtrip)
        if error:
            sys.exit(error)
        break
    elif command == "ipv6\n":
        error = result("ipv6", ipv6_tcp)
        if error:
            sys.exit(error)
        break
    elif command == "variants\n":
        error = result("variants", send_variants)
        if error:
            sys.exit(error)
        break
    elif command == "inherit\n":
        try:
            held = prepare_inheritance()
            error = 0
        except OSError as failure:
            error = failure.errno or errno.EIO
            print(f"inherit: {failure}", file=sys.stderr, flush=True)
        set_name("inherit-ready" if error == 0 else f"inherit-{error}")
        if error:
            sys.exit(error)
    elif command == "send\n":
        error = result("inherit", lambda: send_inheritance(held))
        if error:
            sys.exit(error)
    elif command == "release\n":
        if held is not None:
            client, peer, child = held
            os.kill(child, signal.SIGCONT)
            _, status = os.waitpid(child, 0)
            client.close()
            peer.close()
            if os.waitstatus_to_exitcode(status) != 0:
                sys.exit(errno.EIO)
        break
