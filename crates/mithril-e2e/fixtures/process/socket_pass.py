import array
import ctypes
import errno
import os
import select
import shutil
import socket
import sys
import time


libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
work = sys.argv[1]
mode = sys.argv[2]
endpoint = os.path.join(work, "cross-pass.sock") if mode.endswith("-net") else "\0mithril-pass"

if mode == "main-unmatched":
    os.makedirs(os.path.join(work, "bin"), exist_ok=True)
    shutil.copy2(sys.executable, os.path.join(work, "bin/python-external"))


def named(value):
    name = ctypes.create_string_buffer(value.encode("ascii"))
    if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


def hold():
    while not os.path.exists(os.path.join(work, "release")):
        time.sleep(0.01)


if mode == "unmatched":
    print("native-fixture-ready", flush=True)
    sys.stdin.buffer.readline()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(endpoint)
        listener.listen(1)
        named("pass-listening")
        hold()
elif mode in ("receiver", "approved", "stale", "receiver-net", "approved-net"):
    if mode == "receiver-net":
        if libc.unshare(0x40000000) != 0:
            raise OSError(ctypes.get_errno(), "unshare network namespace")
    if mode == "approved-net":
        host, local, inode = sys.argv[3].split(":")
        expected = int(inode)
        for pid in (host, local):
            path = f"/proc/{pid}/ns/net"
            try:
                if os.stat(path).st_ino != expected:
                    continue
                with open(path, "rb") as namespace:
                    if libc.setns(namespace.fileno(), 0x40000000) != 0:
                        raise OSError(ctypes.get_errno(), "join network namespace")
                break
            except FileNotFoundError:
                continue
        else:
            raise RuntimeError("the namespace holder is unavailable")
        if os.stat("/proc/self/ns/net").st_ino != expected:
            raise RuntimeError("the receiver did not join the holder namespace")
    print("native-fixture-ready", flush=True)
    sys.stdin.buffer.readline()
    named("rx-create")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        named("rx-bind")
        try:
            listener.bind(endpoint)
        except OSError as failure:
            named(f"rx-bind-{failure.errno}")
            hold()
            raise
        named("rx-listen")
        listener.listen(1)
        named("pass-listening")
        with listener.accept()[0] as control:
            _, ancillary, _, _ = control.recvmsg(1, socket.CMSG_SPACE(4))
            fds = array.array("i")
            for level, kind, data in ancillary:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    fds.frombytes(data[: len(data) - len(data) % fds.itemsize])
            if len(fds) != 1:
                raise RuntimeError(f"expected one passed socket, got {len(fds)}")
            with socket.socket(fileno=fds[0]) as passed:
                if mode in ("approved", "approved-net", "stale"):
                    try:
                        passed.sendall(b"ok")
                    except OSError as failure:
                        sent = failure.errno or errno.EIO
                    else:
                        sent = 0
                    control.sendall(b"done")
                    named("fd1-ok" if sent == 0 else f"fd1-{sent}")
                    if mode != "stale":
                        hold()
                    sys.exit(sent)
                try:
                    passed.sendall(b"blocked")
                except OSError as failure:
                    sent = failure.errno or errno.EIO
                else:
                    sent = 0
                try:
                    passed.recv(1)
                except OSError as failure:
                    received = failure.errno or errno.EIO
                else:
                    received = 0
                control.sendall(b"done")
                named(f"fd1-{sent}-{received}")
                hold()
                sys.exit(0 if (sent, received) == (errno.EACCES, errno.EACCES) else 1)
elif mode == "namespace-holder":
    if libc.unshare(0x40000000) != 0:
        raise OSError(ctypes.get_errno(), "unshare network namespace")
    print("native-fixture-ready", flush=True)
    hold()
else:
    print("native-fixture-ready", flush=True)
    sys.stdin.buffer.readline()
    stage = "bind"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            named(stage)
            listener.bind(("127.0.0.1", 19097))
            listener.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                client.bind(("127.0.0.1", 19098))
                stage = "connect"
                named(stage)
                client.connect(listener.getsockname())
                stage = "accept"
                named(stage)
                if not select.select([listener], [], [], 3)[0]:
                    raise TimeoutError(errno.ETIMEDOUT, "TCP accept did not become ready")
                with listener.accept()[0] as passed:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
                        stage = "unix"
                        named(stage)
                        control.connect(endpoint)
                        fd = array.array("i", [passed.fileno()])
                        stage = "pass"
                        named(stage)
                        control.sendmsg([b"socket"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fd)])
                        stage = "send"
                        named(stage)
                        client.sendall(b"q")
                        stage = "ack"
                        named(stage)
                        if not select.select([control], [], [], 3)[0] or control.recv(4) != b"done":
                            raise RuntimeError("receiver did not finish")
                        stage = "read"
                        named(stage)
                        if mode in ("main-approved", "main-approved-net", "main-stale", "main-inherit", "main-unmatched"):
                            payload = bytearray()
                            while len(payload) < 2 and select.select([client], [], [], 3)[0]:
                                chunk = client.recv(2 - len(payload))
                                if not chunk:
                                    break
                                payload.extend(chunk)
                            if payload != b"ok":
                                named("peer-missing")
                            elif mode in ("main-stale", "main-unmatched"):
                                named("peer-ready")
                            else:
                                named("peer-ok")
                            if mode == "main-stale":
                                if sys.stdin.buffer.readline() != b"probe\n":
                                    raise RuntimeError("expected stale-peer probe")
                                try:
                                    control.sendall(b"stale")
                                except OSError as failure:
                                    named(f"stale-{failure.errno or errno.EIO}")
                                else:
                                    named("stale-0")
                            if mode == "main-unmatched":
                                if sys.stdin.buffer.readline() != b"probe\n":
                                    raise RuntimeError("expected unmatched-peer probe")
                                try:
                                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as other:
                                        other.connect(endpoint)
                                        other.sendall(b"probe")
                                except OSError as failure:
                                    named(f"unmatch-{failure.errno or errno.EIO}")
                                else:
                                    named("unmatch-0")
                            if mode == "main-inherit":
                                if sys.stdin.buffer.readline() != b"fork\n":
                                    raise RuntimeError("expected fork action")
                                start_read, start_write = os.pipe()
                                result_read, result_write = os.pipe()
                                child = os.fork()
                                if child == 0:
                                    os.close(start_write)
                                    os.close(result_read)
                                    os.read(start_read, 1)
                                    try:
                                        control.sendall(b"fork")
                                    except OSError as failure:
                                        result = failure.errno or errno.EIO
                                    else:
                                        result = 0
                                    os.write(result_write, bytes([result]))
                                    os._exit(0)
                                os.close(start_read)
                                os.close(result_write)
                                named("fork-ready")
                                if sys.stdin.buffer.readline() != b"probe\n":
                                    raise RuntimeError("expected child probe")
                                os.write(start_write, b"x")
                                result = os.read(result_read, 1)
                                os.waitpid(child, 0)
                                named(f"fork-{result[0] if result else errno.EIO}")
                        elif select.select([client], [], [], 0.5)[0]:
                            payload = client.recv(1)
                            named("peer-bytes" if payload else "peer-closed")
                        else:
                            named("peer-empty")
                        hold()
    except OSError as failure:
        named(f"{stage}-{failure.errno}")
        hold()
        raise
