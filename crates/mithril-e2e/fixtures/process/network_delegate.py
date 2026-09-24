import ctypes
import errno
import json
from pathlib import Path
import socket
import sys


work = Path(sys.argv[1])
mode = sys.argv[2]
endpoint = "\0mithril-delegate"
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]


def named(value):
    name = ctypes.create_string_buffer(value.encode("ascii"))
    if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


if mode == "requester":
    print("native-fixture-ready", flush=True)
    for command in sys.stdin:
        command = command.strip()
        if command == "release":
            break
        if command not in ("deny", "allow"):
            raise RuntimeError(f"unexpected request: {command}")
        address = "127.0.0.53" if command == "deny" else "127.0.0.1"
        request = {"id": f"{command}-1", "address": address, "port": 19120}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            control.connect(endpoint)
            control.sendall(json.dumps(request).encode("ascii"))
        named(f"{command}-sent")
elif mode == "delegate":
    print("native-fixture-ready", flush=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        if sys.stdin.readline() != "listen\n":
            raise RuntimeError("expected listener command")
        listener.bind(endpoint)
        listener.listen(2)
        named("proxy-ready")
        (work / "delegate-ready").write_text("ready\n", encoding="ascii")
        for command in sys.stdin:
            command = command.strip()
            if command == "release":
                break
            if command != "once":
                raise RuntimeError(f"unexpected delegate command: {command}")
            with listener.accept()[0] as control:
                with control.makefile("r", encoding="ascii") as data:
                    request = json.load(data)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                try:
                    connection.connect((request["address"], request["port"]))
                except OSError as failure:
                    connect = failure.errno or errno.EIO
                    sent = None
                else:
                    connect = 0
                    try:
                        connection.sendall(b"delegated")
                    except OSError as failure:
                        sent = failure.errno or errno.EIO
                    else:
                        sent = 0
            result = {
                "id": request["id"], "requested": request["address"],
                "final": request["address"], "port": request["port"],
                "connect": connect, "send": sent,
            }
            (work / f"{request['id']}.json").write_text(json.dumps(result), encoding="ascii")
            named(f"{request['id'].split('-')[0]}-{connect}")
else:
    raise RuntimeError(f"unexpected mode: {mode}")
