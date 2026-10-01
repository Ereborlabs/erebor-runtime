import ctypes
import json
import os
from pathlib import Path
import sys
import threading


work = Path(sys.argv[1])
mode = sys.argv[2]


def open_errno(path, flags=os.O_WRONLY):
    try:
        descriptor = os.open(path, flags)
        os.close(descriptor)
        return 0
    except OSError as error:
        return error.errno


def write(name, value):
    with (work / name).open("w", encoding="ascii") as output:
        output.write(value)


def mark(libc, action, error):
    name = ctypes.create_string_buffer(f"link-{action}-{error}".encode("ascii"))
    if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


if mode == "single":
    print("native-fixture-ready", flush=True)
    for command, name in [
        ("before", "expired-result"),
        ("first", "again-result"),
        ("second", "race-result"),
    ]:
        if sys.stdin.readline() != f"{command}\n":
            raise RuntimeError(f"expected {command}")
        write(name, str(open_errno(work / "expired-secret")))
elif mode == "read":
    secret = Path("/tmp/mithril-observe-secret")
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_bytes(b"secret")
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "read\n":
        raise RuntimeError("expected read")
    write("expired-result", str(open_errno(secret, os.O_RDONLY)))
elif mode in ("symlink", "procfd", "bind", "bind-allowed"):
    secret = Path(
        "/tmp/mithril-descriptor-allowed"
        if mode == "bind-allowed"
        else "/tmp/mithril-observe-secret"
    )
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_bytes(b"secret")
    if mode == "bind-allowed":
        Path("/tmp/mithril-descriptor-secret").write_bytes(b"secret")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    if mode in ("bind", "bind-allowed"):
        names = ("allowed",) if mode == "bind-allowed" else (1, 2)
        aliases = [work / f"bind-{index}" for index in names]
        for alias in aliases:
            alias.mkdir()
        libc.unshare.argtypes = [ctypes.c_int]
        libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
        if mode == "bind":
            if libc.unshare(0x00020000) != 0:
                raise OSError(ctypes.get_errno(), "unshare mount namespace")
            if libc.mount(None, b"/", None, 16384 | 1 << 18, None) != 0:
                raise OSError(ctypes.get_errno(), "make mounts private")
        if libc.mount(os.fsencode(secret.parent), os.fsencode(secret.parent), None, 4096, None) != 0:
            raise OSError(ctypes.get_errno(), "self-bind source")
        for alias in aliases:
            if libc.mount(os.fsencode(secret.parent), os.fsencode(alias), None, 4096, None) != 0:
                raise OSError(ctypes.get_errno(), f"bind {alias}")
        if mode == "bind-allowed":
            actions = [("base", secret), ("alias", aliases[0] / secret.name)]
        else:
            actions = [
                ("base", secret),
                ("confirm", secret),
                ("first", aliases[0] / secret.name),
                ("second", aliases[1] / secret.name),
            ]
            write("bind-paths", json.dumps([str(path) for _, path in actions[1:]]))
    elif mode == "symlink":
        alias = Path("/tmp/mithril-observe-link")
        alias.symlink_to(secret)
        command = "link"
    else:
        held = os.open(secret, os.O_RDWR)
        alias = Path(f"/proc/self/fd/{held}")
        command = "fd"
    print("native-fixture-ready", flush=True)
    if mode not in ("bind", "bind-allowed"):
        actions = [("base", secret), ("confirm", secret)]
        if mode == "procfd":
            actions.extend((f"hf{number}", secret) for number in (6, 8, 9, 10))
        actions.append((command, alias))
    if mode == "bind":
        paths = dict(actions)
        libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
        while command := sys.stdin.readline():
            action = command.rstrip("\n")
            if action == "stop":
                break
            if action in paths:
                error = open_errno(paths[action], os.O_RDONLY)
            elif action == "mount":
                alias = work / "bind-3"
                alias.mkdir()
                result = libc.mount(os.fsencode(secret.parent), os.fsencode(alias), None, 4096, None)
                write("bind-change-mount", str(ctypes.get_errno() if result else 0))
                error = open_errno(alias / secret.name, os.O_RDONLY)
                action = "change"
            elif action == "replace":
                source = work / "replacement-file"
                source.write_bytes(b"benign replacement\n")
                result = libc.mount(os.fsencode(source), os.fsencode(secret), None, 4096, None)
                error = ctypes.get_errno() if result else 0
            elif action == "restore":
                result = libc.umount2(os.fsencode(secret), 0)
                error = ctypes.get_errno() if result else 0
            elif action == "read":
                error = open_errno(secret, os.O_RDONLY)
            else:
                raise RuntimeError(f"unknown bind action {action}")
            mark(libc, action, error)
        sys.exit(0)
    for action, path in actions:
        if sys.stdin.readline() != f"{action}\n":
            raise RuntimeError(f"expected {action}")
        mark(libc, action, open_errno(path, os.O_RDONLY))
elif mode == "race":
    started = threading.Barrier(9)
    release = threading.Event()
    tids = [0] * 8
    errors = [0] * 8

    def attempt(index):
        tids[index] = threading.get_native_id()
        started.wait()
        release.wait()
        errors[index] = open_errno(work / "bounded-secret")

    threads = [threading.Thread(target=attempt, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    started.wait()
    write("thread-ids", json.dumps(tids))
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "race\n":
        raise RuntimeError("expected race")
    release.set()
    for thread in threads:
        thread.join()
    write("race-result", json.dumps(errors))
    command = sys.stdin.readline()
    if command == "stop\n":
        sys.exit(0)
    if command != "again\n":
        raise RuntimeError("expected again")
    write("again-result", str(open_errno(work / "bounded-secret")))
else:
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "expired\n":
        raise RuntimeError("expected expired")
    write("expired-result", str(open_errno(work / "expired-secret")))

if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
