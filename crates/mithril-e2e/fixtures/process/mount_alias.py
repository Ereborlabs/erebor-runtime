import ctypes
import errno
import json
import os
import sys
import threading


libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
]
libc.open_tree.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
libc.open_tree.restype = ctypes.c_int
libc.move_mount.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
libc.move_mount.restype = ctypes.c_int


class MountAttr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    ]


libc.mount_setattr.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
    ctypes.POINTER(MountAttr),
    ctypes.c_size_t,
]
libc.mount_setattr.restype = ctypes.c_int
libc.prctl.argtypes = [
    ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong
]
AT_FDCWD = -100
AT_RECURSIVE = 0x8000
CLONE_NEWNS = 0x00020000
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_SHARED = 1 << 20
OPEN_TREE_CLONE = 1
MOVE_EMPTY_PATH = 4


def check(result):
    if result:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def open_tree(source):
    tree = libc.open_tree(AT_FDCWD, source.encode(), OPEN_TREE_CLONE | os.O_CLOEXEC)
    return tree if tree >= 0 else -ctypes.get_errno()


def move_tree(tree, target):
    if tree < 0:
        return -tree
    try:
        result = libc.move_mount(tree, b"", AT_FDCWD, target.encode(), MOVE_EMPTY_PATH)
        return ctypes.get_errno() if result else 0
    finally:
        os.close(tree)


def read_file(path):
    try:
        with open(path, encoding="utf-8") as source:
            return {"errno": 0, "value": source.read()}
    except OSError as error:
        return {"errno": error.errno, "value": None}


args = sys.argv[2:]
if args == ["external-setattr"]:
    pid = int(sys.argv[1])
    namespace = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
    root = os.open(f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY)
    try:
        libc.setns.argtypes = [ctypes.c_int, ctypes.c_int]
        check(libc.setns(namespace, CLONE_NEWNS))
        os.fchdir(root)
        os.chroot(".")
        os.chdir("/")
    finally:
        os.close(root)
        os.close(namespace)
    target = b"/work/mount/allowed-alias"
    print("native-fixture-ready", flush=True)
    for command in sys.stdin:
        if command == "stop\n":
            sys.exit(0)
        if command not in ("ro\n", "rw\n"):
            sys.exit(2)
        readonly = command == "ro\n"
        attr = MountAttr(int(readonly), int(not readonly), 0, 0)
        check(libc.mount_setattr(
            AT_FDCWD, target, AT_RECURSIVE, ctypes.byref(attr), ctypes.sizeof(attr)
        ))
        actual = bool(os.statvfs(target).f_flag & os.ST_RDONLY)
        if actual != readonly:
            raise RuntimeError(f"mount read-only state is {actual}; expected {readonly}")
        name = ctypes.create_string_buffer(f"mnt-{command.strip()}-{int(actual)}".encode())
        check(libc.prctl(15, name, 0, 0, 0))
    sys.exit(0)
if args not in (
    [], ["late"], ["recursive"], ["move"], ["prepared"], ["setattr"], ["propagate"], ["future"], ["race"], ["runtime"], ["subpath"], ["reconfigure"], ["cache"]
):
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

if mode == "subpath":
    print("native-fixture-ready", flush=True)
    if sys.stdin.readline() != "read\n":
        sys.exit(2)
    denied = {}
    for name, path in {
        "source": "/home/secret/models/secret",
        "older": "/home/kubelet-attack/secret",
        "newer": "/home/kubelet-attack-newer/secret",
    }.items():
        try:
            with open(path, encoding="utf-8"):
                denied[name] = 0
        except OSError as error:
            denied[name] = error.errno
    with open(result_path, "w", encoding="utf-8") as output:
        json.dump(denied, output)
    sys.exit(0)

mount_error = 0
if mode not in ("future", "runtime"):
    check(libc.unshare(CLONE_NEWNS))
    check(libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None))
mount_namespace = os.stat("/proc/self/ns/mnt").st_ino
if mode == "early":
    check(libc.mount(secret.encode(), denied_alias.encode(), None, MS_BIND, None))
if mode not in ("recursive", "future", "runtime", "reconfigure"):
    check(libc.mount(allowed.encode(), allowed_alias.encode(), None, MS_BIND, None))
prepared_tree = None
if mode == "prepared":
    prepared_tree = open_tree(secret)
    if prepared_tree < 0:
        raise OSError(-prepared_tree, os.strerror(-prepared_tree))
    with open(result_path, "w", encoding="utf-8") as output:
        json.dump({"phase": "opened", "open": 0}, output)
race_results = [None] * 8
race_barrier = threading.Barrier(9)
race_threads = []
if mode == "race":
    def run_mount(index):
        race_barrier.wait()
        result = libc.mount(allowed.encode(), secret.encode(), None, MS_BIND, None)
        race_results[index] = ctypes.get_errno() if result else 0

    race_threads = [threading.Thread(target=run_mount, args=(index,)) for index in range(8)]
    for thread in race_threads:
        thread.start()
print("native-fixture-ready", flush=True)
command = sys.stdin.readline()
if mode == "cache":
    peer, request, reply = None, None, None
    while command != "stop\n":
        if command == "peer\n" and peer is None:
            rx, tx = os.pipe()
            rd, wr = os.pipe()
            peer = os.fork()
            if peer == 0:
                os.close(tx)
                os.close(rd)
                check(libc.unshare(CLONE_NEWNS))
                with os.fdopen(rx) as commands, os.fdopen(wr, "w") as replies:
                    replies.write("ready\n")
                    replies.flush()
                    for phase in commands:
                        if phase == "stop\n":
                            break
                        if phase not in ("b\n", "ro\n", "rw\n"):
                            sys.exit(2)
                        replies.write(json.dumps(read_file(os.path.join(allowed, "open"))) + "\n")
                        replies.flush()
                sys.exit(0)
            os.close(rx)
            os.close(wr)
            request = os.fdopen(tx, "w")
            reply = os.fdopen(rd)
            if reply.readline() != "ready\n":
                raise RuntimeError("mount peer did not become ready")
            check(libc.prctl(15, ctypes.create_string_buffer(b"cache-peer-up"), 0, 0, 0))
            command = sys.stdin.readline()
            continue
        if command not in ("b\n", "ro\n", "rw\n", "pb\n", "pro\n", "prw\n"):
            sys.exit(2)
        if command.startswith("p"):
            request.write(command[1:])
            request.flush()
            result = json.loads(reply.readline())
        else:
            result = read_file(os.path.join(allowed, "open"))
        with open(result_path, "w", encoding="utf-8") as output:
            json.dump(result, output)
        name = ctypes.create_string_buffer(f"cache-{command.strip()}-{result['errno']}".encode())
        check(libc.prctl(15, name, 0, 0, 0))
        command = sys.stdin.readline()
    if peer is not None:
        request.write("stop\n")
        request.flush()
        request.close()
        reply.close()
        _, status = os.waitpid(peer, 0)
        if status:
            raise RuntimeError(f"mount peer failed: {status}")
    sys.exit(0)
if mode == "reconfigure":
    FSPICK_CLOEXEC = 1
    FSCONFIG_SET_STRING = 1
    FSCONFIG_CMD_RECONFIGURE = 7
    libc.fspick.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    libc.fsconfig.argtypes = [
        ctypes.c_int, ctypes.c_uint, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int
    ]
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    while command != "stop\n":
        code = 0
        if command == "mount\n":
            check(libc.mount(b"tmpfs", allowed_alias.encode(), b"tmpfs", 0, None))
        elif command == "config\n":
            context = libc.fspick(AT_FDCWD, allowed_alias.encode(), FSPICK_CLOEXEC)
            if context < 0:
                raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            try:
                check(libc.fsconfig(context, FSCONFIG_SET_STRING, b"size", b"4194304", 0))
                check(libc.fsconfig(context, FSCONFIG_CMD_RECONFIGURE, None, None, 0))
            finally:
                os.close(context)
        elif command == "read\n":
            try:
                with open(os.path.join(allowed, "open"), encoding="utf-8") as source:
                    value = source.read()
            except OSError as error:
                code = error.errno
                value = None
            size = os.statvfs(allowed_alias)
            with open(result_path, "w", encoding="utf-8") as output:
                json.dump({"errno": code, "value": value,
                           "size": size.f_blocks * size.f_frsize}, output)
        elif command == "unmount\n":
            check(libc.umount2(allowed_alias.encode(), 0))
        else:
            sys.exit(2)
        name = ctypes.create_string_buffer(f"mnt-{command.strip()}-{code}".encode())
        check(libc.prctl(15, name, 0, 0, 0))
        command = sys.stdin.readline()
    sys.exit(0)
allowed_mount_error = 0
mount_allowed = 0
mount_denied = 0
mount_other = 0
if mode == "future" and command == "read\n":
    check(libc.unshare(CLONE_NEWNS))
    result = libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)
    mount_error = ctypes.get_errno() if result else 0
    mount_namespace = os.stat("/proc/self/ns/mnt").st_ino
elif mode == "race" and command == "race\n":
    race_barrier.wait()
    for thread in race_threads:
        thread.join()
    mount_allowed = race_results.count(0)
    mount_denied = sum(result in (errno.EACCES, errno.EPERM) for result in race_results)
    mount_other = 8 - mount_allowed - mount_denied
elif mode == "move" and command == "open\n":
    denied_tree = open_tree(secret)
    allowed_tree = open_tree(allowed)
    with open(result_path, "r+", encoding="utf-8") as output:
        json.dump(
            {
                "phase": "opened",
                "open": 0 if denied_tree >= 0 else -denied_tree,
                "allowed_open": 0 if allowed_tree >= 0 else -allowed_tree,
            },
            output,
        )
        output.truncate()
    command = sys.stdin.readline()
    if command != "mount\n":
        sys.exit(2)
    mount_error = move_tree(denied_tree, denied_alias)
    allowed_mount_error = move_tree(allowed_tree, allowed_alias)
    with open(result_path, "r+", encoding="utf-8") as output:
        json.dump(
            {
                "phase": "mounted",
                "mount": mount_error,
                "allowed_mount": allowed_mount_error,
            },
            output,
        )
        output.truncate()
    command = sys.stdin.readline()
elif mode == "prepared" and command == "mount\n":
    mount_error = move_tree(prepared_tree, denied_alias)
    with open(result_path, "w", encoding="utf-8") as output:
        json.dump({"phase": "mounted", "mount": mount_error}, output)
    sys.exit(0)
elif mode == "setattr" and command == "setattr\n":
    attr = MountAttr(1, 0, 0, 0)
    result = libc.mount_setattr(
        AT_FDCWD, allowed_alias.encode(), 0, ctypes.byref(attr), ctypes.sizeof(attr)
    )
    code = ctypes.get_errno() if result else 0
    with open(result_path, "w", encoding="utf-8") as output:
        json.dump({"phase": "setattr", "errno": code}, output)
    sys.exit(0)
elif mode == "propagate" and command == "share\n":
    result = libc.mount(None, allowed_alias.encode(), None, MS_SHARED | MS_REC, None)
    code = ctypes.get_errno() if result else 0
    with open(result_path, "w", encoding="utf-8") as output:
        json.dump({"phase": "shared", "errno": code}, output)
    sys.exit(0)
if mode in ("late", "recursive", "runtime") and command in ("mount-read\n", "mount\n"):
    flags = MS_BIND | (MS_REC if mode == "recursive" else 0)
    result = libc.mount(secret.encode(), denied_alias.encode(), None, flags, None)
    mount_error = ctypes.get_errno() if result else 0
    if mode in ("recursive", "runtime"):
        result = libc.mount(allowed.encode(), allowed_alias.encode(), None, flags, None)
        allowed_mount_error = ctypes.get_errno() if result else 0
    if mode == "runtime" and command == "mount\n":
        with open(result_path, "w", encoding="utf-8") as output:
            json.dump(
                {
                    "phase": "mounted",
                    "mount": mount_error,
                    "allowed_mount": allowed_mount_error,
                },
                output,
            )
        if sys.stdin.readline() != "read\n":
            sys.exit(2)
elif command not in ("read\n", "race\n"):
    sys.exit(2)

try:
    denied_path = secret if mode in ("future", "race") else denied_alias
    with open(os.path.join(denied_path, "blocked"), encoding="utf-8"):
        denied = 0
except OSError as error:
    denied = error.errno
try:
    allowed_path = allowed if mode in ("future", "race") else allowed_alias
    with open(os.path.join(allowed_path, "open"), encoding="utf-8") as source:
        value = source.read()
except OSError as error:
    value = f"errno:{error.errno}"
with open(result_path, "w", encoding="utf-8") as output:
    json.dump(
        {
            "phase": "read",
            "mount_namespace": mount_namespace,
            "mount": mount_error,
            "allowed_mount": allowed_mount_error,
            "mount_allowed": mount_allowed,
            "mount_denied": mount_denied,
            "mount_other": mount_other,
            "denied": denied,
            "allowed": value,
        },
        output,
    )
