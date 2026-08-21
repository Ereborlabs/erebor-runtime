#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
host_shared_directory=
container_shared_directory=
case $# in
  0)
    enforcement_path_tree_root=/var/lib/mithril
    enforcement_prepare_k3s \
      docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
    secret_path=$identity_k3s_secret_path
    host_shared_directory=$identity_k3s_shared_directory
    container_shared_directory=$identity_k3s_container_shared_directory
    ;;
  3)
    enforcement_path_tree_root=$(dirname -- "$3")
    observation_prepare_docker "$1" "$2" "$3"
    secret_path=$3
    ;;
  5)
    enforcement_path_tree_root=$(dirname -- "$3")
    enforcement_prepare_cri_shared "$1" "$2" "$3" "$4" "$5"
    secret_path=$3
    host_shared_directory=$4
    container_shared_directory=$5
    ;;
  *)
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  echo "   or: sudo $0 <node.json> <container-id> <absolute-secret-path> <host-shared-directory> <container-shared-directory>" >&2
  echo "   or: sudo $0" >&2
  exit 2
    ;;
esac
enforcement_mount_target=/tmp/mithril-local-enforcement-mount-target-$$
enforcement_attack_target=$(dirname -- "$secret_path")
enforcement_alias_source=$enforcement_attack_target/mithril-child-bind-source-$$
enforcement_alias_marker=$enforcement_alias_source/x
exec {enforcement_mount_namespace_fd}<"/proc/$identity_init_pid/ns/mnt"
exec {enforcement_root_fd}<"/proc/$identity_init_pid/root"
mkdir -- "/proc/$identity_init_pid/root$enforcement_mount_target"
enforcement_cleanup_mount_target() {
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    umount -- "$enforcement_mount_target" 2>/dev/null || true
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    rm -f -- "$enforcement_alias_marker"
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    rmdir -- "$enforcement_alias_source"
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    rmdir -- "$enforcement_mount_target"
  exec {enforcement_mount_namespace_fd}<&-
  exec {enforcement_root_fd}<&-
}
identity_cleanup_functions+=(enforcement_cleanup_mount_target)

observation_preload_nsenter_probe python3 -c '
import ctypes, errno, os, sys, threading, time
ready, source, target, protected_file = sys.argv[1:]
os.mkdir(source)
with open(os.path.join(source, "x"), "wb") as handle:
    handle.write(b"protected child bind marker\n")
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
barrier = threading.Barrier(9)
release = threading.Event()
results = []
def attack(flags):
    barrier.wait()
    release.wait()
    result = libc.mount(source.encode(), target.encode(), None, flags, None)
    results.append((result, ctypes.get_errno()))
threads = [threading.Thread(target=attack, args=(4096,)) for _ in range(4)]
threads += [threading.Thread(target=attack, args=(4096 | 16384,)) for _ in range(4)]
for thread in threads:
    thread.start()
barrier.wait()
gate_path = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(gate_path, 0o600)
gate = os.open(gate_path, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(gate, 1)
os.close(gate)
release.set()
for thread in threads:
    thread.join()
if any(result == 0 for result, _error in results):
    raise SystemExit("protected bind mount unexpectedly completed")
if any(error not in (errno.EACCES, errno.EPERM) for _result, error in results):
    raise SystemExit(f"unexpected mount errors: {results}")
try:
    with open(os.path.join(target, "x"), "rb") as handle:
        handle.read(1)
except (FileNotFoundError, PermissionError):
    pass
else:
    raise SystemExit("child-directory bind alias exposed the protected marker")
for _ in range(25):
    try:
        with open(protected_file, "rb") as handle:
            handle.read(1)
    except PermissionError:
        time.sleep(0.02)
        continue
    raise SystemExit("mount race widened access to the protected file")
' "$observation_probe_ready" "$enforcement_alias_source" "$enforcement_mount_target" "$secret_path"
observation_release_probe
mount_denial='family=7 operation=19 reason=PATH_TREE_POLICY_DENY'
observation_wait_for_observation "$mount_denial" "$identity_work/effects.txt"
[[ $(grep -c "$mount_denial" "$identity_work/effects.txt") -ge 8 ]]
enforcement_expect_path_tree_denial
identity_pass "PASS: child-directory bind and recursive-bind aliases were denied before they exposed the signed path tree."
