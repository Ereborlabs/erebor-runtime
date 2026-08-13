#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_mount_target=/tmp/mithril-effect-observation-mount-target-$$
mkdir -- "/proc/$identity_init_pid/root$observation_mount_target"
observation_cleanup_mount_target() {
  nsenter -t "$identity_init_pid" -m -r -- \
    umount -- "$observation_mount_target" 2>/dev/null || true
  rmdir -- "/proc/$identity_init_pid/root$observation_mount_target"
}
identity_cleanup_functions+=(observation_cleanup_mount_target)

observation_preload_nsenter_probe python3 -c '
import ctypes, errno, os, sys, threading, time
ready, source, target, protected_file = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
]
libc.mount.restype = ctypes.c_int
MS_BIND = 4096  # linux/uapi/linux/mount.h
barrier = threading.Barrier(8)
results = []
def attack():
    barrier.wait()
    result = libc.mount(source.encode(), target.encode(), None, MS_BIND, None)
    results.append((result, ctypes.get_errno()))
threads = [threading.Thread(target=attack) for _ in range(8)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
if any(result == 0 for result, _error in results):
    raise SystemExit("protected bind mount unexpectedly completed")
for _result, mount_errno in results:
    if mount_errno not in (errno.EACCES, errno.EPERM):
        raise OSError(mount_errno, os.strerror(mount_errno))
deadline = time.monotonic() + 5
while True:
    try:
        with open(protected_file, "rb") as handle:
            handle.read(1)
        break
    except PermissionError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.1)
' "$observation_probe_ready" "$(dirname -- "$3")" "$observation_mount_target" "$3"
observation_release_probe
observation_wait_for_observation 'reason=UNSUPPORTED_OBJECT' "$identity_work/effects.txt"
observation_wait_for_observation 'reason=WOULD_DENY' "$identity_work/effects.txt"
identity_pass "PASS: concurrent protected mount attacks were hard-denied; DIRTY reconciliation restored observe-only file decisions."
