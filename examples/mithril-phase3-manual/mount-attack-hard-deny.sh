#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_mount_target=/tmp/mithril-phase3-mount-target-$$
mkdir -- "/proc/$phase2_init_pid/root$phase3_mount_target"
phase3_cleanup_mount_target() {
  nsenter -t "$phase2_init_pid" -m -r -- \
    umount -- "$phase3_mount_target" 2>/dev/null || true
  rmdir -- "/proc/$phase2_init_pid/root$phase3_mount_target"
}
phase2_cleanup_functions+=(phase3_cleanup_mount_target)

phase3_preload_nsenter_probe python3 -c '
import ctypes, errno, os, signal, sys, threading, time
ready, source, target, protected_file = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
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
' "$phase3_probe_ready" "$(dirname -- "$3")" "$phase3_mount_target" "$3"
phase3_release_probe
phase3_wait_for_observation 'reason=UNSUPPORTED_OBJECT' "$phase2_work/effects.txt"
phase3_wait_for_observation 'reason=WOULD_DENY' "$phase2_work/effects.txt"
phase2_pass "PASS: concurrent protected mount attacks were hard-denied; DIRTY reconciliation restored observe-only file decisions."
