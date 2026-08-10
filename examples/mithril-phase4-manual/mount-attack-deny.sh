#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase4_mount_target=/tmp/mithril-phase4-mount-target-$$
mkdir -- "/proc/$phase2_init_pid/root$phase4_mount_target"
phase4_cleanup_mount_target() {
  nsenter -t "$phase2_init_pid" -m -r -- \
    umount -- "$phase4_mount_target" 2>/dev/null || true
  rmdir -- "/proc/$phase2_init_pid/root$phase4_mount_target"
}
phase2_cleanup_functions+=(phase4_cleanup_mount_target)

phase3_preload_nsenter_probe python3 -c '
import ctypes, errno, os, signal, sys, threading, time
ready, source, target, protected_file = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
barrier = threading.Barrier(9)
release = threading.Event()
results = []
def attack():
    barrier.wait()
    release.wait()
    result = libc.mount(source.encode(), target.encode(), None, 4096, None)
    results.append((result, ctypes.get_errno()))
threads = [threading.Thread(target=attack) for _ in range(8)]
for thread in threads:
    thread.start()
barrier.wait()
signal.signal(signal.SIGUSR1, lambda _signum, _frame: release.set())
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
for thread in threads:
    thread.join()
if any(result == 0 for result, _error in results):
    raise SystemExit("protected bind mount unexpectedly completed")
if any(error not in (errno.EACCES, errno.EPERM) for _result, error in results):
    raise SystemExit(f"unexpected mount errors: {results}")
for _ in range(25):
    try:
        with open(protected_file, "rb") as handle:
            handle.read(1)
    except PermissionError:
        time.sleep(0.02)
        continue
    raise SystemExit("mount race widened access to the protected file")
' "$phase3_probe_ready" "$(dirname -- "$3")" "$phase4_mount_target" "$3"
phase3_release_probe
phase3_wait_for_observation 'reason=UNSUPPORTED_OBJECT' "$phase2_work/effects.txt"
phase4_expect_exact_denial
phase2_pass "PASS: every protected mount attempt was denied and no file retry widened authority."
