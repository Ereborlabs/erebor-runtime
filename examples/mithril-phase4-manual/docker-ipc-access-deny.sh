#!/usr/bin/env bash
set -euo pipefail

# Keep one private SysV segment attached and already marked IPC_RMID. This lets
# the live permission attempt run while guaranteeing kernel cleanup on exit.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import ctypes, errno, os, signal, sys
ready = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)
libc.shmat.restype = ctypes.c_void_p
segment = libc.shmget(0, 4096, 0o600)
if segment < 0:
    raise SystemExit("could not prepare private SysV shared memory")
address = libc.shmat(segment, None, 0x1000)
if address == ctypes.c_void_p(-1).value:
    libc.shmctl(segment, 0, None)
    raise SystemExit("could not attach private SysV shared memory")
if libc.shmctl(segment, 0, None) != 0:
    libc.shmdt(address)
    raise SystemExit("could not mark shared memory for automatic deletion")
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
info = ctypes.create_string_buffer(512)
result = libc.shmctl(segment, 2, ctypes.byref(info))
error = ctypes.get_errno()
libc.shmdt(address)
if result == -1 and error in (errno.EACCES, errno.EPERM):
    raise SystemExit(0)
raise SystemExit("Mithril did not hard-close unqualified SysV IPC access")
' "$phase3_probe_ready"
phase3_release_probe
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: unqualified SysV IPC access was denied and the segment self-removed."
