#!/usr/bin/env bash
set -euo pipefail

# Prepare the process first, then request a new UTS namespace only after the
# signed PROTECT generation is active. The current privilege surface is
# intentionally hard closed, so no namespace is created.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import ctypes, errno, os, sys
ready = sys.argv[1]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.argtypes = [ctypes.c_int]
libc.unshare.restype = ctypes.c_int
CLONE_NEWUTS = 0x04000000  # linux/uapi/linux/sched.h
result = libc.unshare(CLONE_NEWUTS)
error = ctypes.get_errno()
if result == -1:
    if error in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
    raise OSError(error, os.strerror(error))
raise SystemExit("Mithril allowed creation of an unqualified UTS namespace")
' "$observation_probe_ready"
observation_release_probe
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: the protected task could not create an unqualified namespace."
