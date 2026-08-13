#!/usr/bin/env bash
set -euo pipefail

# Allocate RW memory before activation, then try the separate RW->RX effect.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import ctypes, errno, mmap, os, sys
ready = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
page = mmap.PAGESIZE
address = libc.mmap(None, page, mmap.PROT_READ | mmap.PROT_WRITE,
                    mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
if address == ctypes.c_void_p(-1).value:
    raise SystemExit("could not prepare anonymous RW memory")
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
result = libc.mprotect(address, page, mmap.PROT_READ | mmap.PROT_EXEC)
error = ctypes.get_errno()
libc.munmap(address, page)
if result == -1 and error in (errno.EACCES, errno.EPERM):
    raise SystemExit(0)
raise SystemExit("Mithril allowed anonymous memory to become executable")
' "$observation_probe_ready"
observation_release_probe
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: anonymous RW memory could not become executable."
