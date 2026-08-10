#!/usr/bin/env bash
set -euo pipefail

# Allocate RW memory before activation, then try the separate RW->RX effect.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import ctypes, errno, mmap, os, signal, sys
ready = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
page = mmap.PAGESIZE
address = libc.mmap(None, page, mmap.PROT_READ | mmap.PROT_WRITE,
                    mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
if address == ctypes.c_void_p(-1).value:
    raise SystemExit("could not prepare anonymous RW memory")
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
result = libc.mprotect(address, page, mmap.PROT_READ | mmap.PROT_EXEC)
error = ctypes.get_errno()
libc.munmap(address, page)
if result == -1 and error in (errno.EACCES, errno.EPERM):
    raise SystemExit(0)
raise SystemExit("Mithril allowed anonymous memory to become executable")
' "$phase3_probe_ready"
phase3_release_probe
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: anonymous RW memory could not become executable."
