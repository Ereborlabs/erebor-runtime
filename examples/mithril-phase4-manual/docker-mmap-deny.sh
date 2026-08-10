#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import errno, mmap, os, signal, sys
ready, path = sys.argv[1:]
secret = open(path, "rb")
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    mmap.mmap(secret.fileno(), 0, access=mmap.ACCESS_READ)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("descriptor acquired before activation bypassed the mmap decision")
' "$phase3_probe_ready" "$3"
phase3_release_probe
phase4_expect_exact_denial
phase2_pass "PASS: file-backed mmap was denied before a protected mapping existed."
