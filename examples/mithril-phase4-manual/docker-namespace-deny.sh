#!/usr/bin/env bash
set -euo pipefail

# Prepare the process first, then request a new UTS namespace only after the
# signed PROTECT generation is active. The current privilege surface is
# intentionally hard closed, so no namespace is created.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready = sys.argv[1]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.unshare(os.CLONE_NEWUTS)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("Mithril allowed creation of an unqualified UTS namespace")
' "$phase3_probe_ready"
phase3_release_probe
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: the protected task could not create an unqualified namespace."
