#!/usr/bin/env bash
set -euo pipefail

# Start Python before activation, then attempt a new executable image. The
# command must never replace the prepared process.
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
    os.execv("/bin/true", ["true"])
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("Mithril allowed an unqualified executable image")
' "$phase3_probe_ready"
phase3_release_probe
phase4_expect_hard_close UNRESOLVED_OBJECT
phase2_pass "PASS: an unqualified executable image never replaced the prepared task."
