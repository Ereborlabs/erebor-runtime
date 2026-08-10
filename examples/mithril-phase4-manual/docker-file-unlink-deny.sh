#!/usr/bin/env bash
set -euo pipefail

# Delete is a separate pre-effect decision from open/write. The victim must
# still exist with the same bytes after the attempt.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-phase4-unlink-$$
printf 'keep\n' >"/proc/$phase2_init_pid/root$target"
cleanup_target() { rm -f -- "/proc/$phase2_init_pid/root$target"; }
phase2_cleanup_functions+=(cleanup_target)
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready, target = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.unlink(target)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and open(target, "rb").read() == b"keep\n":
        raise SystemExit(0)
raise SystemExit("denied unlink removed or changed the victim")
' "$phase3_probe_ready" "$target"
phase3_release_probe
[[ $(cat "/proc/$phase2_init_pid/root$target") == keep ]]
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: denied unlink left the victim and bytes unchanged."
