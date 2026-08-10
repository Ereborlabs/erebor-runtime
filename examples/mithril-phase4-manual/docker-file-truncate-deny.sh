#!/usr/bin/env bash
set -euo pipefail

# Truncate is checked independently from chmod and ordinary write. The original
# length and bytes must remain after EACCES.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-phase4-truncate-$$
printf 'truncate\n' >"/proc/$phase2_init_pid/root$target"
cleanup_target() { rm -f -- "/proc/$phase2_init_pid/root$target"; }
phase2_cleanup_functions+=(cleanup_target)
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready, target = sys.argv[1:]
before = open(target, "rb").read()
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.truncate(target, 0)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and open(target, "rb").read() == before:
        raise SystemExit(0)
raise SystemExit("denied truncate changed the file")
' "$phase3_probe_ready" "$target"
phase3_release_probe
[[ $(cat "/proc/$phase2_init_pid/root$target") == truncate ]]
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: denied truncate left the file length and bytes unchanged."
