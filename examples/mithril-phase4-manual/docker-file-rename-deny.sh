#!/usr/bin/env bash
set -euo pipefail

# Rename must preserve both sides: the source remains and the destination does
# not appear.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
source_path=/tmp/mithril-phase4-rename-source-$$
target=/tmp/mithril-phase4-rename-target-$$
printf 'source\n' >"/proc/$phase2_init_pid/root$source_path"
cleanup_targets() {
  rm -f -- "/proc/$phase2_init_pid/root$source_path" "/proc/$phase2_init_pid/root$target"
}
phase2_cleanup_functions+=(cleanup_targets)
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready, source, target = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.rename(source, target)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and os.path.exists(source) and not os.path.exists(target):
        raise SystemExit(0)
raise SystemExit("denied rename changed the source or destination")
' "$phase3_probe_ready" "$source_path" "$target"
phase3_release_probe
[[ -e /proc/$phase2_init_pid/root$source_path && ! -e /proc/$phase2_init_pid/root$target ]]
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: denied rename preserved source and destination state."
