#!/usr/bin/env bash
set -euo pipefail

# A hard link must not create a new alias for an unqualified object.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
source_path=/tmp/mithril-phase4-link-source-$$
target=/tmp/mithril-phase4-link-target-$$
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
    os.link(source, target)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and not os.path.exists(target):
        raise SystemExit(0)
raise SystemExit("denied link created a new alias")
' "$phase3_probe_ready" "$source_path" "$target"
phase3_release_probe
[[ -e /proc/$phase2_init_pid/root$source_path && ! -e /proc/$phase2_init_pid/root$target ]]
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: denied hard-link creation left no alias."
