#!/usr/bin/env bash
set -euo pipefail

# Prepare one ordinary file, then prove chmod is denied before its mode changes.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-phase4-setattr-$$
printf 'mode\n' >"/proc/$phase2_init_pid/root$target"
chmod 600 "/proc/$phase2_init_pid/root$target"
cleanup_target() { rm -f -- "/proc/$phase2_init_pid/root$target"; }
phase2_cleanup_functions+=(cleanup_target)
phase3_preload_probe python3 -c '
import errno, os, signal, stat, sys
ready, target = sys.argv[1:]
before = stat.S_IMODE(os.stat(target).st_mode)
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.chmod(target, 0)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and stat.S_IMODE(os.stat(target).st_mode) == before:
        raise SystemExit(0)
raise SystemExit("denied chmod changed the file mode")
' "$phase3_probe_ready" "$target"
phase3_release_probe
[[ $(stat -c %a "/proc/$phase2_init_pid/root$target") == 600 ]]
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: denied chmod left the exact file mode unchanged."
