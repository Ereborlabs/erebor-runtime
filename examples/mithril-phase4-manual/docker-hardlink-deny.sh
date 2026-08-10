#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase4_hardlink=$(dirname -- "$3")/.mithril-phase4-hardlink-$$
ln -- "/proc/$phase2_init_pid/root$3" "/proc/$phase2_init_pid/root$phase4_hardlink"
phase4_cleanup_hardlink() {
  rm -f -- "/proc/$phase2_init_pid/root$phase4_hardlink"
}
phase2_cleanup_functions+=(phase4_cleanup_hardlink)
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready, path = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.open(path, os.O_RDONLY)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("hard-link alias returned a protected fd")
' "$phase3_probe_ready" "$phase4_hardlink"
phase3_release_probe
phase3_wait_for_observation 'reason=UNRESOLVED_OBJECT' "$phase2_work/effects.txt"
phase2_pass "PASS: an undeclared hard-link alias returned no protected fd."
