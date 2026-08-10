#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase4_bind_directory=/tmp/mithril-phase4-bind-alias-$$
phase4_bind_alias=$phase4_bind_directory/$(basename -- "$3")
mkdir -- "/proc/$phase2_init_pid/root$phase4_bind_directory"
nsenter -t "$phase2_init_pid" -m -r -- \
  mount --bind -- "$(dirname -- "$3")" "$phase4_bind_directory"
phase4_cleanup_bind_alias() {
  nsenter -t "$phase2_init_pid" -m -r -- \
    umount -- "$phase4_bind_directory" 2>/dev/null || true
  rmdir -- "/proc/$phase2_init_pid/root$phase4_bind_directory"
}
phase2_cleanup_functions+=(phase4_cleanup_bind_alias)
phase3_preload_nsenter_probe python3 -c '
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
raise SystemExit("bind alias returned a protected fd")
' "$phase3_probe_ready" "$phase4_bind_alias"
phase3_release_probe
phase4_expect_exact_denial
phase2_pass "PASS: the pre-existing bind alias canonicalized to the same exact denial."
