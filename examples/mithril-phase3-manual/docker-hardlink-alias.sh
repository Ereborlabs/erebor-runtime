#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container>" >&2
  exit 2
}

phase2_prepare_docker "$1" "$2"
phase3_hardlink_directory=/tmp/mithril-phase3-hardlink-$$
phase3_hardlink_original=$phase3_hardlink_directory/original
phase3_hardlink_alias=$phase3_hardlink_directory/alias
docker exec "$2" sh -c 'mkdir -p "$1"; printf "secret\n" >"$2"; ln "$2" "$3"' \
  sh "$phase3_hardlink_directory" "$phase3_hardlink_original" "$phase3_hardlink_alias"

phase3_cleanup_hardlink() {
  rm -f -- "/proc/$phase2_init_pid/root$phase3_hardlink_alias" \
    "/proc/$phase2_init_pid/root$phase3_hardlink_original"
  rmdir -- "/proc/$phase2_init_pid/root$phase3_hardlink_directory" 2>/dev/null || true
}
phase2_cleanup_functions+=(phase3_cleanup_hardlink)
phase3_configure_secret "$phase3_hardlink_original"
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready, original, alias = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
with open(original, "rb") as source:
    source.read(1)
try:
    with open(alias, "rb") as source:
        source.read(1)
except OSError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
    raise
raise SystemExit("hard-link alias inherited a path decision")
' "$phase3_probe_ready" "$phase3_hardlink_original" "$phase3_hardlink_alias"
phase3_release_probe
phase3_wait_for_observation 'reason=WOULD_DENY' "$phase2_work/effects.txt"
phase3_wait_for_observation 'reason=UNRESOLVED_OBJECT' "$phase2_work/effects.txt"
phase2_pass "PASS: the original path simulated denial and the hard-link alias stayed unresolved."
