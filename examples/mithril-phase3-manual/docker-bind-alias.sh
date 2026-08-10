#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 4 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <mounted-secret-path> <alias-directory>" >&2
  exit 2
}

phase2_prepare_docker "$1" "$2"
phase2_require_command nsenter
phase3_bind_secret=$3
phase3_bind_original=$(dirname -- "$phase3_bind_secret")
phase3_bind_name=${phase3_bind_secret##*/}
phase3_bind_alias=$4
[[ $phase3_bind_secret == /* && $phase3_bind_alias == /* ]] || {
  echo "secret and alias paths must be absolute" >&2
  exit 2
}

phase3_cleanup_bind_alias() {
  nsenter -t "$phase2_init_pid" -m -r -- umount "$phase3_bind_alias" 2>/dev/null || true
  rmdir -- "/proc/$phase2_init_pid/root$phase3_bind_alias" 2>/dev/null || true
}
phase2_cleanup_functions+=(phase3_cleanup_bind_alias)

nsenter -t "$phase2_init_pid" -m -r -- sh -c '
  mkdir -p "$2"
  mount --bind "$1" "$2"
' sh "$phase3_bind_original" "$phase3_bind_alias"

phase3_configure_secret "$phase3_bind_secret"
phase3_preload_probe python3 -c '
import os, signal, sys
ready, alias = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
with open(alias, "rb") as source:
    source.read(1)
' "$phase3_probe_ready" "$phase3_bind_alias/$phase3_bind_name"
phase3_release_probe
phase3_wait_for_observation 'reason=WOULD_DENY' "$phase2_work/effects.txt"
grep -q 'result=UNKNOWN_AFTER_PRE_EFFECT' "$phase2_work/effects.txt"
phase2_pass "PASS: the later bind alias canonicalized to the original tracked mount and simulated denial."
