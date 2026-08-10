#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_nsenter_probe python3 -c '
import os, signal, sys
ready, path = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
with open(path, "rb") as source:
    source.read(1)
' "$phase3_probe_ready" "$3"
phase3_release_probe
phase3_wait_for_observation 'reason=WOULD_DENY' "$phase2_work/effects.txt"
grep -q 'result=UNKNOWN_AFTER_PRE_EFFECT' "$phase2_work/effects.txt"
phase2_pass "PASS: a raw nsenter process was attributed after cgroup join and reported WOULD_DENY."
