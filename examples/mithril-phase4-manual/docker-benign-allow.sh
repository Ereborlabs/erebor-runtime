#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import os, signal, sys
ready, path = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
with open(path, "rb") as source:
    if source.read() != b"benign\n":
        raise SystemExit("benign control returned unexpected bytes")
' "$phase3_probe_ready" "$phase4_benign_path"
phase3_release_probe
phase3_wait_for_observation 'reason=EXACT_POLICY_ALLOW' "$phase2_work/effects.txt"
phase2_pass "PASS: the exact benign same-container control remained readable in protect mode."
