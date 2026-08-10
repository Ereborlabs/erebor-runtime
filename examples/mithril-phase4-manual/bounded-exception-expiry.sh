#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

# The node converts this signed one-second lifetime into a monotonic BPF
# deadline. The probe exists before activation so setup cannot consume it.
phase4_exception_lifetime_ns=1000000000
phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready, path = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.open(path, os.O_WRONLY)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("expired exception allowed a write-open")
' "$phase3_probe_ready" "$3"
sleep 2
phase3_release_probe
phase3_wait_for_observation 'reason=EXCEPTION_UNAVAILABLE' "$phase2_work/effects.txt"
phase2_pass "PASS: the signed exception expired before use and no write fd was returned."
