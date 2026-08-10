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
import errno, os, signal, socket, sys
ready = sys.argv[1]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    socket.create_connection(("127.0.0.1", 9), timeout=1)
except OSError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
    raise
raise SystemExit("unsupported protected network connect unexpectedly completed")
' "$phase3_probe_ready"
phase3_release_probe
phase3_wait_for_observation 'reason=UNSUPPORTED_OBJECT' "$phase2_work/effects.txt"
grep -q 'result=DENIED_BEFORE_EFFECT' "$phase2_work/effects.txt"
phase2_pass "PASS: unsupported network identity stayed a hard denial in observe mode."
