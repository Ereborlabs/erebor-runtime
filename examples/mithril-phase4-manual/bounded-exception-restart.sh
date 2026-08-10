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
import ctypes, errno, os, signal, sys, threading
ready, path = sys.argv[1:]
release = threading.Event()
restarted = threading.Event()
signal.signal(signal.SIGUSR1, lambda _signum, _frame: release.set())
signal.signal(signal.SIGUSR2, lambda _signum, _frame: restarted.set())
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
release.wait()
for _ in range(2):
    descriptor = os.open(path, os.O_WRONLY)
    os.close(descriptor)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(15, b"exc-used", 0, 0, 0) != 0:
    raise SystemExit(f"prctl failed with errno {ctypes.get_errno()}")
restarted.wait()
try:
    os.open(path, os.O_WRONLY)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("loader restart revived the exhausted exception")
' "$phase3_probe_ready" "$3"

kill -USR1 "$phase3_probe_host_pid"
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ $(<"/proc/$phase3_probe_host_pid/comm") == exc-used ]] && break
  sleep 0.02
done
[[ $(<"/proc/$phase3_probe_host_pid/comm") == exc-used ]] || {
  echo "exception probe did not consume its first two uses" >&2
  exit 1
}
phase3_wait_for_observation 'reason=EXACT_POLICY_ALLOW' \
  "$phase2_work/effects-before-restart.txt"
[[ $(grep -c 'reason=EXACT_POLICY_ALLOW' \
  "$phase2_work/effects-before-restart.txt") -eq 2 ]]
phase2_stop_node
phase2_start_node
phase3_wait_for_runtime_socket
kill -USR2 "$phase3_probe_host_pid"
wait "$phase3_probe_pid"
phase3_probe_pid=
phase3_probe_host_pid=
phase3_wait_for_observation 'reason=EXCEPTION_UNAVAILABLE' "$phase2_work/effects.txt"
phase2_pass "PASS: loader restart preserved exhaustion and the third write-open stayed denied."
