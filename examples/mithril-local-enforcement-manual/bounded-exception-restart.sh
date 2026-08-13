#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import ctypes, errno, os, sys
ready, path = sys.argv[1:]
gate_path = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(gate_path, 0o600)
gate = os.open(gate_path, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(gate, 1)
for _ in range(2):
    descriptor = os.open(path, os.O_WRONLY)
    os.close(descriptor)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(15, b"exc-used", 0, 0, 0) != 0:
    raise SystemExit(f"prctl failed with errno {ctypes.get_errno()}")
os.read(gate, 1)
os.close(gate)
try:
    os.open(path, os.O_WRONLY)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("loader restart revived the exhausted exception")
' "$observation_probe_ready" "$3"

observation_open_probe_gate
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ $(<"/proc/$observation_probe_host_pid/comm") == exc-used ]] && break
  sleep 0.02
done
[[ $(<"/proc/$observation_probe_host_pid/comm") == exc-used ]] || {
  echo "exception probe did not consume its first two uses" >&2
  exit 1
}
observation_wait_for_observation 'reason=EXACT_POLICY_ALLOW' \
  "$identity_work/effects-before-restart.txt"
[[ $(grep -c 'reason=EXACT_POLICY_ALLOW' \
  "$identity_work/effects-before-restart.txt") -eq 2 ]]
identity_stop_node
identity_start_node
observation_wait_for_runtime_socket
observation_open_probe_gate
wait "$observation_probe_pid"
observation_probe_pid=
observation_probe_host_pid=
observation_wait_for_observation 'reason=EXCEPTION_UNAVAILABLE' "$identity_work/effects.txt"
identity_pass "PASS: loader restart preserved exhaustion and the third write-open stayed denied."
