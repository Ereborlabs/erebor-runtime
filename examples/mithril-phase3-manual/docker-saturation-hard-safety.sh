#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 || $# -eq 4 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path> [opens]" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_opens=${4:-50000}
[[ $phase3_opens =~ ^[1-9][0-9]*$ ]] || {
  echo "opens must be a positive integer" >&2
  exit 2
}
phase3_preload_probe python3 -c '
import errno, os, signal, socket, sys
ready, path, iterations = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
for _ in range(int(iterations)):
    with open(path, "rb"):
        pass
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    probe.connect(("127.0.0.1", 9))
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise
else:
    raise SystemExit("unsupported network effect was not hard-denied")
finally:
    probe.close()
' "$phase3_probe_ready" "$3" "$phase3_opens"

# The kernel must decide independently of userspace ring consumption.
kill -STOP "$phase2_node_pid"
phase3_release_probe
kill -CONT "$phase2_node_pid"

for ((attempt = 0; attempt < 100; attempt++)); do
  "$phase2_inspect" effects --socket-path "$phase3_socket" \
    --cgroup-scope "$phase3_scope" >"$phase2_work/effects.txt"
  phase3_lost=$(phase3_health_field lost "$phase2_work/effects.txt")
  [[ -n $phase3_lost && $phase3_lost -gt 0 ]] && break
  sleep 0.1
done
[[ -n ${phase3_lost:-} && $phase3_lost -gt 0 ]] || {
  cat "$phase2_work/effects.txt" >&2
  echo "the observation ring did not report saturation loss" >&2
  exit 1
}
phase3_attempted=$(phase3_health_field attempted "$phase2_work/effects.txt")
phase3_emitted=$(phase3_health_field emitted "$phase2_work/effects.txt")
[[ $phase3_attempted -gt $phase3_emitted \
  && $phase3_attempted -eq $((phase3_emitted + phase3_lost)) ]] || {
  cat "$phase2_work/effects.txt" >&2
  echo "saturation counters are inconsistent" >&2
  exit 1
}
phase2_pass "PASS: ring saturation was explicit and an unsupported network effect remained physically denied."
