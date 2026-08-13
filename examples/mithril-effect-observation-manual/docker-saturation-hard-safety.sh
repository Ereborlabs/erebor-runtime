#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
[[ $# -eq 3 || $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path> [opens]" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_opens=${4:-50000}
[[ $observation_opens =~ ^[1-9][0-9]*$ ]] || {
  echo "opens must be a positive integer" >&2
  exit 2
}
observation_preload_probe python3 -c '
import errno, os, socket, sys
ready, path, iterations = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
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
' "$observation_probe_ready" "$3" "$observation_opens"

# The kernel must decide independently of userspace ring consumption.
kill -STOP "$identity_node_pid"
observation_release_probe
kill -CONT "$identity_node_pid"

for ((attempt = 0; attempt < 100; attempt++)); do
  "$identity_inspect" effects --socket-path "$observation_socket" \
    --cgroup-scope "$observation_scope" >"$identity_work/effects.txt"
  observation_lost=$(observation_health_field lost "$identity_work/effects.txt")
  [[ -n $observation_lost && $observation_lost -gt 0 ]] && break
  sleep 0.1
done
[[ -n ${observation_lost:-} && $observation_lost -gt 0 ]] || {
  cat "$identity_work/effects.txt" >&2
  echo "the observation ring did not report saturation loss" >&2
  exit 1
}
observation_attempted=$(observation_health_field attempted "$identity_work/effects.txt")
observation_emitted=$(observation_health_field emitted "$identity_work/effects.txt")
[[ $observation_attempted -gt $observation_emitted \
  && $observation_attempted -eq $((observation_emitted + observation_lost)) ]] || {
  cat "$identity_work/effects.txt" >&2
  echo "saturation counters are inconsistent" >&2
  exit 1
}
identity_pass "PASS: ring saturation was explicit and an unsupported network effect remained physically denied."
