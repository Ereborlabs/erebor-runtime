#!/usr/bin/env bash
set -euo pipefail

# Signal zero performs the Linux permission check without changing the target.
# Both processes start before the signed policy becomes active.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import os, sys
ready = sys.argv[1]
read_end, write_end = os.pipe()
target = os.fork()
if target == 0:
    os.close(write_end)
    os.read(read_end, 1)
    os._exit(0)
os.close(read_end)
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
os.kill(target, 0)
os.close(write_end)
os.waitpid(target, 0)
' "$observation_probe_ready"
observation_release_probe
observation_wait_for_observation 'reason=EXACT_POLICY_ALLOW' "$identity_work/effects.txt"
identity_pass "PASS: the exact process-control rule allowed signal zero to the labeled target."
