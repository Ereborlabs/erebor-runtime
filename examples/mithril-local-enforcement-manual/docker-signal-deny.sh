#!/usr/bin/env bash
set -euo pipefail

# SIGCONT has no effect on the running target. The policy does not list this
# signal argument, so the signed wildcard denial must apply.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import os, signal, sys
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
denied = False
try:
    os.kill(target, signal.SIGCONT)
except PermissionError:
    denied = True
os.close(write_end)
os.waitpid(target, 0)
if not denied:
    raise SystemExit("Mithril allowed an unlisted signal to the labeled target")
' "$observation_probe_ready"
observation_release_probe
observation_wait_for_observation 'reason=EXACT_POLICY_DENY' "$identity_work/effects.txt"
identity_pass "PASS: the process-control rule denied an unlisted signal to the labeled target."
