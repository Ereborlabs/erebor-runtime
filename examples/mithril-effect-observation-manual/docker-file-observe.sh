#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import os, sys
ready, path = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    with open(path, "rb") as source:
        source.read(1)
except BaseException:
    os._exit(42)
os._exit(0)
' "$observation_probe_ready" "$3"
observation_release_probe
observation_wait_for_observation 'reason=WOULD_DENY' "$identity_work/effects.txt"
grep -q 'result=UNKNOWN_AFTER_PRE_EFFECT' "$identity_work/effects.txt"
identity_pass "PASS: file read completed and Mithril reported the exact observe-only WOULD_DENY."
