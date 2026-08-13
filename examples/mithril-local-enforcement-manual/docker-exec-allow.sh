#!/usr/bin/env bash
set -euo pipefail

# The supplied executable must exit with status zero. A static executable such
# as BusyBox avoids a separate dynamic-loader image in this exact-image check.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path> <allowed-executable>" >&2
  exit 2
}

observation_extra_exact_path=$4
observation_extra_exact_key=12
observation_extra_exact_class=MANUAL_EXEC_ALLOWED
observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import os, sys
ready, executable = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
os.execv(executable, ["sh", "-c", "exit 0"])
' "$observation_probe_ready" "$4"
observation_release_probe
observation_wait_for_observation 'reason=EXACT_POLICY_ALLOW' "$identity_work/effects.txt"
identity_pass "PASS: the signed allowed executable image replaced the prepared task and exited cleanly."
