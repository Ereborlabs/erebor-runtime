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
import errno, os, socket, sys
ready = sys.argv[1]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    socket.create_connection(("127.0.0.1", 9), timeout=1)
except OSError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
    raise
raise SystemExit("unsupported protected network connect unexpectedly completed")
' "$observation_probe_ready"
observation_release_probe
observation_wait_for_observation 'reason=UNSUPPORTED_OBJECT' "$identity_work/effects.txt"
grep -q 'result=DENIED_BEFORE_EFFECT' "$identity_work/effects.txt"
identity_pass "PASS: unsupported network identity stayed a hard denial in observe mode."
