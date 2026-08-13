#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

# The node converts this signed one-second lifetime into a monotonic BPF
# deadline. The probe exists before activation so setup cannot consume it.
enforcement_exception_lifetime_ns=1000000000
observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import errno, os, sys
ready, path = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    os.open(path, os.O_WRONLY)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("expired exception allowed a write-open")
' "$observation_probe_ready" "$3"
sleep 2
observation_release_probe
observation_wait_for_observation 'reason=EXCEPTION_UNAVAILABLE' "$identity_work/effects.txt"
identity_pass "PASS: the signed exception expired before use and no write fd was returned."
