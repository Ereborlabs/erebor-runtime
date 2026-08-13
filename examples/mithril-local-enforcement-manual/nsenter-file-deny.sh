#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_nsenter_probe python3 -c '
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
    with open(path, "rb") as source:
        source.read(1)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("raw nsenter task bypassed Mithril")
' "$observation_probe_ready" "$3"
observation_release_probe
enforcement_expect_exact_denial
identity_pass "PASS: raw nsenter placement received the same exact pre-effect denial."
