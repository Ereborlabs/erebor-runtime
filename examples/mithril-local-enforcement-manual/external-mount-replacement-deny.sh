#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path> <absolute-benign-path>" >&2
  exit 2
}

enforcement_benign_path=$4
observation_prepare_docker "$1" "$2" "$3"
enforcement_replacement_target=$3
enforcement_cleanup_replacement() {
  nsenter -t "$identity_init_pid" -m -r -- \
    umount -- "$enforcement_replacement_target" 2>/dev/null || true
}
identity_cleanup_functions+=(enforcement_cleanup_replacement)
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
    os.open(path, os.O_RDONLY)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("external mount replacement made the protected path readable")
' "$observation_probe_ready" "$3"
nsenter -t "$identity_init_pid" -m -r -- \
  mount --bind -- "$enforcement_benign_path" "$3"
observation_release_probe
observation_wait_for_observation 'reason=UNRESOLVED_OBJECT' "$identity_work/effects.txt"
identity_pass "PASS: an external bind replacement dirtied the view and returned no fd or bytes."
