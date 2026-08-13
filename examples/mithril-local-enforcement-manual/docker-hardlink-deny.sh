#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
enforcement_hardlink=$(dirname -- "$3")/.mithril-local-enforcement-hardlink-$$
ln -- "/proc/$identity_init_pid/root$3" "/proc/$identity_init_pid/root$enforcement_hardlink"
enforcement_cleanup_hardlink() {
  rm -f -- "/proc/$identity_init_pid/root$enforcement_hardlink"
}
identity_cleanup_functions+=(enforcement_cleanup_hardlink)
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
    os.open(path, os.O_RDONLY)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("hard-link alias returned a protected fd")
' "$observation_probe_ready" "$enforcement_hardlink"
observation_release_probe
observation_wait_for_observation 'reason=UNRESOLVED_OBJECT' "$identity_work/effects.txt"
identity_pass "PASS: an undeclared hard-link alias returned no protected fd."
