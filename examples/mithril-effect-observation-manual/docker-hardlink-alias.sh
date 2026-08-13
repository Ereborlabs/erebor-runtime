#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/observation-runtime.sh"
[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 <node.json> <container>" >&2
  exit 2
}

identity_prepare_docker "$1" "$2"
observation_hardlink_directory=/tmp/mithril-effect-observation-hardlink-$$
observation_hardlink_original=$observation_hardlink_directory/original
observation_hardlink_alias=$observation_hardlink_directory/alias
docker exec "$2" sh -c 'mkdir -p "$1"; printf "secret\n" >"$2"; ln "$2" "$3"' \
  sh "$observation_hardlink_directory" "$observation_hardlink_original" "$observation_hardlink_alias"

observation_cleanup_hardlink() {
  rm -f -- "/proc/$identity_init_pid/root$observation_hardlink_alias" \
    "/proc/$identity_init_pid/root$observation_hardlink_original"
  rmdir -- "/proc/$identity_init_pid/root$observation_hardlink_directory" 2>/dev/null || true
}
identity_cleanup_functions+=(observation_cleanup_hardlink)
observation_configure_secret "$observation_hardlink_original"
observation_preload_probe python3 -c '
import errno, os, sys
ready, original, alias = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
with open(original, "rb") as source:
    source.read(1)
try:
    with open(alias, "rb") as source:
        source.read(1)
except OSError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
    raise
raise SystemExit("hard-link alias inherited a path decision")
' "$observation_probe_ready" "$observation_hardlink_original" "$observation_hardlink_alias"
observation_release_probe
observation_wait_for_observation 'reason=WOULD_DENY' "$identity_work/effects.txt"
observation_wait_for_observation 'reason=UNRESOLVED_OBJECT' "$identity_work/effects.txt"
identity_pass "PASS: the original path simulated denial and the hard-link alias stayed unresolved."
