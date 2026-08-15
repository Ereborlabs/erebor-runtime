#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
enforcement_bind_directory=/tmp/mithril-local-enforcement-bind-alias-$$
enforcement_second_bind_directory=/tmp/mithril-local-enforcement-second-bind-alias-$$
enforcement_bind_alias=$enforcement_bind_directory/$(basename -- "$3")
enforcement_second_bind_alias=$enforcement_second_bind_directory/$(basename -- "$3")
mkdir -- \
  "/proc/$identity_init_pid/root$enforcement_bind_directory" \
  "/proc/$identity_init_pid/root$enforcement_second_bind_directory"
nsenter -t "$identity_init_pid" -m -r -- \
  mount --bind -- "$(dirname -- "$3")" "$enforcement_bind_directory"
nsenter -t "$identity_init_pid" -m -r -- \
  mount --bind -- "$(dirname -- "$3")" "$enforcement_second_bind_directory"
enforcement_cleanup_bind_alias() {
  nsenter -t "$identity_init_pid" -m -r -- \
    umount -- "$enforcement_bind_directory" 2>/dev/null || true
  nsenter -t "$identity_init_pid" -m -r -- \
    umount -- "$enforcement_second_bind_directory" 2>/dev/null || true
  rmdir -- "/proc/$identity_init_pid/root$enforcement_bind_directory"
  rmdir -- "/proc/$identity_init_pid/root$enforcement_second_bind_directory"
}
identity_cleanup_functions+=(enforcement_cleanup_bind_alias)
observation_preload_nsenter_probe python3 -c '
import errno, os, sys
ready, *paths = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
for path in paths:
    try:
        os.open(path, os.O_RDONLY)
    except PermissionError as error:
        if error.errno in (errno.EACCES, errno.EPERM):
            continue
    raise SystemExit("bind alias returned a protected fd")
' "$observation_probe_ready" "$enforcement_bind_alias" "$enforcement_second_bind_alias"
observation_release_probe
enforcement_expect_exact_denial
identity_pass "PASS: two pre-existing bind aliases canonicalized to the same exact denial."
