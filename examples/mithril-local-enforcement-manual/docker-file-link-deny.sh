#!/usr/bin/env bash
set -euo pipefail

# A hard link must not create a new alias for an unqualified object.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
source_path=/tmp/mithril-local-enforcement-link-source-$$
target=/tmp/mithril-local-enforcement-link-target-$$
printf 'source\n' >"/proc/$identity_init_pid/root$source_path"
cleanup_targets() {
  rm -f -- "/proc/$identity_init_pid/root$source_path" "/proc/$identity_init_pid/root$target"
}
identity_cleanup_functions+=(cleanup_targets)
observation_preload_probe python3 -c '
import errno, os, sys
ready, source, target = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    os.link(source, target)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and not os.path.exists(target):
        raise SystemExit(0)
raise SystemExit("denied link created a new alias")
' "$observation_probe_ready" "$source_path" "$target"
observation_release_probe
[[ -e /proc/$identity_init_pid/root$source_path && ! -e /proc/$identity_init_pid/root$target ]]
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: denied hard-link creation left no alias."
