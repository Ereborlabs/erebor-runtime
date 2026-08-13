#!/usr/bin/env bash
set -euo pipefail

# Delete is a separate pre-effect decision from open/write. The victim must
# still exist with the same bytes after the attempt.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-local-enforcement-unlink-$$
printf 'keep\n' >"/proc/$identity_init_pid/root$target"
cleanup_target() { rm -f -- "/proc/$identity_init_pid/root$target"; }
identity_cleanup_functions+=(cleanup_target)
observation_preload_probe python3 -c '
import errno, os, sys
ready, target = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    os.unlink(target)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and open(target, "rb").read() == b"keep\n":
        raise SystemExit(0)
raise SystemExit("denied unlink removed or changed the victim")
' "$observation_probe_ready" "$target"
observation_release_probe
[[ $(cat "/proc/$identity_init_pid/root$target") == keep ]]
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: denied unlink left the victim and bytes unchanged."
