#!/usr/bin/env bash
set -euo pipefail

# Truncate is checked independently from chmod and ordinary write. The original
# length and bytes must remain after EACCES.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-local-enforcement-truncate-$$
printf 'truncate\n' >"/proc/$identity_init_pid/root$target"
cleanup_target() { rm -f -- "/proc/$identity_init_pid/root$target"; }
identity_cleanup_functions+=(cleanup_target)
observation_preload_probe python3 -c '
import errno, os, sys
ready, target = sys.argv[1:]
before = open(target, "rb").read()
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    os.truncate(target, 0)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and open(target, "rb").read() == before:
        raise SystemExit(0)
raise SystemExit("denied truncate changed the file")
' "$observation_probe_ready" "$target"
observation_release_probe
[[ $(cat "/proc/$identity_init_pid/root$target") == truncate ]]
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: denied truncate left the file length and bytes unchanged."
