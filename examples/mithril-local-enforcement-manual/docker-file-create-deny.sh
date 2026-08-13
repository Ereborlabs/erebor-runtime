#!/usr/bin/env bash
set -euo pipefail

# The physical oracle is absence: an EACCES returned after creating the file
# would still fail this case.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-local-enforcement-create-$$
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
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and not os.path.exists(target):
        raise SystemExit(0)
else:
    os.close(descriptor)
raise SystemExit("denied creation left an object behind")
' "$observation_probe_ready" "$target"
observation_release_probe
[[ ! -e /proc/$identity_init_pid/root$target ]]
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: denied file creation left no filesystem object."
