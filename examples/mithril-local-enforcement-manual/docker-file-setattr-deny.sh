#!/usr/bin/env bash
set -euo pipefail

# Prepare one ordinary file, then prove chmod is denied before its mode changes.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-local-enforcement-setattr-$$
printf 'mode\n' >"/proc/$identity_init_pid/root$target"
chmod 600 "/proc/$identity_init_pid/root$target"
cleanup_target() { rm -f -- "/proc/$identity_init_pid/root$target"; }
identity_cleanup_functions+=(cleanup_target)
observation_preload_probe python3 -c '
import errno, os, stat, sys
ready, target = sys.argv[1:]
before = stat.S_IMODE(os.stat(target).st_mode)
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    os.chmod(target, 0)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and stat.S_IMODE(os.stat(target).st_mode) == before:
        raise SystemExit(0)
raise SystemExit("denied chmod changed the file mode")
' "$observation_probe_ready" "$target"
observation_release_probe
[[ $(stat -c %a "/proc/$identity_init_pid/root$target") == 600 ]]
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: denied chmod left the exact file mode unchanged."
