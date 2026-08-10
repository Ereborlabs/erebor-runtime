#!/usr/bin/env bash
set -euo pipefail

# The physical oracle is absence: an EACCES returned after creating the file
# would still fail this case.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
target=/tmp/mithril-phase4-create-$$
cleanup_target() { rm -f -- "/proc/$phase2_init_pid/root$target"; }
phase2_cleanup_functions+=(cleanup_target)
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready, target = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and not os.path.exists(target):
        raise SystemExit(0)
else:
    os.close(descriptor)
raise SystemExit("denied creation left an object behind")
' "$phase3_probe_ready" "$target"
phase3_release_probe
[[ ! -e /proc/$phase2_init_pid/root$target ]]
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: denied file creation left no filesystem object."
