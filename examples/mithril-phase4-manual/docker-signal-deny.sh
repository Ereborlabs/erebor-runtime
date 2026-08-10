#!/usr/bin/env bash
set -euo pipefail

# Signal zero has no target-side effect, so success would be an unambiguous
# process-control authorization failure.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import errno, os, signal, sys
ready = sys.argv[1]
read_end, write_end = os.pipe()
target = os.fork()
if target == 0:
    os.close(write_end)
    os.read(read_end, 1)
    os._exit(0)
os.close(read_end)
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.kill(target, 0)
except PermissionError as error:
    denied = error.errno in (errno.EACCES, errno.EPERM)
else:
    denied = False
os.close(write_end)
os.waitpid(target, 0)
if denied:
    raise SystemExit(0)
raise SystemExit("Mithril allowed the signal permission check")
' "$phase3_probe_ready"
phase3_release_probe
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: signal process control was denied without affecting the target."
