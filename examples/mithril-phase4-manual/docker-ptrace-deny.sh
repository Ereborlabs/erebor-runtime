#!/usr/bin/env bash
set -euo pipefail

# Fork the target before activation so the test cannot depend on post-policy
# allocation. A parent ptrace of its child is normally valid; Mithril denies it.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_preload_probe python3 -c '
import ctypes, errno, os, signal, sys
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
libc = ctypes.CDLL(None, use_errno=True)
result = libc.ptrace(16, target, None, None)
error = ctypes.get_errno()
os.close(write_end)
os.waitpid(target, 0)
if result == -1 and error in (errno.EACCES, errno.EPERM):
    raise SystemExit(0)
raise SystemExit("Mithril allowed ptrace attachment")
' "$phase3_probe_ready"
phase3_release_probe
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: ptrace could not attach to the prepared target."
