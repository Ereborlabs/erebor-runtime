#!/usr/bin/env bash
set -euo pipefail

# Fork the target before activation so the test cannot depend on post-policy
# allocation. A parent ptrace of its child is normally valid; Mithril denies it.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import ctypes, errno, os, sys
ready = sys.argv[1]
read_end, write_end = os.pipe()
target = os.fork()
if target == 0:
    os.close(write_end)
    os.read(read_end, 1)
    os._exit(0)
os.close(read_end)
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
libc = ctypes.CDLL(None, use_errno=True)
result = libc.ptrace(16, target, None, None)
error = ctypes.get_errno()
os.close(write_end)
os.waitpid(target, 0)
if result == -1 and error in (errno.EACCES, errno.EPERM):
    raise SystemExit(0)
raise SystemExit("Mithril allowed ptrace attachment")
' "$observation_probe_ready"
observation_release_probe
enforcement_expect_exact_denial
identity_pass "PASS: the exact process-control rule denied ptrace of the labeled target."
