#!/usr/bin/env bash
set -euo pipefail

# This probe runs on the host, is moved into the protected cgroup while policy
# is inactive, then tries to unlink Mithril's real pinned file-open LSM link.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase3_begin_preload
host_ready=/proc/$phase2_init_pid/root$phase3_probe_ready
target=$phase2_pin_root/links/erebor_identity_file_open
python3 -c '
import errno, os, signal, sys
ready, target = sys.argv[1:]
signal.signal(signal.SIGUSR1, lambda _signum, _frame: None)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
signal.pause()
try:
    os.unlink(target)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM) and os.path.exists(target):
        raise SystemExit(0)
raise SystemExit("Mithril allowed removal of its pinned LSM link")
' "$host_ready" "$target" &
phase3_probe_pid=$!
phase3_finish_preload true
[[ -e $target ]]
phase3_release_probe
[[ -e $target ]]
phase4_expect_hard_close UNSUPPORTED_OBJECT
phase2_pass "PASS: the protected task could not remove Mithril's pinned LSM link."
