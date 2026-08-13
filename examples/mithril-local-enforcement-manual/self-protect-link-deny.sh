#!/usr/bin/env bash
set -euo pipefail

# This probe runs on the host, is moved into the protected cgroup while policy
# is inactive, then tries to unlink Mithril's real pinned file-open LSM link.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

observation_prepare_docker "$1" "$2" "$3"
observation_begin_preload
host_ready=/proc/$identity_init_pid/root$observation_probe_ready
host_release=/proc/$identity_init_pid/root$observation_probe_release
target=$identity_pin_root/links/erebor_identity_file_open
MITHRIL_MANUAL_RELEASE=$host_release python3 -c '
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
    if error.errno in (errno.EACCES, errno.EPERM) and os.path.exists(target):
        raise SystemExit(0)
raise SystemExit("Mithril allowed removal of its pinned LSM link")
' "$host_ready" "$target" &
observation_probe_pid=$!
observation_finish_preload true
[[ -e $target ]]
observation_release_probe
[[ -e $target ]]
enforcement_expect_hard_close UNSUPPORTED_OBJECT
identity_pass "PASS: the protected task could not remove Mithril's pinned LSM link."
