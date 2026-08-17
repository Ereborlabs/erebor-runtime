#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

enforcement_path_tree_root=$(dirname -- "$3")
observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import errno, os, sys
ready, path = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    with open(path, "rb") as source:
        source.read(1)
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        os._exit(0)
os._exit(1)
' "$observation_probe_ready" "$3"
observation_release_probe
enforcement_expect_path_tree_denial
identity_pass "PASS: the signed canonical path-tree floor denied the secret before returning an fd or bytes."
