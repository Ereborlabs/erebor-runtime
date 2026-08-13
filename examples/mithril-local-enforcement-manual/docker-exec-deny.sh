#!/usr/bin/env bash
set -euo pipefail

# Start Python before activation, then attempt the signed denied executable.
# The image must never replace the prepared process.
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path> <denied-executable>" >&2
  exit 2
}

observation_extra_exact_path=$4
observation_extra_exact_key=9
observation_extra_exact_class=MANUAL_EXEC
observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import errno, os, sys
ready, executable = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
try:
    os.execv(executable, [os.path.basename(executable)])
except PermissionError as error:
    if error.errno in (errno.EACCES, errno.EPERM):
        raise SystemExit(0)
raise SystemExit("Mithril allowed the signed denied executable image")
' "$observation_probe_ready" "$4"
observation_release_probe
enforcement_expect_exact_denial
identity_pass "PASS: the signed denied executable image never replaced the prepared task."
