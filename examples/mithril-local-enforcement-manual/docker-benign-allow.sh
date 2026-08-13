#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
[[ $# -eq 4 ]] || {
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path> <absolute-benign-path>" >&2
  exit 2
}

enforcement_benign_path=$4
observation_prepare_docker "$1" "$2" "$3"
observation_preload_probe python3 -c '
import mmap, os, sys
ready, path = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
with open(path, "rb") as source:
    if source.read() != b"benign\n":
        raise SystemExit("benign control returned unexpected bytes")
    source.seek(0)
    with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapping:
        if mapping[:] != b"benign\n":
            raise SystemExit("benign mapping returned unexpected bytes")
' "$observation_probe_ready" "$enforcement_benign_path"
observation_release_probe
observation_wait_for_observation 'reason=EXACT_POLICY_ALLOW' "$identity_work/effects.txt"
identity_pass "PASS: the exact benign file remained readable and mappable in protect mode."
